"""Safe JBD2 journal replay for internal EXT4 journals.

This module implements the recovery subset needed before enabling direct writes
from Windows.  It intentionally fails closed: unsupported journal features,
checksum errors, malformed tags, out-of-range block numbers, or incomplete
transactions leave the filesystem untouched and the caller can mount read-only.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ext4lib.fs import constants as C
from ext4lib.fs.crc32c import crc32c
from ext4lib.debuglog import LOG
from ext4lib.fs.extents import Extent, file_extents
from ext4lib.fs.superblock import parse_superblock

if TYPE_CHECKING:
    from ext4lib.fs.volume import Ext4Volume


JBD2_DESCRIPTOR_BLOCK = 1
JBD2_COMMIT_BLOCK = 2
JBD2_REVOKE_BLOCK = 5
JBD2_FC_BLOCK = 6

JBD2_FLAG_ESCAPE = 0x1
JBD2_FLAG_SAME_UUID = 0x2
JBD2_FLAG_DELETED = 0x4
JBD2_FLAG_LAST_TAG = 0x8

JBD2_FEATURE_COMPAT_CHECKSUM = 0x1

JBD2_FEATURE_INCOMPAT_REVOKE = 0x1
JBD2_FEATURE_INCOMPAT_64BIT = 0x2
JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT = 0x4
JBD2_FEATURE_INCOMPAT_CSUM_V2 = 0x8
JBD2_FEATURE_INCOMPAT_CSUM_V3 = 0x10
JBD2_FEATURE_INCOMPAT_FAST_COMMIT = 0x20

JBD2_KNOWN_INCOMPAT = (
    JBD2_FEATURE_INCOMPAT_REVOKE
    | JBD2_FEATURE_INCOMPAT_64BIT
    | JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT
    | JBD2_FEATURE_INCOMPAT_CSUM_V2
    | JBD2_FEATURE_INCOMPAT_CSUM_V3
    | JBD2_FEATURE_INCOMPAT_FAST_COMMIT
)

JBD2_CRC32C_CHKSUM = 4


class JournalRecoveryError(RuntimeError):
    """Journal cannot be replayed safely by this implementation."""


class JournalWriteError(RuntimeError):
    """A new JBD2 transaction cannot be written safely."""


@dataclass(frozen=True)
class JournalInfo:
    block_size: int
    maxlen: int
    first: int
    sequence: int
    start: int
    feature_compat: int
    feature_incompat: int
    feature_ro_compat: int
    uuid: bytes
    checksum_type: int
    nr_users: int


@dataclass(frozen=True)
class JournalTag:
    target_block: int
    flags: int
    checksum: int
    journal_block: int


@dataclass
class JournalTransaction:
    sequence: int
    writes: list[JournalTag] = field(default_factory=list)
    revokes: set[int] = field(default_factory=set)


@dataclass(frozen=True)
class ReplayStats:
    transactions: int
    replayed_blocks: int
    revoked_blocks: int
    next_sequence: int


class _JournalLog:
    def __init__(self, vol: "Ext4Volume"):
        if not vol.dev.writable:
            raise JournalRecoveryError("장치를 쓰기 가능으로 열어야 저널을 복구할 수 있습니다.")
        if not vol.sb.has_journal:
            raise JournalRecoveryError("이 파일시스템에는 내부 저널이 없습니다.")
        if not vol.sb.journal_inum:
            raise JournalRecoveryError("외부 저널은 지원하지 않습니다.")

        self.vol = vol
        self.fs_block_size = vol.sb.block_size
        inode = vol.read_inode(vol.sb.journal_inum)
        self.extents = [
            Extent(e.logical, e.length, e.physical, e.uninitialized)
            for e in file_extents(vol, inode)
        ]
        if not self.extents:
            raise JournalRecoveryError("저널 inode의 블록 매핑을 찾지 못했습니다.")
        if any(e.uninitialized or e.length <= 0 for e in self.extents):
            raise JournalRecoveryError("저널 inode에 초기화되지 않은 extent가 있습니다.")

        sb_block = self.read_block(0)
        if len(sb_block) < 1024:
            raise JournalRecoveryError("JBD2 슈퍼블록이 너무 짧습니다.")
        self.super_raw = bytearray(sb_block[:1024])
        self.info = self._parse_superblock(self.super_raw)
        self._validate_layout(inode.size)
        self.csum_seed = crc32c(0xFFFFFFFF, self.info.uuid)

    def _physical(self, logical: int) -> int:
        for ex in self.extents:
            if ex.logical <= logical < ex.logical + ex.length:
                return ex.physical + (logical - ex.logical)
        raise JournalRecoveryError(f"저널 논리 블록 {logical}의 실제 위치를 찾지 못했습니다.")

    def read_block(self, logical: int) -> bytes:
        return self.vol.read_block(self._physical(logical))

    def write_superblock(self, raw: bytes) -> None:
        if len(raw) != 1024:
            raise JournalRecoveryError("JBD2 슈퍼블록 크기가 잘못되었습니다.")
        phys = self._physical(0)
        self.vol.write_bytes(phys * self.fs_block_size, raw)

    @staticmethod
    def _parse_superblock(raw: bytes) -> JournalInfo:
        magic, blocktype, _seq = struct.unpack_from(">III", raw, 0)
        if magic != C.JBD2_MAGIC_NUMBER:
            raise JournalRecoveryError("JBD2 매직 값이 올바르지 않습니다.")
        if blocktype not in (C.JBD2_SUPERBLOCK_V1, C.JBD2_SUPERBLOCK_V2):
            raise JournalRecoveryError(f"지원하지 않는 JBD2 슈퍼블록 형식입니다: {blocktype}")

        block_size, maxlen, first, sequence, start = struct.unpack_from(">IIIII", raw, 0x0C)
        if blocktype == C.JBD2_SUPERBLOCK_V2:
            compat, incompat, ro_compat = struct.unpack_from(">III", raw, 0x24)
            uuid = bytes(raw[0x30:0x40])
            nr_users = struct.unpack_from(">I", raw, 0x40)[0]
            checksum_type = raw[0x50]
        else:
            compat = incompat = ro_compat = 0
            uuid = bytes(raw[0x30:0x40])
            nr_users = 1
            checksum_type = 0

        return JournalInfo(
            block_size=block_size,
            maxlen=maxlen,
            first=first,
            sequence=sequence,
            start=start,
            feature_compat=compat,
            feature_incompat=incompat,
            feature_ro_compat=ro_compat,
            uuid=uuid,
            checksum_type=checksum_type,
            nr_users=nr_users,
        )

    def _validate_layout(self, journal_inode_size: int) -> None:
        i = self.info
        if i.block_size != self.fs_block_size:
            raise JournalRecoveryError(
                f"내부 저널 블록 크기({i.block_size})와 EXT4 블록 크기({self.fs_block_size})가 다릅니다."
            )
        if i.maxlen <= 1 or i.first <= 0 or i.first >= i.maxlen:
            raise JournalRecoveryError("JBD2 저널 범위가 올바르지 않습니다.")
        inode_blocks = (journal_inode_size + self.fs_block_size - 1) // self.fs_block_size
        if i.maxlen > inode_blocks:
            raise JournalRecoveryError("JBD2 s_maxlen이 저널 inode 크기를 벗어납니다.")
        if i.start and not (i.first <= i.start < i.maxlen):
            raise JournalRecoveryError("JBD2 s_start가 저널 범위를 벗어납니다.")
        if i.nr_users not in (0, 1):
            raise JournalRecoveryError("여러 파일시스템이 공유하는 저널은 지원하지 않습니다.")
        if i.feature_ro_compat:
            raise JournalRecoveryError(
                f"알 수 없는 JBD2 ro_compat 기능(0x{i.feature_ro_compat:X})이 있습니다."
            )

        unknown = i.feature_incompat & ~JBD2_KNOWN_INCOMPAT
        if unknown:
            raise JournalRecoveryError(f"알 수 없는 JBD2 incompat 기능(0x{unknown:X})이 있습니다.")
        if i.feature_incompat & JBD2_FEATURE_INCOMPAT_FAST_COMMIT:
            raise JournalRecoveryError("JBD2 fast-commit 저널은 아직 안전하게 복구할 수 없습니다.")

        csum2 = bool(i.feature_incompat & JBD2_FEATURE_INCOMPAT_CSUM_V2)
        csum3 = bool(i.feature_incompat & JBD2_FEATURE_INCOMPAT_CSUM_V3)
        if csum2 and csum3:
            raise JournalRecoveryError("JBD2 checksum v2와 v3가 동시에 설정되어 있습니다.")
        if (csum2 or csum3) and i.checksum_type != JBD2_CRC32C_CHKSUM:
            raise JournalRecoveryError(
                f"지원하지 않는 JBD2 checksum 형식입니다: {i.checksum_type}"
            )
        if (i.feature_compat & JBD2_FEATURE_COMPAT_CHECKSUM) and not (csum2 or csum3):
            # v1 uses crc32-be over a transaction stream. Failing closed is safer
            # than replaying a transaction that we cannot verify.
            raise JournalRecoveryError("JBD2 checksum v1 저널은 아직 지원하지 않습니다.")

        if csum2 or csum3:
            provided = struct.unpack_from(">I", self.super_raw, 0xFC)[0]
            tmp = bytearray(self.super_raw)
            struct.pack_into(">I", tmp, 0xFC, 0)
            calculated = crc32c(0xFFFFFFFF, tmp)
            if provided != calculated:
                raise JournalRecoveryError(
                    f"JBD2 슈퍼블록 checksum 오류: disk=0x{provided:08X} calc=0x{calculated:08X}"
                )

    @property
    def has_csum2(self) -> bool:
        return bool(self.info.feature_incompat & JBD2_FEATURE_INCOMPAT_CSUM_V2)

    @property
    def has_csum3(self) -> bool:
        return bool(self.info.feature_incompat & JBD2_FEATURE_INCOMPAT_CSUM_V3)

    @property
    def has_csum(self) -> bool:
        return self.has_csum2 or self.has_csum3

    @property
    def has_64bit(self) -> bool:
        return bool(self.info.feature_incompat & JBD2_FEATURE_INCOMPAT_64BIT)

    def next_block(self, block: int) -> int:
        block += 1
        if block >= self.info.maxlen:
            block = self.info.first
        return block

    def _verify_descriptor_checksum(self, block: bytes, what: str) -> None:
        if not self.has_csum:
            return
        provided = struct.unpack_from(">I", block, self.fs_block_size - 4)[0]
        tmp = bytearray(block)
        struct.pack_into(">I", tmp, self.fs_block_size - 4, 0)
        calculated = crc32c(self.csum_seed, tmp)
        if provided != calculated:
            raise JournalRecoveryError(
                f"{what} checksum 오류: disk=0x{provided:08X} calc=0x{calculated:08X}"
            )

    def _verify_commit_checksum(self, block: bytes) -> None:
        if not self.has_csum:
            return
        if len(block) < 0x14:
            raise JournalRecoveryError("JBD2 commit 블록이 너무 짧습니다.")

        # For JBD2 checksum v2/v3 Linux deliberately stores h_chksum_type=0
        # and h_chksum_size=0 in commit_header, then places the CRC32C in
        # h_chksum[0] (offset 0x10).  The type/size fields are used by the
        # legacy v1 transaction checksum path, not by v2/v3.
        provided = struct.unpack_from(">I", block, 0x10)[0]
        tmp = bytearray(block)
        struct.pack_into(">I", tmp, 0x10, 0)
        calculated = crc32c(self.csum_seed, tmp)
        if provided != calculated:
            raise JournalRecoveryError(
                f"JBD2 commit checksum 오류: disk=0x{provided:08X} calc=0x{calculated:08X}"
            )

    def _tag_bytes(self) -> int:
        if self.has_csum3:
            return 16
        size = 12
        if self.has_csum2:
            size += 2
        if not self.has_64bit:
            size -= 4
        return size

    def parse_descriptor(self, block: bytes) -> list[tuple[int, int, int]]:
        self._verify_descriptor_checksum(block, "JBD2 descriptor")
        tag_bytes = self._tag_bytes()
        limit = self.fs_block_size - (4 if self.has_csum else 0)
        off = 12
        out: list[tuple[int, int, int]] = []

        while off + tag_bytes <= limit:
            if self.has_csum3:
                lo, flags, hi, checksum = struct.unpack_from(">IIII", block, off)
                if not self.has_64bit:
                    hi = 0
            else:
                lo = struct.unpack_from(">I", block, off)[0]
                checksum = struct.unpack_from(">H", block, off + 4)[0]
                flags = struct.unpack_from(">H", block, off + 6)[0]
                hi = struct.unpack_from(">I", block, off + 8)[0] if self.has_64bit else 0

            target = (hi << 32) | lo
            off += tag_bytes
            if not (flags & JBD2_FLAG_SAME_UUID):
                if off + 16 > limit:
                    raise JournalRecoveryError("JBD2 descriptor UUID가 블록 끝을 벗어납니다.")
                off += 16
            out.append((target, flags, checksum))
            if flags & JBD2_FLAG_LAST_TAG:
                break

        if not out or not (out[-1][1] & JBD2_FLAG_LAST_TAG):
            raise JournalRecoveryError("JBD2 descriptor의 마지막 tag를 찾지 못했습니다.")
        return out

    def data_checksum(self, sequence: int, block: bytes) -> int:
        if not self.has_csum:
            return 0
        crc = crc32c(self.csum_seed, struct.pack(">I", sequence & 0xFFFFFFFF))
        return crc32c(crc, block)

    def verify_data_checksum(self, sequence: int, block: bytes, checksum: int) -> None:
        if not self.has_csum:
            return
        crc = self.data_checksum(sequence, block)
        if self.has_csum3:
            ok = checksum == crc
            expected = f"0x{checksum:08X}"
        else:
            ok = checksum == (crc & 0xFFFF)
            expected = f"0x{checksum:04X}"
        if not ok:
            raise JournalRecoveryError(
                f"JBD2 data checksum 오류: disk={expected} calc=0x{crc:08X}"
            )

    def build_descriptor(
        self, sequence: int, target_block: int, block: bytes
    ) -> tuple[bytes, bytes]:
        """Build a one-tag descriptor and the exact journal data image.

        Using one descriptor per metadata block is deliberately conservative:
        it avoids tag packing ambiguity across checksum/64-bit variants while
        remaining fully valid JBD2. The transaction writer still batches all
        descriptors under one commit record.
        """
        if len(block) != self.fs_block_size:
            raise JournalWriteError("JBD2 metadata block size가 파일시스템 블록 크기와 다릅니다.")

        stored = bytearray(block)
        flags = JBD2_FLAG_LAST_TAG
        if struct.unpack_from(">I", stored, 0)[0] == C.JBD2_MAGIC_NUMBER:
            struct.pack_into(">I", stored, 0, 0)
            flags |= JBD2_FLAG_ESCAPE

        checksum = self.data_checksum(sequence, bytes(stored))
        tag_bytes = self._tag_bytes()
        tail = 4 if self.has_csum else 0
        need = 12 + tag_bytes + 16 + tail
        if need > self.fs_block_size:
            raise JournalWriteError("JBD2 descriptor에 tag와 UUID를 넣을 공간이 없습니다.")

        desc = bytearray(self.fs_block_size)
        struct.pack_into(
            ">III",
            desc,
            0,
            C.JBD2_MAGIC_NUMBER,
            JBD2_DESCRIPTOR_BLOCK,
            sequence & 0xFFFFFFFF,
        )
        off = 12
        lo = target_block & 0xFFFFFFFF
        hi = (target_block >> 32) & 0xFFFFFFFF
        if self.has_csum3:
            struct.pack_into(">IIII", desc, off, lo, flags, hi if self.has_64bit else 0, checksum)
        else:
            struct.pack_into(">IHH", desc, off, lo, checksum & 0xFFFF, flags & 0xFFFF)
            if self.has_64bit:
                struct.pack_into(">I", desc, off + 8, hi)
            # checksum-v2's on-disk tag length contains two historical
            # compatibility bytes beyond the fields parsed above. The buffer is
            # zero-filled, so advancing by _tag_bytes() produces Linux's layout.
        off += tag_bytes
        desc[off : off + 16] = self.info.uuid

        if self.has_csum:
            struct.pack_into(">I", desc, self.fs_block_size - 4, 0)
            csum = crc32c(self.csum_seed, desc)
            struct.pack_into(">I", desc, self.fs_block_size - 4, csum)
        return bytes(desc), bytes(stored)

    def build_commit(self, sequence: int) -> bytes:
        block = bytearray(self.fs_block_size)
        struct.pack_into(
            ">III",
            block,
            0,
            C.JBD2_MAGIC_NUMBER,
            JBD2_COMMIT_BLOCK,
            sequence & 0xFFFFFFFF,
        )
        now = time.time_ns()
        struct.pack_into(">Q", block, 0x30, (now // 1_000_000_000) & 0xFFFFFFFFFFFFFFFF)
        struct.pack_into(">I", block, 0x38, (now % 1_000_000_000) & 0xFFFFFFFF)
        if self.has_csum:
            # checksum-v2/v3 leaves h_chksum_type/size zero and stores the
            # CRC32C in h_chksum[0].
            struct.pack_into(">I", block, 0x10, 0)
            csum = crc32c(self.csum_seed, block)
            struct.pack_into(">I", block, 0x10, csum)
        return bytes(block)

    def write_dynamic_super(
        self, *, sequence: int, start: int, head: int | None = None
    ) -> None:
        raw = bytearray(self.super_raw)
        struct.pack_into(">I", raw, 0x18, sequence & 0xFFFFFFFF)
        struct.pack_into(">I", raw, 0x1C, start & 0xFFFFFFFF)
        blocktype = struct.unpack_from(">I", raw, 4)[0]
        if head is not None and blocktype == C.JBD2_SUPERBLOCK_V2:
            struct.pack_into(">I", raw, 0x58, head & 0xFFFFFFFF)
        if self.has_csum:
            struct.pack_into(">I", raw, 0xFC, 0)
            csum = crc32c(0xFFFFFFFF, raw)
            struct.pack_into(">I", raw, 0xFC, csum)
        self.write_superblock(bytes(raw))
        self.super_raw = raw

    def parse_revokes(self, block: bytes) -> set[int]:
        self._verify_descriptor_checksum(block, "JBD2 revoke")
        if len(block) < 16:
            raise JournalRecoveryError("JBD2 revoke 블록이 너무 짧습니다.")
        count = struct.unpack_from(">I", block, 12)[0]
        tail = 4 if self.has_csum else 0
        if count < 16 or count > self.fs_block_size - tail:
            raise JournalRecoveryError("JBD2 revoke r_count가 올바르지 않습니다.")
        rec_len = 8 if self.has_64bit else 4
        if (count - 16) % rec_len:
            raise JournalRecoveryError("JBD2 revoke record 길이가 올바르지 않습니다.")

        out: set[int] = set()
        off = 16
        while off < count:
            if rec_len == 8:
                blocknr = struct.unpack_from(">Q", block, off)[0]
            else:
                blocknr = struct.unpack_from(">I", block, off)[0]
            out.add(blocknr)
            off += rec_len
        return out

    def scan_transactions(self) -> tuple[list[JournalTransaction], int, int]:
        if self.info.start == 0:
            return [], self.info.sequence, 0

        cursor = self.info.start
        sequence = self.info.sequence
        scanned = 0
        transactions: list[JournalTransaction] = []
        current = JournalTransaction(sequence=sequence)
        # A valid log cannot consume more than the ring once without hitting
        # stale data. This also prevents malformed journals from looping forever.
        budget = self.info.maxlen - self.info.first

        while scanned < budget:
            block = self.read_block(cursor)
            if len(block) != self.fs_block_size:
                raise JournalRecoveryError("JBD2 블록 읽기 길이가 올바르지 않습니다.")
            magic, blocktype, blockseq = struct.unpack_from(">III", block, 0)
            if magic != C.JBD2_MAGIC_NUMBER or blockseq != sequence:
                break

            if blocktype == JBD2_DESCRIPTOR_BLOCK:
                tags = self.parse_descriptor(block)
                cursor = self.next_block(cursor)
                scanned += 1
                for target, flags, checksum in tags:
                    if scanned >= budget:
                        return transactions, sequence, cursor
                    if target >= self.vol.sb.blocks_count:
                        raise JournalRecoveryError(
                            f"저널 tag의 대상 블록 {target}가 EXT4 범위를 벗어납니다."
                        )
                    data_log_block = cursor
                    data = self.read_block(data_log_block)
                    self.verify_data_checksum(sequence, data, checksum)
                    current.writes.append(
                        JournalTag(
                            target_block=target,
                            flags=flags,
                            checksum=checksum,
                            journal_block=data_log_block,
                        )
                    )
                    cursor = self.next_block(cursor)
                    scanned += 1
                continue

            if blocktype == JBD2_REVOKE_BLOCK:
                current.revokes.update(self.parse_revokes(block))
                cursor = self.next_block(cursor)
                scanned += 1
                continue

            if blocktype == JBD2_COMMIT_BLOCK:
                self._verify_commit_checksum(block)
                transactions.append(current)
                cursor = self.next_block(cursor)
                scanned += 1
                sequence = (sequence + 1) & 0xFFFFFFFF
                current = JournalTransaction(sequence=sequence)
                continue

            if blocktype == JBD2_FC_BLOCK:
                raise JournalRecoveryError("JBD2 fast-commit 블록을 발견했습니다.")

            break

        # current is deliberately discarded: without a matching commit block the
        # transaction is not durable and must not be replayed.
        return transactions, sequence, cursor

    def mark_clean(self, next_sequence: int, head: int | None = None) -> None:
        self.write_dynamic_super(sequence=next_sequence, start=0, head=head)


class JournalWriter:
    """Synchronous metadata-only JBD2 writer.

    The implementation intentionally keeps at most one live transaction.
    File data is flushed to its home blocks first (ordered mode), metadata is
    written to the journal and committed, then checkpointed synchronously to
    home blocks. Before the next transaction the journal tail is advanced only
    after the previous checkpoint is durable.
    """

    def __init__(self, vol: "Ext4Volume"):
        try:
            self.log = _JournalLog(vol)
        except JournalRecoveryError as exc:
            raise JournalWriteError(str(exc)) from exc
        if self.log.info.start != 0:
            raise JournalWriteError("미복구 JBD2 transaction이 남아 있어 새 transaction을 시작할 수 없습니다.")
        self.vol = vol
        head = self.log.info.first
        blocktype = struct.unpack_from(">I", self.log.super_raw, 4)[0]
        if blocktype == C.JBD2_SUPERBLOCK_V2:
            disk_head = struct.unpack_from(">I", self.log.super_raw, 0x58)[0]
            if self.log.info.first <= disk_head < self.log.info.maxlen:
                head = disk_head
        self.head = head
        self.sequence = (self.log.info.sequence + 1) & 0xFFFFFFFF
        self.last_sequence = self.log.info.sequence & 0xFFFFFFFF
        self.committed = False

    def _next(self, block: int) -> int:
        return self.log.next_block(block)

    def _write_log_block(self, logical: int, data: bytes) -> None:
        if len(data) != self.log.fs_block_size:
            raise JournalWriteError("JBD2 log block 크기가 올바르지 않습니다.")
        phys = self.log._physical(logical)
        self.vol.write_bytes(phys * self.log.fs_block_size, data)

    def _declare(self, sequence: int, start: int) -> None:
        # EXT4 must advertise recovery before a new transaction can become
        # durable. A crash in this window is safe: recovery will see either the
        # previous checkpointed transaction or an incomplete new transaction.
        if not self.vol.sb.needs_recovery:
            self.vol._set_home_super_flags(recover=True, valid=False, flush=True)
        self.log.write_dynamic_super(sequence=sequence, start=start)
        self.vol.dev.flush()
        self.vol._data_dirty = False
        # The EXT4 superblock itself is metadata. Keep the journaled copy in
        # sync with the direct RECOVER flag update without leaking other pending
        # metadata to its home location.
        self.vol._refresh_pending_superblock()

    def commit(self) -> int:
        """Commit pending metadata and checkpoint it to home blocks."""
        if not self.vol._metadata_overlay:
            if self.vol._data_dirty:
                self.vol.dev.flush()
                self.vol._data_dirty = False
            return 0

        # ordered mode: file data reaches stable storage before the metadata
        # transaction that can make those blocks reachable.
        self.vol.dev.flush()
        self.vol._data_dirty = False

        sequence = self.sequence
        start = self.head
        self._declare(sequence, start)
        metadata = {
            block: bytes(data)
            for block, data in sorted(self.vol._metadata_overlay.items())
        }
        needed = len(metadata) * 2 + 1
        capacity = self.log.info.maxlen - self.log.info.first
        if needed >= capacity:
            raise JournalWriteError(
                f"JBD2 transaction이 저널보다 큽니다: need={needed} capacity={capacity}"
            )
        for target in metadata:
            if target < 0 or target >= self.vol.sb.blocks_count:
                raise JournalWriteError(f"JBD2 대상 블록이 EXT4 범위를 벗어났습니다: {target}")

        cursor = start
        for target, home_image in metadata.items():
            descriptor, journal_image = self.log.build_descriptor(
                sequence, target, home_image
            )
            self._write_log_block(cursor, descriptor)
            cursor = self._next(cursor)
            self._write_log_block(cursor, journal_image)
            cursor = self._next(cursor)

        # Descriptor + metadata copies must be durable before the commit record.
        self.vol.dev.flush()
        self.vol._data_dirty = False

        commit_block = self.log.build_commit(sequence)
        self._write_log_block(cursor, commit_block)
        cursor = self._next(cursor)
        self.vol.dev.flush()
        self.vol._data_dirty = False

        # Only a committed transaction may reach the metadata home locations.
        self.vol._checkpoint_metadata_blocks(metadata)
        self.vol.dev.flush()
        self.vol._data_dirty = False
        self.vol._metadata_overlay.clear()

        self.head = cursor
        self.last_sequence = sequence
        self.sequence = (sequence + 1) & 0xFFFFFFFF
        self.committed = True
        LOG.info(
            "JBD2 write commit 완료 sequence=%s metadata_blocks=%s next_head=%s",
            sequence,
            len(metadata),
            self.head,
        )
        return len(metadata)

    def mark_clean(self) -> None:
        """Mark the journal empty after the final metadata checkpoint."""
        if not self.committed and not self.vol.sb.needs_recovery:
            return
        self.log.mark_clean(self.last_sequence, head=self.head)
        self.vol.dev.flush()
        self.vol._data_dirty = False
        self.committed = False


def _tid_geq(x: int, y: int) -> bool:
    """JBD2 transaction-id comparison with 32-bit wraparound."""
    diff = (x - y) & 0xFFFFFFFF
    return diff == 0 or diff < 0x80000000


def _clear_ext4_recovery_flag(vol: "Ext4Volume") -> None:
    raw = vol.dev.read(vol.part_offset + 1024, 1024)
    sb = parse_superblock(raw)
    sb.feature_incompat &= ~C.EXT4_FEATURE_INCOMPAT_RECOVER
    struct.pack_into("<I", sb.raw, 0x60, sb.feature_incompat)
    sb.state |= C.EXT4_VALID_FS
    struct.pack_into("<H", sb.raw, 0x3A, sb.state)
    sb.write_checksum()
    vol.dev.write(vol.part_offset + 1024, bytes(sb.raw[:1024]))


def recover_journal(vol: "Ext4Volume") -> ReplayStats:
    """Replay committed JBD2 transactions, then mark the journal clean.

    The operation is intentionally ordered so that a power loss before the
    journal is marked clean merely causes an idempotent replay on the next run.
    """

    log = _JournalLog(vol)
    if log.info.start == 0:
        # Linux JBD2 treats a zero journal tail as "no recovery required".
        # RECOVER can remain set if power is lost between cleaning the journal
        # superblock and clearing the EXT4 flag, so clear that flag here.
        if vol.sb.needs_recovery:
            _clear_ext4_recovery_flag(vol)
            vol.dev.flush()
            vol.reload_metadata()
        return ReplayStats(0, 0, 0, log.info.sequence)

    transactions, next_sequence, _head = log.scan_transactions()
    if not transactions:
        # A declared transaction without a commit record is intentionally
        # discarded by JBD2. No metadata from it has reached home through our
        # writer, so invalidate the incomplete log and clear RECOVER.
        log.mark_clean(log.info.sequence, head=_head or log.info.first)
        _clear_ext4_recovery_flag(vol)
        vol.dev.flush()
        vol.reload_metadata()
        LOG.warning("미완료 JBD2 transaction을 버리고 저널을 clean 상태로 되돌렸습니다.")
        return ReplayStats(0, 0, 0, log.info.sequence)

    # Recovery uses a separate revoke pass. A revoke from a later transaction
    # suppresses replay of the same filesystem block from an earlier transaction.
    revoke_table: dict[int, int] = {}
    for tx in transactions:
        for blocknr in tx.revokes:
            prev = revoke_table.get(blocknr)
            if prev is None or _tid_geq(tx.sequence, prev):
                revoke_table[blocknr] = tx.sequence

    replayed = 0
    revoked = 0
    for tx in transactions:
        for tag in tx.writes:
            revoke_seq = revoke_table.get(tag.target_block)
            if revoke_seq is not None and _tid_geq(revoke_seq, tx.sequence):
                revoked += 1
                continue

            data = bytearray(log.read_block(tag.journal_block))
            log.verify_data_checksum(tx.sequence, data, tag.checksum)
            if tag.flags & JBD2_FLAG_ESCAPE:
                struct.pack_into(">I", data, 0, C.JBD2_MAGIC_NUMBER)
            vol.write_block(tag.target_block, bytes(data))
            replayed += 1

    # First make replayed metadata durable. If power is lost here, repeating the
    # replay is safe. Only afterwards clear the journal and EXT4 recovery flag.
    vol.dev.flush()
    log.mark_clean(next_sequence, head=_head)
    _clear_ext4_recovery_flag(vol)
    vol.dev.flush()
    vol.reload_metadata()

    LOG.info(
        "JBD2 복구 완료 transactions=%s replayed=%s revoked=%s next_sequence=%s",
        len(transactions),
        replayed,
        revoked,
        next_sequence,
    )
    return ReplayStats(len(transactions), replayed, revoked, next_sequence)
