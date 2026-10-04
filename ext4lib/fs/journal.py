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


@dataclass(frozen=True)
class JournalWriteStats:
    sequence: int
    journal_blocks: int
    checkpointed_blocks: int
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

    def write_block(self, logical: int, data: bytes) -> None:
        if len(data) != self.fs_block_size:
            raise JournalWriteError("JBD2 블록은 파일시스템 블록 크기와 같아야 합니다.")
        self.vol.write_block(self._physical(logical), data)

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

    def verify_data_checksum(self, sequence: int, block: bytes, checksum: int) -> None:
        if not self.has_csum:
            return
        crc = crc32c(self.csum_seed, struct.pack(">I", sequence & 0xFFFFFFFF))
        crc = crc32c(crc, block)
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

    def _write_dynamic_super(self, sequence: int, start: int) -> None:
        raw = bytearray(self.super_raw)
        struct.pack_into(">I", raw, 0x18, sequence & 0xFFFFFFFF)
        struct.pack_into(">I", raw, 0x1C, start & 0xFFFFFFFF)
        if len(raw) >= 0x5C:
            struct.pack_into(">I", raw, 0x58, (start if start else self.info.first) & 0xFFFFFFFF)
        if self.has_csum:
            struct.pack_into(">I", raw, 0xFC, 0)
            csum = crc32c(0xFFFFFFFF, raw)
            struct.pack_into(">I", raw, 0xFC, csum)
        self.write_superblock(bytes(raw))
        self.super_raw = raw

    def mark_active(self, sequence: int, start: int) -> None:
        if not (self.info.first <= start < self.info.maxlen):
            raise JournalWriteError("JBD2 transaction 시작 블록이 저널 범위를 벗어납니다.")
        self._write_dynamic_super(sequence, start)

    def mark_clean(self, next_sequence: int) -> None:
        self._write_dynamic_super(next_sequence, 0)



def _set_ext4_recovery_flag(vol: "Ext4Volume", enabled: bool) -> None:
    """Persist EXT4 RECOVER without claiming the mounted filesystem is clean."""
    raw = bytearray(vol.dev.read(vol.part_offset + 1024, 1024))
    sb = parse_superblock(raw)
    if enabled:
        sb.feature_incompat |= C.EXT4_FEATURE_INCOMPAT_RECOVER
        sb.state &= ~C.EXT4_VALID_FS
    else:
        sb.feature_incompat &= ~C.EXT4_FEATURE_INCOMPAT_RECOVER
    struct.pack_into("<I", sb.raw, 0x60, sb.feature_incompat)
    struct.pack_into("<H", sb.raw, 0x3A, sb.state & 0xFFFF)
    sb.write_checksum()
    vol.dev.write(vol.part_offset + 1024, bytes(sb.raw[:1024]))
    vol.sb.feature_incompat = sb.feature_incompat
    vol.sb.state = sb.state
    vol.sb.raw[:] = sb.raw


def _journal_data_checksum(log: _JournalLog, sequence: int, data: bytes) -> int:
    crc = crc32c(log.csum_seed, struct.pack(">I", sequence & 0xFFFFFFFF))
    return crc32c(crc, data)


def _descriptor_block(
    log: _JournalLog,
    sequence: int,
    entries: list[tuple[int, bytes, int]],
) -> bytes:
    bs = log.fs_block_size
    tail = 4 if log.has_csum else 0
    out = bytearray(bs)
    struct.pack_into(">III", out, 0, C.JBD2_MAGIC_NUMBER, JBD2_DESCRIPTOR_BLOCK, sequence)
    off = 12
    for index, (target, stored, extra_flags) in enumerate(entries):
        flags = extra_flags
        if index:
            flags |= JBD2_FLAG_SAME_UUID
        if index == len(entries) - 1:
            flags |= JBD2_FLAG_LAST_TAG
        checksum = _journal_data_checksum(log, sequence, stored) if log.has_csum else 0
        if log.has_csum3:
            tag = struct.pack(
                ">IIII",
                target & 0xFFFFFFFF,
                flags & 0xFFFFFFFF,
                (target >> 32) & 0xFFFFFFFF if log.has_64bit else 0,
                checksum & 0xFFFFFFFF,
            )
        else:
            tag = struct.pack(
                ">IHH",
                target & 0xFFFFFFFF,
                checksum & 0xFFFF,
                flags & 0xFFFF,
            )
            if log.has_64bit:
                tag += struct.pack(">I", (target >> 32) & 0xFFFFFFFF)
        need = len(tag) + (0 if flags & JBD2_FLAG_SAME_UUID else 16)
        if off + need > bs - tail:
            raise JournalWriteError("JBD2 descriptor 한 블록에 transaction tag가 모두 들어가지 않습니다.")
        out[off : off + len(tag)] = tag
        off += len(tag)
        if not (flags & JBD2_FLAG_SAME_UUID):
            out[off : off + 16] = log.info.uuid
            off += 16
    if log.has_csum:
        struct.pack_into(">I", out, bs - 4, 0)
        struct.pack_into(">I", out, bs - 4, crc32c(log.csum_seed, out))
    return bytes(out)


def _commit_block(log: _JournalLog, sequence: int) -> bytes:
    out = bytearray(log.fs_block_size)
    struct.pack_into(">III", out, 0, C.JBD2_MAGIC_NUMBER, JBD2_COMMIT_BLOCK, sequence)
    now = time.time_ns()
    struct.pack_into(">Q", out, 0x30, now // 1_000_000_000)
    struct.pack_into(">I", out, 0x38, now % 1_000_000_000)
    if log.has_csum:
        struct.pack_into(">I", out, 0x10, 0)
        struct.pack_into(">I", out, 0x10, crc32c(log.csum_seed, out))
    return bytes(out)


def commit_journal_transaction(
    vol: "Ext4Volume",
    writes: list[tuple[int, bytes]] | tuple[tuple[int, bytes], ...],
) -> JournalWriteStats:
    """Commit one JBD2 transaction and checkpoint it to home blocks.

    The first write-side milestone intentionally uses one descriptor block per
    transaction. Oversized requests fail closed instead of spanning descriptors.
    """
    if not writes:
        raise JournalWriteError("빈 JBD2 transaction은 기록하지 않습니다.")
    log = _JournalLog(vol)
    if log.info.start != 0 or vol.sb.needs_recovery:
        raise JournalWriteError("미복구 JBD2 transaction이 남아 있어 새 transaction을 시작할 수 없습니다.")
    if log.info.feature_incompat & JBD2_FEATURE_INCOMPAT_FAST_COMMIT:
        raise JournalWriteError("fast-commit 저널에는 신규 transaction을 기록하지 않습니다.")

    sequence = log.info.sequence & 0xFFFFFFFF
    normalized: list[tuple[int, bytes, int]] = []
    journal_phys = {log._physical(i) for i in range(log.info.maxlen)}
    seen: set[int] = set()
    originals: list[tuple[int, bytes]] = []
    for target, block in writes:
        if target in seen:
            raise JournalWriteError(f"같은 대상 블록이 transaction에 두 번 포함되었습니다: {target}")
        seen.add(target)
        if target < 0 or target >= vol.sb.blocks_count:
            raise JournalWriteError(f"대상 블록이 EXT4 범위를 벗어납니다: {target}")
        if target in journal_phys:
            raise JournalWriteError("내부 journal 자체를 transaction 대상으로 사용할 수 없습니다.")
        original = bytes(block)
        if len(original) != log.fs_block_size:
            raise JournalWriteError("transaction 데이터는 정확히 한 블록이어야 합니다.")
        stored = original
        flags = 0
        if struct.unpack_from(">I", stored, 0)[0] == C.JBD2_MAGIC_NUMBER:
            escaped = bytearray(stored)
            struct.pack_into(">I", escaped, 0, 0)
            stored = bytes(escaped)
            flags |= JBD2_FLAG_ESCAPE
        originals.append((target, original))
        normalized.append((target, stored, flags))

    descriptor = _descriptor_block(log, sequence, normalized)
    cursor = log.info.first
    descriptor_pos = cursor
    used = {descriptor_pos}
    cursor = log.next_block(cursor)
    data_positions: list[int] = []
    for _ in normalized:
        if cursor in used:
            raise JournalWriteError("JBD2 journal 공간이 transaction보다 작습니다.")
        data_positions.append(cursor)
        used.add(cursor)
        cursor = log.next_block(cursor)
    commit_pos = cursor
    if commit_pos in used:
        raise JournalWriteError("JBD2 journal에 commit block 공간이 없습니다.")

    # Descriptor and journaled data must be durable before commit publication.
    log.write_block(descriptor_pos, descriptor)
    for pos, (_target, stored, _flags) in zip(data_positions, normalized):
        log.write_block(pos, stored)
    vol.dev.flush()

    # Publish the active log head and EXT4 recovery requirement.
    log.mark_active(sequence, descriptor_pos)
    _set_ext4_recovery_flag(vol, True)
    vol.dev.flush()

    # A durable commit block makes the transaction replayable.
    log.write_block(commit_pos, _commit_block(log, sequence))
    vol.dev.flush()

    # Checkpoint committed blocks to their final filesystem locations.
    for target, original in originals:
        vol.write_block(target, original)
    vol.dev.flush()

    # Retire the transaction only after checkpointing is durable.
    next_sequence = (sequence + 1) & 0xFFFFFFFF
    log.mark_clean(next_sequence)
    _set_ext4_recovery_flag(vol, False)
    vol.dev.flush()
    vol._data_dirty = False

    LOG.info(
        "JBD2 transaction 기록 완료 sequence=%s blocks=%s next_sequence=%s",
        sequence,
        len(originals),
        next_sequence,
    )
    return JournalWriteStats(
        sequence=sequence,
        journal_blocks=len(originals) + 2,
        checkpointed_blocks=len(originals),
        next_sequence=next_sequence,
    )

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
        if vol.sb.needs_recovery:
            raise JournalRecoveryError(
                "EXT4 RECOVER 플래그가 남아 있지만 JBD2 s_start=0입니다. "
                "s_start만으로 clean 여부를 확정할 수 없어 자동 복구를 중단합니다."
            )
        return ReplayStats(0, 0, 0, log.info.sequence)

    transactions, next_sequence, _head = log.scan_transactions()
    if not transactions:
        raise JournalRecoveryError(
            "완료된 JBD2 transaction을 찾지 못했습니다. 안전을 위해 쓰기를 중단합니다."
        )

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
    log.mark_clean(next_sequence)
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
