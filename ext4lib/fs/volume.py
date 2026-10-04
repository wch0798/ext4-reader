"""Mounted EXT4 volume: block/inode I/O, discovery, metadata flush."""

from __future__ import annotations

import struct
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from ext4lib.fs import constants as C
from ext4lib.debuglog import LOG
from ext4lib.fs.inode import Inode, parse_inode
from ext4lib.io.backend import BlockDevice
from ext4lib.fs.partitions import list_partitions
from ext4lib.fs.superblock import (
    Superblock,
    parse_group_desc,
    parse_superblock,
    update_group_desc_fields,
)


class Ext4Error(RuntimeError):
    pass


@dataclass
class VolumeInfo:
    offset: int
    size: int
    partition_index: int
    partition_name: str
    scheme: str
    sb: Superblock
    write_blockers: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return self.sb.volume_name or "(이름 없음)"

    @property
    def writable(self) -> bool:
        return not self.write_blockers


class Ext4Volume:
    def __init__(self, dev: BlockDevice, offset: int = 0, size: int = 0, owns_device: bool = True):
        self.dev = dev
        self.owns_device = owns_device
        self.part_offset = offset
        self.part_size = size or max(0, dev.size() - offset)
        raw = self.dev.read(offset + 1024, 1024)
        self.sb = parse_superblock(raw)
        LOG.info(
            "Ext4Volume 열기 offset=%s size=%s block=%s inodes=%s inode_size=%s groups=%s label=%s "
            "state=0x%X incompat=0x%X ro_compat=0x%X recover=%s valid=%s journal=%s",
            offset,
            self.part_size,
            self.sb.block_size,
            self.sb.inodes_count,
            self.sb.inode_size,
            self.sb.groups_count,
            self.sb.volume_name,
            self.sb.state,
            self.sb.feature_incompat,
            self.sb.feature_ro_compat,
            self.sb.needs_recovery,
            bool(self.sb.state & C.EXT4_VALID_FS),
            self.sb.has_journal,
        )
        if self.sb.feature_incompat & C.EXT4_FEATURE_INCOMPAT_CASEFOLD:
            LOG.info("casefold 볼륨 — 파일 이름 대소문자는 구분하지 않습니다. 쓰기는 가능합니다.")
        self.dirty_groups: set[int] = set()
        self.dirty_super = False
        self._data_dirty = False
        self._block_cache: OrderedDict[int, bytes] = OrderedDict()
        self._block_cache_cap = 2048
        self._inode_cache: OrderedDict[int, bytes] = OrderedDict()
        self._inode_cache_cap = 4096
        self._extent_cache: OrderedDict[int, tuple[bytes, list]] = OrderedDict()
        self._extent_cache_cap = 512
        self._block_bm_cache: dict = {}
        self._inode_bm_cache: dict = {}
        self._dirty_block_bm: set[int] = set()
        self._dirty_inode_bm: set[int] = set()
        self._alloc_hint: dict[int, int] = {}
        self._dir_list: dict = {}
        self._dir_index: dict = {}
        self._write_session_active = False
        self._metadata_overlay: dict[int, bytearray] = {}
        self._journal_writer = None
        self._load_groups()

    def reload_metadata(self) -> None:
        """Drop cached metadata and re-read the superblock/GDT after journal replay."""
        self._block_cache.clear()
        self._inode_cache.clear()
        self._extent_cache.clear()
        self._block_bm_cache.clear()
        self._inode_bm_cache.clear()
        self._dirty_block_bm.clear()
        self._dirty_inode_bm.clear()
        self._alloc_hint.clear()
        self._dir_list.clear()
        self._dir_index.clear()
        self._metadata_overlay.clear()
        raw = self.dev.read(self.part_offset + 1024, 1024)
        self.sb = parse_superblock(raw)
        self._load_groups()

    def _load_groups(self) -> None:
        gdt_block = self.sb.first_data_block + 1
        total = self.sb.groups_count * self.sb.desc_size
        data = self.read_bytes(gdt_block * self.sb.block_size, total)
        groups = []
        for g in range(self.sb.groups_count):
            rec = data[g * self.sb.desc_size : (g + 1) * self.sb.desc_size]
            groups.append(parse_group_desc(self.sb, g, rec))
        self.groups = groups

    def read_bytes(self, fs_offset: int, length: int) -> bytes:
        data = bytearray(self.dev.read(self.part_offset + fs_offset, length))
        overlay = getattr(self, "_metadata_overlay", None)
        if not data or not overlay:
            return bytes(data)
        bs = self.sb.block_size
        first = fs_offset // bs
        last = (fs_offset + len(data) - 1) // bs
        req_end = fs_offset + len(data)
        for phys in range(first, last + 1):
            pending = overlay.get(phys)
            if pending is None:
                continue
            block_start = phys * bs
            lo = max(fs_offset, block_start)
            hi = min(req_end, block_start + bs)
            if lo >= hi:
                continue
            src = lo - block_start
            dst = lo - fs_offset
            data[dst : dst + (hi - lo)] = pending[src : src + (hi - lo)]
        return bytes(data)

    def write_bytes(self, fs_offset: int, data: bytes) -> None:
        if not data:
            return
        bs = self.sb.block_size
        first = fs_offset // bs
        last = (fs_offset + len(data) - 1) // bs
        self._invalidate_block_cache(first, last)
        self._data_dirty = True
        self.dev.write(self.part_offset + fs_offset, data)

    def _read_home_block(self, phys: int) -> bytes:
        if phys < 0 or phys >= self.sb.blocks_count:
            raise Ext4Error(f"블록 번호가 범위를 벗어났습니다: {phys}")
        return self.dev.read(
            self.part_offset + phys * self.sb.block_size,
            self.sb.block_size,
        )

    def write_metadata_bytes(self, fs_offset: int, data: bytes) -> None:
        """Queue metadata in memory while JBD2 journaling is active."""
        if not data:
            return
        if self._journal_writer is None:
            self.write_bytes(fs_offset, data)
            return
        bs = self.sb.block_size
        pos = 0
        while pos < len(data):
            absolute = fs_offset + pos
            phys = absolute // bs
            boff = absolute % bs
            take = min(bs - boff, len(data) - pos)
            block = self._metadata_overlay.get(phys)
            if block is None:
                block = bytearray(self._read_home_block(phys))
                if len(block) < bs:
                    block.extend(b"\x00" * (bs - len(block)))
                elif len(block) > bs:
                    del block[bs:]
            block[boff : boff + take] = data[pos : pos + take]
            self._metadata_overlay[phys] = block
            pos += take
        first = fs_offset // bs
        last = (fs_offset + len(data) - 1) // bs
        self._invalidate_block_cache(first, last)

    def write_metadata_block(self, phys: int, data: bytes) -> None:
        bs = self.sb.block_size
        blob = bytes(data[:bs]).ljust(bs, b"\x00")
        if self._journal_writer is None:
            self.write_block(phys, blob)
            return
        if phys < 0 or phys >= self.sb.blocks_count:
            raise Ext4Error(f"블록 번호가 범위를 벗어났습니다: {phys}")
        self._metadata_overlay[phys] = bytearray(blob)
        self._invalidate_block_cache(phys, phys)

    def _checkpoint_metadata_blocks(self, metadata: dict[int, bytes]) -> None:
        """Write committed metadata to its final EXT4 home blocks."""
        bs = self.sb.block_size
        for phys, data in sorted(metadata.items()):
            if len(data) != bs:
                raise Ext4Error("checkpoint metadata 블록 크기가 올바르지 않습니다.")
            self.dev.write(self.part_offset + phys * bs, data)
            self._invalidate_block_cache(phys, phys)
        if metadata:
            self._data_dirty = True

    def _set_home_super_flags(
        self,
        *,
        recover: bool | None = None,
        valid: bool | None = None,
        flush: bool = True,
    ) -> None:
        """Update only crash-state flags in the on-disk superblock."""
        raw = self.dev.read(self.part_offset + 1024, 1024)
        disk_sb = parse_superblock(raw)
        if recover is not None:
            if recover:
                disk_sb.feature_incompat |= C.EXT4_FEATURE_INCOMPAT_RECOVER
                self.sb.feature_incompat |= C.EXT4_FEATURE_INCOMPAT_RECOVER
            else:
                disk_sb.feature_incompat &= ~C.EXT4_FEATURE_INCOMPAT_RECOVER
                self.sb.feature_incompat &= ~C.EXT4_FEATURE_INCOMPAT_RECOVER
            struct.pack_into("<I", disk_sb.raw, 0x60, disk_sb.feature_incompat)
            struct.pack_into("<I", self.sb.raw, 0x60, self.sb.feature_incompat)
        if valid is not None:
            if valid:
                disk_sb.state |= C.EXT4_VALID_FS
                self.sb.state |= C.EXT4_VALID_FS
            else:
                disk_sb.state &= ~C.EXT4_VALID_FS
                self.sb.state &= ~C.EXT4_VALID_FS
            struct.pack_into("<H", disk_sb.raw, 0x3A, disk_sb.state)
            struct.pack_into("<H", self.sb.raw, 0x3A, self.sb.state)
        disk_sb.write_checksum()
        self.sb.write_checksum()
        self.dev.write(self.part_offset + 1024, bytes(disk_sb.raw[:1024]))
        bs = self.sb.block_size
        self._invalidate_block_cache(1024 // bs, (1024 + 1023) // bs)
        if flush:
            self.dev.flush()
            self._data_dirty = False
        else:
            self._data_dirty = True

    def _refresh_pending_superblock(self) -> None:
        if self._journal_writer is None:
            return
        self.sb.write_checksum()
        self.write_metadata_bytes(1024, bytes(self.sb.raw[:1024]))

    def _cache_block(self, phys: int, data: bytes) -> None:
        cache = self._block_cache
        cache[phys] = data
        cache.move_to_end(phys)
        while len(cache) > self._block_cache_cap:
            cache.popitem(last=False)

    def _invalidate_block_cache(self, first: int, last: int) -> None:
        cache = self._block_cache
        if not cache or last < first:
            return
        if last - first + 1 > len(cache):
            for key in [k for k in cache if first <= k <= last]:
                del cache[key]
            return
        for phys in range(first, last + 1):
            cache.pop(phys, None)

    def drop_dir_cache(self, ino: int) -> None:
        self._dir_list.pop(ino, None)
        self._dir_index.pop(ino, None)

    def read_block(self, phys: int) -> bytes:
        if phys < 0 or phys >= self.sb.blocks_count:
            raise Ext4Error(f"블록 번호가 범위를 벗어났습니다: {phys}")
        hit = self._block_cache.get(phys)
        if hit is not None:
            self._block_cache.move_to_end(phys)
            return hit
        data = self.read_bytes(phys * self.sb.block_size, self.sb.block_size)
        self._cache_block(phys, data)
        return data

    def write_block(self, phys: int, data: bytes) -> None:
        if len(data) != self.sb.block_size:
            if len(data) < self.sb.block_size:
                data = data + b"\x00" * (self.sb.block_size - len(data))
            else:
                data = data[: self.sb.block_size]
        self.write_bytes(phys * self.sb.block_size, data)
        self._cache_block(phys, data if isinstance(data, bytes) else bytes(data))

    def _inode_loc(self, ino: int) -> tuple[int, int]:
        if ino < 1 or ino > self.sb.inodes_count:
            raise Ext4Error(f"잘못된 inode: {ino}")
        g = (ino - 1) // self.sb.inodes_per_group
        index = (ino - 1) % self.sb.inodes_per_group
        gd = self.groups[g]
        offset = gd.inode_table * self.sb.block_size + index * self.sb.inode_size
        return g, offset

    def _remember_inode(self, ino: int, raw: bytes) -> None:
        self._inode_cache[ino] = raw
        self._inode_cache.move_to_end(ino)
        while len(self._inode_cache) > self._inode_cache_cap:
            self._inode_cache.popitem(last=False)

    def read_inode(self, ino: int) -> Inode:
        cached = self._inode_cache.get(ino)
        if cached is not None:
            self._inode_cache.move_to_end(ino)
            return parse_inode(self.sb, ino, cached)
        _g, off = self._inode_loc(ino)
        raw = bytes(self.read_bytes(off, self.sb.inode_size))
        self._remember_inode(ino, raw)
        return parse_inode(self.sb, ino, raw)

    def write_inode(self, inode: Inode) -> None:
        if inode.blocks > 0xFFFFFFFF and not (
            self.sb.feature_ro_compat & C.EXT4_FEATURE_RO_COMPAT_HUGE_FILE
        ):
            self.sb.feature_ro_compat |= C.EXT4_FEATURE_RO_COMPAT_HUGE_FILE
            struct.pack_into("<I", self.sb.raw, 0x64, self.sb.feature_ro_compat)
            self.dirty_super = True
        inode.apply_checksum(self.sb)
        raw = bytes(inode.raw[: self.sb.inode_size])
        self._remember_inode(inode.ino, raw)
        self._extent_cache.pop(inode.ino, None)
        self.drop_dir_cache(inode.ino)
        _g, off = self._inode_loc(inode.ino)
        self.write_metadata_bytes(off, raw)

    def _store_dirty_bitmaps(self) -> None:
        bs = self.sb.block_size
        for g in sorted(self._dirty_block_bm):
            bm = self._block_bm_cache.get(g)
            if bm is not None:
                blob = bytes(bm.data[:bs]).ljust(bs, b"\x00")
                self.write_metadata_block(self.groups[g].block_bitmap, blob)
            self._dirty_block_bm.discard(g)
        for g in sorted(self._dirty_inode_bm):
            bm = self._inode_bm_cache.get(g)
            if bm is not None:
                blob = bytes(bm.data[:bs]).ljust(bs, b"\x00")
                self.write_metadata_block(self.groups[g].inode_bitmap, blob)
            self._dirty_inode_bm.discard(g)

    def commit_metadata(self, sync: bool = True) -> None:
        """Write dirty bitmaps, group descriptors and the superblock.

        ``sync`` waits until the device cache is on media. Copying a large file
        calls this very often; waiting every time is what makes USB/SD feel stuck.
        """
        self._store_dirty_bitmaps()
        if self.dirty_groups:
            gdt_block = self.sb.first_data_block + 1
            for g in sorted(self.dirty_groups):
                gd = self.groups[g]
                update_group_desc_fields(self.sb, gd)
                off = gdt_block * self.sb.block_size + g * self.sb.desc_size
                self.write_metadata_bytes(off, bytes(gd.raw[: self.sb.desc_size]))
            self.dirty_groups.clear()
        if self.dirty_super:
            self.sb.update_counts()
            self.sb.write_checksum()
            self.write_metadata_bytes(1024, bytes(self.sb.raw[:1024]))
            self.dirty_super = False
        if sync:
            if self._journal_writer is not None and self._metadata_overlay:
                self._journal_writer.commit()
            elif self._data_dirty:
                self.dev.flush()
                self._data_dirty = False

    def flush_metadata(self) -> None:
        self.commit_metadata(sync=True)

    def _write_super_state(self) -> None:
        struct.pack_into("<H", self.sb.raw, 0x3A, self.sb.state & 0xFFFF)
        self.sb.write_checksum()
        self.dev.write(self.part_offset + 1024, bytes(self.sb.raw[:1024]))
        self.dev.flush()
        self._data_dirty = False

    def begin_write_session(self) -> None:
        """Start a writable session and validate JBD2 before exposing writes."""
        if self._write_session_active:
            return
        if not self.dev.writable:
            raise Ext4Error("쓰기 세션을 시작하려면 장치를 쓰기 가능으로 열어야 합니다.")

        writer = None
        if getattr(self.sb, "has_journal", False):
            try:
                from ext4lib.fs.journal import JournalWriteError, JournalWriter

                writer = JournalWriter(self)
            except JournalWriteError as exc:
                raise Ext4Error(f"JBD2 쓰기 저널을 시작할 수 없습니다: {exc}") from exc

        self._journal_writer = writer
        if writer is None:
            self.sb.state &= ~C.EXT4_VALID_FS
            self._write_super_state()
        else:
            self._set_home_super_flags(valid=False, flush=True)
        self._write_session_active = True
        LOG.warning(
            "RW 세션 시작: EXT4 clean 플래그 해제, JBD2 write=%s",
            "on" if writer is not None else "off",
        )

    def finish_write_session(self) -> None:
        """Durably commit/checkpoint metadata and mark the session clean."""
        if not self._write_session_active:
            return
        self.commit_metadata(sync=True)
        if self._journal_writer is not None:
            self._journal_writer.mark_clean()
            self._set_home_super_flags(recover=False, valid=True, flush=True)
        else:
            self.sb.state |= C.EXT4_VALID_FS
            self._write_super_state()
        self._write_session_active = False
        self._journal_writer = None
        overlay = getattr(self, "_metadata_overlay", None)
        if overlay is not None:
            overlay.clear()
        LOG.info("RW 세션 정상 종료: JBD2/EXT4 clean 상태를 복원했습니다.")

    def journal_start(self) -> int | None:
        if not self.sb.has_journal or not self.sb.journal_inum:
            return 0
        try:
            from ext4lib.fs.extents import file_extents

            j = self.read_inode(self.sb.journal_inum)
            ex = file_extents(self, j)
            if not ex:
                return None
            block = self.read_block(ex[0].physical)
            magic = struct.unpack(">I", block[0:4])[0]
            if magic != C.JBD2_MAGIC_NUMBER:
                return None
            return struct.unpack(">I", block[28:32])[0]
        except Exception as exc:
            LOG.warning("저널 슈퍼블록을 읽지 못함: %s", exc)
            return None

    def journal_needs_recovery(self) -> bool:
        s_start = self.journal_start()
        if s_start is None:
            return bool(self.sb.needs_recovery)
        if s_start != 0:
            LOG.info("저널 재생 필요 s_start=%s recover_flag=%s", s_start, self.sb.needs_recovery)
            return True
        if self.sb.needs_recovery:
            # JBD2 문서상 s_start == 0만으로 journal이 clean하다고 단정할 수 없다.
            LOG.warning("RECOVER 플래그가 남아 있지만 JBD2 s_start=0입니다. 안전을 위해 복구 필요로 취급합니다.")
            return True
        return False

    def recover_pending_journal(self):
        """Replay a pending internal JBD2 journal on Windows.

        Returns ReplayStats. Unsupported/corrupt journals raise Ext4Error and
        remain read-only; no recovery flag is cleared on failure.
        """
        if not self.dev.writable:
            raise Ext4Error("저널 복구를 하려면 장치를 쓰기 가능으로 열어야 합니다.")
        if not self.journal_needs_recovery() and not self.sb.needs_recovery:
            from ext4lib.fs.journal import ReplayStats
            return ReplayStats(0, 0, 0, 0)
        try:
            from ext4lib.fs.journal import JournalRecoveryError, recover_journal
            return recover_journal(self)
        except JournalRecoveryError as exc:
            raise Ext4Error(f"Windows 저널 복구 실패: {exc}") from exc

    def fs_write_blockers(self) -> list[str]:
        return self.hard_write_blockers() + self.soft_write_warnings()

    def hard_write_blockers(self) -> list[str]:
        reasons = []
        if self.journal_needs_recovery():
            reasons.append(
                "저널에 재생하지 않은 기록이 있습니다. 쓰기 연결 시 Windows에서 자동 복구를 시도합니다."
            )
        unknown = self.sb.feature_incompat & ~C.SUPPORTED_INCOMPAT_WRITE
        if unknown & C.EXT4_FEATURE_INCOMPAT_ENCRYPT:
            reasons.append("암호화된 파일시스템입니다.")
        if unknown & C.EXT4_FEATURE_INCOMPAT_META_BG:
            reasons.append("META_BG 레이아웃은 쓰기를 지원하지 않습니다.")
        if unknown & C.EXT4_FEATURE_INCOMPAT_MMP:
            reasons.append("다중 마운트 보호(MMP)가 켜져 있습니다.")
        if self.sb.state & C.EXT4_ERROR_FS:
            reasons.append("EXT4 슈퍼블록에 파일시스템 오류 상태가 기록되어 있습니다.")
        if self.sb.feature_ro_compat & C.EXT4_FEATURE_RO_COMPAT_BIGALLOC:
            reasons.append("bigalloc 파일시스템은 쓰기를 지원하지 않습니다.")
        if self.sb.feature_ro_compat & C.EXT4_FEATURE_RO_COMPAT_READONLY:
            reasons.append("읽기 전용으로 표시된 파일시스템입니다.")
        leftover = self.sb.feature_incompat & ~C.SUPPORTED_INCOMPAT_WRITE & ~C.EXT4_FEATURE_INCOMPAT_RECOVER
        leftover &= ~(
            C.EXT4_FEATURE_INCOMPAT_ENCRYPT
            | C.EXT4_FEATURE_INCOMPAT_CASEFOLD
            | C.EXT4_FEATURE_INCOMPAT_META_BG
            | C.EXT4_FEATURE_INCOMPAT_MMP
            | C.EXT4_FEATURE_INCOMPAT_INLINE_DATA
        )
        if leftover:
            reasons.append(f"알 수 없는 incompat 기능(0x{leftover:X})이 있습니다.")
        if not self.sb.has_extents:
            reasons.append("EXT4 extents가 없는 볼륨(EXT2/3)에는 쓸 수 없습니다.")
        return reasons

    def soft_write_warnings(self) -> list[str]:
        reasons = []
        if not (self.sb.state & C.EXT4_VALID_FS):
            reasons.append("파일시스템이 깨끗하게 언마운트되지 않았습니다.")
        return reasons

    def write_blockers(self) -> list[str]:
        reasons = []
        if not self.dev.writable:
            reasons.append("장치를 읽기 전용으로 열었습니다.")
        reasons.extend(self.fs_write_blockers())
        return reasons

    def require_write(self) -> None:
        reasons = []
        if not self.dev.writable:
            reasons.append("장치를 읽기 전용으로 열었습니다.")
        reasons.extend(self.hard_write_blockers())
        if reasons:
            raise Ext4Error("쓸 수 없습니다:\n- " + "\n- ".join(reasons))

    def close(self) -> None:
        try:
            if self._write_session_active:
                LOG.warning(
                    "RW 세션이 clean 완료 없이 닫힙니다. pending metadata를 추가 commit하지 않습니다."
                )
            else:
                self.flush_metadata()
        finally:
            if self.owns_device:
                self.dev.close()


def probe_superblock(dev: BlockDevice, offset: int) -> Superblock | None:
    try:
        data = dev.read(offset + 1024, 1024)
        if len(data) < 1024:
            return None
        return parse_superblock(data)
    except Exception:
        return None


def discover_volumes(dev: BlockDevice) -> list[VolumeInfo]:
    found: list[VolumeInfo] = []
    seen_off: set[int] = set()
    parts = []
    try:
        parts = list_partitions(dev)
    except Exception:
        parts = []

    candidates: list[tuple[int, int, int, str, str]] = []
    for p in parts:
        candidates.append((p.start, p.size, p.index, p.name, p.scheme))
    if not candidates:
        candidates.append((0, dev.size(), 0, "", "전체"))

    for start, size, idx, name, scheme in candidates:
        if start in seen_off:
            continue
        sb = probe_superblock(dev, start)
        if not sb:
            continue
        seen_off.add(start)
        info = VolumeInfo(
            offset=start,
            size=size or (sb.blocks_count * sb.block_size),
            partition_index=idx,
            partition_name=name,
            scheme=scheme,
            sb=sb,
        )
        try:
            tmp = Ext4Volume(dev, start, info.size, owns_device=False)
            info.write_blockers = tmp.hard_write_blockers()
        except Exception:
            pass
        found.append(info)

    if not found:
        sb = probe_superblock(dev, 0)
        if sb:
            found.append(
                VolumeInfo(
                    offset=0,
                    size=dev.size(),
                    partition_index=0,
                    partition_name="",
                    scheme="슈퍼블록",
                    sb=sb,
                )
            )
    return found


def format_bytes(n: int) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(n)} {unit}"
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def format_time(ts: int) -> str:
    if not ts:
        return "-"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except Exception:
        return str(ts)
