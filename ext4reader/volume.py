"""Mounted EXT4 volume: block/inode I/O, discovery, metadata flush."""

from __future__ import annotations

import struct
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from ext4reader import constants as C
from ext4reader.debuglog import LOG
from ext4reader.inode import Inode, parse_inode
from ext4reader.io_backend import BlockDevice
from ext4reader.partitions import list_partitions
from ext4reader.superblock import (
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
        return self.dev.read(self.part_offset + fs_offset, length)

    def write_bytes(self, fs_offset: int, data: bytes) -> None:
        if not data:
            return
        bs = self.sb.block_size
        first = fs_offset // bs
        last = (fs_offset + len(data) - 1) // bs
        self._invalidate_block_cache(first, last)
        self._data_dirty = True
        self.dev.write(self.part_offset + fs_offset, data)

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
        self.write_bytes(off, raw)

    def _store_dirty_bitmaps(self) -> None:
        bs = self.sb.block_size
        for g in sorted(self._dirty_block_bm):
            bm = self._block_bm_cache.get(g)
            if bm is not None:
                blob = bytes(bm.data[:bs]).ljust(bs, b"\x00")
                self.write_block(self.groups[g].block_bitmap, blob)
            self._dirty_block_bm.discard(g)
        for g in sorted(self._dirty_inode_bm):
            bm = self._inode_bm_cache.get(g)
            if bm is not None:
                blob = bytes(bm.data[:bs]).ljust(bs, b"\x00")
                self.write_block(self.groups[g].inode_bitmap, blob)
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
                self.write_bytes(off, bytes(gd.raw[: self.sb.desc_size]))
            self.dirty_groups.clear()
        if self.dirty_super:
            self.sb.update_counts()
            self.sb.write_checksum()
            self.write_bytes(1024, bytes(self.sb.raw[:1024]))
            self.dirty_super = False
        if sync and self._data_dirty:
            self.dev.flush()
            self._data_dirty = False

    def flush_metadata(self) -> None:
        self.commit_metadata(sync=True)

    def journal_start(self) -> int | None:
        if not self.sb.has_journal or not self.sb.journal_inum:
            return 0
        try:
            from ext4reader.extents import file_extents

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
            LOG.info("RECOVER 플래그는 있으나 저널이 비어 있습니다 (s_start=0). 쓰기를 막을 필요는 없습니다.")
        return False

    def recover_pending_journal(self):
        """Replay a pending internal JBD2 journal on Windows.

        Returns ReplayStats. Unsupported/corrupt journals raise Ext4Error and
        remain read-only; no recovery flag is cleared on failure.
        """
        if not self.dev.writable:
            raise Ext4Error("저널 복구를 하려면 장치를 쓰기 가능으로 열어야 합니다.")
        if not self.journal_needs_recovery() and not self.sb.needs_recovery:
            from ext4reader.journal import ReplayStats
            return ReplayStats(0, 0, 0, 0)
        try:
            from ext4reader.journal import JournalRecoveryError, recover_journal
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
