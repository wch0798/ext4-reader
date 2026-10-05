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
    group_desc_checksum_valid,
    parse_group_desc,
    parse_superblock,
    superblock_checksum_valid,
    superblock_error_info,
    update_group_desc_fields,
)


class Ext4Error(RuntimeError):
    pass


@dataclass(frozen=True)
class ErrorRepairStats:
    repaired: bool
    groups_checked: int
    bitmaps_checked: int
    root_entries_checked: int
    error_count: int
    bitmap_checksums_repaired: int = 0


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
        # Defaults for content created from Windows. These are instance fields
        # so a future GUI preference can override them without changing writer
        # APIs or on-disk parsing.
        self.default_uid = C.DEFAULT_LINUX_UID
        self.default_gid = C.DEFAULT_LINUX_GID
        self.default_file_mode = C.DEFAULT_LINUX_FILE_MODE
        self.default_dir_mode = C.DEFAULT_LINUX_DIR_MODE
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
        LOG.info(
            "Linux 신규 inode 기본값 uid=%s gid=%s file_mode=%04o dir_mode=%04o",
            self.default_uid,
            self.default_gid,
            self.default_file_mode,
            self.default_dir_mode,
        )
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
        self._pending_block_frees: list[tuple[int, int]] = []
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
        self._pending_block_frees.clear()
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
        if sync and self._journal_writer is not None and self._pending_block_frees:
            # Do not expose freed blocks to the allocator until the transaction
            # that removes their old references is about to become durable.
            from ext4lib.fs.bitmap import apply_pending_block_frees

            apply_pending_block_frees(self)

        # The block bitmap is the allocation source of truth. Reconcile every
        # dirty group's descriptor count before serializing either structure.
        # This prevents a torn/duplicated allocation update from advertising
        # more free blocks than the bitmap actually contains (the Steam Deck
        # failure was exactly +8192 blocks in one group).
        if self._dirty_block_bm:
            from ext4lib.fs.bitmap import bitmap_free_count, group_block_range

            for g in sorted(self._dirty_block_bm):
                bm = self._block_bm_cache.get(g)
                if bm is None:
                    continue
                start, end = group_block_range(self, g)
                actual = bitmap_free_count(bm.data, max(0, end - start))
                gd = self.groups[g]
                if gd.free_blocks != actual:
                    delta = actual - gd.free_blocks
                    LOG.warning(
                        "block group free count 자동 보정 group=%s stored=%s bitmap=%s delta=%+d",
                        g, gd.free_blocks, actual, delta,
                    )
                    gd.free_blocks = actual
                    self.sb.free_blocks_count += delta
                    self.dirty_groups.add(g)
                    self.dirty_super = True
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
        """Durably commit pending metadata without closing the mount session.

        Namespace operations call this at durability boundaries.  Keep the same
        JBD2 writer/session alive across a burst of file operations so we do not
        flip EXT4 clean/dirty state and rebuild the journal writer for every
        Explorer create/rename/truncate.  Normal close/unmount performs the one
        final clean transition via finish_write_session().
        """
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

        # s_free_blocks_count is only an aggregate cache.  If an earlier crash
        # or buggy writer left it stale, using it as the allocation baseline
        # can underflow during a perfectly valid large copy.  Group descriptor
        # counters are maintained with the allocation bitmaps and are the same
        # aggregate used by statfs, so repair the superblock baseline before
        # the first writable transaction.
        group_free = sum(max(0, int(gd.free_blocks)) for gd in self.groups)
        group_free = min(group_free, int(self.sb.blocks_count))
        if int(self.sb.free_blocks_count) != group_free:
            LOG.warning(
                "RW 시작 전 superblock free count 자동 보정: super=%d groups=%d",
                int(self.sb.free_blocks_count), group_free,
            )
            self.sb.free_blocks_count = group_free
            self.dirty_super = True

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
        LOG.info(
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

    def recover_pending_orphans(self, progress=None):
        """Recover EXT4 orphan-file / legacy orphan state on Windows."""
        try:
            from ext4lib.fs.orphan import OrphanRecoveryError, recover_orphans

            return recover_orphans(self, progress)
        except OrphanRecoveryError as exc:
            raise Ext4Error(f"Windows orphan 복구 실패: {exc}") from exc

    def _repair_known_legacy_bitmap_checksums(
        self, progress=None, error_info=None
    ) -> int:
        """Repair checksum-only bitmap damage after strict structural validation.

        Two cases are accepted:
        1) the exact old Ext4Reader misplaced-high-half signature; or
        2) for a Linux ext4_validate_block_bitmap error, the bitmap's low
           16 checksum bits already match and only the high 16 bits are stale.

        Everything else remains read-only.
        """
        if not self.sb.has_metadata_csum:
            return 0

        from ext4lib.fs.bitmap import (
            Bitmap,
            apply_legacy_bitmap_checksum_repair,
            bitmap_checksum_valid,
            bitmap_checksum_values,
            bitmap_free_count,
            bitmap_padding_is_set,
            group_block_range,
            inode_table_blocks,
            legacy_bitmap_checksum_signature,
            rebuild_block_bitmap_from_metadata,
            write_block_bitmap,
        )

        repairs: list[tuple[int, str, bytes]] = []
        rebuilds: list[tuple[int, Bitmap]] = []
        ng = len(self.groups)
        flex_bg = bool(self.sb.feature_incompat & C.EXT4_FEATURE_INCOMPAT_FLEX_BG)

        for g, gd in enumerate(self.groups):
            if progress is not None and (g % 128 == 0 or g + 1 == ng):
                progress(f"EXT4 legacy bitmap checksum 검사 {g + 1}/{ng}")
            if not group_desc_checksum_valid(self.sb, gd):
                raise Ext4Error(
                    f"block group {g} descriptor checksum 불일치 — bitmap checksum 자동 복구를 중단합니다."
                )

            start, end = group_block_range(self, g)
            group_blocks = max(0, end - start)
            inode_start = g * self.sb.inodes_per_group
            group_inodes = max(
                0,
                min(self.sb.inodes_per_group, self.sb.inodes_count - inode_start),
            )

            if not (gd.flags & C.BG_BLOCK_UNINIT):
                raw = self.read_block(gd.block_bitmap)
                if not bitmap_checksum_valid(self, gd, "block", raw):
                    actual = bitmap_free_count(raw, group_blocks)
                    first_func = str((error_info or {}).get("first_func", ""))
                    last_func = str((error_info or {}).get("last_func", ""))
                    linux_block_csum_error = (
                        first_func == "ext4_validate_block_bitmap"
                        or last_func == "ext4_validate_block_bitmap"
                    )
                    if actual != gd.free_blocks:
                        if not linux_block_csum_error:
                            raise Ext4Error(
                                f"block group {g} block bitmap checksum과 free count가 함께 불일치합니다. "
                                f"descriptor={gd.free_blocks} bitmap={actual}; 알려진 Linux bitmap 오류가 아닙니다."
                            )
                        try:
                            candidate = rebuild_block_bitmap_from_metadata(
                                self, g, progress
                            )
                        except Exception as exc:
                            raise Ext4Error(
                                f"block group {g} block bitmap 재구성 실패: {exc}"
                            ) from exc
                        candidate_raw = bytes(
                            candidate.data[: self.sb.block_size]
                        )
                        candidate_free = bitmap_free_count(
                            candidate_raw, group_blocks
                        )
                        stored_candidate, calc_candidate = bitmap_checksum_values(
                            self, gd, "block", candidate_raw
                        )
                        if candidate_free != gd.free_blocks:
                            raise Ext4Error(
                                f"block group {g} 재구성 free count 불일치: "
                                f"descriptor={gd.free_blocks} rebuilt={candidate_free}"
                            )
                        if stored_candidate != calc_candidate:
                            raise Ext4Error(
                                f"block group {g} 재구성 checksum이 기존 descriptor와 일치하지 않습니다: "
                                f"stored=0x{stored_candidate:08X} rebuilt=0x{calc_candidate:08X}"
                            )
                        if not bitmap_padding_is_set(
                            candidate_raw,
                            group_blocks,
                            self.sb.blocks_per_group,
                        ):
                            raise Ext4Error(
                                f"block group {g} 재구성 bitmap padding 검증 실패"
                            )
                        LOG.warning(
                            "block group %s bitmap 재구성 검증 성공 "
                            "free=%s checksum=0x%08X — JBD2 복구 예약",
                            g,
                            candidate_free,
                            calc_candidate,
                        )
                        rebuilds.append((g, candidate))
                        # Do not run checksum-only logic against the corrupt
                        # on-disk bitmap; the reconstructed candidate is the
                        # exact descriptor-matching replacement.
                        continue
                    if not bitmap_padding_is_set(
                        raw, group_blocks, self.sb.blocks_per_group
                    ):
                        raise Ext4Error(
                            f"block group {g} block bitmap padding이 손상되어 checksum-only 복구를 중단합니다."
                        )
                    if not flex_bg:
                        bm = Bitmap(bytearray(raw), self.sb.blocks_per_group)
                        required = [gd.block_bitmap, gd.inode_bitmap]
                        required.extend(
                            range(gd.inode_table, gd.inode_table + inode_table_blocks(self))
                        )
                        for block in required:
                            if start <= block < end and not bm.test(block - start):
                                raise Ext4Error(
                                    f"block group {g} metadata block {block}가 block bitmap에서 비어 있습니다."
                                )
                    stored, calculated = bitmap_checksum_values(
                        self, gd, "block", raw
                    )
                    legacy = legacy_bitmap_checksum_signature(
                        self, gd, "block", raw
                    )
                    low_matches = (stored & 0xFFFF) == (calculated & 0xFFFF)
                    misplaced_hi = int.from_bytes(gd.raw[0x34:0x36], "little")
                    LOG.warning(
                        "bitmap checksum 진단 group=%s type=block stored=0x%08X "
                        "calculated=0x%08X low_match=%s legacy=%s misplaced_hi=0x%04X "
                        "linux_error=%s",
                        g,
                        stored,
                        calculated,
                        low_matches,
                        legacy,
                        misplaced_hi,
                        linux_block_csum_error,
                    )
                    if not legacy and not (low_matches and linux_block_csum_error):
                        raise Ext4Error(
                            f"block group {g} block bitmap checksum 불일치가 안전한 "
                            f"checksum-only 복구 조건을 만족하지 않습니다 "
                            f"(stored=0x{stored:08X}, calculated=0x{calculated:08X})."
                        )
                    repairs.append((g, "block", raw))

            if not (gd.flags & C.BG_INODE_UNINIT):
                raw = self.read_block(gd.inode_bitmap)
                if not bitmap_checksum_valid(self, gd, "inode", raw):
                    actual = bitmap_free_count(raw, group_inodes)
                    if actual != gd.free_inodes:
                        raise Ext4Error(
                            f"block group {g} inode bitmap checksum과 free count가 함께 불일치합니다. "
                            f"descriptor={gd.free_inodes} bitmap={actual}; checksum-only 복구 대상이 아닙니다."
                        )
                    if not bitmap_padding_is_set(
                        raw, group_inodes, self.sb.inodes_per_group
                    ):
                        raise Ext4Error(
                            f"block group {g} inode bitmap padding이 손상되어 checksum-only 복구를 중단합니다."
                        )
                    stored, calculated = bitmap_checksum_values(
                        self, gd, "inode", raw
                    )
                    legacy = legacy_bitmap_checksum_signature(
                        self, gd, "inode", raw
                    )
                    LOG.warning(
                        "bitmap checksum 진단 group=%s type=inode stored=0x%08X "
                        "calculated=0x%08X legacy=%s",
                        g,
                        stored,
                        calculated,
                        legacy,
                    )
                    if not legacy:
                        raise Ext4Error(
                            f"block group {g} inode bitmap checksum 불일치가 "
                            f"알려진 구버전 Ext4Reader 패턴과 일치하지 않습니다 "
                            f"(stored=0x{stored:08X}, calculated=0x{calculated:08X})."
                        )
                    repairs.append((g, "inode", raw))

        if not repairs and not rebuilds:
            return 0

        LOG.warning(
            "EXT4 bitmap 자동 복구 준비: checksum_repairs=%s rebuilds=%s groups=%s",
            len(repairs),
            len(rebuilds),
            sorted(
                {g for g, _which, _raw in repairs}
                | {g for g, _bm in rebuilds}
            ),
        )
        if progress is not None:
            progress(
                f"EXT4 bitmap 복구: checksum={len(repairs)} rebuild={len(rebuilds)}"
            )

        started = False
        try:
            self.begin_write_session()
            started = True
            for g, candidate in rebuilds:
                gd = self.groups[g]
                write_block_bitmap(self, gd, candidate)
                self.dirty_groups.add(g)
            for g, which, raw in repairs:
                gd = self.groups[g]
                if legacy_bitmap_checksum_signature(self, gd, which, raw):
                    apply_legacy_bitmap_checksum_repair(self, gd, which, raw)
                else:
                    # High-half-only corruption: preserve bitmap contents and
                    # recompute only the Linux metadata_csum fields.
                    from ext4lib.fs.bitmap import apply_bitmap_csum

                    if which == "block":
                        calculated_hi = (
                            bitmap_checksum_values(self, gd, which, raw)[1] >> 16
                        ) & 0xFFFF
                        if int.from_bytes(gd.raw[0x34:0x36], "little") == calculated_hi:
                            gd.raw[0x34:0x36] = b"\x00\x00"
                        nbits = self.sb.blocks_per_group
                    else:
                        nbits = self.sb.inodes_per_group
                    apply_bitmap_csum(
                        self,
                        gd,
                        which,
                        Bitmap(bytearray(raw), nbits),
                    )
                self.dirty_groups.add(g)
            self.finish_write_session()
            started = False
        except Exception:
            if started:
                # Never let a later read-only unmount turn a failed repair into
                # a fabricated clean finish. Preserve whatever journal/recovery
                # markers reached the medium and drop only in-memory pending state.
                self._write_session_active = False
                self._journal_writer = None
                self._metadata_overlay.clear()
                self.dirty_groups.clear()
                self.dirty_super = False
                self._dirty_block_bm.clear()
                self._dirty_inode_bm.clear()
                self._pending_block_frees.clear()
                try:
                    self.reload_metadata()
                except Exception:
                    pass
            raise

        self.reload_metadata()
        for g, _candidate in rebuilds:
            gd = self.groups[g]
            current = self.read_block(gd.block_bitmap)
            current_free = bitmap_free_count(
                current,
                max(
                    0,
                    group_block_range(self, g)[1]
                    - group_block_range(self, g)[0],
                ),
            )
            if current_free != gd.free_blocks:
                raise Ext4Error(
                    f"block group {g} 재구성 후 free count 검증 실패: "
                    f"descriptor={gd.free_blocks} bitmap={current_free}"
                )
            if not bitmap_checksum_valid(self, gd, "block", current):
                raise Ext4Error(
                    f"block group {g} 재구성 후 checksum 검증 실패"
                )
        for g, which, _raw in repairs:
            gd = self.groups[g]
            if not group_desc_checksum_valid(self.sb, gd):
                raise Ext4Error(
                    f"block group {g} descriptor checksum 복구 검증 실패"
                )
            current = self.read_block(
                gd.block_bitmap if which == "block" else gd.inode_bitmap
            )
            if not bitmap_checksum_valid(self, gd, which, current):
                raise Ext4Error(
                    f"block group {g} {which} bitmap checksum 복구 검증 실패"
                )

        LOG.warning(
            "EXT4 bitmap 자동 복구 완료 checksum_repairs=%s rebuilds=%s",
            len(repairs),
            len(rebuilds),
        )
        return len(repairs) + len(rebuilds)

    def repair_error_state_if_safe(self, progress=None) -> ErrorRepairStats:
        """Clear a stale EXT4_ERROR_FS only after a conservative metadata scrub.

        This is intentionally not a general-purpose fsck. It repairs the common
        stale-error state left by interrupted/older writer versions only when
        the journal is already clean and the metadata structures required for
        safe allocation/navigation all validate.
        """
        if not (self.sb.state & C.EXT4_ERROR_FS):
            return ErrorRepairStats(False, 0, 0, 0, 0)
        if not self.dev.writable:
            raise Ext4Error("EXT4 오류 상태를 복구하려면 장치를 쓰기 가능으로 열어야 합니다.")
        if self.journal_needs_recovery() or self.sb.needs_recovery:
            raise Ext4Error("JBD2 저널이 아직 clean 상태가 아니어서 ERROR_FS를 복구할 수 없습니다.")
        if self.sb.state & C.EXT4_ORPHAN_FS:
            raise Ext4Error("orphan 복구 진행 상태가 남아 있어 ERROR_FS 검사를 중단합니다.")
        if self.sb.feature_ro_compat & C.EXT4_FEATURE_RO_COMPAT_ORPHAN_PRESENT:
            raise Ext4Error("ORPHAN_PRESENT 상태가 남아 있어 ERROR_FS 검사를 중단합니다.")
        if getattr(self.sb, "last_orphan", 0):
            raise Ext4Error("legacy orphan list가 남아 있어 ERROR_FS 검사를 중단합니다.")
        if not superblock_checksum_valid(self.sb):
            raise Ext4Error("EXT4 superblock checksum이 일치하지 않습니다.")

        info = superblock_error_info(self.sb)
        LOG.warning(
            "EXT4 ERROR_FS 자동 점검 시작 count=%s first=%s:%s ino=%s block=%s last=%s:%s ino=%s block=%s",
            info["count"],
            info["first_func"],
            info["first_line"],
            info["first_ino"],
            info["first_block"],
            info["last_func"],
            info["last_line"],
            info["last_ino"],
            info["last_block"],
        )

        bitmap_checksums_repaired = self._repair_known_legacy_bitmap_checksums(
            progress, info
        )
        from ext4lib.fs.bitmap import (
            bitmap_checksum_valid,
            bitmap_free_count,
            group_block_range,
            inode_table_blocks,
        )
        from ext4lib.fs.directory import (
            _htree_leaves,
            dir_block_checksum_valid,
            dir_block_count,
            list_dir,
            read_dir_lblock,
        )
        from ext4lib.fs.extents import file_extents
        from ext4lib.fs.inode import inode_checksum_valid

        groups_checked = 0
        bitmaps_checked = 0
        free_blocks_total = 0
        free_inodes_total = 0
        ng = len(self.groups)

        for g, gd in enumerate(self.groups):
            if progress is not None and (g % 64 == 0 or g + 1 == ng):
                progress(f"EXT4 메타데이터 검사 {g + 1}/{ng}")

            if not group_desc_checksum_valid(self.sb, gd):
                raise Ext4Error(f"block group {g} descriptor checksum 불일치")

            it_blocks = inode_table_blocks(self)
            for label, block in (
                ("block bitmap", gd.block_bitmap),
                ("inode bitmap", gd.inode_bitmap),
                ("inode table", gd.inode_table),
            ):
                if block < self.sb.first_data_block or block >= self.sb.blocks_count:
                    raise Ext4Error(f"block group {g} {label} 위치가 범위를 벗어났습니다: {block}")
            if gd.inode_table + it_blocks > self.sb.blocks_count:
                raise Ext4Error(f"block group {g} inode table 끝이 파일시스템 범위를 벗어났습니다.")

            start, end = group_block_range(self, g)
            group_blocks = max(0, end - start)
            inode_start = g * self.sb.inodes_per_group
            group_inodes = max(
                0,
                min(self.sb.inodes_per_group, self.sb.inodes_count - inode_start),
            )
            if gd.free_blocks < 0 or gd.free_blocks > group_blocks:
                raise Ext4Error(f"block group {g} free block count가 비정상입니다.")
            if gd.free_inodes < 0 or gd.free_inodes > group_inodes:
                raise Ext4Error(f"block group {g} free inode count가 비정상입니다.")

            if not (gd.flags & C.BG_BLOCK_UNINIT):
                raw = self.read_block(gd.block_bitmap)
                if not bitmap_checksum_valid(self, gd, "block", raw):
                    raise Ext4Error(f"block group {g} block bitmap checksum 불일치")
                actual = bitmap_free_count(raw, group_blocks)
                if actual != gd.free_blocks:
                    raise Ext4Error(
                        f"block group {g} free block count 불일치: descriptor={gd.free_blocks} bitmap={actual}"
                    )
                bitmaps_checked += 1

            if not (gd.flags & C.BG_INODE_UNINIT):
                raw = self.read_block(gd.inode_bitmap)
                if not bitmap_checksum_valid(self, gd, "inode", raw):
                    raise Ext4Error(f"block group {g} inode bitmap checksum 불일치")
                actual = bitmap_free_count(raw, group_inodes)
                if actual != gd.free_inodes:
                    raise Ext4Error(
                        f"block group {g} free inode count 불일치: descriptor={gd.free_inodes} bitmap={actual}"
                    )
                bitmaps_checked += 1

            free_blocks_total += gd.free_blocks
            free_inodes_total += gd.free_inodes
            groups_checked += 1

        if free_blocks_total != self.sb.free_blocks_count:
            raise Ext4Error(
                "superblock/group descriptor free block 합계가 일치하지 않습니다: "
                f"super={self.sb.free_blocks_count} groups={free_blocks_total}"
            )
        if free_inodes_total != self.sb.free_inodes_count:
            raise Ext4Error(
                "superblock/group descriptor free inode 합계가 일치하지 않습니다: "
                f"super={self.sb.free_inodes_count} groups={free_inodes_total}"
            )

        root = self.read_inode(C.EXT4_ROOT_INO)
        if not root.is_dir or root.links < 2:
            raise Ext4Error("root inode 구조가 올바르지 않습니다.")
        if not inode_checksum_valid(self.sb, root):
            raise Ext4Error("root inode checksum이 일치하지 않습니다.")

        for ex in file_extents(self, root):
            if ex.physical < self.sb.first_data_block or ex.physical + ex.length > self.sb.blocks_count:
                raise Ext4Error("root directory extent가 파일시스템 범위를 벗어났습니다.")

        if self.sb.has_journal and self.sb.journal_inum:
            journal_inode = self.read_inode(self.sb.journal_inum)
            if not inode_checksum_valid(self.sb, journal_inode):
                raise Ext4Error("journal inode checksum이 일치하지 않습니다.")
            for ex in file_extents(self, journal_inode):
                if ex.physical < self.sb.first_data_block or ex.physical + ex.length > self.sb.blocks_count:
                    raise Ext4Error("journal extent가 파일시스템 범위를 벗어났습니다.")

        if root.is_indexed:
            lblocks = _htree_leaves(self, root)
        else:
            lblocks = list(range(max(1, dir_block_count(root, self.sb.block_size))))
        for lblk in lblocks:
            block = read_dir_lblock(self, root, lblk)
            if not dir_block_checksum_valid(self, root, block):
                raise Ext4Error(f"root directory block {lblk} checksum이 일치하지 않습니다.")

        root_entries = list_dir(self, root)
        for entry in root_entries:
            if entry.inode < 1 or entry.inode > self.sb.inodes_count:
                raise Ext4Error(
                    f"root directory entry '{entry.name}' inode가 범위를 벗어났습니다: {entry.inode}"
                )

        # Re-read the on-disk superblock immediately before changing state so a
        # stale GUI selection cannot clear an error bit on a different medium.
        raw = self.dev.read(self.part_offset + 1024, 1024)
        disk_sb = parse_superblock(raw)
        if disk_sb.uuid != self.sb.uuid:
            raise Ext4Error("검사 중 저장장치가 바뀌어 ERROR_FS 복구를 중단했습니다.")
        if not superblock_checksum_valid(disk_sb):
            raise Ext4Error("최종 확인에서 superblock checksum이 일치하지 않습니다.")
        if disk_sb.needs_recovery or self.journal_start() != 0:
            raise Ext4Error("최종 확인에서 JBD2가 clean 상태가 아닙니다.")
        if not (disk_sb.state & C.EXT4_ERROR_FS):
            self.reload_metadata()
            return ErrorRepairStats(
                False,
                groups_checked,
                bitmaps_checked,
                len(root_entries),
                int(info["count"]),
                bitmap_checksums_repaired,
            )

        disk_sb.state &= ~C.EXT4_ERROR_FS
        struct.pack_into("<H", disk_sb.raw, 0x3A, disk_sb.state & 0xFFFF)
        disk_sb.write_checksum()
        self.dev.write(self.part_offset + 1024, bytes(disk_sb.raw[:1024]))
        self.dev.flush()
        self.reload_metadata()

        if self.sb.state & C.EXT4_ERROR_FS:
            raise Ext4Error("ERROR_FS 상태를 디스크에 반영하지 못했습니다.")
        LOG.warning(
            "EXT4 ERROR_FS 자동 복구 완료 groups=%s bitmaps=%s root_entries=%s "
            "historical_errors=%s bitmap_checksum_repairs=%s",
            groups_checked,
            bitmaps_checked,
            len(root_entries),
            info["count"],
            bitmap_checksums_repaired,
        )
        return ErrorRepairStats(
            True,
            groups_checked,
            bitmaps_checked,
            len(root_entries),
            int(info["count"]),
            bitmap_checksums_repaired,
        )

    def fs_write_blockers(self) -> list[str]:
        return self.hard_write_blockers() + self.soft_write_warnings()

    def hard_write_blockers(self) -> list[str]:
        reasons = []
        owns_live_journal = bool(
            getattr(self, "_write_session_active", False)
            and getattr(self, "_journal_writer", None) is not None
        )
        if not owns_live_journal and self.journal_needs_recovery():
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
        if self.sb.feature_ro_compat & C.EXT4_FEATURE_RO_COMPAT_ORPHAN_PRESENT:
            reasons.append("EXT4 orphan file 정리가 필요합니다.")
        if getattr(self.sb, "last_orphan", 0):
            reasons.append("EXT4 legacy orphan list 정리가 필요합니다.")
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
        if not self._write_session_active:
            self.begin_write_session()

    def close(self, abort: bool = False) -> None:
        try:
            if abort:
                LOG.info(
                    "이전 쓰기 오류가 있어 close 단계의 추가 flush/commit을 생략합니다."
                )
            elif self._write_session_active:
                # A normal close is a clean filesystem boundary.  All ordinary
                # operation-level commits stay inside one JBD2 session and only
                # this final boundary clears RECOVER/restores EXT4_VALID_FS.
                self.finish_write_session()
            else:
                self.commit_metadata(sync=True)
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


def _raw_ext4_scan_offsets(dev: BlockDevice) -> list[int]:
    """Conservative byte offsets to try when Windows exposes no partitions.

    Modern GPT/MBR tools normally align the first partition at 1 MiB. Some
    USB/card-reader stacks expose the physical disk but fail to surface the
    partition table, so probing a small set of standard raw offsets lets us
    recover the filesystem without depending on Windows' partition manager.
    """
    size = int(dev.size() or 0)
    mib = 1024 * 1024
    offsets: set[int] = {0}

    # Cover the usual modern alignment area without turning startup into a
    # whole-disk signature scan.
    max_mib = min(64, max(0, (size - 2048) // mib))
    for i in range(1, max_mib + 1):
        offsets.add(i * mib)

    # Old DOS/CHS and sector-based starts occasionally used by removable media.
    reported = int(getattr(dev, "sector_size", 512) or 512)
    for sector in {512, 4096, reported}:
        for lba in (63, 128, 256, 2048, 4096):
            off = int(lba) * int(sector)
            if 0 <= off + 2048 <= size:
                offsets.add(off)

    return sorted(off for off in offsets if 0 <= off + 2048 <= size)


def discover_volumes(dev: BlockDevice) -> list[VolumeInfo]:
    found: list[VolumeInfo] = []
    seen_off: set[int] = set()
    parts = []
    try:
        parts = list_partitions(dev)
    except Exception as exc:
        LOG.warning("파티션 테이블 검사 실패 — raw EXT4 탐색으로 계속합니다: %s", exc)
        parts = []

    candidates: list[tuple[int, int, int, str, str]] = []
    for p in parts:
        candidates.append((p.start, p.size, p.index, p.name, p.scheme))

    def add_candidate(
        start: int,
        size: int,
        idx: int,
        name: str,
        scheme: str,
        *,
        raw_scan: bool = False,
    ) -> bool:
        if start in seen_off:
            return False
        sb = probe_superblock(dev, start)
        if not sb:
            return False

        # Backup EXT superblocks contain their block-group number. A raw
        # signature scan must only accept the primary superblock.
        if raw_scan and int(getattr(sb, "block_group_nr", 0) or 0) != 0:
            return False

        fs_size = int(sb.blocks_count) * int(sb.block_size)
        disk_size = int(dev.size() or 0)
        if fs_size <= 0:
            return False
        if disk_size and start + fs_size > disk_size:
            return False

        effective_size = int(size or fs_size)
        if raw_scan:
            # Without a trustworthy partition table, bind writes to the exact
            # filesystem extent advertised by its primary superblock.
            effective_size = fs_size

        info = VolumeInfo(
            offset=start,
            size=effective_size,
            partition_index=idx,
            partition_name=name,
            scheme=scheme,
            sb=sb,
        )
        try:
            tmp = Ext4Volume(dev, start, info.size, owns_device=False)
            info.write_blockers = tmp.hard_write_blockers()
        except Exception as exc:
            if raw_scan:
                LOG.debug(
                    "raw EXT4 후보 검증 실패 offset=%s: %s",
                    start,
                    exc,
                )
                return False

        seen_off.add(start)
        found.append(info)
        if raw_scan:
            LOG.warning(
                "파티션 테이블 없이 EXT4 직접 발견 offset=%s size=%s "
                "uuid=%s label=%s",
                start,
                effective_size,
                sb.uuid.hex(),
                sb.volume_name or "-",
            )
        return True

    for start, size, idx, name, scheme in candidates:
        add_candidate(start, size, idx, name, scheme)

    if not found:
        for start in _raw_ext4_scan_offsets(dev):
            if add_candidate(
                start,
                0,
                0,
                "RAW EXT4",
                "RAW-SCAN",
                raw_scan=True,
            ):
                # The user's common case is one large removable-media
                # filesystem. Keep scanning the small prefix in case there are
                # multiple explicitly aligned EXT filesystems, but never scan
                # the whole disk.
                continue

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
