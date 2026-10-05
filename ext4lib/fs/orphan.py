"""EXT4 orphan-list/orphan-file recovery for Windows writable mounts."""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass

from ext4lib.debuglog import LOG
from ext4lib.fs import constants as C
from ext4lib.fs.bitmap import (
    free_inode,
    free_phys_runs,
    read_inode_bitmap,
)
from ext4lib.fs.crc32c import crc32c
from ext4lib.fs.extents import (
    Extent,
    build_extent_tree,
    discard_old_extent_indexes,
    extent_at,
    file_extents,
)
from ext4lib.fs.inode import Inode, inode_checksum_valid


class OrphanRecoveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class OrphanRecoveryStats:
    orphan_file_blocks: int = 0
    entries_found: int = 0
    deleted: int = 0
    truncated: int = 0
    cleared_present: bool = False
    cleared_legacy: bool = False


def _inode_csum_seed(vol, inode: Inode) -> int:
    seed = crc32c(vol.sb.csum_seed(), struct.pack("<I", inode.ino))
    return crc32c(seed, struct.pack("<I", inode.generation))


def _orphan_block_checksum(vol, inode: Inode, phys: int, block: bytes) -> int:
    seed = _inode_csum_seed(vol, inode)
    crc = crc32c(seed, struct.pack("<Q", phys))
    return crc32c(crc, block[: vol.sb.block_size - 8])


def _map_file_blocks(vol, inode: Inode, count: int) -> list[int]:
    exts = file_extents(vol, inode)
    out: list[int] = []
    for lblk in range(count):
        ex = extent_at(exts, lblk)
        if ex is None or ex.uninitialized:
            raise OrphanRecoveryError(
                f"orphan file logical block {lblk}가 매핑되어 있지 않습니다."
            )
        phys = ex.physical + (lblk - ex.logical)
        if phys < vol.sb.first_data_block or phys >= vol.sb.blocks_count:
            raise OrphanRecoveryError(
                f"orphan file block {lblk}의 물리 블록이 범위를 벗어났습니다: {phys}"
            )
        out.append(phys)
    return out


def _inode_allocated(vol, ino: int) -> bool:
    if ino < vol.sb.first_ino or ino > vol.sb.inodes_count:
        return False
    group = (ino - 1) // vol.sb.inodes_per_group
    bit = (ino - 1) % vol.sb.inodes_per_group
    gd = vol.groups[group]
    if gd.flags & C.BG_INODE_UNINIT:
        return False
    return read_inode_bitmap(vol, gd).test(bit)


def _validate_orphan_inode(vol, ino: int) -> Inode:
    if ino < vol.sb.first_ino or ino > vol.sb.inodes_count:
        raise OrphanRecoveryError(f"orphan inode 번호가 범위를 벗어났습니다: {ino}")
    if not _inode_allocated(vol, ino):
        raise OrphanRecoveryError(f"orphan inode {ino}의 inode bitmap bit가 비어 있습니다.")
    inode = vol.read_inode(ino)
    if not inode_checksum_valid(vol.sb, inode):
        raise OrphanRecoveryError(f"orphan inode {ino} checksum이 일치하지 않습니다.")
    if inode.links and not (inode.is_reg or inode.is_dir or inode.is_lnk):
        raise OrphanRecoveryError(
            f"orphan inode {ino}는 안전하게 truncate할 수 없는 inode 형식입니다."
        )
    if inode.file_acl and inode.links == 0:
        raise OrphanRecoveryError(
            f"orphan inode {ino}에 외부 xattr block이 있어 자동 삭제를 중단합니다."
        )
    if not inode.uses_extents and inode.blocks and not (inode.is_lnk and inode.size <= 60):
        raise OrphanRecoveryError(
            f"orphan inode {ino}는 non-extent 데이터 블록을 사용해 자동 정리를 중단합니다."
        )
    return inode


def _scan_orphan_file(vol) -> tuple[Inode | None, list[int], list[bytearray], list[int]]:
    if not (vol.sb.feature_compat & C.EXT4_FEATURE_COMPAT_ORPHAN_FILE):
        if vol.sb.feature_ro_compat & C.EXT4_FEATURE_RO_COMPAT_ORPHAN_PRESENT:
            raise OrphanRecoveryError(
                "ORPHAN_PRESENT가 있지만 COMPAT_ORPHAN_FILE 기능이 없습니다."
            )
        return None, [], [], []

    ino = int(vol.sb.orphan_file_inum or 0)
    if ino < vol.sb.first_ino or ino > vol.sb.inodes_count:
        raise OrphanRecoveryError(f"orphan file inode 번호가 잘못되었습니다: {ino}")
    inode = _validate_orphan_inode(vol, ino)
    bs = vol.sb.block_size
    if inode.size % bs:
        raise OrphanRecoveryError("orphan file 크기가 block size 배수가 아닙니다.")
    blocks = inode.size // bs
    if blocks < 1 or blocks > C.EXT4_MAX_ORPHAN_FILE_BLOCKS:
        raise OrphanRecoveryError(f"orphan file block 수가 비정상입니다: {blocks}")

    phys_blocks = _map_file_blocks(vol, inode, blocks)
    raw_blocks: list[bytearray] = []
    entries: list[int] = []
    slots = (bs - 8) // 4

    for idx, phys in enumerate(phys_blocks):
        raw = bytearray(vol.read_block(phys))
        if len(raw) != bs:
            raise OrphanRecoveryError(f"orphan file block {idx} 읽기 길이가 잘못되었습니다.")
        magic = struct.unpack_from("<I", raw, bs - 8)[0]
        if magic != C.EXT4_ORPHAN_BLOCK_MAGIC:
            raise OrphanRecoveryError(
                f"orphan file block {idx} magic이 잘못되었습니다: 0x{magic:08X}"
            )
        if vol.sb.has_metadata_csum:
            stored = struct.unpack_from("<I", raw, bs - 4)[0]
            calc = _orphan_block_checksum(vol, inode, phys, raw)
            if stored != calc:
                raise OrphanRecoveryError(
                    f"orphan file block {idx} checksum 불일치"
                )
        for slot in range(slots):
            child = struct.unpack_from("<I", raw, slot * 4)[0]
            if child:
                entries.append(child)
        raw_blocks.append(raw)
    return inode, phys_blocks, raw_blocks, entries


def _scan_legacy_chain(vol) -> list[int]:
    current = int(vol.sb.last_orphan or 0)
    if current == 0:
        return []
    out: list[int] = []
    seen: set[int] = set()
    while current:
        if current in seen:
            raise OrphanRecoveryError("legacy orphan list에 순환 참조가 있습니다.")
        seen.add(current)
        inode = _validate_orphan_inode(vol, current)
        out.append(current)
        nxt = int(inode.dtime or 0)
        if nxt > vol.sb.inodes_count:
            raise OrphanRecoveryError(
                f"legacy orphan inode {current}의 next 값이 잘못되었습니다: {nxt}"
            )
        current = nxt
        if len(out) > vol.sb.inodes_count:
            raise OrphanRecoveryError("legacy orphan list가 비정상적으로 깁니다.")
    return out


def _truncate_orphan(vol, inode: Inode) -> None:
    """Drop extent allocations beyond the already-recorded i_size."""
    if inode.is_lnk and inode.size <= 60:
        inode.dtime = 0
        struct.pack_into("<I", inode.raw, 0x14, 0)
        vol.write_inode(inode)
        return

    bs = vol.sb.block_size
    keep_blocks = (inode.size + bs - 1) // bs if inode.size else 0
    keep: list[Extent] = []
    frees: list[tuple[int, int]] = []
    for ex in file_extents(vol, inode):
        end = ex.logical + ex.length
        if end <= keep_blocks:
            keep.append(Extent(ex.logical, ex.length, ex.physical, ex.uninitialized))
            continue
        if ex.logical >= keep_blocks:
            frees.append((ex.physical, ex.length))
            continue
        n = keep_blocks - ex.logical
        keep.append(Extent(ex.logical, n, ex.physical, ex.uninitialized))
        frees.append((ex.physical + n, ex.length - n))

    if frees:
        free_phys_runs(vol, frees)

    # i_blocks is not just file-data extents.  Linux/e2fsck counts every
    # filesystem block owned by the inode, including extent-tree metadata and
    # an external xattr (i_file_acl) block.  Set the data+xattr baseline before
    # rebuilding the tree; build_extent_tree() then adds any newly allocated
    # extent-index blocks.  Omitting i_file_acl leaves i_blocks short by one
    # 4 KiB block (8 sectors), which is exactly what e2fsck reports on Steam
    # Deck volumes after orphan truncation.
    owned_blocks = sum(ex.length for ex in keep)
    if inode.file_acl:
        owned_blocks += 1
    inode.set_blocks(owned_blocks, bs)
    inode.set_i_block(build_extent_tree(vol, inode, keep))
    inode.dtime = 0
    struct.pack_into("<I", inode.raw, 0x14, 0)
    vol.write_inode(inode)
    discard_old_extent_indexes(vol, inode)


def _delete_orphan(vol, inode: Inode) -> None:
    from ext4lib.fs.writer import release_inode_blocks

    if inode.ino < vol.sb.first_ino:
        raise OrphanRecoveryError(f"예약 inode {inode.ino}는 자동 삭제할 수 없습니다.")
    if inode.is_dir:
        group = (inode.ino - 1) // vol.sb.inodes_per_group
        if vol.groups[group].used_dirs:
            vol.groups[group].used_dirs -= 1
            vol.dirty_groups.add(group)
    release_inode_blocks(vol, inode)

    _g, off = vol._inode_loc(inode.ino)
    raw = bytearray(vol.sb.inode_size)
    struct.pack_into("<I", raw, 0x14, int(time.time()) & 0xFFFFFFFF)
    vol.write_metadata_bytes(off, bytes(raw))
    vol._inode_cache.pop(inode.ino, None)
    vol._extent_cache.pop(inode.ino, None)
    free_inode(vol, inode.ino)


def _rewrite_orphan_blocks_empty(
    vol, orphan_inode: Inode, phys_blocks: list[int], blocks: list[bytearray]
) -> None:
    bs = vol.sb.block_size
    slots_bytes = bs - 8
    for phys, raw in zip(phys_blocks, blocks):
        raw[:slots_bytes] = b"\x00" * slots_bytes
        struct.pack_into("<I", raw, bs - 8, C.EXT4_ORPHAN_BLOCK_MAGIC)
        if vol.sb.has_metadata_csum:
            struct.pack_into("<I", raw, bs - 4, 0)
            csum = _orphan_block_checksum(vol, orphan_inode, phys, raw)
            struct.pack_into("<I", raw, bs - 4, csum)
        vol.write_metadata_block(phys, bytes(raw))


def recover_orphans(vol, progress=None) -> OrphanRecoveryStats:
    """Recover pending EXT4 orphan metadata without Linux/e2fsck.

    All orphan metadata and referenced inodes are validated before the first
    write.  Cleanup itself is journaled using the existing JBD2 writer.
    """
    has_present = bool(
        vol.sb.feature_ro_compat & C.EXT4_FEATURE_RO_COMPAT_ORPHAN_PRESENT
    )
    has_legacy = bool(vol.sb.last_orphan)
    if not has_present and not has_legacy:
        return OrphanRecoveryStats()

    if not vol.dev.writable:
        raise OrphanRecoveryError("orphan 복구에는 쓰기 가능한 장치가 필요합니다.")
    if vol.journal_needs_recovery() or vol.sb.needs_recovery:
        raise OrphanRecoveryError("JBD2 복구를 먼저 완료해야 orphan 복구를 할 수 있습니다.")

    orphan_inode: Inode | None = None
    phys_blocks: list[int] = []
    orphan_blocks: list[bytearray] = []
    file_entries: list[int] = []
    if has_present:
        if progress:
            progress("orphan file 구조와 checksum 검사")
        orphan_inode, phys_blocks, orphan_blocks, file_entries = _scan_orphan_file(vol)

    if progress:
        progress("legacy orphan list 검사")
    legacy_entries = _scan_legacy_chain(vol)

    ordered: list[int] = []
    seen: set[int] = set()
    for ino in [*legacy_entries, *file_entries]:
        if orphan_inode is not None and ino == orphan_inode.ino:
            raise OrphanRecoveryError("orphan file이 자기 자신을 orphan으로 참조합니다.")
        if ino not in seen:
            _validate_orphan_inode(vol, ino)
            seen.add(ino)
            ordered.append(ino)

    LOG.warning(
        "EXT4 orphan 복구 검사 완료 orphan_file_blocks=%s entries=%s legacy=%s",
        len(phys_blocks),
        len(file_entries),
        len(legacy_entries),
    )

    # Empty orphan file / empty legacy list is common after an error-state
    # mount. Clear only the stale presence metadata, but still journal/flush it.
    vol.begin_write_session()
    deleted = 0
    truncated = 0
    try:
        for idx, ino in enumerate(ordered):
            if progress:
                progress(f"orphan inode 정리 {idx + 1}/{len(ordered)}")
            inode = vol.read_inode(ino)
            if inode.links:
                _truncate_orphan(vol, inode)
                truncated += 1
            else:
                _delete_orphan(vol, inode)
                deleted += 1

        if orphan_inode is not None:
            _rewrite_orphan_blocks_empty(vol, orphan_inode, phys_blocks, orphan_blocks)

        if has_present:
            vol.sb.feature_ro_compat &= ~C.EXT4_FEATURE_RO_COMPAT_ORPHAN_PRESENT
            struct.pack_into("<I", vol.sb.raw, 0x64, vol.sb.feature_ro_compat)
            vol.dirty_super = True
        if has_legacy:
            vol.sb.last_orphan = 0
            struct.pack_into("<I", vol.sb.raw, 0xE8, 0)
            vol.dirty_super = True

        vol.finish_write_session()
    except Exception:
        # Preserve dirty/recovery state. The caller will keep the volume
        # read-only and JBD2 recovery can replay a committed cleanup if needed.
        raise

    vol.reload_metadata()
    if vol.sb.feature_ro_compat & C.EXT4_FEATURE_RO_COMPAT_ORPHAN_PRESENT:
        raise OrphanRecoveryError("ORPHAN_PRESENT 상태가 디스크에서 제거되지 않았습니다.")
    if vol.sb.last_orphan:
        raise OrphanRecoveryError("legacy orphan list가 디스크에서 제거되지 않았습니다.")

    LOG.warning(
        "EXT4 orphan 자동 복구 완료 entries=%s deleted=%s truncated=%s",
        len(ordered),
        deleted,
        truncated,
    )
    return OrphanRecoveryStats(
        orphan_file_blocks=len(phys_blocks),
        entries_found=len(ordered),
        deleted=deleted,
        truncated=truncated,
        cleared_present=has_present,
        cleared_legacy=has_legacy,
    )
