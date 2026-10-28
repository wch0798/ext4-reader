"""High-level EXT4 read/write operations."""

from __future__ import annotations

import bisect
import os
import struct
import time
from collections.abc import Callable
from pathlib import Path

from ext4lib.fs import constants as C
from ext4lib.fs.bitmap import AllocError, alloc_blocks, alloc_inode, free_inode, free_phys_runs
from ext4lib.fs.directory import (
    DirError,
    add_dir_entry,
    check_new_name,
    dir_parent_ino,
    encode_name,
    init_directory_block,
    list_dir,
    lookup_dir_name,
    remove_dir_entry,
    same_name,
    set_parent_entry,
)
from ext4lib.fs.extents import (
    Extent,
    _collect_index_blocks,
    _collect_indirect_pointer_blocks,
    _node_capacity,
    build_extent_tree,
    discard_old_extent_indexes,
    ensure_extent_layout,
    extent_at,
    file_extents,
    read_mapped,
)
from ext4lib.io.backend import IO_CHUNK
from ext4lib.fs.inode import Inode, file_type_from_mode, new_inode_raw, parse_inode
from ext4lib.fs.volume import Ext4Error, Ext4Volume
from ext4lib.fs.xattr import release_xattr_block

ProgressCb = Callable[[int, int], None]


def read_file_bytes(vol: Ext4Volume, inode: Inode, limit: int | None = None) -> bytes:
    if _is_fast_symlink(inode):
        return inode.i_block[: inode.size]
    remaining = inode.size if limit is None else min(inode.size, limit)
    if remaining <= 0:
        return b""
    return read_mapped(vol, inode, 0, remaining)


def _write_zeros(fp, length: int) -> None:
    buf = b"\x00" * IO_CHUNK
    left = length
    while left > 0:
        n = IO_CHUNK if left > IO_CHUNK else left
        fp.write(buf if n == IO_CHUNK else buf[:n])
        left -= n


def _pwrite(vol: Ext4Volume, fs_off: int, data: bytes | memoryview) -> None:
    mv = data if isinstance(data, memoryview) else memoryview(data)
    pos = 0
    while pos < len(mv):
        n = IO_CHUNK if len(mv) - pos > IO_CHUNK else len(mv) - pos
        vol.write_bytes(fs_off + pos, mv[pos : pos + n])
        pos += n


def extract_inode(
    vol: Ext4Volume,
    inode: Inode,
    dest: str,
    progress: ProgressCb | None = None,
) -> None:
    total = inode.size
    done = 0
    bs = vol.sb.block_size
    os.makedirs(os.path.dirname(os.path.abspath(dest)) or ".", exist_ok=True)
    with open(dest, "wb", buffering=IO_CHUNK) as fp:
        if inode.size == 0:
            if progress:
                progress(0, 0)
            return
        cursor = 0
        for ex in file_extents(vol, inode):
            if done >= total:
                break
            ex_off = ex.logical * bs
            if ex_off > cursor and cursor < total:
                gap = min(ex_off, total) - cursor
                _write_zeros(fp, gap)
                done += gap
                cursor += gap
                if progress:
                    progress(done, total)
            if done >= total:
                break
            take = min(ex.length * bs, total - done)
            if ex.uninitialized:
                _write_zeros(fp, take)
                done += take
            else:
                disk = ex.physical * bs
                left = take
                while left:
                    n = IO_CHUNK if left > IO_CHUNK else left
                    fp.write(vol.read_bytes(disk, n))
                    disk += n
                    left -= n
                    done += n
                    if progress and (done == total or n == IO_CHUNK):
                        progress(done, total)
            cursor = ex_off + take
            if progress and done == total:
                progress(done, total)
        if done < total:
            _write_zeros(fp, total - done)
            done = total
            if progress:
                progress(done, total)
    try:
        os.utime(dest, (inode.atime or time.time(), inode.mtime or time.time()))
    except OSError:
        pass


def _runs_from_blocks(blocks: list[int]) -> list[Extent]:
    if not blocks:
        return []
    exts: list[Extent] = []
    log = 0
    i = 0
    while i < len(blocks):
        start = blocks[i]
        run = 1
        while i + run < len(blocks) and blocks[i + run] == start + run:
            run += 1
            if run >= C.EXT_UNINIT_MAX_LEN:
                break
        exts.append(Extent(log, run, start, False))
        log += run
        i += run
    return exts


# Source bytes read per write_range() call while copying a file in.
_COPY_CHUNK = 8 * IO_CHUNK


def create_file(
    vol: Ext4Volume,
    parent: Inode,
    name: str,
    source_path: str,
    progress: ProgressCb | None = None,
) -> Inode:
    """Copy a host file in. The file is linked first and then filled by
    bounded write steps, so a copy of any size fits a small JBD2 journal and
    every intermediate commit is a valid (shorter) file."""
    vol.require_write()
    check_new_name(vol, parent, name)
    size = os.path.getsize(source_path)
    bs = vol.sb.block_size
    nblocks = (size + bs - 1) // bs
    if nblocks > vol.sb.free_blocks_count:
        raise AllocError(f"자유 블록이 부족합니다 ({vol.sb.free_blocks_count}/{nblocks}).")
    inode = create_empty_file(vol, parent, name, flush=False)
    try:
        with open(source_path, "rb", buffering=IO_CHUNK) as fp:
            done = 0
            while done < size:
                n = min(_COPY_CHUNK, size - done)
                raw = fp.read(n)
                if len(raw) < n:
                    raw = raw + b"\x00" * (n - len(raw))
                write_range(vol, inode, done, raw)
                done += n
                if progress:
                    progress(done, size)
    except BaseException:
        # ENOSPC or a source read error: drop the partial file instead of
        # leaving it (and its blocks) behind.
        try:
            unlink(vol, vol.read_inode(parent.ino), name)
        except Exception:
            pass
        raise
    if not size and progress:
        progress(0, 0)
    vol.flush_metadata()
    return inode


def _link_new_inode(vol: Ext4Volume, parent_ino: int, name: str, inode: Inode, ftype: int) -> Inode:
    try:
        return add_dir_entry(vol, vol.read_inode(parent_ino), name, inode.ino, ftype)
    except Exception:
        # An allocated inode no directory names is an e2fsck "unattached
        # inode"; give its blocks and number back before reporting the error.
        release_inode_blocks(vol, inode)
        clear_freed_inode(vol, inode)
        free_inode(vol, inode.ino)
        raise


def _dir_is_indexed(vol: Ext4Volume, parent: Inode) -> bool:
    # Linux is_dx(): dir_index feature and EXT4_INDEX_FL on this directory.
    return bool(
        vol.sb.feature_compat & C.EXT4_FEATURE_COMPAT_DIR_INDEX
        and parent.flags & C.EXT4_INDEX_FL
    )


def _ensure_dir_link_room(vol: Ext4Volume, parent: Inode) -> None:
    # Linux EXT4_DIR_LINK_MAX(), checked before the directory entry changes.
    # dir_nlink is off (or the directory is not indexed): EMLINK once
    # i_links_count is already EXT4_LINK_MAX. 64998 subdirectories fit;
    # the next one does not.
    if parent.links >= C.EXT4_LINK_MAX and not (
        vol.sb.feature_ro_compat & C.EXT4_FEATURE_RO_COMPAT_DIR_NLINK
        and _dir_is_indexed(vol, parent)
    ):
        raise DirError("폴더의 하위 폴더 수가 최대치를 넘었습니다.")


def _enable_dir_nlink(vol: Ext4Volume) -> None:
    # The nlink==1 sentinel is defined only with DIR_NLINK. Linux used to
    # set the ro_compat bit in ext4_inc_count(); e2fsck pass4 still sets it
    # when a directory has more than EXT2_LINK_MAX links. Do it at the
    # moment we store the sentinel so the superblock matches the inode.
    sb = vol.sb
    bit = C.EXT4_FEATURE_RO_COMPAT_DIR_NLINK
    if sb.feature_ro_compat & bit:
        return
    sb.feature_ro_compat |= bit
    raw = getattr(sb, "raw", None)
    if raw is not None and len(raw) >= 0x68:
        struct.pack_into("<I", raw, 0x64, sb.feature_ro_compat)
    if hasattr(vol, "dirty_super"):
        vol.dirty_super = True


def _inc_dir_links(vol: Ext4Volume, parent: Inode) -> None:
    # Linux fs/ext4/namei.c ext4_inc_count():
    #   inc_nlink();
    #   if (is_dx() && (i_nlink > EXT4_LINK_MAX || i_nlink == 2))
    #       set_nlink(1);
    # 65000 itself is kept (64998 subdirectories). The next subdirectory
    # makes the count 65001, which is stored as 1, and every further
    # subdirectory stays at 1 because 1 increments to the sentinel 2.
    # A directory that is not indexed is never forced to 1. Directories
    # created here start linear and become indexed in make_indexed_dir()
    # once they grow past one block, so this sentinel applies to them too.
    _ensure_dir_link_room(vol, parent)
    links = parent.links + 1
    if _dir_is_indexed(vol, parent) and (links > C.EXT4_LINK_MAX or links == 2):
        links = 1
        _enable_dir_nlink(vol)
    parent.set_links(links)


def _dec_dir_links(parent: Inode) -> None:
    # Linux ext4_dec_count() for a directory: drop_nlink only when
    # i_nlink > 2. A count of 1 means there are more than EXT4_LINK_MAX
    # links and must not decrease, including after rmdir/rename brings
    # the real number of subdirectories back under the limit. A count of
    # 2 is the empty-directory value and is left unchanged.
    if parent.links > 2:
        parent.set_links(parent.links - 1)


def mkdir(vol: Ext4Volume, parent: Inode, name: str) -> Inode:
    vol.require_write()
    check_new_name(vol, parent, name)
    _ensure_dir_link_room(vol, parent)
    prefer = (parent.ino - 1) // vol.sb.inodes_per_group
    ino = alloc_inode(vol, prefer)
    inode = new_inode_raw(
        vol.sb,
        ino,
        C.S_IFDIR | int(getattr(vol, "default_dir_mode", C.DEFAULT_LINUX_DIR_MODE)),
        uid=int(getattr(vol, "default_uid", C.DEFAULT_LINUX_UID)),
        gid=int(getattr(vol, "default_gid", C.DEFAULT_LINUX_GID)),
    )
    inode.set_links(2)
    inode.flags |= C.EXT4_EXTENTS_FL
    # EXT4_FL_INHERITED: a subfolder of a casefold folder is casefold too,
    # otherwise case-insensitive lookups (Steam/Proton) fail on the Deck.
    if parent.flags & C.EXT4_CASEFOLD_FL:
        inode.flags |= C.EXT4_CASEFOLD_FL
    inode.set_flags(inode.flags)
    try:
        phys = alloc_blocks(vol, 1, prefer)[0]
    except BaseException:
        free_inode(vol, ino)
        raise
    inode.set_i_block(build_extent_tree(vol, inode, [Extent(0, 1, phys, False)]))
    inode.set_size(vol.sb.block_size)
    inode.set_blocks(1, vol.sb.block_size)
    init_directory_block(vol, inode, parent.ino, phys)
    vol.write_inode(inode)
    discard_old_extent_indexes(vol, inode)
    parent = _link_new_inode(vol, parent.ino, name, inode, C.EXT4_FT_DIR)
    _inc_dir_links(vol, parent)
    parent.set_times()
    vol.write_inode(parent)
    g = (ino - 1) // vol.sb.inodes_per_group
    vol.groups[g].used_dirs += 1
    vol.dirty_groups.add(g)
    vol.flush_metadata()
    return inode


def _phys_in_runs(runs: list[tuple[int, int]], block: int) -> bool:
    for phys, length in runs:
        if length > 0 and phys <= block < phys + length:
            return True
    return False


def _is_fast_symlink(inode: Inode) -> bool:
    # Same rule as e2fsprogs ext2fs_is_fast_symlink(): the target lives in i_block.
    return inode.is_lnk and 0 < inode.size < 60 and not inode.uses_extents


def release_inode_blocks(vol: Ext4Volume, child: Inode) -> None:
    """Free file data and the block-map metadata (extent index or classic
    indirect pointer blocks) that describe it."""
    if _is_fast_symlink(child) or child.flags & C.EXT4_INLINE_DATA_FL:
        return
    if not (child.is_reg or child.is_dir or child.is_lnk):
        return
    runs = [(ex.physical, ex.length) for ex in file_extents(vol, child) if ex.length]
    meta = _collect_index_blocks(vol, child)
    if not child.uses_extents:
        meta = meta + _collect_indirect_pointer_blocks(vol, child)
    indexes = [block for block in meta if block and not _phys_in_runs(runs, block)]
    if runs:
        free_phys_runs(vol, runs)
    if indexes:
        free_phys_runs(vol, [(block, 1) for block in indexes])


def clear_freed_inode(vol: Ext4Volume, child: Inode) -> None:
    """Release the xattr block, then zero the inode with dtime set and a
    checksum that matches what is stored (i_extra_isize is kept)."""
    release_xattr_block(vol, child)
    raw = bytearray(len(child.raw))
    if len(raw) >= 0x82:
        raw[0x80:0x82] = child.raw[0x80:0x82]
    struct.pack_into("<I", raw, 0x14, int(time.time()) & 0xFFFFFFFF)
    vol.write_inode(parse_inode(vol.sb, child.ino, bytes(raw)))


def unlink(vol: Ext4Volume, parent: Inode, name: str) -> None:
    vol.require_write()
    if name in (".", ".."):
        raise DirError("'.' 또는 '..' 는 지울 수 없습니다.")
    parent = vol.read_inode(parent.ino)
    ents = {e.name: e for e in list_dir(vol, parent)}
    target = ents.get(name)
    if not target:
        raise DirError(f"'{name}' 을(를) 찾지 못했습니다.")
    child = vol.read_inode(target.inode)
    if child.is_dir:
        inner = [e for e in list_dir(vol, child) if e.name not in (".", "..")]
        if inner:
            raise DirError("폴더가 비어 있지 않습니다.")
        if child.ino < vol.sb.first_ino:
            raise DirError("시스템 폴더는 지울 수 없습니다.")
    parent, ino = remove_dir_entry(vol, parent, name)
    child = vol.read_inode(ino)
    if child.is_dir:
        _dec_dir_links(parent)
        g = (ino - 1) // vol.sb.inodes_per_group
        if vol.groups[g].used_dirs:
            vol.groups[g].used_dirs -= 1
            vol.dirty_groups.add(g)
    parent.set_times()
    vol.write_inode(parent)

    # Make the namespace removal durable before the inode can become free.
    # If power/media removal happens between these two commits, the safe
    # failure mode is an unreachable allocated inode (recoverable by fsck),
    # never a directory entry that points at a freed/reused inode.
    vol.flush_metadata()
    parent = vol.read_inode(parent.ino)
    if any(e.name == name for e in list_dir(vol, parent)):
        raise Ext4Error(f"디렉터리 항목 삭제가 디스크에 반영되지 않았습니다: {name}")

    if not child.is_dir and child.links > 1:
        # Another hard link still names this inode: drop one reference only.
        child.set_links(child.links - 1)
        child.set_ctime()
        vol.write_inode(child)
        vol.flush_metadata()
        return

    if child.is_reg and child.uses_extents:
        # A huge fragmented file frees blocks in every group; shrink it in
        # bounded journal steps first, like Linux ext4_truncate().
        child = _shrink_in_steps(vol, child, 0)
    release_inode_blocks(vol, child)
    clear_freed_inode(vol, child)
    free_inode(vol, ino)
    vol.flush_metadata()


def unlink_checked(vol: Ext4Volume, parent: Inode, name: str) -> None:
    """Delete file, or empty directory. Checks directory emptiness first."""
    vol.require_write()
    ents = list_dir(vol, parent)
    target = next((e for e in ents if e.name == name), None)
    if not target:
        raise DirError(f"'{name}' 을(를) 찾지 못했습니다.")
    child = vol.read_inode(target.inode)
    if child.is_dir:
        inner = [e for e in list_dir(vol, child) if e.name not in (".", "..")]
        if inner:
            raise DirError("폴더가 비어 있지 않습니다. 안의 항목을 먼저 지우세요.")
        if child.ino < vol.sb.first_ino:
            raise DirError("시스템 폴더는 지울 수 없습니다.")
    if target.inode < vol.sb.first_ino and target.inode != 0:
        raise DirError("시스템 inode는 지울 수 없습니다.")
    unlink(vol, parent, name)


def rename_entry(vol: Ext4Volume, parent: Inode, old: str, new: str) -> None:
    vol.require_write()
    ents = list_dir(vol, parent)
    src = next((e for e in ents if e.name == old), None)
    if not src:
        raise DirError(f"'{old}' 을(를) 찾지 못했습니다.")
    # Casefold dir: "B" also collides with an existing "b". Checking only after
    # remove_dir_entry() would drop the old entry first. Renaming to another
    # case of itself is allowed, as on Linux.
    new_b = encode_name(new)
    if any(
        e.name == new
        or (e is not src and same_name(vol, parent, e.raw or e.name.encode("utf-8"), new_b))
        for e in ents
    ):
        raise DirError(f"'{new}' 이(가) 이미 있습니다.")
    parent = vol.read_inode(parent.ino)
    parent, ino = remove_dir_entry(vol, parent, old)
    child = vol.read_inode(ino)
    parent = add_dir_entry(vol, parent, new, ino, file_type_from_mode(child.mode))
    parent.set_times()
    vol.write_inode(parent)
    vol.flush_metadata()


def copy_tree_in(
    vol: Ext4Volume,
    parent: Inode,
    src: str,
    progress: ProgressCb | None = None,
) -> None:
    src_path = Path(src)
    if src_path.is_dir():
        folder = mkdir(vol, parent, src_path.name)
        items = list(src_path.iterdir())
        for i, child in enumerate(items):
            copy_tree_in(vol, folder, str(child), progress)
        return
    create_file(vol, parent, src_path.name, str(src_path), progress)


def extract_tree(
    vol: Ext4Volume,
    inode: Inode,
    name: str,
    dest_dir: str,
    progress: ProgressCb | None = None,
) -> None:
    dest = os.path.join(dest_dir, name)
    if inode.is_dir:
        os.makedirs(dest, exist_ok=True)
        for e in list_dir(vol, inode):
            if e.name in (".", ".."):
                continue
            child = vol.read_inode(e.inode)
            extract_tree(vol, child, e.name, dest, progress)
        return
    if inode.is_lnk:
        target = read_file_bytes(vol, inode)
        with open(dest, "wb") as fp:
            fp.write(target)
        return
    extract_inode(vol, inode, dest, progress)


def split_fs_path(path: str) -> list[str]:
    path = path.replace("\\", "/").strip("/")
    return [p for p in path.split("/") if p]


def lookup_path(vol: Ext4Volume, path: str) -> Inode:
    parts = split_fs_path(path)
    if not parts:
        return vol.read_inode(C.EXT4_ROOT_INO)
    ino = C.EXT4_ROOT_INO
    for part in parts:
        node = vol.read_inode(ino)
        if not node.is_dir:
            raise FileNotFoundError(path)
        child = lookup_dir_name(vol, node, part)
        if child is None:
            raise FileNotFoundError(path)
        ino = child
    return vol.read_inode(ino)


def lookup_parent(vol: Ext4Volume, path: str) -> tuple[Inode, str]:
    parts = split_fs_path(path)
    if not parts:
        raise PermissionError("루트는 이름을 바꿀 수 없습니다.")
    parent = lookup_path(vol, "/" + "/".join(parts[:-1]))
    return parent, parts[-1]


def lookup_phys(vol: Ext4Volume, inode: Inode, lblk: int) -> int | None:
    ex = extent_at(file_extents(vol, inode), lblk)
    if ex is None or ex.uninitialized:
        return None
    return ex.physical + (lblk - ex.logical)


def _merge_extents(extents: list[Extent]) -> list[Extent]:
    # Never mutates its input: the list may share Extent objects with the
    # volume's extent cache.
    if not extents:
        return []
    ordered = sorted(extents, key=lambda e: e.logical)
    out: list[Extent] = [ordered[0]]
    for ex in ordered[1:]:
        prev = out[-1]
        contiguous = (
            prev.logical + prev.length == ex.logical
            and prev.physical + prev.length == ex.physical
            and prev.uninitialized == ex.uninitialized
            and prev.length + ex.length <= C.EXT_UNINIT_MAX_LEN
        )
        if contiguous:
            out[-1] = Extent(prev.logical, prev.length + ex.length, prev.physical, prev.uninitialized)
        else:
            out.append(ex)
    return out


def _successor_logical(extents: list[Extent], lblk: int) -> int | None:
    lo = 0
    hi = len(extents)
    while lo < hi:
        mid = (lo + hi) // 2
        if extents[mid].logical <= lblk:
            lo = mid + 1
        else:
            hi = mid
    if lo < len(extents):
        return extents[lo].logical
    return None


def _add_runs(extents: list[Extent], logical: int, blocks: list[int], uninit: bool = False) -> list[Extent]:
    first = logical
    new: list[Extent] = []
    i = 0
    while i < len(blocks):
        start = blocks[i]
        run = 1
        while i + run < len(blocks) and blocks[i + run] == start + run and run < C.EXT_UNINIT_MAX_LEN:
            run += 1
        new.append(Extent(logical, run, start, uninit))
        logical += run
        i += run
    # ``extents`` is sorted: merge only around the insertion point instead of
    # re-sorting a fragmented file's whole extent list for every allocation.
    pos = bisect.bisect_left([e.logical for e in extents], first)
    lo = max(0, pos - 1)
    return extents[:lo] + _merge_extents(extents[lo:pos] + new + extents[pos : pos + 1]) + extents[pos + 1 :]


def _initialize_range(extents: list[Extent], logical: int, nblocks: int) -> list[Extent]:
    if nblocks <= 0:
        return extents
    end = logical + nblocks
    out: list[Extent] = []
    for ex in extents:
        ex_end = ex.logical + ex.length
        if not ex.uninitialized or ex_end <= logical or ex.logical >= end:
            out.append(ex)
            continue
        if ex.logical < logical:
            out.append(Extent(ex.logical, logical - ex.logical, ex.physical, True))
        mid_lo = logical if logical > ex.logical else ex.logical
        mid_hi = end if end < ex_end else ex_end
        out.append(Extent(mid_lo, mid_hi - mid_lo, ex.physical + (mid_lo - ex.logical), False))
        if ex_end > end:
            out.append(Extent(end, ex_end - end, ex.physical + (end - ex.logical), True))
    return _merge_extents(out)


def _write_at_block(
    vol: Ext4Volume,
    phys: int,
    boff: int,
    data: bytes,
    fresh: Callable[[int], bool] | None = None,
) -> None:
    """``fresh(phys)`` is true for a block whose disk content is not file data
    (just allocated, or unwritten extent); a partial write then starts from
    zeros like Linux instead of keeping a deleted file's bytes."""
    bs = vol.sb.block_size
    if not data:
        return
    if boff == 0 and len(data) % bs == 0:
        _pwrite(vol, phys * bs, data)
        return

    def base(block: int) -> bytearray:
        if fresh is not None and fresh(block):
            return bytearray(bs)
        return bytearray(vol.read_block(block))

    if boff:
        take = min(bs - boff, len(data))
        blk = base(phys)
        blk[boff : boff + take] = data[:take]
        vol.write_block(phys, bytes(blk))
        data = data[take:]
        phys += 1
        if not data:
            return
    nfull = len(data) // bs
    if nfull:
        _pwrite(vol, phys * bs, data[: nfull * bs])
        phys += nfull
        data = data[nfull * bs :]
    if data:
        blk = base(phys)
        blk[: len(data)] = data
        vol.write_block(phys, bytes(blk))


def _zero_tail_after_eof(vol: Ext4Volume, inode: Inode, upto: int) -> None:
    """Before i_size grows to ``upto``, zero the rest of the block holding EOF.

    A shrink keeps the old bytes after the new EOF in that block (and older
    writers left garbage there); growing the file must not bring them back.
    """
    bs = vol.sb.block_size
    old = inode.size
    if upto <= old or old % bs == 0:
        return
    phys = lookup_phys(vol, inode, old // bs)
    if phys is None:
        return
    blk = bytearray(vol.read_block(phys))
    blk[old % bs :] = b"\x00" * (bs - old % bs)
    vol.write_block(phys, bytes(blk))


def inode_block_map(vol: Ext4Volume, inode: Inode) -> list[int | None]:
    bs = vol.sb.block_size
    n = (inode.size + bs - 1) // bs
    mapping: list[int | None] = [None] * n
    for ex in file_extents(vol, inode):
        for i in range(ex.length):
            li = ex.logical + i
            while li >= len(mapping):
                mapping.append(None)
            if not ex.uninitialized:
                mapping[li] = ex.physical + i
    return mapping


def mapping_to_extents(mapping: list[int | None]) -> list[Extent]:
    exts: list[Extent] = []
    i = 0
    while i < len(mapping):
        phys = mapping[i]
        if phys is None:
            i += 1
            continue
        run = 1
        while (
            i + run < len(mapping)
            and mapping[i + run] is not None
            and mapping[i + run] == phys + run
            and run < C.EXT_UNINIT_MAX_LEN
        ):
            run += 1
        exts.append(Extent(i, run, phys, False))
        i += run
    return exts


def _commit_mapping(vol: Ext4Volume, inode: Inode, mapping: list[int | None]) -> None:
    exts = mapping_to_extents(mapping)
    # build_extent_tree() adds its index blocks on top of this data count.
    inode.set_owned_blocks(sum(1 for b in mapping if b is not None), vol.sb.block_size)
    inode.set_i_block(build_extent_tree(vol, inode, exts))


def create_empty_file(
    vol: Ext4Volume,
    parent: Inode,
    name: str,
    mode: int | None = None,
    flush: bool = True,
) -> Inode:
    vol.require_write()
    check_new_name(vol, parent, name)
    prefer = (parent.ino - 1) // vol.sb.inodes_per_group
    ino = alloc_inode(vol, prefer)
    file_mode = (
        int(getattr(vol, "default_file_mode", C.DEFAULT_LINUX_FILE_MODE))
        if mode is None
        else int(mode) & 0o777
    )
    inode = new_inode_raw(
        vol.sb,
        ino,
        C.S_IFREG | file_mode,
        uid=int(getattr(vol, "default_uid", C.DEFAULT_LINUX_UID)),
        gid=int(getattr(vol, "default_gid", C.DEFAULT_LINUX_GID)),
    )
    inode.set_size(0)
    inode.set_links(1)
    inode.set_blocks(0, vol.sb.block_size)
    vol.write_inode(inode)
    parent = _link_new_inode(vol, parent.ino, name, inode, C.EXT4_FT_REG_FILE)
    parent.set_times()
    vol.write_inode(parent)
    if flush:
        vol.flush_metadata()
    return inode


def read_range(vol: Ext4Volume, inode: Inode, offset: int, length: int) -> bytes:
    if _is_fast_symlink(inode):
        data = inode.i_block[: inode.size]
        return data[offset : offset + length]
    if offset >= inode.size or length <= 0:
        return b""
    length = min(length, inode.size - offset)
    return read_mapped(vol, inode, offset, length)


# Sequential copies allocate this many blocks at a time so a 1MB write does not
# become its own extent. 8192 * 4KiB is 32MiB.
_PREALLOC_BLOCKS = 8192


# One JBD2 write step allocates at most this many blocks from at most this
# many block groups (fewer when the journal is small), so the metadata it
# dirties -- bitmaps, group descriptors, extent leaves, inode -- is bounded.
_STEP_BLOCKS = 8192
_STEP_GROUPS = 4
# Extent-tree index levels on one root-to-leaf path, plus a new root level.
_TREE_PATH = 5


def _step_credits(vol: Ext4Volume, nblocks: int, ngroups: int) -> int:
    """Worst-case metadata blocks of one step that maps (or frees) up to
    ``nblocks`` blocks in ``ngroups`` groups -- jbd2 handle credits."""
    cap = _node_capacity(vol.sb.block_size, vol.sb.has_metadata_csum)
    # Leaves holding up to one extent per block, the old tail leaf and a
    # boundary leaf merged into the window, then one index node per level.
    tree = nblocks // cap + 3 + 2 * _TREE_PATH
    # Each group touched costs its bitmap and its descriptor block; new or
    # freed tree blocks may sit in groups of their own.
    groups = ngroups + tree
    return 2 + tree + 2 * groups  # + inode table block + superblock


def _write_step(vol: Ext4Volume) -> tuple[int, int | None, int]:
    """(blocks, groups, credits) of one bounded write/truncate step."""
    limit = vol.journal_transaction_limit()
    if limit is None:
        return _STEP_BLOCKS, None, 0
    blocks, groups = _STEP_BLOCKS, _STEP_GROUPS
    # Leave half the transaction for the steps around this one.
    while _step_credits(vol, blocks, groups) > limit // 2:
        if groups > 1:
            groups -= 1
        elif blocks > 1:
            blocks //= 2
        else:
            break
    credits = _step_credits(vol, blocks, groups)
    if credits > limit - 1:
        # JournalWriter refuses such journals up front; never get here mid-write.
        raise Ext4Error(f"JBD2 저널이 너무 작아 쓰기 단계를 나눌 수 없습니다 ({credits}>{limit}).")
    return blocks, groups, credits


def _check_space(vol: Ext4Volume, inode: Inode, offset: int, length: int) -> None:
    """Fail before the first step when the holes in the range cannot be filled,
    so a too-big write leaves the file as it was (steps commit as they go)."""
    bs = vol.sb.block_size
    first = offset // bs
    last = (offset + length - 1) // bs
    mapped = 0
    extents = file_extents(vol, inode)
    i = max(0, bisect.bisect_right([e.logical for e in extents], first) - 1)
    for ex in extents[i:]:
        if ex.logical > last:
            break
        lo = max(first, ex.logical)
        hi = min(last, ex.logical + ex.length - 1)
        if hi >= lo:
            mapped += hi - lo + 1
    need = (last - first + 1) - mapped
    if need > vol.sb.free_blocks_count:
        raise AllocError(f"자유 블록이 부족합니다 ({vol.sb.free_blocks_count}/{need}).")


def write_range(vol: Ext4Volume, inode: Inode, offset: int, data: bytes, flush: bool = False) -> int:
    """Write ``data`` at ``offset`` in bounded steps.

    Each step allocates and writes a bounded number of blocks (data first,
    ordered mode), then stores the extent tree, i_size and inode, so the
    volume is consistent between steps. Before each step the open JBD2
    transaction is committed and checkpointed when the step could push it
    past the transaction limit; a long fragmented copy therefore never
    outgrows a small journal.
    """
    vol.require_write()
    if data is None:
        return 0
    if isinstance(data, memoryview):
        data = data.tobytes()
    else:
        data = bytes(data)
    if not data:
        return 0
    inode = ensure_extent_layout(vol, inode)
    _check_space(vol, inode, offset, len(data))
    step_blocks, step_groups, credits = _write_step(vol)
    bs = vol.sb.block_size
    done = 0
    while done < len(data):
        vol.journal_reserve(credits)
        start = offset + done
        end = min(offset + len(data), (start // bs + step_blocks) * bs)
        done += _write_step_range(vol, inode, start, data[done : end - offset], step_groups)
    if flush:
        vol.flush_metadata()
    return len(data)


def _write_step_range(
    vol: Ext4Volume, inode: Inode, offset: int, data: bytes, max_groups: int | None
) -> int:
    """One write step; returns the bytes it consumed (at least one block's worth)."""
    extents = list(file_extents(vol, inode))
    _zero_tail_after_eof(vol, inode, offset + len(data))
    new_blocks: set[int] = set()
    try:
        consumed, changed = _write_range_blocks(
            vol, inode, offset, data, extents, new_blocks, max_groups
        )
    except BaseException:
        # e.g. ENOSPC part way: the inode was not written, so nothing refers to
        # the blocks this call allocated.
        if new_blocks:
            free_phys_runs(vol, [(e.physical, e.length) for e in _runs_from_blocks(sorted(new_blocks))])
        raise
    new_size = max(inode.size, offset + consumed)
    if new_size != inode.size:
        inode.set_size(new_size)
    inode.set_times()
    # Reserve blocks before the inode points at them. Device flush waits until
    # the caller asks, so a long copy is not stalled on the USB cache.
    vol.commit_metadata(sync=False)
    vol.write_inode(inode)
    discard_old_extent_indexes(vol, inode)
    cache = getattr(vol, "_extent_cache", None)
    if cache is not None:
        # Spare the next step a walk of every leaf of a fragmented file.
        cache[inode.ino] = (
            bytes(inode.i_block[:60]).ljust(60, b"\x00"),
            extents if changed is None else changed,
        )
    if consumed <= 0:
        raise Ext4Error("파일 쓰기가 진행되지 않습니다.")
    return consumed


def _write_range_blocks(
    vol: Ext4Volume,
    inode: Inode,
    offset: int,
    data: bytes,
    extents: list[Extent],
    new_blocks: set[int],
    max_groups: int | None = None,
) -> tuple[int, list[Extent] | None]:
    """Write ``data`` and update ``inode``'s mapping in memory. Every block
    allocated here is added to ``new_blocks``.

    With ``max_groups`` allocation stops once that many block groups were
    used; the bytes written so far and the new extent list (None when the
    mapping did not change) are returned."""
    bs = vol.sb.block_size
    prefer = (inode.ino - 1) // vol.sb.inodes_per_group
    changed = False
    dirty_lo = dirty_hi = None
    groups_left = max_groups
    pos = 0
    guard = 0
    while pos < len(data):
        guard += 1
        if guard > len(data) * 2 + 4:
            raise Ext4Error("파일 쓰기가 진행되지 않습니다.")
        abs_off = offset + pos
        lblk = abs_off // bs
        boff = abs_off % bs
        ex = extent_at(extents, lblk)
        if ex is None:
            if groups_left is not None and groups_left <= 0:
                break
            next_l = _successor_logical(extents, lblk)
            write_last = (offset + len(data) - 1) // bs
            hole_last = write_last if next_l is None else min(write_last, next_l - 1)
            need = hole_last - lblk + 1
            if need <= 0:
                raise Ext4Error("할당할 블록이 없습니다.")
            # Allocate only blocks that this write actually reaches. The old
            # 8192-block (32 MiB at 4 KiB) speculative preallocation left an
            # entire unwritten extent behind when Explorer deleted/interrupted
            # a copy; on the Steam Deck this showed up as an exact 8192-block
            # bitmap/free-count mismatch. Correctness is more important than
            # reducing extent count on removable media.
            phys_list = alloc_blocks(vol, need, prefer, max_groups=groups_left)
            new_blocks.update(phys_list)
            if groups_left is not None:
                first, per = vol.sb.first_data_block, vol.sb.blocks_per_group
                groups_left -= len({(b - first) // per for b in phys_list})
            extents = _add_runs(extents, lblk, phys_list)
            changed = True
            last = lblk + len(phys_list) - 1
            dirty_lo = lblk if dirty_lo is None else min(dirty_lo, lblk)
            dirty_hi = last if dirty_hi is None else max(dirty_hi, last)
            continue
        extent_end = (ex.logical + ex.length) * bs
        take = min(len(data) - pos, extent_end - abs_off)
        if take <= 0:
            raise Ext4Error("파일 쓰기가 진행되지 않습니다.")
        phys = ex.physical + (lblk - ex.logical)
        if ex.uninitialized:
            fresh = lambda _block: True
        else:
            fresh = new_blocks.__contains__
        _write_at_block(vol, phys, boff, data[pos : pos + take], fresh)
        if ex.uninitialized:
            touched = (boff + take + bs - 1) // bs
            extents = _initialize_range(extents, lblk, touched)
            changed = True
            last = lblk + touched - 1
            dirty_lo = lblk if dirty_lo is None else min(dirty_lo, lblk)
            dirty_hi = last if dirty_hi is None else max(dirty_hi, last)
        pos += take
    if not changed:
        return pos, None
    # _add_runs() and _initialize_range() already return merged lists.
    inode.set_owned_blocks(sum(e.length for e in extents), bs)
    inode.set_i_block(build_extent_tree(vol, inode, extents, (dirty_lo, dirty_hi)))
    return pos, extents


def _tail_cut(vol: Ext4Volume, extents: list[Extent], new_n: int, max_blocks: int, max_groups: int) -> int:
    """Logical block from which one bounded truncate step may free the tail:
    ``new_n`` when everything past it fits in one step."""
    first, per = vol.sb.first_data_block, vol.sb.blocks_per_group
    groups: set[int] = set()
    runs = 0
    cut = None
    for ex in reversed(extents):
        end = ex.logical + ex.length
        if end <= new_n:
            break
        lo = max(ex.logical, new_n)
        phys_lo = ex.physical + (lo - ex.logical)
        phys_hi = ex.physical + ex.length - 1
        span = set(range((phys_lo - first) // per, (phys_hi - first) // per + 1))
        if cut is not None and (runs + 1 > max_blocks or len(groups | span) > max_groups):
            return cut
        groups |= span
        runs += 1
        cut = lo
    return new_n


def _shrink_in_steps(vol: Ext4Volume, inode: Inode, new_n: int) -> Inode:
    """Free blocks past ``new_n`` from the end in bounded journal steps.

    Every step drops whole tail extents, lowers i_size to the cut and stores
    the inode, so a crash in between leaves a valid, merely longer file.
    The final step (down to ``new_n``) is left to the caller.
    """
    if vol.journal_transaction_limit() is None:
        return inode
    step_blocks, step_groups, credits = _write_step(vol)
    bs = vol.sb.block_size
    while True:
        cut = _tail_cut(vol, file_extents(vol, inode), new_n, step_blocks, step_groups)
        if cut <= new_n:
            return inode
        vol.journal_reserve(credits)
        _truncate_mapping(vol, inode, cut)
        if inode.size > cut * bs:
            inode.set_size(cut * bs)
        inode.set_times()
        vol.write_inode(inode)
        discard_old_extent_indexes(vol, inode)


def _truncate_mapping(vol: Ext4Volume, inode: Inode, new_n: int) -> None:
    """Drop the mapping from logical block ``new_n`` on (blocks are freed
    when the transaction commits)."""
    bs = vol.sb.block_size
    keep: list[Extent] = []
    runs: list[tuple[int, int]] = []
    for ex in file_extents(vol, inode):
        ex_end = ex.logical + ex.length
        if ex_end <= new_n:
            keep.append(Extent(ex.logical, ex.length, ex.physical, ex.uninitialized))
            continue
        if ex.logical >= new_n:
            runs.append((ex.physical, ex.length))
            continue
        keep_len = new_n - ex.logical
        keep.append(Extent(ex.logical, keep_len, ex.physical, ex.uninitialized))
        runs.append((ex.physical + keep_len, ex.length - keep_len))
    if runs:
        free_phys_runs(vol, runs)
    keep = _merge_extents(keep)
    inode.set_owned_blocks(sum(e.length for e in keep), bs)
    inode.set_i_block(build_extent_tree(vol, inode, keep, (max(0, new_n - 1), 0xFFFFFFFF)))


def set_file_size(vol: Ext4Volume, inode: Inode, new_size: int) -> Inode:
    vol.require_write()
    inode = ensure_extent_layout(vol, inode)
    bs = vol.sb.block_size
    if new_size < 0:
        new_size = 0
    new_n = (new_size + bs - 1) // bs if new_size else 0
    inode = _shrink_in_steps(vol, inode, new_n)
    vol.journal_reserve(_write_step(vol)[2])
    _truncate_mapping(vol, inode, new_n)
    _zero_tail_after_eof(vol, inode, new_size)
    inode.set_size(new_size)
    inode.set_times()
    vol.write_inode(inode)
    discard_old_extent_indexes(vol, inode)
    vol.flush_metadata()
    return inode


def move_entry(vol: Ext4Volume, src_path: str, dst_path: str, replace: bool = False) -> None:
    vol.require_write()
    src_parent, src_name = lookup_parent(vol, src_path)
    dst_parent, dst_name = lookup_parent(vol, dst_path)
    src_ents = {e.name: e for e in list_dir(vol, src_parent)}
    if src_name not in src_ents:
        raise DirError(f"'{src_name}' 을(를) 찾지 못했습니다.")
    dst_ents = {e.name: e for e in list_dir(vol, dst_parent)}
    if dst_name in dst_ents:
        if not replace:
            raise DirError(f"'{dst_name}' 이(가) 이미 있습니다.")
        unlink_checked(vol, dst_parent, dst_name)
        dst_parent = vol.read_inode(dst_parent.ino)
        src_parent = vol.read_inode(src_parent.ino)
    child = vol.read_inode(src_ents[src_name].inode)
    if src_parent.ino == dst_parent.ino:
        rename_entry(vol, src_parent, src_name, dst_name)
        return
    if child.is_dir:
        _ensure_dir_link_room(vol, dst_parent)
        # Refuse moving a folder into itself or one of its own subfolders.
        # '..' comes from block 0 (the dx_root fake dirent when indexed); a
        # chain that cannot be followed to the root is refused, not allowed.
        cur = dst_parent.ino
        for _ in range(4096):
            if cur == child.ino:
                raise DirError("폴더를 자기 자신의 하위 폴더로 옮길 수 없습니다.")
            if cur == C.EXT4_ROOT_INO:
                break
            up = dir_parent_ino(vol, vol.read_inode(cur))
            if up == cur:
                raise DirError("폴더의 '..' 항목이 올바르지 않습니다.")
            cur = up
        else:
            raise DirError("폴더 경로가 너무 깊어 이동을 확인할 수 없습니다.")
    src_parent, ino = remove_dir_entry(vol, src_parent, src_name)
    if child.is_dir:
        _dec_dir_links(src_parent)
    src_parent.set_times()
    vol.write_inode(src_parent)
    dst_parent = add_dir_entry(
        vol, vol.read_inode(dst_parent.ino), dst_name, ino, file_type_from_mode(child.mode)
    )
    if child.is_dir:
        _inc_dir_links(vol, dst_parent)
        set_parent_entry(vol, vol.read_inode(ino), dst_parent.ino)
    dst_parent.set_times()
    vol.write_inode(dst_parent)
    vol.flush_metadata()
