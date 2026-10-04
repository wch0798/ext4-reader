"""High-level EXT4 read/write operations."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from pathlib import Path

from ext4lib.fs import constants as C
from ext4lib.fs.bitmap import AllocError, alloc_blocks, alloc_inode, free_inode, free_phys_runs
from ext4lib.fs.directory import (
    DirError,
    add_dir_entry,
    init_directory_block,
    list_dir,
    lookup_dir_name,
    remove_dir_entry,
)
from ext4lib.fs.extents import (
    Extent,
    _collect_index_blocks,
    build_extent_tree,
    discard_old_extent_indexes,
    extent_at,
    file_extents,
    read_mapped,
)
from ext4lib.io.backend import IO_CHUNK
from ext4lib.fs.inode import Inode, file_type_from_mode, new_inode_raw
from ext4lib.fs.volume import Ext4Error, Ext4Volume

ProgressCb = Callable[[int, int], None]


def read_file_bytes(vol: Ext4Volume, inode: Inode, limit: int | None = None) -> bytes:
    if inode.is_lnk and inode.size <= 60:
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


def create_file(
    vol: Ext4Volume,
    parent: Inode,
    name: str,
    source_path: str,
    progress: ProgressCb | None = None,
) -> Inode:
    vol.require_write()
    size = os.path.getsize(source_path)
    bs = vol.sb.block_size
    nblocks = (size + bs - 1) // bs
    prefer = (parent.ino - 1) // vol.sb.inodes_per_group
    ino = alloc_inode(vol, prefer)
    inode = new_inode_raw(vol.sb, ino, C.S_IFREG | 0o644)
    inode.set_size(size)
    inode.set_links(1)
    if nblocks:
        phys = alloc_blocks(vol, nblocks, prefer)
        with open(source_path, "rb", buffering=IO_CHUNK) as fp:
            i = 0
            while i < len(phys):
                start = phys[i]
                run = 1
                while (
                    i + run < len(phys)
                    and phys[i + run] == start + run
                    and run < C.EXT_UNINIT_MAX_LEN
                ):
                    run += 1
                raw = fp.read(run * bs)
                if len(raw) < run * bs:
                    raw = raw + b"\x00" * (run * bs - len(raw))
                _pwrite(vol, start * bs, raw)
                i += run
                if progress:
                    progress(min(size, i * bs), size)
        exts = _runs_from_blocks(phys)
        inode.set_blocks(nblocks, bs)
        inode.set_i_block(build_extent_tree(vol, inode, exts))
    else:
        inode.set_blocks(0, bs)
        if progress:
            progress(0, 0)
    inode.set_times()
    vol.write_inode(inode)
    discard_old_extent_indexes(vol, inode)
    parent = vol.read_inode(parent.ino)
    parent = add_dir_entry(vol, parent, name, ino, C.EXT4_FT_REG_FILE)
    parent.set_times()
    vol.write_inode(parent)
    vol.flush_metadata()
    return inode


def mkdir(vol: Ext4Volume, parent: Inode, name: str) -> Inode:
    vol.require_write()
    prefer = (parent.ino - 1) // vol.sb.inodes_per_group
    ino = alloc_inode(vol, prefer)
    inode = new_inode_raw(vol.sb, ino, C.S_IFDIR | 0o755)
    inode.set_links(2)
    inode.flags |= C.EXT4_EXTENTS_FL
    inode.set_flags(inode.flags)
    phys = alloc_blocks(vol, 1, prefer)[0]
    inode.set_i_block(build_extent_tree(vol, inode, [Extent(0, 1, phys, False)]))
    inode.set_size(vol.sb.block_size)
    inode.set_blocks(1, vol.sb.block_size)
    init_directory_block(vol, inode, parent.ino, phys)
    vol.write_inode(inode)
    discard_old_extent_indexes(vol, inode)
    parent = vol.read_inode(parent.ino)
    parent = add_dir_entry(vol, parent, name, ino, C.EXT4_FT_DIR)
    parent.set_links(parent.links + 1)
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


def release_inode_blocks(vol: Ext4Volume, child: Inode) -> None:
    """Free file data and the extent-tree index blocks that describe it."""
    runs = [(ex.physical, ex.length) for ex in file_extents(vol, child) if ex.length]
    indexes = [
        block
        for block in _collect_index_blocks(vol, child)
        if block and not _phys_in_runs(runs, block)
    ]
    if runs:
        free_phys_runs(vol, runs)
    if indexes:
        free_phys_runs(vol, [(block, 1) for block in indexes])


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
        parent.set_links(max(1, parent.links - 1))
        g = (ino - 1) // vol.sb.inodes_per_group
        if vol.groups[g].used_dirs:
            vol.groups[g].used_dirs -= 1
            vol.dirty_groups.add(g)
    parent.set_times()
    vol.write_inode(parent)

    release_inode_blocks(vol, child)
    # zero inode
    child.raw[:] = b"\x00" * len(child.raw)
    child.dtime = int(time.time())
    import struct as _st

    _st.pack_into("<I", child.raw, 0x14, child.dtime)
    vol.write_inode(child)
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
    if any(e.name == new for e in ents):
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
            prev.length += ex.length
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
    i = 0
    while i < len(blocks):
        start = blocks[i]
        run = 1
        while i + run < len(blocks) and blocks[i + run] == start + run and run < C.EXT_UNINIT_MAX_LEN:
            run += 1
        extents.append(Extent(logical, run, start, uninit))
        logical += run
        i += run
    return _merge_extents(extents)


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


def _write_at_block(vol: Ext4Volume, phys: int, boff: int, data: bytes) -> None:
    bs = vol.sb.block_size
    if not data:
        return
    if boff == 0 and len(data) % bs == 0:
        _pwrite(vol, phys * bs, data)
        return
    if boff:
        take = min(bs - boff, len(data))
        blk = bytearray(vol.read_block(phys))
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
        blk = bytearray(vol.read_block(phys))
        blk[: len(data)] = data
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
    inode.set_i_block(build_extent_tree(vol, inode, exts))
    inode.set_blocks(sum(1 for b in mapping if b is not None), vol.sb.block_size)


def create_empty_file(vol: Ext4Volume, parent: Inode, name: str, mode: int = 0o644) -> Inode:
    vol.require_write()
    prefer = (parent.ino - 1) // vol.sb.inodes_per_group
    ino = alloc_inode(vol, prefer)
    inode = new_inode_raw(vol.sb, ino, C.S_IFREG | (mode & 0o777))
    inode.set_size(0)
    inode.set_links(1)
    inode.set_blocks(0, vol.sb.block_size)
    vol.write_inode(inode)
    parent = vol.read_inode(parent.ino)
    parent = add_dir_entry(vol, parent, name, ino, C.EXT4_FT_REG_FILE)
    parent.set_times()
    vol.write_inode(parent)
    vol.flush_metadata()
    return inode


def read_range(vol: Ext4Volume, inode: Inode, offset: int, length: int) -> bytes:
    if inode.is_lnk and inode.size <= 60:
        data = inode.i_block[: inode.size]
        return data[offset : offset + length]
    if offset >= inode.size or length <= 0:
        return b""
    length = min(length, inode.size - offset)
    return read_mapped(vol, inode, offset, length)


# Sequential copies allocate this many blocks at a time so a 1MB write does not
# become its own extent. 8192 * 4KiB is 32MiB.
_PREALLOC_BLOCKS = 8192


def write_range(vol: Ext4Volume, inode: Inode, offset: int, data: bytes, flush: bool = False) -> int:
    vol.require_write()
    if data is None:
        return 0
    if isinstance(data, memoryview):
        data = data.tobytes()
    else:
        data = bytes(data)
    if not data:
        return 0
    bs = vol.sb.block_size
    prefer = (inode.ino - 1) // vol.sb.inodes_per_group
    extents = [Extent(e.logical, e.length, e.physical, e.uninitialized) for e in file_extents(vol, inode)]
    changed = False
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
            next_l = _successor_logical(extents, lblk)
            write_last = (offset + len(data) - 1) // bs
            hole_last = write_last if next_l is None else min(write_last, next_l - 1)
            need = hole_last - lblk + 1
            if need <= 0:
                raise Ext4Error("할당할 블록이 없습니다.")
            extra = 0
            if next_l is None and need < _PREALLOC_BLOCKS:
                extra = _PREALLOC_BLOCKS - need
            try:
                phys_list = alloc_blocks(vol, need + extra, prefer)
            except AllocError:
                if not extra:
                    raise
                phys_list = alloc_blocks(vol, need, prefer)
                extra = 0
            if extra and len(phys_list) > need:
                extents = _add_runs(extents, lblk, phys_list[:need])
                extents = _add_runs(extents, lblk + need, phys_list[need:], uninit=True)
            else:
                extents = _add_runs(extents, lblk, phys_list)
            changed = True
            continue
        extent_end = (ex.logical + ex.length) * bs
        take = min(len(data) - pos, extent_end - abs_off)
        if take <= 0:
            raise Ext4Error("파일 쓰기가 진행되지 않습니다.")
        phys = ex.physical + (lblk - ex.logical)
        _write_at_block(vol, phys, boff, data[pos : pos + take])
        if ex.uninitialized:
            touched = (boff + take + bs - 1) // bs
            extents = _initialize_range(extents, lblk, touched)
            changed = True
        pos += take
    if changed:
        extents = _merge_extents(extents)
        inode.set_blocks(sum(e.length for e in extents), bs)
        inode.set_i_block(build_extent_tree(vol, inode, extents))
    new_size = max(inode.size, offset + len(data))
    if new_size != inode.size:
        inode.set_size(new_size)
    inode.set_times()
    # Reserve blocks before the inode points at them. Device flush waits until
    # the caller asks, so a long copy is not stalled on the USB cache.
    vol.commit_metadata(sync=False)
    vol.write_inode(inode)
    discard_old_extent_indexes(vol, inode)
    if flush:
        vol.flush_metadata()
    return len(data)


def set_file_size(vol: Ext4Volume, inode: Inode, new_size: int) -> Inode:
    vol.require_write()
    bs = vol.sb.block_size
    if new_size < 0:
        new_size = 0
    new_n = (new_size + bs - 1) // bs if new_size else 0
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
    inode.set_size(new_size)
    inode.set_blocks(sum(e.length for e in keep), bs)
    inode.set_i_block(build_extent_tree(vol, inode, keep))
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
    src_parent, ino = remove_dir_entry(vol, src_parent, src_name)
    if child.is_dir:
        src_parent.set_links(max(1, src_parent.links - 1))
        dst_parent = vol.read_inode(dst_parent.ino)
        dst_parent.set_links(dst_parent.links + 1)
    src_parent.set_times()
    vol.write_inode(src_parent)
    dst_parent = add_dir_entry(
        vol, vol.read_inode(dst_parent.ino), dst_name, ino, file_type_from_mode(child.mode)
    )
    dst_parent.set_times()
    vol.write_inode(dst_parent)
    vol.flush_metadata()
