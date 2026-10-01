"""High-level EXT4 read/write operations."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from pathlib import Path

from ext4reader import constants as C
from ext4reader.bitmap import alloc_blocks, alloc_inode, free_blocks, free_inode
from ext4reader.directory import (
    DirError,
    add_dir_entry,
    init_directory_block,
    list_dir,
    remove_dir_entry,
)
from ext4reader.extents import Extent, build_extent_tree, file_extents
from ext4reader.inode import Inode, file_type_from_mode, new_inode_raw
from ext4reader.volume import Ext4Error, Ext4Volume

ProgressCb = Callable[[int, int], None]


def read_file_bytes(vol: Ext4Volume, inode: Inode, limit: int | None = None) -> bytes:
    if inode.is_lnk and inode.size <= 60:
        return inode.i_block[: inode.size]
    chunks: list[bytes] = []
    remaining = inode.size if limit is None else min(inode.size, limit)
    got = 0
    bs = vol.sb.block_size
    for ex in file_extents(vol, inode):
        if got >= remaining:
            break
        for i in range(ex.length):
            if got >= remaining:
                break
            take = min(bs, remaining - got)
            if ex.uninitialized:
                chunks.append(b"\x00" * take)
            else:
                block = vol.read_block(ex.physical + i)
                chunks.append(block[:take])
            got += take
    data = b"".join(chunks)
    return data[:remaining]


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
    with open(dest, "wb") as fp:
        if inode.size == 0:
            if progress:
                progress(0, 0)
            return
        for ex in file_extents(vol, inode):
            for i in range(ex.length):
                take = min(bs, total - done)
                if take <= 0:
                    break
                if ex.uninitialized:
                    fp.write(b"\x00" * take)
                else:
                    fp.write(vol.read_block(ex.physical + i)[:take])
                done += take
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
        written = 0
        with open(source_path, "rb") as fp:
            for i, pb in enumerate(phys):
                chunk = fp.read(bs)
                if len(chunk) < bs:
                    chunk = chunk + b"\x00" * (bs - len(chunk))
                vol.write_block(pb, chunk)
                written = min(size, (i + 1) * bs)
                if progress:
                    progress(written, size)
        exts = _runs_from_blocks(phys)
        body = build_extent_tree(vol, inode, exts)
        inode.set_i_block(body)
        inode.set_blocks(nblocks, bs)
    else:
        inode.set_blocks(0, bs)
        if progress:
            progress(0, 0)
    inode.set_times()
    vol.write_inode(inode)
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

    blocks = []
    for ex in file_extents(vol, child):
        if not ex.uninitialized:
            blocks.extend(range(ex.physical, ex.physical + ex.length))
    if blocks:
        free_blocks(vol, blocks)
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
        match = None
        for e in list_dir(vol, node):
            if e.name == part:
                match = e
                break
        if match is None:
            lower = part.lower()
            for e in list_dir(vol, node):
                if e.name.lower() == lower:
                    match = e
                    break
        if match is None:
            raise FileNotFoundError(path)
        ino = match.inode
    return vol.read_inode(ino)


def lookup_parent(vol: Ext4Volume, path: str) -> tuple[Inode, str]:
    parts = split_fs_path(path)
    if not parts:
        raise PermissionError("루트는 이름을 바꿀 수 없습니다.")
    parent = lookup_path(vol, "/" + "/".join(parts[:-1]))
    return parent, parts[-1]


def lookup_phys(vol: Ext4Volume, inode: Inode, lblk: int) -> int | None:
    for ex in file_extents(vol, inode):
        if ex.logical <= lblk < ex.logical + ex.length:
            if ex.uninitialized:
                return None
            return ex.physical + (lblk - ex.logical)
    return None


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
    bs = vol.sb.block_size
    out = bytearray()
    pos = offset
    end = offset + length
    while pos < end:
        lblk = pos // bs
        boff = pos % bs
        take = min(bs - boff, end - pos)
        phys = lookup_phys(vol, inode, lblk)
        if phys is None:
            out += b"\x00" * take
        else:
            out += vol.read_block(phys)[boff : boff + take]
        pos += take
    return bytes(out)


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
    mapping = None
    pos = 0
    while pos < len(data):
        abs_off = offset + pos
        lblk = abs_off // bs
        boff = abs_off % bs
        take = min(bs - boff, len(data) - pos)
        phys = lookup_phys(vol, inode, lblk)
        if phys is None:
            if mapping is None:
                mapping = inode_block_map(vol, inode)
            while lblk >= len(mapping):
                mapping.append(None)
            if mapping[lblk] is None:
                mapping[lblk] = alloc_blocks(vol, 1, prefer)[0]
            phys = mapping[lblk]
        chunk = data[pos : pos + take]
        if take == bs and boff == 0:
            vol.write_block(phys, chunk)
        else:
            blk = bytearray(vol.read_block(phys))
            blk[boff : boff + take] = chunk
            vol.write_block(phys, bytes(blk))
        pos += take
    if mapping is not None:
        _commit_mapping(vol, inode, mapping)
    new_size = max(inode.size, offset + len(data))
    if new_size != inode.size:
        inode.set_size(new_size)
    inode.set_times()
    vol.write_inode(inode)
    if flush:
        vol.flush_metadata()
    return len(data)


def set_file_size(vol: Ext4Volume, inode: Inode, new_size: int) -> Inode:
    vol.require_write()
    bs = vol.sb.block_size
    if new_size < 0:
        new_size = 0
    mapping = inode_block_map(vol, inode)
    new_n = (new_size + bs - 1) // bs if new_size else 0
    extra = [b for b in mapping[new_n:] if b is not None]
    mapping = mapping[:new_n]
    if extra:
        free_blocks(vol, extra)
    inode.set_size(new_size)
    _commit_mapping(vol, inode, mapping)
    inode.set_times()
    vol.write_inode(inode)
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
