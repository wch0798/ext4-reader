"""In-inode xattrs, inline data and external xattr blocks."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ext4lib.fs import constants as C
from ext4lib.fs.crc32c import crc32c
from ext4lib.fs.inode import Inode

XATTR_MAGIC = 0xEA020000
XATTR_INDEX_SYSTEM = 7
INLINE_MIN_SIZE = 60


@dataclass
class IbodyXattr:
    name_index: int
    name: bytes
    value: bytes
    value_inum: int
    value_size: int
    hash: int


def is_inline(inode: Inode) -> bool:
    return bool(inode.flags & C.EXT4_INLINE_DATA_FL)


def _ibody_start(inode: Inode) -> int | None:
    if len(inode.raw) <= 128 or inode.extra_isize < 4:
        return None
    start = 128 + inode.extra_isize
    if start + 4 > len(inode.raw):
        return None
    if struct.unpack_from("<I", inode.raw, start)[0] != XATTR_MAGIC:
        return None
    return start


def ibody_xattrs(inode: Inode) -> list[IbodyXattr]:
    start = _ibody_start(inode)
    if start is None:
        return []
    raw = inode.raw
    first = start + 4
    end = len(raw)
    out: list[IbodyXattr] = []
    off = first
    while off + 16 <= end and struct.unpack_from("<I", raw, off)[0] != 0:
        nlen, idx, voff, vinum, vsize, h = struct.unpack_from("<BBHIII", raw, off)
        name = bytes(raw[off + 16 : off + 16 + nlen])
        value = b""
        if not vinum and vsize:
            if first + voff + vsize > end:
                raise ValueError(f"inode {inode.ino} xattr 값이 inode 범위를 벗어났습니다.")
            value = bytes(raw[first + voff : first + voff + vsize])
        out.append(IbodyXattr(idx, name, value, vinum, vsize, h))
        off += (16 + nlen + 3) & ~3
    return out


def _store_ibody_xattrs(inode: Inode, attrs: list[IbodyXattr]) -> None:
    base = 128 + inode.extra_isize
    end = len(inode.raw)
    inode.raw[base:end] = b"\x00" * (end - base)
    if not attrs:
        return
    first = base + 4
    struct.pack_into("<I", inode.raw, base, XATTR_MAGIC)
    off = first
    vend = end
    for a in attrs:
        voff = 0
        if not a.value_inum and a.value:
            vend -= (len(a.value) + 3) & ~3
            voff = vend - first
            inode.raw[vend : vend + len(a.value)] = a.value
        struct.pack_into("<BBHIII", inode.raw, off, len(a.name), a.name_index, voff, a.value_inum, a.value_size, a.hash)
        inode.raw[off + 16 : off + 16 + len(a.name)] = a.name
        off += (16 + len(a.name) + 3) & ~3
    if off + 4 > vend:
        raise ValueError(f"inode {inode.ino} xattr 영역이 부족합니다.")


def _system_data(inode: Inode) -> bytes:
    for a in ibody_xattrs(inode):
        if a.name_index == XATTR_INDEX_SYSTEM and a.name == b"data":
            return a.value
    return b""


def inline_bytes(inode: Inode) -> bytes:
    """Raw inline area: i_block followed by the system.data xattr value."""
    return inode.i_block + _system_data(inode)


def read_inline(inode: Inode, offset: int, length: int) -> bytes:
    data = inline_bytes(inode)[: inode.size]
    data = data.ljust(inode.size, b"\x00")
    return data[offset : offset + length]


def inline_dir_entries(inode: Inode):
    """Directory entries of an inline directory, including '.' and '..'."""
    from ext4lib.fs.directory import DirEntry, parse_dirent_block

    data = inline_bytes(inode)
    parent = struct.unpack_from("<I", data, 0)[0]
    out = [DirEntry(".", inode.ino, C.EXT4_FT_DIR), DirEntry("..", parent, C.EXT4_FT_DIR)]
    out.extend(parse_dirent_block(data[4:INLINE_MIN_SIZE]))
    extra = data[INLINE_MIN_SIZE:]
    if extra:
        out.extend(parse_dirent_block(extra))
    return out


def uninline(vol, inode: Inode) -> Inode:
    """Move inline file/directory data into a normal extent-mapped block."""
    from ext4lib.fs.bitmap import alloc_blocks
    from ext4lib.fs.directory import _dir_csum_set, _insert_into_block, _tail_size, init_directory_block
    from ext4lib.fs.extents import Extent, build_extent_tree, discard_old_extent_indexes

    if not is_inline(inode):
        return inode
    bs = vol.sb.block_size
    prefer = (inode.ino - 1) // vol.sb.inodes_per_group
    if inode.is_dir:
        entries = [e for e in inline_dir_entries(inode) if e.name not in (".", "..")]
        parent = inline_dir_entries(inode)[1].inode
        data = None
        nblocks = 1
    else:
        entries = []
        parent = 0
        data = read_inline(inode, 0, inode.size)
        nblocks = (len(data) + bs - 1) // bs
    phys = alloc_blocks(vol, nblocks, prefer) if nblocks else []

    attrs = [a for a in ibody_xattrs(inode) if not (a.name_index == XATTR_INDEX_SYSTEM and a.name == b"data")]
    _store_ibody_xattrs(inode, attrs)
    inode.set_flags((inode.flags & ~C.EXT4_INLINE_DATA_FL) | C.EXT4_EXTENTS_FL)
    inode.set_i_block(struct.pack("<HHHHI", C.EXT4_EXT_MAGIC, 0, 4, 0, 0) + b"\x00" * 48)

    if inode.is_dir:
        init_directory_block(vol, inode, parent, phys[0])
        usable = bs - _tail_size(vol)
        block = bytearray(vol.read_block(phys[0]))
        for e in entries:
            if not _insert_into_block(block, usable, e.inode, e.name.encode("utf-8"), e.file_type):
                raise ValueError("inline 디렉터리를 블록으로 옮기지 못했습니다.")
        _dir_csum_set(vol, inode, block)
        vol.write_metadata_block(phys[0], bytes(block))
        inode.set_size(bs)
    elif phys:
        vol.write_bytes(phys[0] * bs, data.ljust(nblocks * bs, b"\x00"))
    exts = [Extent(0, nblocks, phys[0], False)] if phys else []
    inode.set_owned_blocks(nblocks, bs)
    inode.set_i_block(build_extent_tree(vol, inode, exts))
    vol.write_inode(inode)
    discard_old_extent_indexes(vol, inode)
    if inode.is_dir:
        vol.drop_dir_cache(inode.ino)
    return inode


def _xattr_block_csum(vol, phys: int, block: bytearray) -> None:
    if not vol.sb.has_metadata_csum:
        return
    struct.pack_into("<I", block, 0x10, 0)
    crc = crc32c(vol.sb.csum_seed(), struct.pack("<Q", phys))
    crc = crc32c(crc, bytes(block))
    struct.pack_into("<I", block, 0x10, crc)


def release_xattr_block(vol, inode: Inode) -> None:
    """Drop this inode's reference to its external xattr block."""
    from ext4lib.fs.bitmap import free_phys_runs

    phys = inode.file_acl
    if not phys:
        return
    if phys < vol.sb.first_data_block or phys >= vol.sb.blocks_count:
        raise ValueError(f"inode {inode.ino} xattr block이 범위를 벗어났습니다: {phys}")
    block = bytearray(vol.read_block(phys))
    magic, refcount = struct.unpack_from("<II", block, 0)
    if magic == XATTR_MAGIC and refcount > 1:
        struct.pack_into("<I", block, 4, refcount - 1)
        _xattr_block_csum(vol, phys, block)
        vol.write_metadata_block(phys, bytes(block))
        return
    free_phys_runs(vol, [(phys, 1)])
