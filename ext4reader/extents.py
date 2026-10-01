"""EXT4 extent tree and classic indirect block mapping."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ext4reader import constants as C
from ext4reader.crc32c import crc32c
from ext4reader.inode import Inode
from ext4reader.superblock import Superblock

# Avoid circular import: volume passed as protocol


@dataclass
class Extent:
    logical: int
    length: int
    physical: int
    uninitialized: bool = False


def _header(data: bytes, off: int = 0) -> tuple[int, int, int, int]:
    magic, entries, eh_max, depth = struct.unpack_from("<HHHH", data, off)
    return magic, entries, eh_max, depth


def _leaf(data: bytes, off: int) -> Extent:
    block, length, start_hi, start_lo = struct.unpack_from("<IHHI", data, off)
    uninit = False
    if length > C.EXT_INIT_MAX_LEN:
        uninit = True
        length -= C.EXT_INIT_MAX_LEN
    physical = (start_hi << 32) | start_lo
    return Extent(block, length, physical, uninit)


def _idx(data: bytes, off: int) -> tuple[int, int]:
    block, leaf_lo, leaf_hi, _u = struct.unpack_from("<IIHH", data, off)
    return block, (leaf_hi << 32) | leaf_lo


def _extent_block_csum(sb: Superblock, ino: int, generation: int, block: bytearray) -> None:
    if not sb.has_metadata_csum:
        return
    # tail at end of block
    struct.pack_into("<I", block, sb.block_size - 4, 0)
    crc = crc32c(sb.csum_seed(), struct.pack("<I", ino))
    crc = crc32c(crc, struct.pack("<I", generation))
    crc = crc32c(crc, block[: sb.block_size - 4])
    struct.pack_into("<I", block, sb.block_size - 4, crc)


def walk_extents(vol, inode: Inode) -> list[Extent]:
    data = inode.i_block
    magic, entries, eh_max, depth = _header(data, 0)
    if magic != C.EXT4_EXT_MAGIC:
        return []
    return _walk_node(vol, inode, data, depth, entries, in_inode=True)


def _walk_node(vol, inode: Inode, data: bytes, depth: int, entries: int, in_inode: bool) -> list[Extent]:
    out: list[Extent] = []
    if depth == 0:
        for i in range(entries):
            out.append(_leaf(data, 12 + i * 12))
        return out
    for i in range(entries):
        _logical, phys = _idx(data, 12 + i * 12)
        block = vol.read_block(phys)
        magic, ent, _mx, dep = _header(block, 0)
        if magic != C.EXT4_EXT_MAGIC:
            continue
        out.extend(_walk_node(vol, inode, block, dep, ent, in_inode=False))
    return out


def walk_indirect(vol, inode: Inode) -> list[Extent]:
    """Classic ext2/3 block map -> run-length extents."""
    bs = vol.sb.block_size
    ptrs = struct.unpack("<15I", inode.i_block + b"\x00" * (60 - len(inode.i_block)))[:15]
    blocks: list[int] = []

    def read_ptrs(phys: int, count: int) -> list[int]:
        if phys == 0:
            return [0] * count
        raw = vol.read_block(phys)
        n = min(count, bs // 4)
        return list(struct.unpack("<%dI" % n, raw[: n * 4]))

    blocks.extend(ptrs[:12])
    if ptrs[12]:
        blocks.extend(read_ptrs(ptrs[12], bs // 4))
    if ptrs[13]:
        for mid in read_ptrs(ptrs[13], bs // 4):
            if mid:
                blocks.extend(read_ptrs(mid, bs // 4))
            else:
                blocks.extend([0] * (bs // 4))
    if ptrs[14]:
        for hi in read_ptrs(ptrs[14], bs // 4):
            if not hi:
                continue
            for mid in read_ptrs(hi, bs // 4):
                if mid:
                    blocks.extend(read_ptrs(mid, bs // 4))

    extents: list[Extent] = []
    logical = 0
    i = 0
    while i < len(blocks):
        if blocks[i] == 0:
            logical += 1
            i += 1
            continue
        start = blocks[i]
        run = 1
        while i + run < len(blocks) and blocks[i + run] == start + run:
            run += 1
        extents.append(Extent(logical, run, start, False))
        logical += run
        i += run
    return extents


def file_extents(vol, inode: Inode) -> list[Extent]:
    if inode.uses_extents or (inode.i_block[:2] == struct.pack("<H", C.EXT4_EXT_MAGIC)):
        return walk_extents(vol, inode)
    return walk_indirect(vol, inode)


def extents_to_inode_body(extents: list[Extent]) -> bytes:
    if len(extents) > 4:
        raise ValueError("inode 본문에는 extent가 4개까지입니다.")
    buf = bytearray(60)
    hdr = struct.pack("<HHHHI", C.EXT4_EXT_MAGIC, len(extents), 4, 0, 0)
    buf[0:12] = hdr
    for i, ex in enumerate(extents):
        length = ex.length
        if ex.uninitialized:
            length += C.EXT_INIT_MAX_LEN
        rec = struct.pack(
            "<IHHI",
            ex.logical,
            length,
            (ex.physical >> 32) & 0xFFFF,
            ex.physical & 0xFFFFFFFF,
        )
        buf[12 + i * 12 : 24 + i * 12] = rec
    return bytes(buf)


def build_extent_tree(vol, inode: Inode, extents: list[Extent]) -> bytes:
    """Return 60-byte i_block. Allocates index blocks if more than 4 extents."""
    if len(extents) <= 4:
        return extents_to_inode_body(extents)
    bs = vol.sb.block_size
    # one leaf block holds (bs-12-4)/12 extents roughly
    tail = 4 if vol.sb.has_metadata_csum else 0
    per_leaf = (bs - 12 - tail) // 12
    if per_leaf < 2:
        raise ValueError("블록이 너무 작아 extent 트리를 만들 수 없습니다.")
    leaves: list[tuple[int, int]] = []  # (first_logical, phys_block)
    from ext4reader.bitmap import alloc_blocks

    idx = 0
    allocated_index_blocks = 0
    while idx < len(extents):
        chunk = extents[idx : idx + per_leaf]
        phys_list = alloc_blocks(vol, 1)
        phys = phys_list[0]
        block = bytearray(bs)
        hdr = struct.pack("<HHHHI", C.EXT4_EXT_MAGIC, len(chunk), per_leaf, 0, 0)
        block[0:12] = hdr
        for i, ex in enumerate(chunk):
            length = ex.length + (C.EXT_INIT_MAX_LEN if ex.uninitialized else 0)
            rec = struct.pack(
                "<IHHI",
                ex.logical,
                length,
                (ex.physical >> 32) & 0xFFFF,
                ex.physical & 0xFFFFFFFF,
            )
            block[12 + i * 12 : 24 + i * 12] = rec
        _extent_block_csum(vol.sb, inode.ino, inode.generation, block)
        vol.write_block(phys, bytes(block))
        leaves.append((chunk[0].logical, phys))
        allocated_index_blocks += 1
        idx += len(chunk)

    if len(leaves) > 4:
        raise ValueError("파일이 너무 조각나 있습니다. 연속 할당에 실패했습니다.")

    body = bytearray(60)
    hdr = struct.pack("<HHHHI", C.EXT4_EXT_MAGIC, len(leaves), 4, 1, 0)
    body[0:12] = hdr
    for i, (logical, phys) in enumerate(leaves):
        rec = struct.pack("<IIHH", logical, phys & 0xFFFFFFFF, (phys >> 32) & 0xFFFF, 0)
        body[12 + i * 12 : 24 + i * 12] = rec
    inode.set_blocks(
        (inode.blocks * 512) // vol.sb.block_size + allocated_index_blocks,
        vol.sb.block_size,
    )
    return bytes(body)
