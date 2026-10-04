"""EXT4 extent tree and classic indirect block mapping."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ext4lib.fs import constants as C
from ext4lib.fs.crc32c import crc32c
from ext4lib.fs.inode import Inode
from ext4lib.fs.superblock import Superblock

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


def extent_at(extents: list[Extent], lblk: int) -> Extent | None:
    lo = 0
    hi = len(extents)
    while lo < hi:
        mid = (lo + hi) // 2
        ex = extents[mid]
        if lblk < ex.logical:
            hi = mid
        elif lblk >= ex.logical + ex.length:
            lo = mid + 1
        else:
            return ex
    return None


def file_extents(vol, inode: Inode) -> list[Extent]:
    key = bytes(inode.i_block[:60]).ljust(60, b"\x00")
    cache = getattr(vol, "_extent_cache", None)
    if cache is not None:
        hit = cache.get(inode.ino)
        if hit is not None and hit[0] == key:
            cache.move_to_end(inode.ino)
            return hit[1]
    if inode.uses_extents or (inode.i_block[:2] == struct.pack("<H", C.EXT4_EXT_MAGIC)):
        exts = walk_extents(vol, inode)
    else:
        exts = walk_indirect(vol, inode)
    exts.sort(key=lambda e: (e.logical, e.physical))
    if cache is not None:
        cache[inode.ino] = (key, exts)
        cache.move_to_end(inode.ino)
        cap = getattr(vol, "_extent_cache_cap", 512)
        while len(cache) > cap:
            cache.popitem(last=False)
    return exts


def read_mapped(vol, inode: Inode, offset: int, length: int) -> bytes:
    """Read ``length`` bytes at file offset, holes and unwritten extents as zeros."""
    if length <= 0:
        return b""
    from ext4lib.io.backend import IO_CHUNK

    bs = vol.sb.block_size
    out = bytearray(length)
    end = offset + length
    for ex in file_extents(vol, inode):
        if ex.uninitialized or ex.length <= 0:
            continue
        ex_lo = ex.logical * bs
        ex_hi = (ex.logical + ex.length) * bs
        lo = offset if offset > ex_lo else ex_lo
        hi = end if end < ex_hi else ex_hi
        if lo >= hi:
            continue
        disk = ex.physical * bs + (lo - ex_lo)
        dest = lo - offset
        left = hi - lo
        while left:
            n = IO_CHUNK if left > IO_CHUNK else left
            chunk = vol.read_bytes(disk, n)
            out[dest : dest + len(chunk)] = chunk
            if len(chunk) < n:
                break
            disk += n
            dest += n
            left -= n
    return bytes(out)


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


def _node_capacity(block_size: int, checksum: bool) -> int:
    tail = 4 if checksum else 0
    return (block_size - 12 - tail) // 12


def _leaf_record(ex: Extent) -> bytes:
    length = ex.length + (C.EXT_INIT_MAX_LEN if ex.uninitialized else 0)
    return struct.pack(
        "<IHHI",
        ex.logical,
        length,
        (ex.physical >> 32) & 0xFFFF,
        ex.physical & 0xFFFFFFFF,
    )


def _index_record(logical: int, phys: int) -> bytes:
    return struct.pack("<IIHH", logical, phys & 0xFFFFFFFF, (phys >> 32) & 0xFFFF, 0)


def _collect_index_blocks(vol, inode: Inode) -> list[int]:
    """Physical blocks that hold the extent tree, not file data."""
    data = inode.i_block
    if len(data) < 12:
        return []
    magic, entries, _eh_max, depth = _header(data, 0)
    if magic != C.EXT4_EXT_MAGIC or depth <= 0 or entries <= 0:
        return []
    out: list[int] = []
    try:
        _collect_index_node(vol, data, depth, entries, out, set())
    except Exception:
        return out
    return out


def _collect_index_node(vol, data: bytes, depth: int, entries: int, out: list[int], seen: set[int]) -> None:
    if depth <= 0:
        return
    limit = max(0, (len(data) - 12) // 12)
    count = entries if entries < limit else limit
    for i in range(count):
        _logical, phys = _idx(data, 12 + i * 12)
        if phys <= 0 or phys in seen:
            continue
        seen.add(phys)
        out.append(phys)
        try:
            block = vol.read_block(phys)
        except Exception:
            continue
        if len(block) < 12:
            continue
        magic, ent, _mx, dep = _header(block, 0)
        if magic != C.EXT4_EXT_MAGIC or ent <= 0:
            continue
        _collect_index_node(vol, block, dep, ent, out, seen)


def discard_old_extent_indexes(vol, inode: Inode) -> None:
    """Free index blocks left by the previous tree. Call after the new inode is stored."""
    old = getattr(inode, "_extent_index_old", None)
    if not old:
        return
    inode._extent_index_old = []
    from ext4lib.fs.bitmap import free_phys_runs

    free_phys_runs(vol, [(block, 1) for block in old])


def _write_extent_node(vol, inode: Inode, records: list[bytes], depth: int, cap: int, allocated: list[int]) -> int:
    from ext4lib.fs.bitmap import alloc_blocks

    phys = alloc_blocks(vol, 1, metadata=True)[0]
    allocated.append(phys)
    bs = vol.sb.block_size
    block = bytearray(bs)
    block[0:12] = struct.pack("<HHHHI", C.EXT4_EXT_MAGIC, len(records), cap, depth, 0)
    for i, rec in enumerate(records):
        block[12 + i * 12 : 24 + i * 12] = rec
    _extent_block_csum(vol.sb, inode.ino, inode.generation, block)
    vol.write_metadata_block(phys, bytes(block))
    return phys


def build_extent_tree(vol, inode: Inode, extents: list[Extent]) -> bytes:
    """Return 60-byte i_block. Grows a depth-2+ tree when one index level is not enough."""
    old_index = _collect_index_blocks(vol, inode)
    bs = vol.sb.block_size
    allocated: list[int] = []
    try:
        if len(extents) <= 4:
            body = extents_to_inode_body(extents)
        else:
            cap = _node_capacity(bs, vol.sb.has_metadata_csum)
            if cap < 2:
                raise ValueError("블록이 너무 작아 extent 트리를 만들 수 없습니다.")
            nodes: list[tuple[int, int]] = []
            idx = 0
            while idx < len(extents):
                chunk = extents[idx : idx + cap]
                phys = _write_extent_node(vol, inode, [_leaf_record(ex) for ex in chunk], 0, cap, allocated)
                nodes.append((chunk[0].logical, phys))
                idx += len(chunk)
            inode_depth = 1
            while len(nodes) > 4:
                packed: list[tuple[int, int]] = []
                cursor = 0
                while cursor < len(nodes):
                    chunk = nodes[cursor : cursor + cap]
                    phys = _write_extent_node(
                        vol,
                        inode,
                        [_index_record(logical, phys) for logical, phys in chunk],
                        inode_depth,
                        cap,
                        allocated,
                    )
                    packed.append((chunk[0][0], phys))
                    cursor += len(chunk)
                nodes = packed
                inode_depth += 1
            body_buf = bytearray(60)
            body_buf[0:12] = struct.pack("<HHHHI", C.EXT4_EXT_MAGIC, len(nodes), 4, inode_depth, 0)
            for i, (logical, phys) in enumerate(nodes):
                body_buf[12 + i * 12 : 24 + i * 12] = _index_record(logical, phys)
            inode.set_blocks((inode.blocks * 512) // bs + len(allocated), bs)
            body = bytes(body_buf)
    except Exception:
        if allocated:
            from ext4lib.fs.bitmap import free_phys_runs

            try:
                free_phys_runs(vol, [(block, 1) for block in allocated])
            except Exception:
                pass
        raise
    keep = set(allocated)
    inode._extent_index_old = [block for block in old_index if block not in keep]
    return body
