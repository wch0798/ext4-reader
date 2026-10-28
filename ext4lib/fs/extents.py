"""EXT4 extent tree and classic indirect block mapping."""

from __future__ import annotations

import bisect
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
    per = bs // 4
    ptrs = struct.unpack("<15I", inode.i_block + b"\x00" * (60 - len(inode.i_block)))[:15]
    extents: list[Extent] = []

    def add(logical: int, phys: int) -> None:
        last = extents[-1] if extents else None
        if last and last.logical + last.length == logical and last.physical + last.length == phys:
            last.length += 1
        else:
            extents.append(Extent(logical, 1, phys, False))

    def walk(phys: int, depth: int, logical: int) -> None:
        # A hole pointer (0) still covers per**depth logical blocks; callers
        # pass the absolute start so later data keeps its true offset.
        if phys == 0:
            return
        if depth == 0:
            add(logical, phys)
            return
        raw = vol.read_block(phys)
        span = per ** (depth - 1)
        for i, child in enumerate(struct.unpack("<%dI" % per, raw[: per * 4])):
            walk(child, depth - 1, logical + i * span)

    for i in range(12):
        walk(ptrs[i], 0, i)
    walk(ptrs[12], 1, 12)
    walk(ptrs[13], 2, 12 + per)
    walk(ptrs[14], 3, 12 + per + per * per)
    return extents


def _collect_indirect_pointer_blocks(vol, inode: Inode) -> list[int]:
    """Return classic indirect metadata blocks referenced by i_block."""
    if inode.uses_extents:
        return []
    if inode.is_lnk and inode.size <= 60 and inode.blocks == 0:
        return []
    if inode.blocks == 0:
        return []

    bs = vol.sb.block_size
    ptrs = struct.unpack(
        "<15I",
        inode.i_block + b"\x00" * (60 - len(inode.i_block)),
    )[:15]
    out: list[int] = []
    seen: set[int] = set()

    def add_pointer_block(phys: int, depth: int) -> None:
        if not phys or phys in seen:
            return
        if phys < vol.sb.first_data_block or phys >= vol.sb.blocks_count:
            raise ValueError(
                f"inode {inode.ino} indirect block이 범위를 벗어났습니다: {phys}"
            )
        seen.add(phys)
        out.append(phys)
        if depth <= 1:
            return
        raw = vol.read_block(phys)
        count = bs // 4
        values = struct.unpack("<%dI" % count, raw[: count * 4])
        for child in values:
            if child:
                add_pointer_block(child, depth - 1)

    add_pointer_block(ptrs[12], 1)
    add_pointer_block(ptrs[13], 2)
    add_pointer_block(ptrs[14], 3)
    return out


def _reserve_conversion(vol, nextents: int, pointers: list[int]) -> None:
    """The block-map -> extent conversion is one metadata update (one jbd2
    handle). Refuse it before anything is written when it cannot fit the
    journal, otherwise commit the open transaction first if needed."""
    writer = getattr(vol, "_journal_writer", None)
    if writer is None:
        return
    cap = _node_capacity(vol.sb.block_size, vol.sb.has_metadata_csum)
    leaves = nextents // cap + 1
    tree = leaves + leaves // cap + 2
    first, per = vol.sb.first_data_block, vol.sb.blocks_per_group
    groups = len({(b - first) // per for b in pointers}) + tree
    credits = 2 + tree + 2 * groups  # + inode table block + superblock
    if credits > writer.hard_transaction_blocks:
        from ext4lib.fs.volume import Ext4Error

        raise Ext4Error(
            f"extent 변환에 필요한 메타데이터({credits}블록)가 JBD2 저널 "
            f"({writer.hard_transaction_blocks}블록)보다 큽니다. 저널을 키우거나 Linux에서 변환하세요."
        )
    vol.journal_reserve(credits)


def ensure_extent_layout(vol, inode: Inode) -> Inode:
    """Before modifying a file/directory mapping, move inline data or a classic
    ext2/3 block map (left by an ext3 -> ext4 conversion) to an extent tree."""
    if inode.flags & C.EXT4_INLINE_DATA_FL:
        from ext4lib.fs.xattr import uninline

        return uninline(vol, inode)
    if inode.uses_extents or not (inode.is_reg or inode.is_dir):
        return inode
    from ext4lib.fs.bitmap import free_phys_runs

    exts = []
    for ex in walk_indirect(vol, inode):
        done = 0
        while done < ex.length:
            n = min(ex.length - done, C.EXT_INIT_MAX_LEN)
            exts.append(Extent(ex.logical + done, n, ex.physical + done, False))
            done += n
    pointers = _collect_indirect_pointer_blocks(vol, inode)
    _reserve_conversion(vol, len(exts), pointers)
    inode.set_flags(inode.flags | C.EXT4_EXTENTS_FL)
    inode.set_i_block(struct.pack("<HHHHI", C.EXT4_EXT_MAGIC, 0, 4, 0, 0) + b"\x00" * 48)
    inode.set_owned_blocks(sum(e.length for e in exts), vol.sb.block_size)
    inode.set_i_block(build_extent_tree(vol, inode, exts))
    vol.write_inode(inode)
    if pointers:
        free_phys_runs(vol, [(block, 1) for block in pointers])
    return inode


def inode_allocation_blocks(vol, inode: Inode) -> set[int]:
    """All filesystem blocks owned by one allocated inode.

    Includes file data/unwritten extents, extent-tree or classic indirect
    metadata blocks, and the external xattr block when present.
    """
    blocks: set[int] = set()

    if inode.blocks:
        if inode.uses_extents or (
            inode.i_block[:2] == struct.pack("<H", C.EXT4_EXT_MAGIC)
        ):
            for ex in file_extents(vol, inode):
                if ex.length <= 0:
                    continue
                if (
                    ex.physical < vol.sb.first_data_block
                    or ex.physical + ex.length > vol.sb.blocks_count
                ):
                    raise ValueError(
                        f"inode {inode.ino} extent가 범위를 벗어났습니다: "
                        f"{ex.physical}+{ex.length}"
                    )
                blocks.update(range(ex.physical, ex.physical + ex.length))
            blocks.update(_collect_index_blocks(vol, inode))
        elif inode.is_reg or inode.is_dir or inode.is_lnk:
            for ex in walk_indirect(vol, inode):
                if ex.length <= 0:
                    continue
                if (
                    ex.physical < vol.sb.first_data_block
                    or ex.physical + ex.length > vol.sb.blocks_count
                ):
                    raise ValueError(
                        f"inode {inode.ino} indirect data가 범위를 벗어났습니다: "
                        f"{ex.physical}+{ex.length}"
                    )
                blocks.update(range(ex.physical, ex.physical + ex.length))
            blocks.update(_collect_indirect_pointer_blocks(vol, inode))

    if inode.file_acl:
        if (
            inode.file_acl < vol.sb.first_data_block
            or inode.file_acl >= vol.sb.blocks_count
        ):
            raise ValueError(
                f"inode {inode.ino} external xattr block이 범위를 벗어났습니다: "
                f"{inode.file_acl}"
            )
        blocks.add(inode.file_acl)

    sectors_per_block = max(1, vol.sb.block_size // 512)
    expected = inode.blocks // sectors_per_block if inode.blocks else 0
    if inode.blocks and inode.blocks % sectors_per_block == 0:
        # i_blocks counts data + extent/indirect metadata + external xattr.
        # Matching it here is a strong guard that reconstruction did not miss
        # an allocation category before using the result to rebuild a bitmap.
        if len(blocks) != expected:
            raise ValueError(
                f"inode {inode.ino} 할당 블록 수 불일치: "
                f"i_blocks={expected} reconstructed={len(blocks)}"
            )
    return blocks


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
    if inode.flags & C.EXT4_INLINE_DATA_FL:
        exts = []
    elif inode.uses_extents or (inode.i_block[:2] == struct.pack("<H", C.EXT4_EXT_MAGIC)):
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
    if inode.flags & C.EXT4_INLINE_DATA_FL:
        from ext4lib.fs.xattr import read_inline

        return read_inline(inode, offset, length).ljust(length, b"\x00")
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


def _write_extent_node(vol, inode: Inode, phys: int, records: list[bytes], depth: int, cap: int, reused: bool) -> None:
    bs = vol.sb.block_size
    block = bytearray(bs)
    block[0:12] = struct.pack("<HHHHI", C.EXT4_EXT_MAGIC, len(records), cap, depth, 0)
    for i, rec in enumerate(records):
        block[12 + i * 12 : 24 + i * 12] = rec
    _extent_block_csum(vol.sb, inode.ino, inode.generation, block)
    # An unchanged node costs no journal space.
    if reused and bytes(vol.read_block(phys)) == bytes(block):
        return
    (getattr(vol, "write_metadata_block", None) or vol.write_block)(phys, bytes(block))


def _tree_levels(vol, inode: Inode) -> tuple[list[list[tuple[int, int]]], bool]:
    """(index key, block) of every extent-tree node, one list per depth with
    leaves first, each in logical order. Leaf blocks themselves are not read.
    The flag is False when the walk hit anything unexpected."""
    data = inode.i_block
    if len(data) < 12:
        return [], True
    magic, entries, _eh_max, depth = _header(data, 0)
    if magic != C.EXT4_EXT_MAGIC or depth <= 0 or entries <= 0:
        return [], True
    levels: list[list[tuple[int, int]]] = [[] for _ in range(depth)]
    seen: set[int] = set()
    complete = True

    def visit(node: bytes, d: int, n: int) -> None:
        nonlocal complete
        limit = max(0, (len(node) - 12) // 12)
        if n > limit:
            complete = False
        for i in range(min(n, limit)):
            logical, phys = _idx(node, 12 + i * 12)
            if phys <= 0 or phys in seen:
                complete = False
                continue
            seen.add(phys)
            level = levels[d - 1]
            if level and level[-1][0] >= logical:
                complete = False
            level.append((logical, phys))
            if d - 1 > 0:
                block = vol.read_block(phys)
                if len(block) < 12:
                    complete = False
                    continue
                magic, ent, _mx, dep = _header(block, 0)
                if magic == C.EXT4_EXT_MAGIC and ent > 0 and dep == d - 1:
                    visit(block, d - 1, ent)
                else:
                    complete = False

    try:
        visit(bytes(data), depth, entries)
    except Exception:
        complete = False
    return levels, complete


def _leaf_window(
    extents: list[Extent], keys: list[int], dirty: tuple[int, int] | None
) -> tuple[int, int, int, int]:
    """Old leaves [k0, k1) and new extents [i0, i1) to repack.

    Old leaf k covers logical [keys[k], keys[k+1]). A leaf whose range is
    outside the changed window ``dirty`` (inclusive logical blocks) maps the
    same blocks as before and is kept as is, so appending to a huge
    fragmented file rewrites only its last leaf instead of the whole tree.
    """
    n_old = len(keys)
    if dirty is None or not n_old:
        return 0, n_old, 0, len(extents)
    lo, hi = dirty
    k0 = max(0, bisect.bisect_right(keys, lo) - 1)
    k1 = max(k0 + 1, bisect.bisect_right(keys, hi))
    starts = [ex.logical for ex in extents]

    def straddles(boundary: int) -> bool:
        i = bisect.bisect_left(starts, boundary) - 1
        return i >= 0 and extents[i].logical + extents[i].length > boundary

    # A new extent crossing a window edge (merged with its neighbour) pulls
    # that neighbouring leaf into the window.
    while k0 > 0 and straddles(keys[k0]):
        k0 -= 1
    while k1 < n_old and straddles(keys[k1]):
        k1 += 1
    i0 = bisect.bisect_left(starts, keys[k0]) if k0 else 0
    i1 = bisect.bisect_left(starts, keys[k1]) if k1 < n_old else len(extents)
    return k0, k1, i0, i1


def build_extent_tree(
    vol, inode: Inode, extents: list[Extent], dirty: tuple[int, int] | None = None
) -> bytes:
    """Return 60-byte i_block. Grows a depth-2+ tree when one index level is not enough.

    Existing tree blocks are rewritten in place (journaled with the inode).
    ``dirty`` is the inclusive logical block range whose mapping changed;
    leaves outside it are left untouched. That bounds the metadata one write
    step puts in a JBD2 transaction.
    """
    from ext4lib.fs.bitmap import alloc_blocks

    levels, complete = _tree_levels(vol, inode)
    old_blocks = [phys for level in levels for _key, phys in level]
    if not complete:
        # Odd old tree: build a fresh one, as before, and only free the old.
        levels = []
    bs = vol.sb.block_size
    allocated: list[int] = []
    tree: list[int] = []
    try:
        if len(extents) <= 4:
            body = extents_to_inode_body(extents)
        else:
            cap = _node_capacity(bs, vol.sb.has_metadata_csum)
            if cap < 2:
                raise ValueError("블록이 너무 작아 extent 트리를 만들 수 없습니다.")
            old_leaves = levels[0] if levels else []
            k0, k1, i0, i1 = _leaf_window(extents, [k for k, _p in old_leaves], dirty)
            window = extents[i0:i1]
            chunks = [window[i : i + cap] for i in range(0, len(window), cap)]
            reuse = [phys for _k, phys in old_leaves[k0:k1]]

            # Allocate every new node up front: a failure must not leave a
            # half-rewritten tree behind the old inode.
            counts = [k0 + len(chunks) + len(old_leaves) - k1]
            while counts[-1] > 4:
                counts.append((counts[-1] + cap - 1) // cap)
            need = max(0, len(chunks) - len(reuse))
            for d in range(1, len(counts)):
                have = len(levels[d]) if d < len(levels) else 0
                need += max(0, counts[d] - have)
            if need:
                allocated = alloc_blocks(vol, need, metadata=True)
            pool = list(allocated)

            nodes: list[tuple[int, int]] = list(old_leaves[:k0])
            for j, chunk in enumerate(chunks):
                reused = j < len(reuse)
                phys = reuse[j] if reused else pool.pop(0)
                _write_extent_node(vol, inode, phys, [_leaf_record(ex) for ex in chunk], 0, cap, reused)
                nodes.append((chunk[0].logical, phys))
            nodes.extend(old_leaves[k1:])
            tree.extend(phys for _k, phys in nodes)

            inode_depth = 1
            while len(nodes) > 4:
                old_level = levels[inode_depth] if inode_depth < len(levels) else []
                packed: list[tuple[int, int]] = []
                for j, cursor in enumerate(range(0, len(nodes), cap)):
                    chunk = nodes[cursor : cursor + cap]
                    reused = j < len(old_level)
                    phys = old_level[j][1] if reused else pool.pop(0)
                    _write_extent_node(
                        vol,
                        inode,
                        phys,
                        [_index_record(logical, child) for logical, child in chunk],
                        inode_depth,
                        cap,
                        reused,
                    )
                    packed.append((chunk[0][0], phys))
                    tree.append(phys)
                nodes = packed
                inode_depth += 1
            body_buf = bytearray(60)
            body_buf[0:12] = struct.pack("<HHHHI", C.EXT4_EXT_MAGIC, len(nodes), 4, inode_depth, 0)
            for i, (logical, phys) in enumerate(nodes):
                body_buf[12 + i * 12 : 24 + i * 12] = _index_record(logical, phys)
            inode.set_blocks((inode.blocks * 512) // bs + len(tree), bs)
            body = bytes(body_buf)
    except Exception:
        if allocated:
            from ext4lib.fs.bitmap import free_phys_runs

            try:
                free_phys_runs(vol, [(block, 1) for block in allocated])
            except Exception:
                pass
        raise
    keep = set(tree)
    inode._extent_index_old = [block for block in old_blocks if block not in keep]
    return body
