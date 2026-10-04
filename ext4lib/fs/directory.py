"""Directory listing, htree walk, dirent insert/remove."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ext4lib.fs import constants as C
from ext4lib.fs.crc32c import crc32c
from ext4lib.fs.extents import extent_at, file_extents, read_mapped
from ext4lib.fs.hashdir import dirhash
from ext4lib.fs.inode import Inode


@dataclass
class DirEntry:
    name: str
    inode: int
    file_type: int
    rec_len: int = 0


def rec_len_needed(name_len: int) -> int:
    return (8 + name_len + 3) & ~3


def _tail_size(vol) -> int:
    return 12 if vol.sb.has_metadata_csum else 0


def _dir_csum_set(vol, inode: Inode, block: bytearray) -> None:
    if not vol.sb.has_metadata_csum:
        return
    bs = vol.sb.block_size
    # ext4_dir_entry_tail at end
    tail_off = bs - 12
    struct.pack_into("<I", block, tail_off, 0)
    struct.pack_into("<H", block, tail_off + 4, 12)
    block[tail_off + 6] = 0
    block[tail_off + 7] = C.EXT4_FT_DIR_CSUM
    struct.pack_into("<I", block, tail_off + 8, 0)
    # Linux precomputes i_csum_seed from fs seed + inode number +
    # generation, then checksums a classic directory leaf only up to the
    # ext4_dir_entry_tail. The 12-byte fake tail itself is excluded.
    crc = crc32c(vol.sb.csum_seed(), struct.pack("<I", inode.ino))
    crc = crc32c(crc, struct.pack("<I", inode.generation))
    crc = crc32c(crc, block[:tail_off])
    struct.pack_into("<I", block, tail_off + 8, crc)




def dir_block_checksum_valid(vol, inode: Inode, block: bytes) -> bool:
    if not vol.sb.has_metadata_csum:
        return True
    bs = vol.sb.block_size
    if len(block) != bs or bs < 12:
        return False
    tail_off = bs - 12
    ino, rec_len, name_len, file_type = struct.unpack_from("<IHBB", block, tail_off)
    if ino != 0 or rec_len != 12 or name_len != 0 or file_type != C.EXT4_FT_DIR_CSUM:
        return False
    stored = struct.unpack_from("<I", block, tail_off + 8)[0]
    crc = crc32c(vol.sb.csum_seed(), struct.pack("<I", inode.ino))
    crc = crc32c(crc, struct.pack("<I", inode.generation))
    crc = crc32c(crc, block[:tail_off])
    return stored == crc

def parse_dirent_block(data: bytes, max_off: int | None = None) -> list[DirEntry]:
    if max_off is None:
        max_off = len(data)
    out: list[DirEntry] = []
    off = 0
    while off + 8 <= max_off:
        ino, rec, nlen, ftype = struct.unpack_from("<IHBB", data, off)
        if rec < 8 or off + rec > max_off:
            break
        if ftype == C.EXT4_FT_DIR_CSUM or (ino == 0 and nlen == 0):
            off += rec
            continue
        if ino != 0 and nlen > 0 and nlen <= C.EXT4_NAME_LEN and off + 8 + nlen <= off + rec:
            raw = data[off + 8 : off + 8 + nlen]
            try:
                name = raw.decode("utf-8")
            except UnicodeDecodeError:
                name = raw.decode("latin-1")
            out.append(DirEntry(name=name, inode=ino, file_type=ftype, rec_len=rec))
        off += rec
    return out


def logical_to_phys(vol, inode: Inode, lblk: int) -> int | None:
    ex = extent_at(file_extents(vol, inode), lblk)
    if ex is None or ex.uninitialized:
        return None
    return ex.physical + (lblk - ex.logical)


def dir_block_count(inode: Inode, block_size: int) -> int:
    return (inode.size + block_size - 1) // block_size


def read_dir_lblock(vol, inode: Inode, lblk: int) -> bytes:
    phys = logical_to_phys(vol, inode, lblk)
    if phys is None:
        return b"\x00" * vol.sb.block_size
    return vol.read_block(phys)


def _dx_entries(data: bytes, entries_off: int) -> tuple[int, int, list[tuple[int, int]]]:
    limit, count = struct.unpack_from("<HH", data, entries_off)
    items: list[tuple[int, int]] = []
    for i in range(count):
        h, blk = struct.unpack_from("<II", data, entries_off + i * 8)
        if i == 0:
            items.append((0, blk))
        else:
            items.append((h, blk))
    return limit, count, items


def _htree_leaves(vol, inode: Inode) -> list[int]:
    root = read_dir_lblock(vol, inode, 0)
    if len(root) < 40:
        return [0]
    hash_version = root[28]
    info_length = root[29] or 8
    levels = root[30]
    entries_off = 24 + info_length
    if entries_off + 8 > len(root):
        return [0]
    _limit, _count, items = _dx_entries(root, entries_off)
    if not items:
        return [0]
    leaves: list[int] = []

    def walk(entries: list[tuple[int, int]], depth: int) -> None:
        if depth == 0:
            for _h, blk in entries:
                leaves.append(blk)
            return
        for _h, blk in entries:
            node = read_dir_lblock(vol, inode, blk)
            # dx_node: fake dirent 8 bytes, then countlimit+entries
            _, _, child = _dx_entries(node, 8)
            walk(child, depth - 1)

    walk(items, levels)
    return leaves or [0]


def _consume_lblocks(vol, inode: Inode, lblocks: list[int], consume) -> None:
    bs = vol.sb.block_size
    step = max(1, (8 * 1024 * 1024) // bs)
    i = 0
    n = len(lblocks)
    while i < n:
        start = lblocks[i]
        j = i + 1
        while j < n and j - i < step and lblocks[j] == start + (j - i):
            j += 1
        count = j - i
        blob = read_mapped(vol, inode, start * bs, count * bs)
        for k in range(count):
            consume(blob[k * bs : (k + 1) * bs])
        i = j


def list_dir(vol, inode: Inode) -> list[DirEntry]:
    cache = getattr(vol, "_dir_list", None)
    if cache is not None:
        hit = cache.get(inode.ino)
        if hit is not None:
            return list(hit)
    bs = vol.sb.block_size
    tail = _tail_size(vol)
    usable = bs - tail
    seen: set[tuple[int, str]] = set()
    out: list[DirEntry] = []

    def consume(data: bytes) -> None:
        for e in parse_dirent_block(data, usable):
            key = (e.inode, e.name)
            if key in seen:
                continue
            seen.add(key)
            out.append(e)

    if inode.is_indexed:
        try:
            _consume_lblocks(vol, inode, _htree_leaves(vol, inode), consume)
            if cache is not None:
                cache[inode.ino] = out
            return list(out)
        except Exception:
            out.clear()
            seen.clear()
    n = dir_block_count(inode, bs)
    if n:
        _consume_lblocks(vol, inode, list(range(n)), consume)
    if cache is not None:
        cache[inode.ino] = out
        while len(cache) > 128:
            cache.pop(next(iter(cache)))
    return list(out)


def lookup_dir_name(vol, inode: Inode, name: str) -> int | None:
    if not inode.is_dir:
        return None
    index = getattr(vol, "_dir_index", None)
    if index is None:
        index = {}
        vol._dir_index = index
    hit = index.get(inode.ino)
    if hit is None:
        exact: dict[str, int] = {}
        folded: dict[str, int] = {}
        for e in list_dir(vol, inode):
            exact.setdefault(e.name, e.inode)
            folded.setdefault(e.name.lower(), e.inode)
        hit = (exact, folded)
        index[inode.ino] = hit
    exact, folded = hit
    found = exact.get(name)
    if found is not None:
        return found
    return folded.get(name.lower())


def _insert_into_block(block: bytearray, usable: int, ino: int, name: bytes, ftype: int) -> bool:
    need = rec_len_needed(len(name))
    off = 0
    while off + 8 <= usable:
        e_ino, rec, nlen, _ft = struct.unpack_from("<IHBB", block, off)
        if rec < 8 or off + rec > usable:
            return False
        real = rec_len_needed(nlen) if (e_ino and nlen) else 8
        extra = rec - real
        if extra >= need:
            if e_ino and nlen:
                struct.pack_into("<H", block, off + 4, real)
                new_off = off + real
            else:
                new_off = off
                real = 0
            rest = rec - real
            struct.pack_into("<IHBB", block, new_off, ino, rest, len(name), ftype)
            block[new_off + 8 : new_off + 8 + len(name)] = name
            return True
        off += rec
    return False


def _empty_dirent_block(bs: int, usable: int) -> bytearray:
    buf = bytearray(bs)
    struct.pack_into("<IHBB", buf, 0, 0, usable, 0, 0)
    return buf


def _dx_insert_entry(block: bytearray, entries_off: int, h: int, lblk: int) -> bool:
    limit, count = struct.unpack_from("<HH", block, entries_off)
    if count >= limit:
        return False
    # find position: first entry with hash > h
    pos = count
    for i in range(1, count):
        eh, _b = struct.unpack_from("<II", block, entries_off + i * 8)
        if eh > h:
            pos = i
            break
    # shift
    src = entries_off + pos * 8
    dst = src + 8
    end = entries_off + count * 8
    block[dst:dst + (end - src)] = block[src:end]
    struct.pack_into("<II", block, src, h, lblk)
    struct.pack_into("<H", block, entries_off + 2, count + 1)
    return True


def _dx_pick(items: list[tuple[int, int]], h: int) -> int:
    if not items:
        raise DirError("디렉터리 인덱스가 비어 있습니다.")
    idx = 0
    for i, (eh, _blk) in enumerate(items):
        if i == 0:
            continue
        if eh <= h:
            idx = i
        else:
            break
    return items[idx][1]


def _dx_place(entries: list[tuple[int, int]], h: int, blk: int) -> list[tuple[int, int]]:
    """Insert a dx pointer. Entry 0 stays the leftmost child."""
    out = list(entries)
    pos = len(out)
    for i in range(1, len(out)):
        if out[i][0] > h:
            pos = i
            break
    out.insert(pos, (h & 0xFFFFFFFF, blk))
    return out


def _dx_node_limit(bs: int, entries_off: int, tail: int) -> int:
    return max(0, (bs - tail - entries_off) // 8)


def _write_dx_entries(block: bytearray, off: int, limit: int, entries: list[tuple[int, int]]) -> None:
    count = len(entries)
    if count < 1 or count > limit:
        raise DirError("디렉터리 인덱스 항목 수가 맞지 않습니다.")
    struct.pack_into("<HH", block, off, limit, count)
    struct.pack_into("<I", block, off + 4, entries[0][1] & 0xFFFFFFFF)
    for i in range(1, count):
        eh, blk = entries[i]
        struct.pack_into("<II", block, off + i * 8, eh & 0xFFFFFFFF, blk & 0xFFFFFFFF)


def _format_dx_node(bs: int, tail: int, entries: list[tuple[int, int]]) -> bytearray:
    limit = _dx_node_limit(bs, 8, tail)
    buf = bytearray(bs)
    struct.pack_into("<IHBB", buf, 0, 0, bs & 0xFFFF, 0, 0)
    _write_dx_entries(buf, 8, limit, entries)
    return buf


def _dx_insert_pointer(load_block, root: bytearray, h: int, target: int, bs: int, tail: int, alloc_logical) -> dict[int, bytearray]:
    """Link ``target`` under ``h``. Grows index levels in memory and returns dirty blocks.

    Nothing is written here. The caller allocates the new logical blocks and
    writes the returned blocks only after the plan succeeds.
    """
    info_length = root[29] or 8
    levels = root[30]
    entries_off = 24 + info_length
    dirty: dict[int, bytearray] = {0: root}
    cache: dict[int, bytearray] = {0: root}

    def block_at(lblk: int) -> bytearray:
        hit = cache.get(lblk)
        if hit is not None:
            return hit
        buf = bytearray(load_block(lblk))
        cache[lblk] = buf
        return buf

    path = [[0, entries_off, root]]
    node_l = _dx_pick(_dx_entries(root, entries_off)[2], h)
    for _ in range(levels):
        node = block_at(node_l)
        path.append([node_l, 8, node])
        node_l = _dx_pick(_dx_entries(node, 8)[2], h)

    insert_h = h & 0xFFFFFFFF
    insert_blk = target
    while True:
        lblk, off, block = path[-1]
        limit, count, items = _dx_entries(block, off)
        if count < limit:
            _write_dx_entries(block, off, limit, _dx_place(items, insert_h, insert_blk))
            dirty[lblk] = block
            break
        if lblk == 0:
            if block[30] >= 255:
                raise DirError("디렉터리 인덱스 단계가 너무 깊습니다.")
            node_limit = _dx_node_limit(bs, 8, tail)
            if len(items) < 1 or len(items) > node_limit:
                raise DirError("디렉터리 인덱스를 한 단계 올릴 수 없습니다.")
            child_l = alloc_logical()
            child = _format_dx_node(bs, tail, items)
            _write_dx_entries(block, off, limit, [(0, child_l)])
            block[30] = block[30] + 1
            dirty[0] = block
            dirty[child_l] = child
            cache[child_l] = child
            path.append([child_l, 8, child])
            continue
        if len(items) < 2:
            raise DirError("디렉터리 인덱스를 나눌 수 없습니다.")
        mid = len(items) // 2
        left, right = items[:mid], items[mid:]
        split_h = right[0][0]
        if insert_h >= split_h:
            right = _dx_place(right, insert_h, insert_blk)
        else:
            left = _dx_place(left, insert_h, insert_blk)
        _write_dx_entries(block, off, limit, left)
        dirty[lblk] = block
        new_l = alloc_logical()
        right_b = _format_dx_node(bs, tail, right)
        dirty[new_l] = right_b
        cache[new_l] = right_b
        path.pop()
        if not path:
            raise DirError("디렉터리 인덱스를 확장할 수 없습니다.")
        insert_h, insert_blk = split_h, new_l
    return dirty


def _probe_leaf(vol, inode: Inode, name: bytes) -> tuple[int, bytes, int]:
    """Return (logical_leaf, root_block, hash)."""
    root = bytearray(read_dir_lblock(vol, inode, 0))
    hv = root[28]
    info_length = root[29] or 8
    levels = root[30]
    seed = vol.sb.hash_seed
    h = dirhash(name, hv, seed)
    entries_off = 24 + info_length
    _limit, _count, items = _dx_entries(root, entries_off)
    lblk = _dx_pick(items, h)
    for _ in range(levels):
        node = read_dir_lblock(vol, inode, lblk)
        _l, _c, child = _dx_entries(node, 8)
        lblk = _dx_pick(child, h)
    return lblk, bytes(root), h


class DirError(RuntimeError):
    pass


def add_dir_entry(vol, dir_inode: Inode, name: str, ino: int, ftype: int) -> Inode:
    from ext4lib.fs.extents import Extent, build_extent_tree, discard_old_extent_indexes, file_extents
    from ext4lib.fs.bitmap import alloc_blocks, free_phys_runs

    name_b = name.encode("utf-8")
    if len(name_b) > C.EXT4_NAME_LEN:
        raise DirError("이름이 너무 깁니다.")
    existing = list_dir(vol, dir_inode)
    for e in existing:
        if e.name == name:
            raise DirError(f"'{name}' 이(가) 이미 있습니다.")
    bs = vol.sb.block_size
    tail = _tail_size(vol)
    usable = bs - tail

    def write_lblock(inode: Inode, lblk: int, data: bytearray) -> None:
        drop = getattr(vol, "drop_dir_cache", None)
        if drop is not None:
            drop(inode.ino)
        _dir_csum_set(vol, inode, data)
        phys = logical_to_phys(vol, inode, lblk)
        if phys is None:
            raise DirError("디렉터리 블록을 찾을 수 없습니다.")
        (getattr(vol, "write_metadata_block", None) or vol.write_block)(phys, bytes(data))

    if dir_inode.is_indexed:
        lblk, _root, h = _probe_leaf(vol, dir_inode, name_b)
        leaf = bytearray(read_dir_lblock(vol, dir_inode, lblk))
        if _insert_into_block(leaf, usable, ino, name_b, ftype):
            write_lblock(dir_inode, lblk, leaf)
            dir_inode.set_times()
            vol.write_inode(dir_inode)
            return dir_inode
        # split: new leaf + dx entry. The leaf is rewritten only after the index plan succeeds.
        old_ents = [e for e in parse_dirent_block(bytes(leaf), usable) if e.name not in (".", "..")]
        dummy = DirEntry(name=name, inode=ino, file_type=ftype)
        old_ents.append(dummy)
        hv = read_dir_lblock(vol, dir_inode, 0)[28]
        hashed = []
        for e in old_ents:
            try:
                hh = dirhash(e.name.encode("utf-8"), hv, vol.sb.hash_seed)
            except Exception:
                hh = 0
            hashed.append((hh, e))
        hashed.sort(key=lambda x: x[0])
        mid = max(1, len(hashed) // 2)
        left, right = hashed[:mid], hashed[mid:]
        if not right:
            raise DirError("디렉터리 분할에 실패했습니다.")
        split_hash = right[0][0]

        def pack_ents(ents: list[DirEntry]) -> bytearray:
            buf = _empty_dirent_block(bs, usable)
            for e in ents:
                nb = e.name.encode("utf-8")
                if not _insert_into_block(buf, usable, e.inode, nb, e.file_type):
                    raise DirError("디렉터리 분할에 실패했습니다.")
            return buf

        left_b = pack_ents([e for _h, e in left])
        right_b = pack_ents([e for _h, e in right])
        # Plan the index link before any leaf is rewritten. A full root grows
        # another level; a failed plan leaves the old leaf intact.
        exts = file_extents(vol, dir_inode)
        next_l = 0
        for ex in exts:
            next_l = max(next_l, ex.logical + ex.length)
        root = bytearray(read_dir_lblock(vol, dir_inode, 0))
        cursor = next_l + 1

        def alloc_logical() -> int:
            nonlocal cursor
            logical = cursor
            cursor += 1
            return logical

        dirty = _dx_insert_pointer(
            lambda lb: read_dir_lblock(vol, dir_inode, lb),
            root,
            split_hash,
            next_l,
            bs,
            tail,
            alloc_logical,
        )
        new_logicals = [next_l, *range(next_l + 1, cursor)]
        phys_list = alloc_blocks(
            vol,
            len(new_logicals),
            prefer_group=(dir_inode.ino - 1) // vol.sb.inodes_per_group,
        )
        new_exts = list(exts) + [
            Extent(logical, 1, phys, False) for logical, phys in zip(new_logicals, phys_list)
        ]
        try:
            body = build_extent_tree(vol, dir_inode, new_exts)
        except ValueError:
            free_phys_runs(vol, [(phys, 1) for phys in phys_list])
            raise DirError("디렉터리 extent 트리를 확장할 수 없습니다.")
        except Exception:
            free_phys_runs(vol, [(phys, 1) for phys in phys_list])
            raise
        dir_inode.set_i_block(body)
        dir_inode.set_size(cursor * bs)
        dir_inode.set_blocks(sum(e.length for e in new_exts if not e.uninitialized), bs)
        vol.write_inode(dir_inode)
        discard_old_extent_indexes(vol, dir_inode)
        for logical, data in dirty.items():
            if logical != 0:
                write_lblock(dir_inode, logical, data)
        write_lblock(dir_inode, next_l, right_b)
        write_lblock(dir_inode, 0, dirty[0])
        write_lblock(dir_inode, lblk, left_b)
        return dir_inode

    # linear
    n = max(1, dir_block_count(dir_inode, bs))
    for lblk in range(n):
        blk = bytearray(read_dir_lblock(vol, dir_inode, lblk))
        if _insert_into_block(blk, usable, ino, name_b, ftype):
            write_lblock(dir_inode, lblk, blk)
            dir_inode.set_times()
            vol.write_inode(dir_inode)
            return dir_inode
    # grow
    new_phys = alloc_blocks(vol, 1, prefer_group=(dir_inode.ino - 1) // vol.sb.inodes_per_group)[0]
    buf = _empty_dirent_block(bs, usable)
    if not _insert_into_block(buf, usable, ino, name_b, ftype):
        raise DirError("새 디렉터리 블록에 항목을 넣지 못했습니다.")
    exts = file_extents(vol, dir_inode)
    next_l = 0
    for ex in exts:
        next_l = max(next_l, ex.logical + ex.length)
    new_exts = list(exts) + [Extent(next_l, 1, new_phys, False)]
    body = build_extent_tree(vol, dir_inode, new_exts)
    dir_inode.set_i_block(body)
    dir_inode.set_size((next_l + 1) * bs)
    dir_inode.set_blocks(sum(e.length for e in new_exts), bs)
    vol.write_inode(dir_inode)
    discard_old_extent_indexes(vol, dir_inode)
    _dir_csum_set(vol, dir_inode, buf)
    (getattr(vol, "write_metadata_block", None) or vol.write_block)(new_phys, bytes(buf))
    return dir_inode


def remove_dir_entry(vol, dir_inode: Inode, name: str) -> tuple[Inode, int]:
    """Remove name, return (dir_inode, removed_inode_num)."""
    bs = vol.sb.block_size
    tail = _tail_size(vol)
    usable = bs - tail
    target = None
    blocks = []
    if dir_inode.is_indexed:
        blocks = _htree_leaves(vol, dir_inode)
    else:
        blocks = list(range(max(1, dir_block_count(dir_inode, bs))))
    name_b = name.encode("utf-8")
    for lblk in blocks:
        data = bytearray(read_dir_lblock(vol, dir_inode, lblk))
        off = 0
        prev = None
        while off + 8 <= usable:
            ino, rec, nlen, ftype = struct.unpack_from("<IHBB", data, off)
            if rec < 8 or off + rec > usable:
                break
            raw = data[off + 8 : off + 8 + nlen] if nlen else b""
            if ino and raw == name_b:
                target = ino
                if prev is None:
                    struct.pack_into("<I", data, off, 0)
                else:
                    p_ino, p_rec, p_nlen, p_ft = struct.unpack_from("<IHBB", data, prev)
                    struct.pack_into("<H", data, prev + 4, p_rec + rec)
                _dir_csum_set(vol, dir_inode, data)
                phys = logical_to_phys(vol, dir_inode, lblk)
                if phys is not None:
                    (getattr(vol, "write_metadata_block", None) or vol.write_block)(phys, bytes(data))
                return dir_inode, target
            prev = off
            off += rec
    raise DirError(f"'{name}' 을(를) 찾지 못했습니다.")


def init_directory_block(vol, inode: Inode, parent_ino: int, phys: int) -> None:
    bs = vol.sb.block_size
    tail = _tail_size(vol)
    usable = bs - tail
    buf = bytearray(bs)
    # .
    struct.pack_into("<IHBB", buf, 0, inode.ino, 12, 1, C.EXT4_FT_DIR)
    buf[8:9] = b"."
    # ..
    rest = usable - 12
    struct.pack_into("<IHBB", buf, 12, parent_ino, rest, 2, C.EXT4_FT_DIR)
    buf[20:22] = b".."
    _dir_csum_set(vol, inode, buf)
    (getattr(vol, "write_metadata_block", None) or vol.write_block)(phys, bytes(buf))
