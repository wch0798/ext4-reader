"""Directory listing, htree walk, dirent insert/remove."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ext4reader import constants as C
from ext4reader.crc32c import crc32c
from ext4reader.extents import file_extents
from ext4reader.hashdir import dirhash
from ext4reader.inode import Inode


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
    crc = crc32c(vol.sb.csum_seed(), struct.pack("<I", inode.ino))
    crc = crc32c(crc, struct.pack("<I", inode.generation))
    crc = crc32c(crc, block[: bs - 4])
    struct.pack_into("<I", block, tail_off + 8, crc)


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
    for ex in file_extents(vol, inode):
        if ex.uninitialized:
            continue
        if ex.logical <= lblk < ex.logical + ex.length:
            return ex.physical + (lblk - ex.logical)
    return None


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


def list_dir(vol, inode: Inode) -> list[DirEntry]:
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
            for lblk in _htree_leaves(vol, inode):
                consume(read_dir_lblock(vol, inode, lblk))
            return out
        except Exception:
            pass
    n = dir_block_count(inode, bs)
    for lblk in range(n):
        consume(read_dir_lblock(vol, inode, lblk))
    return out


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


def _probe_leaf(vol, inode: Inode, name: bytes) -> tuple[int, bytes, int]:
    """Return (logical_leaf, root_block, hash)."""
    root = bytearray(read_dir_lblock(vol, inode, 0))
    hv = root[28]
    info_length = root[29] or 8
    levels = root[30]
    seed = vol.sb.hash_seed
    h = dirhash(name, hv, seed)
    entries_off = 24 + info_length
    _limit, count, items = _dx_entries(root, entries_off)
    # binary-ish linear search
    idx = 0
    for i, (eh, _blk) in enumerate(items):
        if i == 0:
            continue
        if eh <= h:
            idx = i
        else:
            break
    lblk = items[idx][1]
    if levels > 0:
        node = read_dir_lblock(vol, inode, lblk)
        _l, _c, child = _dx_entries(node, 8)
        cidx = 0
        for i, (eh, _blk) in enumerate(child):
            if i == 0:
                continue
            if eh <= h:
                cidx = i
            else:
                break
        lblk = child[cidx][1]
    return lblk, bytes(root), h


class DirError(RuntimeError):
    pass


def add_dir_entry(vol, dir_inode: Inode, name: str, ino: int, ftype: int) -> Inode:
    from ext4reader.extents import build_extent_tree, file_extents, Extent
    from ext4reader.bitmap import alloc_blocks

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
        _dir_csum_set(vol, inode, data)
        phys = logical_to_phys(vol, inode, lblk)
        if phys is None:
            raise DirError("디렉터리 블록을 찾을 수 없습니다.")
        vol.write_block(phys, bytes(data))

    if dir_inode.is_indexed:
        lblk, _root, h = _probe_leaf(vol, dir_inode, name_b)
        leaf = bytearray(read_dir_lblock(vol, dir_inode, lblk))
        if _insert_into_block(leaf, usable, ino, name_b, ftype):
            write_lblock(dir_inode, lblk, leaf)
            dir_inode.set_times()
            vol.write_inode(dir_inode)
            return dir_inode
        # split: new leaf + dx entry
        new_phys = alloc_blocks(vol, 1, prefer_group=(dir_inode.ino - 1) // vol.sb.inodes_per_group)[0]
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
        split_hash = right[0][0] if right else hashed[-1][0]

        def pack_ents(ents: list[DirEntry]) -> bytearray:
            buf = _empty_dirent_block(bs, usable)
            for e in ents:
                nb = e.name.encode("utf-8")
                if not _insert_into_block(buf, usable, e.inode, nb, e.file_type):
                    raise DirError("디렉터리 분할에 실패했습니다.")
            return buf

        left_b = pack_ents([e for _h, e in left])
        right_b = pack_ents([e for _h, e in right])
        write_lblock(dir_inode, lblk, left_b)
        # append logical block to directory
        exts = file_extents(vol, dir_inode)
        next_l = 0
        for ex in exts:
            next_l = max(next_l, ex.logical + ex.length)
        new_exts = list(exts) + [Extent(next_l, 1, new_phys, False)]
        try:
            body = build_extent_tree(vol, dir_inode, new_exts)
        except ValueError:
            raise DirError("디렉터리 extent 트리를 확장할 수 없습니다.")
        dir_inode.set_i_block(body)
        dir_inode.set_size((next_l + 1) * bs)
        dir_inode.set_blocks(
            sum(e.length for e in new_exts if not e.uninitialized),
            bs,
        )
        vol.write_inode(dir_inode)
        _dir_csum_set(vol, dir_inode, right_b)
        vol.write_block(new_phys, bytes(right_b))
        root = bytearray(read_dir_lblock(vol, dir_inode, 0))
        info_length = root[29] or 8
        levels = root[30]
        if levels != 0:
            raise DirError("2단 해시 디렉터리 분할은 지원하지 않습니다.")
        entries_off = 24 + info_length
        if not _dx_insert_entry(root, entries_off, split_hash, next_l):
            raise DirError("디렉터리 인덱스가 가득 찼습니다.")
        write_lblock(dir_inode, 0, root)
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
    _dir_csum_set(vol, dir_inode, buf)
    vol.write_block(new_phys, bytes(buf))
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
                    vol.write_block(phys, bytes(data))
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
    vol.write_block(phys, bytes(buf))
