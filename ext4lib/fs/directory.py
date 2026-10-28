"""Directory listing, htree walk, dirent insert/remove."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ext4lib.fs import constants as C
from ext4lib.fs.casefold import utf8_casefold, utf8_validate
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
    raw: bytes = b""


def rec_len_needed(name_len: int) -> int:
    return (8 + name_len + 3) & ~3


def encode_name(name: str) -> bytes:
    """Name from Windows/FUSE -> on-disk bytes. ext4 forbids '/' and NUL."""
    if not name or name in (".", "..") or "/" in name or "\x00" in name:
        raise DirError(f"EXT4에서 쓸 수 없는 이름입니다: {name!r}")
    try:
        # surrogateescape round-trips the bytes the FUSE layer decoded.
        raw = name.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError as exc:
        raise DirError(f"UTF-8로 바꿀 수 없는 이름입니다: {name!r}") from exc
    if len(raw) > C.EXT4_NAME_LEN:
        raise DirError("이름이 너무 깁니다.")
    return raw


def casefold_name(name: bytes) -> bytes | None:
    """Linux utf8_casefold() with the ext4 Unicode 12.1 table. None if it fails."""
    return utf8_casefold(name)


def is_casefold_dir(vol, inode: Inode) -> bool:
    return bool(inode.flags & C.EXT4_CASEFOLD_FL) and bool(
        vol.sb.feature_incompat & C.EXT4_FEATURE_INCOMPAT_CASEFOLD
    )


def same_name(vol, dir_inode: Inode, a: bytes, b: bytes) -> bool:
    """Linux ext4_match(): equal bytes, or equal casefold in a casefold dir.

    Names that cannot be casefolded only match byte for byte.
    """
    if a == b:
        return True
    if not is_casefold_dir(vol, dir_inode):
        return False
    fa = casefold_name(a)
    return fa is not None and fa == casefold_name(b)


def name_hash(vol, dir_inode: Inode, name: bytes, hash_version: int) -> int:
    # Linux ext4fs_dirhash(): a casefold directory hashes the folded name;
    # invalid UTF-8 falls back to the raw bytes.
    if is_casefold_dir(vol, dir_inode):
        folded = casefold_name(name)
        if folded is not None:
            name = folded
    return dirhash(name, hash_version, vol.sb.hash_seed)


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
            out.append(DirEntry(name=name, inode=ino, file_type=ftype, rec_len=rec, raw=bytes(raw)))
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


def _htree_max_levels(vol) -> int:
    # Linux ext4_dir_htree_level(): EXT4_HTREE_LEVEL (3) with largedir,
    # otherwise EXT4_HTREE_LEVEL_COMPAT (2). Counts the root as one level.
    if vol.sb.feature_incompat & C.EXT4_FEATURE_INCOMPAT_LARGEDIR:
        return 3
    return 2


def _dx_checked_entries(vol, data: bytes, entries_off: int) -> list[tuple[int, int]]:
    # Linux dx_probe(): a limit other than dx_root_limit()/dx_node_limit(),
    # or a count of 0 or above it, is ERR_BAD_DX_DIR. This is also what
    # catches a leaf block that the index wrongly treats as an index node.
    if entries_off + 8 > len(data):
        raise DxCorrupt("디렉터리 인덱스 위치가 잘못되었습니다.")
    limit, count = struct.unpack_from("<HH", data, entries_off)
    expect = _dx_node_limit(vol.sb.block_size, entries_off, vol.sb.has_metadata_csum)
    if limit != expect or count < 1 or count > limit:
        raise DxCorrupt("디렉터리 인덱스 count/limit가 잘못되었습니다.")
    return _dx_entries(data, entries_off)[2]


def _dx_root_levels(vol, root: bytes) -> tuple[int, int]:
    """(entries_off, indirect_levels) of a dx_root; DxCorrupt like ERR_BAD_DX_DIR."""
    if len(root) < 40:
        raise DxCorrupt("디렉터리 인덱스 root가 너무 짧습니다.")
    info_length = root[29] or 8
    levels = root[30]
    if root[31] & 1:
        raise DxCorrupt("디렉터리 인덱스 hash flag를 지원하지 않습니다.")
    if levels >= _htree_max_levels(vol):
        raise DxCorrupt(f"디렉터리 인덱스 단계가 너무 깊습니다: {levels}")
    return 24 + info_length, levels


def _htree_leaves(vol, inode: Inode) -> list[int]:
    root = read_dir_lblock(vol, inode, 0)
    entries_off, levels = _dx_root_levels(vol, root)
    items = _dx_checked_entries(vol, root, entries_off)
    nblocks = dir_block_count(inode, vol.sb.block_size)
    leaves: list[int] = []

    def walk(entries: list[tuple[int, int]], depth: int) -> None:
        for _h, blk in entries:
            if blk < 1 or blk >= nblocks:
                raise DirError(f"디렉터리 인덱스가 범위 밖 블록을 가리킵니다: {blk}")
            if depth == 0:
                leaves.append(blk)
                continue
            node = read_dir_lblock(vol, inode, blk)
            # dx_node: fake dirent 8 bytes, then countlimit+entries
            walk(_dx_checked_entries(vol, node, 8), depth - 1)

    walk(items, levels)
    return leaves


def _dot_entries(root: bytes) -> list[DirEntry]:
    """'.' and '..' of block 0: the dx_root fake dirents of an indexed dir."""
    out: list[DirEntry] = []
    off = 0
    for name in (b".", b".."):
        if off + 8 + len(name) > len(root):
            break
        ino, rec, nlen, ftype = struct.unpack_from("<IHBB", root, off)
        if nlen != len(name) or bytes(root[off + 8 : off + 8 + nlen]) != name or rec < 12:
            break
        out.append(DirEntry(name=name.decode(), inode=ino, file_type=ftype, rec_len=rec, raw=name))
        off += rec
    return out


def dir_parent_ino(vol, inode: Inode) -> int:
    """Inode of '..'. Linux __ext4_find_entry() reads only block 0 for it."""
    dots = _dot_entries(read_dir_lblock(vol, inode, 0))
    if len(dots) < 2 or not dots[1].inode:
        raise DirError("폴더의 '..' 항목을 찾지 못했습니다.")
    return dots[1].inode


def _is_dx_node_block(data: bytes, bs: int) -> bool:
    # dx_node: one empty fake dirent covering the whole block.
    ino, rec, nlen, _ft = struct.unpack_from("<IHBB", data, 0)
    if bs >= 65536 and rec in (0, 0xFFFF):
        rec = bs
    return ino == 0 and nlen == 0 and rec == bs


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
    if inode.flags & C.EXT4_INLINE_DATA_FL:
        from ext4lib.fs.xattr import inline_dir_entries

        return inline_dir_entries(inode)

    def consume(data: bytes) -> None:
        for e in parse_dirent_block(data, usable):
            key = (e.inode, e.name)
            if key in seen:
                continue
            seen.add(key)
            out.append(e)

    n = dir_block_count(inode, bs)
    if inode.is_indexed:
        try:
            leaves = _htree_leaves(vol, inode)
        except DxCorrupt:
            # Linux ext4_readdir(): only ERR_BAD_DX_DIR falls back to a
            # linear scan; other errors (I/O, bad leaf pointer) propagate.
            leaves = None
        out.extend(_dot_entries(read_dir_lblock(vol, inode, 0)))
        if leaves is not None:
            _consume_lblocks(vol, inode, leaves, consume)
            if cache is not None:
                cache[inode.ino] = out
            return list(out)

        # Block 0 gave '.'/'..' above; skip it and dx_node blocks so index
        # entries are never read as directory entries.
        def consume_leaf(data: bytes) -> None:
            if not _is_dx_node_block(data, bs):
                consume(data)

        if n > 1:
            _consume_lblocks(vol, inode, list(range(1, n)), consume_leaf)
    elif n:
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
    casefold = is_casefold_dir(vol, inode)

    def key(text: str, raw: bytes | None = None):
        # A casefold dir matches like Linux; other dirs keep the Windows-style
        # lower() fallback.
        if not casefold:
            return text.lower()
        return casefold_name(raw or text.encode("utf-8", "surrogateescape"))

    if hit is None:
        exact: dict[str, int] = {}
        folded: dict = {}
        for e in list_dir(vol, inode):
            exact.setdefault(e.name, e.inode)
            k = key(e.name, e.raw)
            if k is not None:
                folded.setdefault(k, e.inode)
        hit = (exact, folded)
        index[inode.ino] = hit
    exact, folded = hit
    found = exact.get(name)
    if found is not None:
        return found
    k = key(name)
    return None if k is None else folded.get(k)


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


def _dx_csum_set(vol, inode: Inode, block: bytearray, entries_off: int) -> None:
    """Set Linux-compatible metadata checksum on an HTREE root/index node."""
    if not vol.sb.has_metadata_csum:
        return
    if entries_off < 0 or entries_off + 8 > len(block):
        raise DirError("HTREE checksum 위치가 잘못되었습니다.")
    limit, count = struct.unpack_from("<HH", block, entries_off)
    if count < 1 or count > limit:
        raise DirError("HTREE checksum 대상 count/limit가 잘못되었습니다.")
    tail_off = entries_off + limit * 8
    if tail_off + 8 > len(block):
        raise DirError("HTREE checksum tail이 block 범위를 벗어났습니다.")

    # Linux ext4_dx_csum(): checksum valid index bytes, then the 4-byte
    # reserved field in dx_tail, then a zero checksum field.
    struct.pack_into("<I", block, tail_off, 0)
    struct.pack_into("<I", block, tail_off + 4, 0)
    seed = crc32c(vol.sb.csum_seed(), struct.pack("<I", inode.ino))
    seed = crc32c(seed, struct.pack("<I", inode.generation))
    size = entries_off + count * 8
    crc = crc32c(seed, block[:size])
    crc = crc32c(crc, block[tail_off:tail_off + 4])
    crc = crc32c(crc, b"\x00\x00\x00\x00")
    struct.pack_into("<I", block, tail_off + 4, crc)


def _dx_entries_off(block: bytes, lblk: int) -> int:
    if lblk == 0:
        info_length = block[29] or 8
        return 24 + info_length
    return 8


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


def _dx_node_limit(bs: int, entries_off: int, metadata_csum: bool) -> int:
    # HTREE index blocks use struct dx_tail (8 bytes), not the 12-byte
    # ext4_dir_entry_tail used by ordinary directory leaf blocks.
    tail = 8 if metadata_csum else 0
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


def _format_dx_node(
    bs: int, metadata_csum: bool, entries: list[tuple[int, int]]
) -> bytearray:
    limit = _dx_node_limit(bs, 8, metadata_csum)
    buf = bytearray(bs)
    struct.pack_into("<IHBB", buf, 0, 0, bs & 0xFFFF, 0, 0)
    _write_dx_entries(buf, 8, limit, entries)
    return buf


def _dx_insert_pointer(
    load_block,
    root: bytearray,
    h: int,
    target: int,
    bs: int,
    metadata_csum: bool,
    alloc_logical,
    max_levels: int = 2,
) -> dict[int, bytearray]:
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
            # Linux ext4_dx_add_entry(): no new level once the path already
            # has ext4_dir_htree_level() levels; that is -ENOSPC.
            if block[30] + 1 >= max_levels:
                raise DirError("디렉터리 인덱스가 가득 찼습니다.")
            node_limit = _dx_node_limit(bs, 8, metadata_csum)
            if len(items) < 1 or len(items) > node_limit:
                raise DirError("디렉터리 인덱스를 한 단계 올릴 수 없습니다.")
            child_l = alloc_logical()
            child = _format_dx_node(bs, metadata_csum, items)
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
        right_b = _format_dx_node(bs, metadata_csum, right)
        dirty[new_l] = right_b
        cache[new_l] = right_b
        path.pop()
        if not path:
            raise DirError("디렉터리 인덱스를 확장할 수 없습니다.")
        insert_h, insert_blk = split_h, new_l
    return dirty


def _dx_hash_version(vol, root: bytes) -> int:
    # Linux dx_probe(): the root stores the base version and the superblock
    # UNSIGNED_HASH flag selects the unsigned variant (matters for non-ASCII names).
    hv = root[28]
    if hv <= C.DX_HASH_TEA and vol.sb.hash_unsigned:
        hv += 3
    return hv


def _new_dx_hash_version(vol) -> tuple[int, int]:
    """(value stored in dx_root, value passed to dirhash).

    Linux make_indexed_dir() stores s_def_hash_version and hashes with
    s_hash_seed. The UNSIGNED_HASH flag is not stored in the root; dx_probe()
    adds it. A casefold directory still uses that version: name_hash() folds
    the name first, which is ext4fs_dirhash() for a non-encrypted directory.
    """
    stored = int(vol.sb.def_hash_version) & 0xFF
    root = bytearray(32)
    root[28] = stored
    return stored, _dx_hash_version(vol, root)


def _relocate_dirents(src: bytes, data_off: int, usable: int, bs: int) -> bytearray:
    """Move the real dirents that followed '..' into a fresh leaf.

    Linux make_indexed_dir() copies that tail, then extends the last rec_len
    to the end of the block (the csum tail stays excluded). '.' and '..' stay
    in block 0 and become the dx_root fake dirents.
    """
    leaf = bytearray(bs)
    span = usable - data_off
    if span <= 0:
        struct.pack_into("<IHBB", leaf, 0, 0, usable & 0xFFFF, 0, 0)
        return leaf
    if data_off < 0 or data_off + span > len(src):
        raise DirError("디렉터리 블록 항목 길이가 잘못되었습니다.")
    leaf[:span] = src[data_off : data_off + span]
    off = 0
    last = None
    while off + 8 <= span:
        rec = struct.unpack_from("<H", leaf, off + 4)[0]
        if rec < 8 or off + rec > span:
            raise DirError("디렉터리 블록 항목 길이가 잘못되었습니다.")
        last = off
        off += rec
    if off != span or last is None:
        raise DirError("디렉터리 블록 항목 길이가 잘못되었습니다.")
    struct.pack_into("<H", leaf, last + 4, usable - last)
    return leaf


def _pack_dirents(bs: int, usable: int, ents: list[DirEntry]) -> bytearray:
    buf = _empty_dirent_block(bs, usable)
    for e in ents:
        raw = e.raw or e.name.encode("utf-8")
        if not _insert_into_block(buf, usable, e.inode, raw, e.file_type):
            raise DirError("디렉터리 분할에 실패했습니다.")
    return buf


def _make_indexed_dir(vol, dir_inode: Inode, block0: bytes, name: str, name_b: bytes, ino: int, ftype: int) -> Inode:
    """Turn a full one-block directory into a 3-block HTREE and add ``name``.

    Same steps as Linux make_indexed_dir() + do_split(): block 0 becomes the
    dx_root, its real dirents move to block 1, that leaf is split into block 2,
    and the new name goes in the half its hash selects. EXT4_INDEX_FL is set
    on the inode. Nothing is committed here. The open journal transaction is
    left holding either the finished index or, if a step fails, the directory
    exactly as it was: _DirUndo puts the old inode and block 0 back and frees
    the new blocks before this returns, so the next commit cannot mix a larger
    i_size with a half-built index.
    """
    from ext4lib.fs.bitmap import alloc_blocks
    from ext4lib.fs.extents import (
        Extent,
        build_extent_tree,
        discard_old_extent_indexes,
        file_extents,
    )

    bs = vol.sb.block_size
    tail = _tail_size(vol)
    usable = bs - tail
    if bs < 64 or bs - 12 > 0xFFFF:
        raise DirError("이 블록 크기에서는 HTREE로 바꿀 수 없습니다.")
    if len(block0) < 24 or block0[6] != 1 or bytes(block0[8:9]) != b".":
        raise DirError("폴더의 '.' 항목이 HTREE root로 바뀌지 않습니다.")
    dot_rec = struct.unpack_from("<H", block0, 4)[0]
    if dot_rec != 12:
        raise DirError("폴더의 '.' 항목이 HTREE root로 바뀌지 않습니다.")
    dotdot_ino, dotdot_rec, dotdot_nlen, dotdot_ft = struct.unpack_from("<IHBB", block0, 12)
    if (
        dotdot_nlen != 2
        or bytes(block0[20:22]) != b".."
        or dotdot_rec < 12
        or 12 + dotdot_rec > usable
    ):
        raise DirError("폴더의 '..' 항목이 HTREE root로 바뀌지 않습니다.")

    leaf = _relocate_dirents(block0, 12 + dotdot_rec, usable, bs)
    stored_hv, hv = _new_dx_hash_version(vol)
    try:
        h = name_hash(vol, dir_inode, name_b, hv)
    except Exception as exc:
        raise DirError(f"디렉터리 이름 hash 계산 실패: {name}") from exc
    old_ents = [
        e for e in parse_dirent_block(bytes(leaf), usable) if e.name not in (".", "..")
    ]
    hashed: list[tuple[int, DirEntry, int]] = []
    for e in old_ents:
        try:
            hh = name_hash(vol, dir_inode, e.raw, hv)
        except Exception as exc:
            raise DirError(f"디렉터리 이름 hash 계산 실패: {e.name}") from exc
        hashed.append((hh, e, e.rec_len))
    hashed.sort(key=lambda item: item[0])
    new_entry = DirEntry(name=name, inode=ino, file_type=ftype, raw=name_b)
    if len(hashed) < 2:
        # do_split() with a single mapped entry uses count/2 == 0 and moves
        # that entry to the new block. The new name then lands by hash.
        left_entries: list[DirEntry] = []
        right_entries = [e for _hh, e, _sz in hashed]
        if hashed and h < hashed[0][0]:
            left_entries.append(new_entry)
        else:
            right_entries.append(new_entry)
        index_hash = hashed[0][0] if hashed else (h & 0xFFFFFFFE)
    else:
        split, index_hash = _dx_split_point(
            [item[0] for item in hashed], [item[2] for item in hashed], bs
        )
        split_hash = hashed[split][0]
        left_entries = [e for _hh, e, _sz in hashed[:split]]
        right_entries = [e for _hh, e, _sz in hashed[split:]]
        if h >= split_hash:
            right_entries.append(new_entry)
        else:
            left_entries.append(new_entry)
    left_b = _pack_dirents(bs, usable, left_entries)
    right_b = _pack_dirents(bs, usable, right_entries)

    exts = file_extents(vol, dir_inode)
    next_l = 0
    for ex in exts:
        next_l = max(next_l, ex.logical + ex.length)
    root = bytearray(bs)
    root[:12] = block0[:12]
    # '..' covers the rest of the root, including dx_root_info and the dx_tail.
    struct.pack_into("<IHBB", root, 12, dotdot_ino, bs - 12, 2, dotdot_ft)
    root[20:22] = b".."
    struct.pack_into("<IBBBB", root, 24, 0, stored_hv, 8, 0, 0)
    limit = _dx_node_limit(bs, 32, vol.sb.has_metadata_csum)
    if limit < 2:
        raise DirError("블록이 너무 작아 HTREE를 만들 수 없습니다.")
    _write_dx_entries(root, 32, limit, [(0, next_l)])
    cursor = next_l + 2

    def alloc_logical() -> int:
        nonlocal cursor
        logical = cursor
        cursor += 1
        return logical

    dirty = _dx_insert_pointer(
        lambda _lb: b"\x00" * bs,
        root,
        index_hash,
        next_l + 1,
        bs,
        vol.sb.has_metadata_csum,
        alloc_logical,
        _htree_max_levels(vol),
    )
    new_logicals = [next_l, next_l + 1, *range(next_l + 2, cursor)]
    phys_list = alloc_blocks(
        vol,
        len(new_logicals),
        prefer_group=(dir_inode.ino - 1) // vol.sb.inodes_per_group,
    )
    undo = _DirUndo(vol, dir_inode)
    undo.new_phys.extend(phys_list)

    def put_block(phys: int, data: bytes) -> None:
        undo.save(phys)
        (getattr(vol, "write_metadata_block", None) or vol.write_block)(phys, data)

    def write_lblock(lblk: int, data: bytearray) -> None:
        drop = getattr(vol, "drop_dir_cache", None)
        if drop is not None:
            drop(dir_inode.ino)
        _dir_csum_set(vol, dir_inode, data)
        phys = logical_to_phys(vol, dir_inode, lblk)
        if phys is None:
            raise DirError("디렉터리 블록을 찾을 수 없습니다.")
        put_block(phys, bytes(data))

    def write_index_lblock(lblk: int, data: bytearray) -> None:
        drop = getattr(vol, "drop_dir_cache", None)
        if drop is not None:
            drop(dir_inode.ino)
        _dx_csum_set(vol, dir_inode, data, _dx_entries_off(data, lblk))
        phys = logical_to_phys(vol, dir_inode, lblk)
        if phys is None:
            raise DirError("HTREE index 블록을 찾을 수 없습니다.")
        put_block(phys, bytes(data))

    new_exts = list(exts) + [
        Extent(logical, 1, phys, False) for logical, phys in zip(new_logicals, phys_list)
    ]
    old_blocks = dir_inode.blocks
    try:
        dir_inode.set_flags(dir_inode.flags | C.EXT4_INDEX_FL)
        dir_inode.set_owned_blocks(sum(e.length for e in new_exts if not e.uninitialized), bs)
        try:
            body = build_extent_tree(vol, dir_inode, new_exts)
        except ValueError:
            dir_inode.set_blocks(old_blocks // (bs // 512), bs)
            raise DirError("디렉터리 extent 트리를 확장할 수 없습니다.")
        dir_inode.set_i_block(body)
        dir_inode.set_size(cursor * bs)
        vol.write_inode(dir_inode)
        for logical, data in dirty.items():
            if logical != 0:
                write_index_lblock(logical, data)
        write_lblock(next_l, left_b)
        write_lblock(next_l + 1, right_b)
        write_index_lblock(0, dirty[0])
    except BaseException:
        undo.rollback(dir_inode)
        raise
    discard_old_extent_indexes(vol, dir_inode)
    return dir_inode


def _probe_leaf(vol, inode: Inode, name: bytes) -> tuple[int, bytes, int]:
    """Return (logical_leaf, root_block, hash)."""
    root = bytearray(read_dir_lblock(vol, inode, 0))
    hv = _dx_hash_version(vol, root)
    entries_off, levels = _dx_root_levels(vol, root)
    h = name_hash(vol, inode, name, hv)
    lblk = _dx_pick(_dx_checked_entries(vol, root, entries_off), h)
    for _ in range(levels):
        node = read_dir_lblock(vol, inode, lblk)
        lblk = _dx_pick(_dx_checked_entries(vol, node, 8), h)
    return lblk, bytes(root), h


def _dx_split_point(hashes: list[int], sizes: list[int], bs: int) -> tuple[int, int]:
    """Linux do_split(): (split index, hash for the new dx entry).

    ``hashes`` is sorted; ``sizes`` are the on-disk rec_len values. Entries
    move from the end while less than half of the next one crosses the block
    middle. Stopping on any entry, including the first, splits at count-move.
    Only a scan that walks off the start (i == -1) falls back to count//2.
    A boundary inside a run of equal hashes sets the low "continued" bit on
    the new index hash so a lookup reads both leaves.
    """
    count = len(hashes)
    size = 0
    move = 0
    i = count - 1
    while i >= 0:
        if size + sizes[i] // 2 > bs // 2:
            break
        size += sizes[i]
        move += 1
        i -= 1
    # CVE-2025-23150 (Linux 6.12.24+ namei.c do_split): i == 0 means the
    # first entry itself crosses the midpoint, so split is count-move.
    # count//2 is only for a scan that consumed every entry (i == -1).
    split = count - move if i >= 0 else count // 2
    if split <= 0 or split >= count:
        raise DirError("디렉터리 HTREE 분할 위치가 올바르지 않습니다.")
    continued = 1 if hashes[split] == hashes[split - 1] else 0
    return split, (hashes[split] + continued) & 0xFFFFFFFF


class _DirUndo:
    """Put a directory back when growing it fails part way.

    Linux grows a directory inside one journal handle, so a failed step never
    reaches a commit. Here each write lands in the open transaction (or on
    disk) at once; remember the old inode and every block rewritten so the
    next commit does not pick up a bigger i_size/i_blocks or a half index.
    """

    def __init__(self, vol, inode: Inode):
        from ext4lib.fs.extents import _collect_index_blocks

        self.vol = vol
        self.raw = bytes(inode.raw)
        self.i_block = inode.i_block
        self.new_phys: list[int] = []
        self.blocks: dict[int, bytes] = {}
        for phys in _collect_index_blocks(vol, inode):
            self.save(phys)

    def save(self, phys: int) -> None:
        if phys not in self.blocks and phys not in self.new_phys:
            self.blocks[phys] = bytes(self.vol.read_block(phys))

    def rollback(self, inode: Inode) -> None:
        from ext4lib.fs.bitmap import _free_phys_runs_now
        from ext4lib.fs.extents import _collect_index_blocks
        from ext4lib.fs.inode import parse_inode

        vol = self.vol
        fresh: list[int] = []
        if inode.i_block != self.i_block:
            fresh = [p for p in _collect_index_blocks(vol, inode) if p not in self.blocks]
        put = getattr(vol, "write_metadata_block", None) or vol.write_block
        for phys, data in self.blocks.items():
            put(phys, data)
        old = parse_inode(vol.sb, inode.ino, self.raw)
        vol.write_inode(old)
        inode.__dict__.update(old.__dict__)
        inode._extent_index_old = []
        # No committed inode ever referenced these: free them now, like a
        # failed allocation, so no stale bitmap bit is committed.
        _free_phys_runs_now(vol, [(p, 1) for p in self.new_phys + fresh])
        drop = getattr(vol, "drop_dir_cache", None)
        if drop is not None:
            drop(inode.ino)


class DirError(RuntimeError):
    pass


class DxCorrupt(DirError):
    """Linux ERR_BAD_DX_DIR: the index is unusable, the leaves may be fine."""


def check_new_name(vol, dir_inode: Inode, name: str) -> bytes:
    """Validate ``name`` for a new entry; return its on-disk bytes.

    Callers run this before allocating the inode so a bad or duplicate name
    cannot leave an allocated inode that no directory references.
    """
    name_b = encode_name(name)
    casefold = is_casefold_dir(vol, dir_inode)
    # Linux generic_ci_validate_strict_name(): strict casefold (s_encoding_flags
    # bit 0) refuses names that are not valid UTF-8 with -EINVAL.
    if casefold and vol.sb.strict_encoding and not utf8_validate(name_b):
        raise DirError(f"올바른 UTF-8 이름이 아닙니다(strict casefold): {name!r}")
    for e in list_dir(vol, dir_inode):
        raw = e.raw or e.name.encode("utf-8")
        if same_name(vol, dir_inode, raw, name_b):
            raise DirError(f"'{name}' 이(가) 이미 있습니다.")
    return name_b


def add_dir_entry(vol, dir_inode: Inode, name: str, ino: int, ftype: int) -> Inode:
    from ext4lib.fs.extents import (
        Extent,
        build_extent_tree,
        discard_old_extent_indexes,
        ensure_extent_layout,
        file_extents,
    )
    from ext4lib.fs.bitmap import alloc_blocks, free_phys_runs

    name_b = check_new_name(vol, dir_inode, name)
    dir_inode = ensure_extent_layout(vol, dir_inode)
    bs = vol.sb.block_size
    tail = _tail_size(vol)
    usable = bs - tail
    undo: _DirUndo | None = None

    def put_block(phys: int, data: bytes) -> None:
        if undo is not None:
            undo.save(phys)
        (getattr(vol, "write_metadata_block", None) or vol.write_block)(phys, data)

    def write_lblock(inode: Inode, lblk: int, data: bytearray) -> None:
        drop = getattr(vol, "drop_dir_cache", None)
        if drop is not None:
            drop(inode.ino)
        _dir_csum_set(vol, inode, data)
        phys = logical_to_phys(vol, inode, lblk)
        if phys is None:
            raise DirError("디렉터리 블록을 찾을 수 없습니다.")
        put_block(phys, bytes(data))

    def write_index_lblock(inode: Inode, lblk: int, data: bytearray) -> None:
        drop = getattr(vol, "drop_dir_cache", None)
        if drop is not None:
            drop(inode.ino)
        _dx_csum_set(vol, inode, data, _dx_entries_off(data, lblk))
        phys = logical_to_phys(vol, inode, lblk)
        if phys is None:
            raise DirError("HTREE index 블록을 찾을 수 없습니다.")
        put_block(phys, bytes(data))

    if dir_inode.is_indexed:
        lblk, _root, h = _probe_leaf(vol, dir_inode, name_b)
        leaf = bytearray(read_dir_lblock(vol, dir_inode, lblk))
        if _insert_into_block(leaf, usable, ino, name_b, ftype):
            write_lblock(dir_inode, lblk, leaf)
            dir_inode.set_times()
            vol.write_inode(dir_inode)
            return dir_inode
        # split: new leaf + dx entry. The leaf is rewritten only after the index plan succeeds.
        old_ents = [
            e
            for e in parse_dirent_block(bytes(leaf), usable)
            if e.name not in (".", "..")
        ]
        hv = _dx_hash_version(vol, read_dir_lblock(vol, dir_inode, 0))
        hashed: list[tuple[int, DirEntry, int]] = []
        for e in old_ents:
            try:
                hh = name_hash(vol, dir_inode, e.raw, hv)
            except Exception as exc:
                raise DirError(f"디렉터리 이름 hash 계산 실패: {e.name}") from exc
            # dx_make_map() sizes an entry by its on-disk rec_len.
            hashed.append((hh, e, e.rec_len))
        hashed.sort(key=lambda x: x[0])
        if len(hashed) < 2:
            raise DirError("디렉터리 분할에 필요한 기존 항목이 부족합니다.")

        # Mirror Linux ext4/namei.c do_split(): split the EXISTING full leaf by
        # byte size, then place the new entry into the appropriate half.
        split, index_hash = _dx_split_point(
            [x[0] for x in hashed], [x[2] for x in hashed], bs
        )
        split_hash = hashed[split][0]
        left_entries = [e for _h, e, _sz in hashed[:split]]
        right_entries = [e for _h, e, _sz in hashed[split:]]
        new_entry = DirEntry(name=name, inode=ino, file_type=ftype, raw=name_b)
        if h >= split_hash:
            right_entries.append(new_entry)
        else:
            left_entries.append(new_entry)

        def pack_ents(ents: list[DirEntry]) -> bytearray:
            buf = _empty_dirent_block(bs, usable)
            for e in ents:
                # Keep the on-disk bytes; re-encoding a non-UTF-8 name renames it.
                if not _insert_into_block(buf, usable, e.inode, e.raw, e.file_type):
                    raise DirError("디렉터리 분할에 실패했습니다.")
            return buf

        left_b = pack_ents(left_entries)
        right_b = pack_ents(right_entries)
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
            index_hash,
            next_l,
            bs,
            vol.sb.has_metadata_csum,
            alloc_logical,
            _htree_max_levels(vol),
        )
        new_logicals = [next_l, *range(next_l + 1, cursor)]
        phys_list = alloc_blocks(
            vol,
            len(new_logicals),
            prefer_group=(dir_inode.ino - 1) // vol.sb.inodes_per_group,
        )
        undo = _DirUndo(vol, dir_inode)
        undo.new_phys.extend(phys_list)
        new_exts = list(exts) + [
            Extent(logical, 1, phys, False) for logical, phys in zip(new_logicals, phys_list)
        ]
        old_blocks = dir_inode.blocks
        # build_extent_tree() adds its index blocks on top of this data count.
        dir_inode.set_owned_blocks(sum(e.length for e in new_exts if not e.uninitialized), bs)
        try:
            body = build_extent_tree(vol, dir_inode, new_exts)
        except ValueError:
            dir_inode.set_blocks(old_blocks // (bs // 512), bs)
            free_phys_runs(vol, [(phys, 1) for phys in phys_list])
            raise DirError("디렉터리 extent 트리를 확장할 수 없습니다.")
        except Exception:
            dir_inode.set_blocks(old_blocks // (bs // 512), bs)
            free_phys_runs(vol, [(phys, 1) for phys in phys_list])
            raise
        try:
            dir_inode.set_i_block(body)
            dir_inode.set_size(cursor * bs)
            vol.write_inode(dir_inode)
            for logical, data in dirty.items():
                if logical != 0:
                    write_index_lblock(dir_inode, logical, data)
            write_lblock(dir_inode, next_l, right_b)
            write_index_lblock(dir_inode, 0, dirty[0])
            write_lblock(dir_inode, lblk, left_b)
        except BaseException:
            undo.rollback(dir_inode)
            raise
        # Old extent-tree blocks are freed only once nothing can roll back.
        discard_old_extent_indexes(vol, dir_inode)
        return dir_inode

    # linear. Linux ext4_add_entry() converts a one-block directory that
    # cannot take the new name (dir_index feature on) instead of appending
    # a second linear block. A directory this program created starts as one
    # block, so it becomes an HTREE here, and ext4_inc_count() can then store
    # nlink 1 once it would pass EXT4_LINK_MAX.
    n = max(1, dir_block_count(dir_inode, bs))
    for lblk in range(n):
        blk = bytearray(read_dir_lblock(vol, dir_inode, lblk))
        if _insert_into_block(blk, usable, ino, name_b, ftype):
            write_lblock(dir_inode, lblk, blk)
            dir_inode.set_times()
            vol.write_inode(dir_inode)
            return dir_inode
        if n == 1 and vol.sb.has_dir_index:
            return _make_indexed_dir(vol, dir_inode, bytes(blk), name, name_b, ino, ftype)
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
    undo = _DirUndo(vol, dir_inode)
    undo.new_phys.append(new_phys)
    try:
        # build_extent_tree() adds its index blocks on top of this data count.
        dir_inode.set_owned_blocks(sum(e.length for e in new_exts), bs)
        body = build_extent_tree(vol, dir_inode, new_exts)
        dir_inode.set_i_block(body)
        dir_inode.set_size((next_l + 1) * bs)
        vol.write_inode(dir_inode)
        _dir_csum_set(vol, dir_inode, buf)
        put_block(new_phys, bytes(buf))
    except BaseException:
        undo.rollback(dir_inode)
        raise
    discard_old_extent_indexes(vol, dir_inode)
    return dir_inode


def remove_dir_entry(vol, dir_inode: Inode, name: str) -> tuple[Inode, int]:
    """Remove name, return (dir_inode, removed_inode_num)."""
    from ext4lib.fs.extents import ensure_extent_layout

    dir_inode = ensure_extent_layout(vol, dir_inode)
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
                # rename_entry() re-adds right away; a stale listing would still
                # hold the removed name and fail the casefold duplicate check.
                drop = getattr(vol, "drop_dir_cache", None)
                if drop is not None:
                    drop(dir_inode.ino)
                _dir_csum_set(vol, dir_inode, data)
                phys = logical_to_phys(vol, dir_inode, lblk)
                if phys is not None:
                    (getattr(vol, "write_metadata_block", None) or vol.write_block)(phys, bytes(data))
                return dir_inode, target
            prev = off
            off += rec
    raise DirError(f"'{name}' 을(를) 찾지 못했습니다.")


def set_parent_entry(vol, dir_inode: Inode, parent_ino: int) -> Inode:
    """Point the '..' entry of a moved directory at its new parent."""
    from ext4lib.fs.extents import ensure_extent_layout

    dir_inode = ensure_extent_layout(vol, dir_inode)
    block = bytearray(read_dir_lblock(vol, dir_inode, 0))
    first_rec = struct.unpack_from("<H", block, 4)[0]
    if first_rec < 12 or first_rec + 10 > len(block):
        raise DirError("폴더의 '..' 항목을 찾지 못했습니다.")
    nlen = block[first_rec + 6]
    if nlen != 2 or bytes(block[first_rec + 8 : first_rec + 10]) != b"..":
        raise DirError("폴더의 '..' 항목을 찾지 못했습니다.")
    struct.pack_into("<I", block, first_rec, parent_ino)
    if dir_inode.is_indexed:
        _dx_csum_set(vol, dir_inode, block, _dx_entries_off(block, 0))
    else:
        _dir_csum_set(vol, dir_inode, block)
    phys = logical_to_phys(vol, dir_inode, 0)
    if phys is None:
        raise DirError("폴더 블록을 찾을 수 없습니다.")
    vol.drop_dir_cache(dir_inode.ino)
    (getattr(vol, "write_metadata_block", None) or vol.write_block)(phys, bytes(block))
    return dir_inode


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
