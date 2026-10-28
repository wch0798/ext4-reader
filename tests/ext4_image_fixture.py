"""Build a small ext4 image laid out like a Steam Deck SD card. Pure Python.

SteamOS formats cards with ``mkfs.ext4 -m 0 -O casefold``; the mke2fs ext4
defaults add has_journal, ext_attr, resize_inode, dir_index, filetype,
extent, 64bit, flex_bg, sparse_super, large_file, huge_file, dir_nlink,
extra_isize and metadata_csum. This writes the same features, the same
reserved-GDT / resize-inode layout and the same uninit_bg flags so tests run
on Windows without e2fsprogs. Groups are small (blocks_per_group=2048, like
``mke2fs -g 2048``) so a 40 MiB image still has backup groups and a short
last group.

Usage: python -m tests.ext4_image_fixture OUT.img
"""

from __future__ import annotations

import os
import struct
import time
import uuid as uuidlib

from ext4lib.fs import constants as C
from ext4lib.fs.crc32c import crc32c

BS = 4096
BPG = 2048
IPG = 512
INODE_SIZE = 256
RESERVED_GDT = 16
JOURNAL_BLOCKS = 1024
LPF_BLOCKS = 4
FLEX_LOG = 4

COMPAT = (
    C.EXT4_FEATURE_COMPAT_HAS_JOURNAL
    | 0x0008  # ext_attr
    | 0x0010  # resize_inode
    | C.EXT4_FEATURE_COMPAT_DIR_INDEX
)
INCOMPAT = (
    C.EXT4_FEATURE_INCOMPAT_FILETYPE
    | C.EXT4_FEATURE_INCOMPAT_EXTENTS
    | C.EXT4_FEATURE_INCOMPAT_64BIT
    | C.EXT4_FEATURE_INCOMPAT_FLEX_BG
    | C.EXT4_FEATURE_INCOMPAT_CASEFOLD
)
RO_COMPAT = (
    C.EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER
    | C.EXT4_FEATURE_RO_COMPAT_LARGE_FILE
    | C.EXT4_FEATURE_RO_COMPAT_HUGE_FILE
    | C.EXT4_FEATURE_RO_COMPAT_DIR_NLINK
    | C.EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE
    | C.EXT4_FEATURE_RO_COMPAT_METADATA_CSUM
)


def _has_super(g: int) -> bool:
    if g <= 1:
        return True
    for p in (3, 5, 7):
        x = p
        while x < g:
            x *= p
        if x == g:
            return True
    return False


class _Image:
    def __init__(self, path: str, blocks: int):
        self.fp = open(path, "w+b")
        self.fp.truncate(blocks * BS)

    def put(self, block: int, data: bytes, off: int = 0) -> None:
        self.fp.seek(block * BS + off)
        self.fp.write(data)

    def close(self) -> None:
        self.fp.close()


def _bitmap(used: set[int], nbits: int) -> bytearray:
    bm = bytearray(BS)
    for bit in list(used) + list(range(nbits, BS * 8)):
        bm[bit >> 3] |= 1 << (bit & 7)
    return bm


def _extent_body(runs: list[tuple[int, int, int]]) -> bytes:
    body = bytearray(60)
    struct.pack_into("<HHHHI", body, 0, C.EXT4_EXT_MAGIC, len(runs), 4, 0, 0)
    for i, (logical, length, phys) in enumerate(runs):
        struct.pack_into("<IHHI", body, 12 + i * 12, logical, length, phys >> 32, phys & 0xFFFFFFFF)
    return bytes(body)


def make_steamdeck_image(
    path: str,
    groups: int = 5,
    last_group_blocks: int = 1500,
    casefold_htree_dir: str | None = None,
) -> dict:
    """Write the image. Returns a dict describing the layout."""
    blocks = (groups - 1) * BPG + last_group_blocks
    fs_uuid = uuidlib.uuid4().bytes
    seed = crc32c(0xFFFFFFFF, fs_uuid)
    now = int(time.time())
    desc_blocks = (groups * 64 + BS - 1) // BS
    itb = IPG * INODE_SIZE // BS

    # Group 0: sb, GDT, reserved GDT, then flex_bg packed bitmaps / tables.
    cur = 1 + desc_blocks + RESERVED_GDT
    bb = list(range(cur, cur + groups)); cur += groups
    ib = list(range(cur, cur + groups)); cur += groups
    it = [cur + g * itb for g in range(groups)]; cur += groups * itb
    root_blk = cur; cur += 1
    lpf_blk = cur; cur += LPF_BLOCKS
    dind_blk = cur; cur += 1
    journal_blk = cur; cur += JOURNAL_BLOCKS
    cf_blocks = []
    if casefold_htree_dir:
        cf_blocks = [cur, cur + 1]; cur += 2
    g0_used_blocks = cur
    backups = [g for g in range(1, groups) if _has_super(g)]

    img = _Image(path, blocks)
    inodes: dict[int, bytearray] = {}

    def inode(ino, mode, links, size, nblocks, flags, i_block, uid=0, gid=0):
        raw = bytearray(INODE_SIZE)
        struct.pack_into("<HHIIIII", raw, 0, mode, uid, size & 0xFFFFFFFF, now, now, now, 0)
        struct.pack_into("<HHI", raw, 0x18, gid, links, nblocks * (BS // 512))
        struct.pack_into("<I", raw, 0x20, flags)
        raw[0x28:0x64] = i_block
        struct.pack_into("<I", raw, 0x64, 0)  # generation
        struct.pack_into("<I", raw, 0x6C, size >> 32)
        struct.pack_into("<H", raw, 0x80, 32)
        struct.pack_into("<I", raw, 0x90, now)
        inodes[ino] = raw
        return raw

    def dir_block(entries: list[tuple[int, bytes, int]], ino: int) -> bytearray:
        buf = bytearray(BS)
        off = 0
        for i, (e_ino, name, ft) in enumerate(entries):
            rec = (8 + len(name) + 3) & ~3
            if i == len(entries) - 1:
                rec = BS - 12 - off
            struct.pack_into("<IHBB", buf, off, e_ino, rec, len(name), ft)
            buf[off + 8 : off + 8 + len(name)] = name
            off += rec
        struct.pack_into("<IHBB", buf, BS - 12, 0, 12, 0, C.EXT4_FT_DIR_CSUM)
        crc = crc32c(seed, struct.pack("<II", ino, 0))
        struct.pack_into("<I", buf, BS - 4, crc32c(crc, buf[: BS - 12]))
        return buf

    root_links = 3
    root_entries = [(2, b".", 2), (2, b"..", 2), (11, b"lost+found", 2)]
    if casefold_htree_dir:
        root_links += 1
        root_entries.append((12, casefold_htree_dir.encode("utf-8"), 2))
    inode(2, 0o40755, root_links, BS, 1, C.EXT4_EXTENTS_FL, _extent_body([(0, 1, root_blk)]))
    img.put(root_blk, dir_block(root_entries, 2))

    inode(11, 0o40700, 2, LPF_BLOCKS * BS, LPF_BLOCKS, C.EXT4_EXTENTS_FL,
          _extent_body([(0, LPF_BLOCKS, lpf_blk)]))
    img.put(lpf_blk, dir_block([(11, b".", 2), (2, b"..", 2)], 11))
    for i in range(1, LPF_BLOCKS):
        img.put(lpf_blk + i, dir_block([(0, b"", 0)], 11))

    if casefold_htree_dir:
        # An already-indexed casefold directory (what Linux leaves after a
        # folder outgrows one block). Entry 0 points at the one empty leaf.
        flags = C.EXT4_EXTENTS_FL | C.EXT4_INDEX_FL | C.EXT4_CASEFOLD_FL
        inode(12, 0o40755, 2, 2 * BS, 2, flags, _extent_body([(0, 2, cf_blocks[0])]), 1000, 1000)
        root = bytearray(BS)
        struct.pack_into("<IHBB", root, 0, 12, 12, 1, 2)
        root[8:9] = b"."
        struct.pack_into("<IHBB", root, 12, 2, BS - 12, 2, 2)
        root[20:22] = b".."
        struct.pack_into("<IBBBB", root, 24, 0, C.DX_HASH_HALF_MD4, 8, 0, 0)
        limit = (BS - 32 - 8) // 8
        struct.pack_into("<HHI", root, 32, limit, 1, 1)
        tail = 32 + limit * 8
        crc = crc32c(seed, struct.pack("<II", 12, 0))
        crc = crc32c(crc, root[: 32 + 8])
        crc = crc32c(crc, root[tail : tail + 4])
        crc = crc32c(crc, b"\0\0\0\0")
        struct.pack_into("<I", root, tail + 4, crc)
        img.put(cf_blocks[0], root)
        img.put(cf_blocks[1], dir_block([(0, b"", 0)], 12))

    # Journal (inode 8): empty JBD2 v2 superblock with csum v3.
    j_body = _extent_body([(0, JOURNAL_BLOCKS, journal_blk)])
    inode(8, 0o100600, 1, JOURNAL_BLOCKS * BS, JOURNAL_BLOCKS, C.EXT4_EXTENTS_FL, j_body)
    jsb = bytearray(1024)
    struct.pack_into(">III", jsb, 0, C.JBD2_MAGIC_NUMBER, C.JBD2_SUPERBLOCK_V2, 0)
    struct.pack_into(">IIIII", jsb, 0x0C, BS, JOURNAL_BLOCKS, 1, 1, 0)
    struct.pack_into(">III", jsb, 0x24, 0, 0x02 | 0x10, 0)  # 64bit | csum_v3
    jsb[0x30:0x40] = fs_uuid
    struct.pack_into(">I", jsb, 0x40, 1)
    jsb[0x50] = 4  # JBD2_CRC32C_CHKSUM
    jsb[0x100:0x110] = fs_uuid
    struct.pack_into(">I", jsb, 0xFC, crc32c(0xFFFFFFFF, jsb))
    img.put(journal_blk, jsb)

    # Resize inode (7): indirect map. DIND -> primary reserved GDT blocks,
    # each of which lists its copies in the backup groups.
    apb = BS // 4
    dind = bytearray(BS)
    for r in range(RESERVED_GDT):
        pblk = 1 + desc_blocks + r
        struct.pack_into("<I", dind, ((desc_blocks + r) % apb) * 4, pblk)
        ind = bytearray(BS)
        for k, g in enumerate(backups):
            struct.pack_into("<I", ind, k * 4, pblk + g * BPG)
        img.put(pblk, ind)
    img.put(dind_blk, dind)
    rblock = bytearray(60)
    struct.pack_into("<I", rblock, 13 * 4, dind_blk)
    resize_size = (apb * apb + apb + 12) * BS
    inode(7, 0o100600, 1, resize_size, 1 + RESERVED_GDT * (1 + len(backups)), 0, bytes(rblock))

    # Bitmaps and group descriptors.
    descs = []
    total_free_blocks = 0
    used_inodes = 12 if casefold_htree_dir else 11
    for g in range(groups):
        nblocks = BPG if g < groups - 1 else last_group_blocks
        if g == 0:
            used = set(range(g0_used_blocks))
        elif g in backups:
            used = set(range(1 + desc_blocks + RESERVED_GDT))
        else:
            used = set()
        bbm = _bitmap(used, nblocks)
        ibm = _bitmap(set(range(used_inodes)) if g == 0 else set(), IPG)
        img.put(bb[g], bbm)
        img.put(ib[g], ibm)
        free_b = nblocks - len(used)
        total_free_blocks += free_b
        if g == 0:
            flags, unused, free_i, dirs = C.BG_INODE_ZEROED, IPG - used_inodes, IPG - used_inodes, 3 if casefold_htree_dir else 2
        else:
            flags = C.BG_INODE_UNINIT | C.BG_INODE_ZEROED
            if g < groups - 1:
                flags |= C.BG_BLOCK_UNINIT
            unused, free_i, dirs = IPG, IPG, 0
        d = bytearray(64)
        struct.pack_into("<III", d, 0, bb[g], ib[g], it[g])
        struct.pack_into("<HHHH", d, 0x0C, free_b, free_i, dirs, flags)
        struct.pack_into("<H", d, 0x1C, unused)
        bcrc = crc32c(seed, bbm[: BPG // 8])
        icrc = crc32c(seed, ibm[: IPG // 8])
        struct.pack_into("<HH", d, 0x18, bcrc & 0xFFFF, icrc & 0xFFFF)
        struct.pack_into("<HH", d, 0x38, bcrc >> 16, icrc >> 16)
        gcrc = crc32c(crc32c(seed, struct.pack("<I", g)), d)
        struct.pack_into("<H", d, 0x1E, gcrc & 0xFFFF)
        descs.append(bytes(d))

    for ino, raw in inodes.items():
        crc = crc32c(seed, struct.pack("<II", ino, 0))
        crc = crc32c(crc, raw)
        struct.pack_into("<H", raw, 0x7C, crc & 0xFFFF)
        struct.pack_into("<H", raw, 0x82, crc >> 16)
        g, idx = divmod(ino - 1, IPG)
        img.put(it[g], raw, idx * INODE_SIZE)

    sb = bytearray(1024)
    struct.pack_into(
        "<IIIIIIIIIII",
        sb, 0,
        groups * IPG, blocks, 0, total_free_blocks, groups * IPG - used_inodes,
        0, 2, 2, BPG, BPG, IPG,
    )
    struct.pack_into("<IIHHHHHHII", sb, 0x2C, 0, now, 0, 0xFFFF, C.EXT4_SUPER_MAGIC,
                     C.EXT4_VALID_FS, 1, 0, now, 0)
    struct.pack_into("<IIHHIHHIII", sb, 0x48, 0, 1, 0, 0, 11, INODE_SIZE, 0,
                     COMPAT, INCOMPAT, RO_COMPAT)
    sb[0x68:0x78] = fs_uuid
    sb[0x78:0x80] = b"SteamSD\0"
    struct.pack_into("<H", sb, 0xCE, RESERVED_GDT)
    struct.pack_into("<I", sb, 0xE0, 8)
    sb[0xEC:0xFC] = uuidlib.uuid4().bytes
    sb[0xFC] = C.DX_HASH_HALF_MD4
    sb[0xFD] = 1  # EXT3_JNL_BACKUP_BLOCKS
    struct.pack_into("<H", sb, 0xFE, 64)
    struct.pack_into("<I", sb, 0x100, 0x000C)  # user_xattr | acl
    struct.pack_into("<I", sb, 0x108, now)
    sb[0x10C:0x10C + 60] = j_body
    struct.pack_into("<II", sb, 0x10C + 60, 0, JOURNAL_BLOCKS * BS)
    struct.pack_into("<HH", sb, 0x15C, 32, 32)
    struct.pack_into("<I", sb, 0x160, C.EXT2_FLAGS_SIGNED_HASH)  # x86 host
    sb[0x174] = FLEX_LOG
    sb[0x175] = 1  # crc32c
    struct.pack_into("<HH", sb, 0x27C, 1, 0)  # s_encoding = utf8-12.1
    gdt = b"".join(descs)
    for g in [0] + backups:
        copy = bytearray(sb)
        struct.pack_into("<H", copy, 0x5A, g)
        struct.pack_into("<I", copy, 0x3FC, crc32c(0xFFFFFFFF, copy[:0x3FC]))
        base = g * BPG
        img.put(base, bytes(copy), 1024 if g == 0 else 0)
        img.put(base + 1, gdt)
    img.close()
    return {
        "blocks": blocks,
        "groups": groups,
        "backups": backups,
        "journal": (journal_blk, JOURNAL_BLOCKS),
        "casefold_dir_ino": 12 if casefold_htree_dir else None,
    }


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "steamdeck_test.img"
    info = make_steamdeck_image(target, casefold_htree_dir="steamapps")
    print(f"wrote {target} ({os.path.getsize(target)} bytes) {info}")
