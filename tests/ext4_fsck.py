"""Pure-Python read-only ext4 consistency check, roughly ``e2fsck -fn``.

Runs on Windows with no e2fsprogs. It reads the image with its own parser
(only crc32c, the htree hash and the Unicode 12.1 casefold are shared
with ext4lib) and reports:

* superblock / group descriptor / bitmap / inode / extent / dirent / dx
  checksums (metadata_csum)
* uninit_bg flags, itable_unused, free block / inode counts in every group
  descriptor and in the superblock, used_dirs
* block ownership: superblock + GDT + reserved GDT backups, bitmaps, inode
  tables, the resize inode, the journal and every file; double use and
  bitmap differences
* directories: rec_len/name_len, file types, '.'/'..', htree layout and
  hash ranges (casefold aware), casefold duplicates, link counts, reachability
* journal: JBD2 superblock checksum and that it is empty

Usage: python -m tests.ext4_fsck IMAGE
"""

from __future__ import annotations

import stat
import struct
import sys

from ext4lib.fs.casefold import utf8_casefold
from ext4lib.fs.crc32c import crc32c
from ext4lib.fs.hashdir import dirhash

EXT4_MAGIC = 0xEF53
EXT_MAGIC = 0xF30A
JBD2_MAGIC = 0xC03B3998
INDEX_FL = 0x1000
EXTENTS_FL = 0x80000
INLINE_FL = 0x10000000
CASEFOLD_FL = 0x40000000
HUGE_FILE_FL = 0x40000
INCOMPAT_RECOVER = 0x4
INCOMPAT_64BIT = 0x80
INCOMPAT_CASEFOLD = 0x20000
INCOMPAT_CSUM_SEED = 0x2000
RO_METADATA_CSUM = 0x400
RO_DIR_NLINK = 0x20
# e2fsck EXT2_LINK_MAX. Pass 4 collapses a directory to nlink 1 only when
# the counted links are strictly greater than this.
EXT2_LINK_MAX = 65000
RO_SPARSE = 0x1
COMPAT_JOURNAL = 0x4
COMPAT_RESIZE = 0x10
BG_INODE_UNINIT, BG_BLOCK_UNINIT = 1, 2
FT_BY_MODE = {
    stat.S_IFREG: 1, stat.S_IFDIR: 2, stat.S_IFCHR: 3, stat.S_IFBLK: 4,
    stat.S_IFIFO: 5, stat.S_IFSOCK: 6, stat.S_IFLNK: 7,
}


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


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


def pass4_dir_link_errors(
    ino: int, stored: int, counted: int, flags: int, ro_compat: int
) -> list[str]:
    """e2fsck pass4 directory link-count problems (read-only, like -fn).

    When the real count is above EXT2_LINK_MAX, the on-disk value must be 1
    and DIR_NLINK must be set. Exactly 65000 is still an ordinary count.
    An indexed directory left at 1 after the real count falls back to
    65000 or below is PR_4_DIR_OVERFLOW_REF_COUNT.
    """
    if counted > EXT2_LINK_MAX:
        errors = []
        if not ro_compat & RO_DIR_NLINK:
            errors.append(
                f"dir {ino}: {counted} links exceeds EXT2_LINK_MAX but DIR_NLINK is off"
            )
        if stored != 1:
            errors.append(f"dir {ino}: i_links_count {stored} should be 1")
        return errors
    if stored == 1 and counted > 1 and flags & INDEX_FL:
        return [f"dir {ino}: i_links_count is 1 but counted links are {counted}"]
    if stored != counted:
        return [f"dir {ino}: i_links_count {stored} should be {counted}"]
    return []


def casefold(name: bytes) -> bytes | None:
    # e2fsck uses the same Unicode 12.1 utf8 table as the kernel, never the
    # interpreter's unicodedata.
    return utf8_casefold(name)


class Fsck:
    def __init__(self, path: str, offset: int = 0):
        self.fp = open(path, "rb")
        self.offset = offset
        self.errors: list[str] = []
        self.stats: dict[str, int] = {}

    def err(self, msg: str) -> None:
        self.errors.append(msg)

    def read(self, off: int, n: int) -> bytes:
        self.fp.seek(self.offset + off)
        data = self.fp.read(n)
        return data.ljust(n, b"\0")

    def block(self, b: int) -> bytes:
        return self.read(b * self.bs, self.bs)

    # -- superblock / descriptors ------------------------------------------------

    def load_super(self) -> bool:
        sb = self.read(1024, 1024)
        self.sb = sb
        if _u16(sb, 0x38) != EXT4_MAGIC:
            self.err("superblock: bad magic")
            return False
        self.bs = 1024 << _u32(sb, 0x18)
        self.compat, self.incompat, self.ro = _u32(sb, 0x5C), _u32(sb, 0x60), _u32(sb, 0x64)
        self.csum = bool(self.ro & RO_METADATA_CSUM)
        is64 = bool(self.incompat & INCOMPAT_64BIT)
        self.blocks = _u32(sb, 4) | ((_u32(sb, 0x150) << 32) if is64 else 0)
        self.free_blocks = _u32(sb, 0x0C) | ((_u32(sb, 0x158) << 32) if is64 else 0)
        self.inodes, self.free_inodes = _u32(sb, 0), _u32(sb, 0x10)
        self.first_data = _u32(sb, 0x14)
        self.bpg, self.ipg = _u32(sb, 0x20), _u32(sb, 0x28)
        self.isz = _u16(sb, 0x58)
        self.first_ino = _u32(sb, 0x54)
        self.desc_size = _u16(sb, 0xFE) if is64 else 32
        self.ngroups = (self.blocks - self.first_data + self.bpg - 1) // self.bpg
        self.reserved_gdt = _u16(sb, 0xCE) if self.compat & COMPAT_RESIZE else 0
        self.desc_blocks = (self.ngroups * self.desc_size + self.bs - 1) // self.bs
        self.hash_seed = sb[0xEC:0xFC]
        self.unsigned_hash = bool(_u32(sb, 0x160) & 2)
        uuid = sb[0x68:0x78]
        self.seed = _u32(sb, 0x270) if self.incompat & INCOMPAT_CSUM_SEED else crc32c(0xFFFFFFFF, uuid)
        if self.csum and _u32(sb, 0x3FC) != crc32c(0xFFFFFFFF, sb[:0x3FC]):
            self.err("superblock: checksum mismatch")
        if not _u16(sb, 0x3A) & 1:
            self.err("superblock: not marked clean (EXT4_VALID_FS)")
        if _u16(sb, 0x3A) & 2:
            self.err("superblock: EXT4_ERROR_FS set")
        if self.incompat & INCOMPAT_RECOVER:
            self.err("superblock: needs_recovery set")
        if _u32(sb, 0xE8):
            self.err("superblock: orphan list not empty")
        if self.incompat & INCOMPAT_CASEFOLD and _u16(sb, 0x27C) != 1:
            self.err("superblock: casefold without utf8 encoding")
        return True

    def load_groups(self) -> None:
        gdt = self.read((self.first_data + 1) * self.bs, self.ngroups * self.desc_size)
        self.gd = []
        big = self.desc_size >= 64
        for g in range(self.ngroups):
            d = gdt[g * self.desc_size : (g + 1) * self.desc_size]

            def f32(lo, hi):
                return _u32(d, lo) | ((_u32(d, hi) << 32) if big else 0)

            def f16(lo, hi):
                return _u16(d, lo) | ((_u16(d, hi) << 16) if big else 0)

            self.gd.append({
                "raw": d,
                "bb": f32(0, 0x20), "ib": f32(4, 0x24), "it": f32(8, 0x28),
                "free_b": f16(0x0C, 0x2C), "free_i": f16(0x0E, 0x2E),
                "dirs": f16(0x10, 0x30), "flags": _u16(d, 0x12),
                "unused": f16(0x1C, 0x32),
                "bcsum": f16(0x18, 0x38), "icsum": f16(0x1A, 0x3A),
            })
            if self.csum:
                tmp = bytearray(d)
                struct.pack_into("<H", tmp, 0x1E, 0)
                want = crc32c(crc32c(self.seed, struct.pack("<I", g)), tmp) & 0xFFFF
                if _u16(d, 0x1E) != want:
                    self.err(f"group {g}: descriptor checksum mismatch")
        # Backup superblocks must still describe the same filesystem.
        for g in range(1, self.ngroups):
            if self.ro & RO_SPARSE and not _has_super(g):
                continue
            bsb = self.read((self.first_data + g * self.bpg) * self.bs, 1024)
            if _u16(bsb, 0x38) != EXT4_MAGIC or bsb[0x68:0x78] != self.sb[0x68:0x78]:
                self.err(f"group {g}: backup superblock missing")
            elif self.csum and _u32(bsb, 0x3FC) != crc32c(0xFFFFFFFF, bsb[:0x3FC]):
                self.err(f"group {g}: backup superblock checksum mismatch")

    def group_range(self, g: int) -> tuple[int, int]:
        start = self.first_data + g * self.bpg
        return start, min(start + self.bpg, self.blocks)

    # -- inodes -------------------------------------------------------------------

    def inode_raw(self, ino: int) -> bytes:
        g, idx = divmod(ino - 1, self.ipg)
        return self.read(self.gd[g]["it"] * self.bs + idx * self.isz, self.isz)

    def inode_seed(self, ino: int, raw: bytes) -> int:
        return crc32c(crc32c(self.seed, struct.pack("<I", ino)), raw[0x64:0x68])

    def check_inode_csum(self, ino: int, raw: bytes) -> None:
        if not self.csum or not any(raw):
            return
        extra = _u16(raw, 0x80) if self.isz > 128 else 0
        tmp = bytearray(raw)
        struct.pack_into("<H", tmp, 0x7C, 0)
        has_hi = extra >= 4
        if has_hi:
            struct.pack_into("<H", tmp, 0x82, 0)
        crc = crc32c(self.inode_seed(ino, raw), tmp)
        stored = _u16(raw, 0x7C) | ((_u16(raw, 0x82) << 16) if has_hi else 0)
        if stored != (crc if has_hi else crc & 0xFFFF):
            self.err(f"inode {ino}: checksum mismatch")

    def check_inode_fields(self, ino: int, raw: bytes) -> None:
        if self.isz <= 128:
            return
        extra = _u16(raw, 0x80)
        if extra & 3 or extra > self.isz - 128 or (extra and extra < 4):
            self.err(f"inode {ino}: bad i_extra_isize {extra}")
        for off in (0x84, 0x88, 0x8C, 0x94):
            if extra >= off + 4 - 128 and (_u32(raw, off) >> 2) >= 1_000_000_000:
                self.err(f"inode {ino}: nanoseconds out of range at 0x{off:X}")

    def extents(self, ino: int, raw: bytes, meta: list[int]) -> list[tuple[int, int, int]]:
        out: list[tuple[int, int, int]] = []

        def node(data: bytes, depth_expect: int | None, in_inode: bool, lmin: int) -> None:
            magic, entries, emax, depth = struct.unpack_from("<HHHH", data, 0)
            if magic != EXT_MAGIC:
                self.err(f"inode {ino}: bad extent header magic")
                return
            cap = 4 if in_inode else (self.bs - 12) // 12
            if emax > cap or entries > emax:
                self.err(f"inode {ino}: extent header entries {entries}/{emax} cap {cap}")
                return
            if depth_expect is not None and depth != depth_expect:
                self.err(f"inode {ino}: extent depth {depth} expected {depth_expect}")
            prev = -1
            for i in range(entries):
                rec = data[12 + i * 12 : 24 + i * 12]
                logical = _u32(rec, 0)
                if logical <= prev or logical < lmin:
                    self.err(f"inode {ino}: extents out of order at {logical}")
                prev = logical
                if depth == 0:
                    length = _u16(rec, 4)
                    if length > 32768:
                        length -= 32768
                    else:
                        self.last_init = max(self.last_init, logical + length)
                    phys = (_u16(rec, 6) << 32) | _u32(rec, 8)
                    if length == 0 or phys < self.first_data or phys + length > self.blocks:
                        self.err(f"inode {ino}: extent out of range {phys}+{length}")
                        continue
                    out.append((logical, length, phys))
                else:
                    child = (_u16(rec, 8) << 32) | _u32(rec, 4)
                    if child >= self.blocks or child < self.first_data:
                        self.err(f"inode {ino}: extent index out of range {child}")
                        continue
                    meta.append(child)
                    blk = self.block(child)
                    if self.csum:
                        cmax = _u16(blk, 4)
                        toff = 12 + 12 * cmax
                        if toff + 4 > self.bs or _u32(blk, toff) != crc32c(self.inode_seed(ino, raw), blk[:toff]):
                            self.err(f"inode {ino}: extent block {child} checksum mismatch")
                    node(blk, depth - 1, False, logical)

        node(raw[0x28:0x64], None, True, 0)
        out.sort()
        for a, b in zip(out, out[1:]):
            if a[0] + a[1] > b[0]:
                self.err(f"inode {ino}: overlapping logical extents")
        return out

    def indirect(self, ino: int, raw: bytes, meta: list[int]) -> list[int]:
        apb = self.bs // 4
        data: list[int] = []

        def walk(b: int, depth: int) -> None:
            if not b:
                return
            if b >= self.blocks:
                self.err(f"inode {ino}: indirect block out of range {b}")
                return
            if depth == 0:
                data.append(b)
                return
            meta.append(b)
            blk = self.block(b)
            for i in range(apb):
                walk(_u32(blk, i * 4), depth - 1)

        for i in range(12):
            walk(_u32(raw, 0x28 + i * 4), 0)
        for i, depth in ((12, 1), (13, 2), (14, 3)):
            walk(_u32(raw, 0x28 + i * 4), depth)
        return data

    # -- main pass ----------------------------------------------------------------

    def run(self) -> list[str]:
        if not self.load_super():
            return self.errors
        self.load_groups()
        owner: dict[int, int] = {}

        def claim(b: int, who: int) -> None:
            if b in owner:
                self.err(f"block {b}: claimed by {owner[b]} and {who}")
            owner[b] = who

        # Fixed metadata: -1 sb/gdt/reserved, -2 bitmaps/tables.
        it_blocks = (self.ipg * self.isz + self.bs - 1) // self.bs
        backup_groups = []
        for g in range(self.ngroups):
            if self.ro & RO_SPARSE and not _has_super(g):
                continue
            backup_groups.append(g)
            start, _ = self.group_range(g)
            for b in range(start, start + 1 + self.desc_blocks + self.reserved_gdt):
                claim(b, -1)
        for gd in self.gd:
            claim(gd["bb"], -2)
            claim(gd["ib"], -2)
            for b in range(gd["it"], gd["it"] + it_blocks):
                claim(b, -2)

        # Inode bitmaps (UNINIT groups read as all free).
        in_use: set[int] = set()
        for g, gd in enumerate(self.gd):
            ibm = bytes(self.bs) if gd["flags"] & BG_INODE_UNINIT else self.block(gd["ib"])
            if self.csum and not gd["flags"] & BG_INODE_UNINIT:
                want = crc32c(self.seed, ibm[: self.ipg // 8])
                if gd["icsum"] != (want if self.desc_size >= 64 else want & 0xFFFF):
                    self.err(f"group {g}: inode bitmap checksum mismatch")
            if not gd["flags"] & BG_INODE_UNINIT:
                for bit in range(self.ipg, self.bs * 8):
                    if not ibm[bit >> 3] & (1 << (bit & 7)):
                        self.err(f"group {g}: inode bitmap padding bit {bit} clear")
                        break
            count = 0
            last_used = 0
            for bit in range(self.ipg):
                if ibm[bit >> 3] & (1 << (bit & 7)):
                    in_use.add(g * self.ipg + bit + 1)
                    count += 1
                    last_used = bit + 1
            if gd["free_i"] != self.ipg - count:
                self.err(f"group {g}: free inodes {gd['free_i']} but bitmap says {self.ipg - count}")
            if self.csum and gd["unused"] > self.ipg - last_used:
                self.err(f"group {g}: itable_unused {gd['unused']} hides used inode {last_used}")
            if gd["flags"] & BG_INODE_UNINIT and gd["free_i"] != self.ipg:
                self.err(f"group {g}: INODE_UNINIT but inodes in use")

        # Inodes.
        self.nodes: dict[int, dict] = {}
        dirs_per_group = [0] * self.ngroups
        for ino in sorted(in_use):
            raw = self.inode_raw(ino)
            self.check_inode_csum(ino, raw)
            mode = _u16(raw, 0)
            links = _u16(raw, 0x1A)
            if ino >= self.first_ino and (mode == 0 or links == 0):
                self.err(f"inode {ino}: marked in use but mode={mode:o} links={links}")
                continue
            if mode == 0:
                continue
            self.check_inode_fields(ino, raw)
            flags = _u32(raw, 0x20)
            size = _u32(raw, 4) | (_u32(raw, 0x6C) << 32)
            meta: list[int] = []
            data_blocks: list[int] = []
            runs: list[tuple[int, int, int]] = []
            self.last_init = 0
            fast_link = stat.S_ISLNK(mode) and size < 60 and not flags & EXTENTS_FL
            if flags & INLINE_FL or fast_link or stat.S_IFMT(mode) in (stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK):
                pass
            elif flags & EXTENTS_FL:
                runs = self.extents(ino, raw, meta)
                for _l, n, p in runs:
                    data_blocks.extend(range(p, p + n))
            else:
                data_blocks = self.indirect(ino, raw, meta)
            acl = _u32(raw, 0x68) | (_u16(raw, 0x76) << 32)
            if acl:
                meta.append(acl)
            if ino == 7:
                self.check_resize_inode(raw, meta, data_blocks, backup_groups)
            else:
                for b in data_blocks + meta:
                    claim(b, ino)
            iblocks = _u32(raw, 0x1C) | (_u16(raw, 0x74) << 32)
            if flags & HUGE_FILE_FL:
                iblocks *= self.bs // 512
            want = (len(data_blocks) + len(meta)) * (self.bs // 512)
            if iblocks != want:
                self.err(f"inode {ino}: i_blocks {iblocks} should be {want}")
            if stat.S_ISDIR(mode):
                dirs_per_group[(ino - 1) // self.ipg] += 1
                if not flags & INLINE_FL and size != len(data_blocks) * self.bs:
                    self.err(f"inode {ino}: directory size {size} != {len(data_blocks)} blocks")
            # Initialized blocks past EOF: e2fsck "i_size is X, should be Y".
            if stat.S_ISREG(mode) and self.last_init and (self.last_init - 1) * self.bs >= size:
                self.err(f"inode {ino}: initialized blocks mapped past i_size {size}")
            self.nodes[ino] = {"raw": raw, "mode": mode, "links": links, "flags": flags,
                               "size": size, "runs": runs, "refs": 0, "subdirs": 0}
        for g, gd in enumerate(self.gd):
            if gd["dirs"] != dirs_per_group[g]:
                self.err(f"group {g}: used_dirs {gd['dirs']} but found {dirs_per_group[g]}")

        if self.compat & COMPAT_JOURNAL:
            self.check_journal()
        self.check_block_bitmaps(owner)
        self.check_directories()

        total_free_i = sum(gd["free_i"] for gd in self.gd)
        if total_free_i != self.free_inodes:
            self.err(f"superblock: free inodes {self.free_inodes} but groups sum {total_free_i}")
        self.stats.update(inodes=len(self.nodes), blocks_used=len(owner))
        self.fp.close()
        return self.errors

    def check_resize_inode(self, raw, meta, data_blocks, backup_groups) -> None:
        dind = _u32(raw, 0x28 + 13 * 4)
        others = [i for i in range(15) if i != 13 and _u32(raw, 0x28 + i * 4)]
        if others or not dind:
            self.err("inode 7: resize inode block map invalid")
            return
        blk = self.block(dind)
        apb = self.bs // 4
        for r in range(self.reserved_gdt):
            pblk = self.first_data + 1 + self.desc_blocks + r
            if _u32(blk, ((self.desc_blocks + r) % apb) * 4) != pblk:
                self.err(f"inode 7: dind slot for reserved GDT {pblk} wrong")
                continue
            ind = self.block(pblk)
            for k, g in enumerate(gg for gg in backup_groups if gg):
                if _u32(ind, k * 4) != pblk + g * self.bpg:
                    self.err(f"inode 7: reserved GDT {pblk} backup {g} not listed")
        # dind is the only block the resize inode owns outright; the reserved
        # GDT blocks it maps are already claimed as fixed metadata.
        self.dind_block = dind
        self._owner_extra = [dind]

    def check_journal(self) -> None:
        ino = _u32(self.sb, 0xE0)
        node = self.nodes.get(ino)
        if node is None or not node["runs"]:
            self.err("journal: inode missing or unmapped")
            return
        _l, _n, phys = node["runs"][0]
        jsb = self.block(phys)[:1024]
        magic, btype = struct.unpack_from(">II", jsb, 0)
        if magic != JBD2_MAGIC or btype not in (3, 4):
            self.err("journal: bad JBD2 superblock")
            return
        start = struct.unpack_from(">I", jsb, 0x1C)[0]
        if start != 0:
            self.err(f"journal: not empty (s_start={start})")
        incompat = struct.unpack_from(">I", jsb, 0x28)[0]
        if incompat & 0x18:
            tmp = bytearray(jsb)
            struct.pack_into(">I", tmp, 0xFC, 0)
            if struct.unpack_from(">I", jsb, 0xFC)[0] != crc32c(0xFFFFFFFF, tmp):
                self.err("journal: superblock checksum mismatch")
        if bytes(self.sb[0x10C:0x10C + 60]) != bytes(node["raw"][0x28:0x64]) and self.sb[0xFD] == 1:
            self.err("superblock: s_jnl_blocks backup differs from journal inode")

    def check_block_bitmaps(self, owner: dict[int, int]) -> None:
        for b in getattr(self, "_owner_extra", []):
            if b in owner:
                self.err(f"block {b}: claimed by {owner[b]} and resize inode")
            owner[b] = 7
        total_free = 0
        for g, gd in enumerate(self.gd):
            start, end = self.group_range(g)
            n = end - start
            if gd["flags"] & BG_BLOCK_UNINIT:
                if g == self.ngroups - 1:
                    self.err(f"group {g}: last group marked BLOCK_UNINIT")
                bm = None
            else:
                bm = self.block(gd["bb"])
                if self.csum:
                    want = crc32c(self.seed, bm[: self.bpg // 8])
                    if gd["bcsum"] != (want if self.desc_size >= 64 else want & 0xFFFF):
                        self.err(f"group {g}: block bitmap checksum mismatch")
                for bit in range(n, self.bs * 8):
                    if not bm[bit >> 3] & (1 << (bit & 7)):
                        self.err(f"group {g}: block bitmap padding bit {bit} clear")
                        break
            # Linux rebuilds a BLOCK_UNINIT bitmap from this group's own
            # super/GDT/reserved GDT and own bitmaps/table only.
            it_blocks = (self.ipg * self.isz + self.bs - 1) // self.bs
            own = {gd["bb"], gd["ib"], *range(gd["it"], gd["it"] + it_blocks)}
            used = 0
            diffs = []
            for bit in range(n):
                b = start + bit
                ondisk = (b in owner) if bm is None else bool(bm[bit >> 3] & (1 << (bit & 7)))
                if bm is None and b in owner and (owner[b] > 0 or (owner[b] == -2 and b not in own)):
                    diffs.append(b)
                if bm is not None and ondisk != (b in owner):
                    diffs.append(b)
                used += ondisk
            if diffs:
                self.err(f"group {g}: block bitmap differences {diffs[:8]}{'...' if len(diffs) > 8 else ''} ({len(diffs)})")
            free = n - used
            total_free += gd["free_b"]
            if gd["free_b"] != free:
                self.err(f"group {g}: free blocks {gd['free_b']} but bitmap says {free}")
        if total_free != self.free_blocks:
            self.err(f"superblock: free blocks {self.free_blocks} but groups sum {total_free}")

    # -- directories --------------------------------------------------------------

    def dir_hash(self, node: dict, name: bytes, hv: int) -> int:
        if node["flags"] & CASEFOLD_FL and self.incompat & INCOMPAT_CASEFOLD:
            folded = casefold(name)
            if folded is not None:
                name = folded
        return dirhash(name, hv, self.hash_seed)

    def lblock(self, node: dict, lblk: int) -> bytes | None:
        for l, n, p in node["runs"]:
            if l <= lblk < l + n:
                return self.block(p + lblk - l)
        return None

    def check_dirent_tail(self, ino: int, node: dict, blk: bytes, lblk: int) -> int:
        if not self.csum:
            return self.bs
        t = self.bs - 12
        e_ino, rec, nlen, ft = struct.unpack_from("<IHBB", blk, t)
        if e_ino or rec != 12 or nlen or ft != 0xDE:
            self.err(f"dir {ino}: block {lblk} missing dirent tail")
        elif _u32(blk, t + 8) != crc32c(self.inode_seed(ino, node["raw"]), blk[:t]):
            self.err(f"dir {ino}: block {lblk} dirent checksum mismatch")
        return t

    def parse_leaf(self, ino: int, node: dict, blk: bytes, lblk: int, usable: int) -> list[tuple[bytes, int, int]]:
        out = []
        off = 0
        while off < usable:
            if off + 8 > usable:
                self.err(f"dir {ino}: block {lblk} truncated dirent at {off}")
                break
            e_ino, rec, nlen, ft = struct.unpack_from("<IHBB", blk, off)
            if rec < 8 or rec % 4 or off + rec > usable or 8 + nlen > rec:
                self.err(f"dir {ino}: block {lblk} bad rec_len {rec} at {off}")
                break
            if e_ino:
                name = bytes(blk[off + 8 : off + 8 + nlen])
                if not nlen or b"/" in name or b"\0" in name:
                    self.err(f"dir {ino}: illegal name {name!r}")
                out.append((name, e_ino, ft))
            off += rec
        return out

    def check_directories(self) -> None:
        seen_dirs: set[int] = set()
        stack = [(2, 2)]
        reachable = {2}
        while stack:
            ino, parent = stack.pop()
            node = self.nodes.get(ino)
            if node is None or not stat.S_ISDIR(node["mode"]):
                self.err(f"dir {ino}: not an allocated directory")
                continue
            if ino in seen_dirs:
                self.err(f"dir {ino}: reached twice (directory hard link)")
                continue
            seen_dirs.add(ino)
            entries = self.dir_entries(ino, node)
            names: dict[bytes, int] = {}
            folded: dict[bytes, bytes] = {}
            cf = node["flags"] & CASEFOLD_FL and self.incompat & INCOMPAT_CASEFOLD
            for i, (name, e_ino, ft) in enumerate(entries):
                if i == 0 and (name != b"." or e_ino != ino):
                    self.err(f"dir {ino}: first entry is not '.'")
                if i == 1 and (name != b".." or e_ino != parent):
                    self.err(f"dir {ino}: '..' is {e_ino}, expected {parent}")
                if i < 2:
                    continue
                if name in (b".", b".."):
                    self.err(f"dir {ino}: extra {name!r} entry")
                    continue
                if name in names:
                    self.err(f"dir {ino}: duplicate entry {name!r}")
                names[name] = e_ino
                if cf:
                    key = casefold(name)
                    if key is None:
                        key = ("raw", name)
                    if key in folded:
                        self.err(f"dir {ino}: casefold duplicate {name!r} / {folded[key]!r}")
                    folded[key] = name
                child = self.nodes.get(e_ino)
                if child is None:
                    self.err(f"dir {ino}: entry {name!r} -> unallocated inode {e_ino}")
                    continue
                if ft != FT_BY_MODE.get(stat.S_IFMT(child["mode"]), 0):
                    self.err(f"dir {ino}: entry {name!r} file type {ft} does not match inode {e_ino}")
                child["refs"] += 1
                reachable.add(e_ino)
                if stat.S_ISDIR(child["mode"]):
                    node["subdirs"] += 1
                    stack.append((e_ino, ino))
            if len(entries) < 2:
                self.err(f"dir {ino}: missing '.'/'..'")
        for ino, node in self.nodes.items():
            if ino < self.first_ino and ino != 2:
                continue
            if ino not in reachable:
                self.err(f"inode {ino}: allocated but not reachable from /")
                continue
            if stat.S_ISDIR(node["mode"]):
                # '.' plus the name in the parent, plus one '..' per subdirectory.
                for msg in pass4_dir_link_errors(
                    ino, node["links"], 2 + node["subdirs"], node["flags"], self.ro
                ):
                    self.err(msg)
            elif node["links"] != node["refs"]:
                self.err(f"inode {ino}: i_links_count {node['links']} but {node['refs']} names")

    def dir_entries(self, ino: int, node: dict) -> list[tuple[bytes, int, int]]:
        if node["flags"] & INLINE_FL:
            return [(b".", ino, 2), (b"..", _u32(node["raw"], 0x28), 2)]
        nblocks = node["size"] // self.bs
        entries: list[tuple[bytes, int, int]] = []
        if node["flags"] & INDEX_FL:
            return self.htree_entries(ino, node, nblocks)
        for lblk in range(nblocks):
            blk = self.lblock(node, lblk)
            if blk is None:
                self.err(f"dir {ino}: hole at block {lblk}")
                continue
            usable = self.check_dirent_tail(ino, node, blk, lblk)
            entries.extend(self.parse_leaf(ino, node, blk, lblk, usable))
        return entries

    def dx_csum_ok(self, ino: int, node: dict, blk: bytes, off: int) -> bool:
        limit, count = struct.unpack_from("<HH", blk, off)
        tail = off + limit * 8
        if limit != (self.bs - off - 8) // 8 or tail + 8 > self.bs:
            self.err(f"dir {ino}: dx limit {limit} leaves no room for dx_tail")
            return False
        crc = crc32c(self.inode_seed(ino, node["raw"]), blk[: off + count * 8])
        crc = crc32c(crc, blk[tail : tail + 4])
        crc = crc32c(crc, b"\0\0\0\0")
        return _u32(blk, tail + 4) == crc

    def htree_entries(self, ino: int, node: dict, nblocks: int) -> list[tuple[bytes, int, int]]:
        root = self.lblock(node, 0)
        if root is None:
            self.err(f"dir {ino}: htree root unmapped")
            return []
        dot = struct.unpack_from("<IHBB", root, 0)
        dotdot = struct.unpack_from("<IHBB", root, 12)
        entries = [(b".", dot[0], dot[3]), (b"..", dotdot[0], dotdot[3])]
        if dot[1] != 12 or dotdot[1] != self.bs - 12:
            self.err(f"dir {ino}: htree root '.'/'..' rec_len wrong")
        _zero, hv, info_len, levels, _fl = struct.unpack_from("<IBBBB", root, 24)
        if info_len != 8 or levels > 1 or hv > 5:
            self.err(f"dir {ino}: bad dx_root_info hv={hv} len={info_len} levels={levels}")
            return entries
        if hv <= 2 and self.unsigned_hash:
            hv += 3
        if self.csum and not self.dx_csum_ok(ino, node, root, 32):
            self.err(f"dir {ino}: htree root checksum mismatch")
        leaves: list[tuple[int, int, int]] = []  # (lblk, lo, hi_exclusive)
        seen = {0}

        def walk(blk: bytes, off: int, depth: int, lo: int, hi: int) -> None:
            limit, count = struct.unpack_from("<HH", blk, off)
            if not 1 <= count <= limit:
                self.err(f"dir {ino}: dx count {count} limit {limit}")
                return
            ptrs = []
            for i in range(count):
                h, b = struct.unpack_from("<II", blk, off + i * 8)
                ptrs.append((lo if i == 0 else h, b))
            for i in range(1, count):
                if ptrs[i][0] < ptrs[i - 1][0] or ptrs[i][0] < lo:
                    self.err(f"dir {ino}: dx hashes out of order")
            for i, (h, b) in enumerate(ptrs):
                nxt = ptrs[i + 1][0] if i + 1 < count else hi
                if b in seen or b >= nblocks:
                    self.err(f"dir {ino}: dx pointer to bad block {b}")
                    continue
                seen.add(b)
                if depth:
                    child = self.lblock(node, b)
                    if child is None:
                        continue
                    if self.csum and not self.dx_csum_ok(ino, node, child, 8):
                        self.err(f"dir {ino}: dx node {b} checksum mismatch")
                    walk(child, 8, depth - 1, h, nxt)
                else:
                    leaves.append((b, h, nxt))

        walk(root, 32, levels, 0, 1 << 32)
        if len(seen) != nblocks:
            self.err(f"dir {ino}: {nblocks - len(seen)} htree blocks not referenced")
        for b, lo, hi in leaves:
            blk = self.lblock(node, b)
            if blk is None:
                continue
            usable = self.check_dirent_tail(ino, node, blk, b)
            for name, e_ino, ft in self.parse_leaf(ino, node, blk, b, usable):
                h = self.dir_hash(node, name, hv)
                # Bit 0 of an index hash marks a collision continued in the
                # next leaf, so a name may equal the next leaf's start hash.
                lo_c = lo & ~1
                hi_c = hi & ~1 if hi != 1 << 32 else hi
                if not (lo_c <= h and (h < hi_c or (hi & 1 and h == hi_c))):
                    self.err(f"dir {ino}: {name!r} hash {h:#x} outside leaf {b} range [{lo:#x},{hi:#x})")
                entries.append((name, e_ino, ft))
        self.stats["htree_leaves"] = self.stats.get("htree_leaves", 0) + len(leaves)
        return entries


def check_image(path: str, offset: int = 0) -> tuple[list[str], dict]:
    f = Fsck(path, offset)
    errors = f.run()
    return errors, f.stats


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    errors, stats = check_image(argv[0])
    for e in errors:
        print("ERROR:", e)
    print(f"{argv[0]}: {len(errors)} problem(s); {stats}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
