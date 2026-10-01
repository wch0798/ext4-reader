"""Block/inode bitmap allocation and checksums."""

from __future__ import annotations

from ext4reader import constants as C
from ext4reader.crc32c import crc32c
from ext4reader.superblock import GroupDesc, update_group_desc_fields


class Bitmap:
    def __init__(self, data: bytearray, nbits: int):
        self.data = data
        self.nbits = nbits

    def test(self, i: int) -> bool:
        if i < 0 or i >= self.nbits:
            return True
        return bool(self.data[i >> 3] & (1 << (i & 7)))

    def set(self, i: int) -> None:
        self.data[i >> 3] |= 1 << (i & 7)

    def clear(self, i: int) -> None:
        self.data[i >> 3] &= ~(1 << (i & 7))

    def find_run(self, count: int, hint: int = 0) -> int:
        n = self.nbits
        if count <= 0:
            return -1
        start = hint
        for _wrap in range(2):
            i = start
            while i < n:
                if self.test(i):
                    i += 1
                    continue
                run = 1
                while run < count and i + run < n and not self.test(i + run):
                    run += 1
                if run >= count:
                    return i
                i += run
            start = 0
        return -1

    def find_one(self, hint: int = 0) -> int:
        return self.find_run(1, hint)

    def mark_run(self, start: int, count: int) -> None:
        for i in range(start, start + count):
            self.set(i)


def sparse_super(group: int) -> bool:
    if group <= 1:
        return True
    for p in (3, 5, 7):
        x = p
        while x < group:
            x *= p
        if x == group:
            return True
    return False


def bg_has_super(vol, group: int) -> bool:
    if vol.sb.feature_ro_compat & C.EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER:
        return sparse_super(group)
    return True


def group_block_range(vol, group: int) -> tuple[int, int]:
    start = group * vol.sb.blocks_per_group + vol.sb.first_data_block
    end = min(start + vol.sb.blocks_per_group, vol.sb.blocks_count)
    return start, end


def inode_table_blocks(vol) -> int:
    return (
        vol.sb.inodes_per_group * vol.sb.inode_size + vol.sb.block_size - 1
    ) // vol.sb.block_size


def apply_bitmap_csum(vol, gd: GroupDesc, which: str, bitmap: Bitmap) -> None:
    if not vol.sb.has_metadata_csum:
        return
    crc = crc32c(vol.sb.csum_seed(), bitmap.data[: vol.sb.block_size])
    if which == "block":
        # 0x18 lo, 0x34 hi
        gd.raw[0x18:0x1A] = (crc & 0xFFFF).to_bytes(2, "little")
        if vol.sb.desc_size >= 64:
            gd.raw[0x34:0x36] = ((crc >> 16) & 0xFFFF).to_bytes(2, "little")
    else:
        gd.raw[0x1A:0x1C] = (crc & 0xFFFF).to_bytes(2, "little")
        if vol.sb.desc_size >= 64:
            gd.raw[0x36:0x38] = ((crc >> 16) & 0xFFFF).to_bytes(2, "little")
    update_group_desc_fields(vol.sb, gd)


def _init_block_bitmap(vol, gd: GroupDesc) -> Bitmap:
    start, end = group_block_range(vol, gd.group)
    nbits = end - start
    data = bytearray(vol.sb.block_size)
    bm = Bitmap(data, nbits)
    # unused bits at end of bitmap must be 1
    for i in range(nbits, vol.sb.block_size * 8):
        bm.set(i)
    used = [gd.block_bitmap, gd.inode_bitmap]
    it = gd.inode_table
    for b in range(it, it + inode_table_blocks(vol)):
        used.append(b)
    if bg_has_super(vol, gd.group):
        used.append(start)
        # GDT blocks follow super
        gdt_blocks = (
            vol.sb.groups_count * vol.sb.desc_size + vol.sb.block_size - 1
        ) // vol.sb.block_size
        for b in range(start + 1, start + 1 + gdt_blocks):
            used.append(b)
    for b in used:
        if start <= b < end:
            bm.set(b - start)
    gd.flags &= ~C.BG_BLOCK_UNINIT
    return bm


def _init_inode_bitmap(vol, gd: GroupDesc) -> Bitmap:
    nbits = vol.sb.inodes_per_group
    data = bytearray(vol.sb.block_size)
    bm = Bitmap(data, nbits)
    for i in range(nbits, vol.sb.block_size * 8):
        bm.set(i)
    gd.flags &= ~C.BG_INODE_UNINIT
    return bm


def read_block_bitmap(vol, gd: GroupDesc) -> Bitmap:
    start, end = group_block_range(vol, gd.group)
    nbits = end - start
    if gd.flags & C.BG_BLOCK_UNINIT:
        return _init_block_bitmap(vol, gd)
    raw = bytearray(vol.read_block(gd.block_bitmap))
    return Bitmap(raw, nbits)


def read_inode_bitmap(vol, gd: GroupDesc) -> Bitmap:
    if gd.flags & C.BG_INODE_UNINIT:
        return _init_inode_bitmap(vol, gd)
    raw = bytearray(vol.read_block(gd.inode_bitmap))
    return Bitmap(raw, vol.sb.inodes_per_group)


def write_block_bitmap(vol, gd: GroupDesc, bm: Bitmap) -> None:
    apply_bitmap_csum(vol, gd, "block", bm)
    vol.write_block(gd.block_bitmap, bytes(bm.data[: vol.sb.block_size]).ljust(vol.sb.block_size, b"\x00"))


def write_inode_bitmap(vol, gd: GroupDesc, bm: Bitmap) -> None:
    apply_bitmap_csum(vol, gd, "inode", bm)
    vol.write_block(gd.inode_bitmap, bytes(bm.data[: vol.sb.block_size]).ljust(vol.sb.block_size, b"\x00"))


class AllocError(RuntimeError):
    pass


def alloc_blocks(vol, count: int, prefer_group: int | None = None) -> list[int]:
    if count <= 0:
        return []
    ng = vol.sb.groups_count
    order = list(range(ng))
    if prefer_group is not None:
        prefer_group %= ng
        order = list(range(prefer_group, ng)) + list(range(prefer_group))
    remaining = count
    out: list[int] = []
    for g in order:
        if remaining <= 0:
            break
        gd = vol.groups[g]
        if gd.free_blocks <= 0:
            continue
        bm = read_block_bitmap(vol, gd)
        start, _end = group_block_range(vol, g)
        # greedy: largest possible run then smaller
        while remaining > 0 and gd.free_blocks > 0:
            want = min(remaining, gd.free_blocks, C.EXT_UNINIT_MAX_LEN)
            bit = bm.find_run(want)
            got = want
            if bit < 0:
                bit = bm.find_one()
                got = 1
                if bit < 0:
                    break
                # extend
                while got < remaining and bit + got < bm.nbits and not bm.test(bit + got):
                    got += 1
            bm.mark_run(bit, got)
            gd.free_blocks -= got
            vol.sb.free_blocks_count -= got
            for i in range(got):
                out.append(start + bit + i)
            remaining -= got
        write_block_bitmap(vol, gd, bm)
        update_group_desc_fields(vol.sb, gd)
        vol.dirty_groups.add(g)
        vol.dirty_super = True
    if remaining:
        raise AllocError(f"자유 블록이 부족합니다 ({count - remaining}/{count}).")
    return out


def alloc_inode(vol, prefer_group: int | None = None) -> int:
    ng = vol.sb.groups_count
    order = list(range(ng))
    if prefer_group is not None:
        prefer_group %= ng
        order = list(range(prefer_group, ng)) + list(range(prefer_group))
    for g in order:
        gd = vol.groups[g]
        if gd.free_inodes <= 0:
            continue
        bm = read_inode_bitmap(vol, gd)
        hint = 0
        if g == 0:
            hint = max(0, vol.sb.first_ino - 1)
        bit = bm.find_one(hint)
        if bit < 0:
            continue
        if g == 0 and bit + 1 < vol.sb.first_ino:
            bit = bm.find_one(vol.sb.first_ino - 1)
            if bit < 0:
                continue
        bm.set(bit)
        gd.free_inodes -= 1
        vol.sb.free_inodes_count -= 1
        used_index = bit + 1
        unused = vol.sb.inodes_per_group - used_index
        if unused < gd.itable_unused:
            gd.itable_unused = max(0, unused)
        write_inode_bitmap(vol, gd, bm)
        update_group_desc_fields(vol.sb, gd)
        vol.dirty_groups.add(g)
        vol.dirty_super = True
        return g * vol.sb.inodes_per_group + bit + 1
    raise AllocError("자유 inode가 없습니다.")


def free_blocks(vol, blocks: list[int]) -> None:
    by_group: dict[int, list[int]] = {}
    for b in blocks:
        if b < vol.sb.first_data_block:
            continue
        g = (b - vol.sb.first_data_block) // vol.sb.blocks_per_group
        by_group.setdefault(g, []).append(b)
    for g, blist in by_group.items():
        gd = vol.groups[g]
        bm = read_block_bitmap(vol, gd)
        start, _ = group_block_range(vol, g)
        for b in blist:
            bit = b - start
            if 0 <= bit < bm.nbits and bm.test(bit):
                bm.clear(bit)
                gd.free_blocks += 1
                vol.sb.free_blocks_count += 1
        write_block_bitmap(vol, gd, bm)
        update_group_desc_fields(vol.sb, gd)
        vol.dirty_groups.add(g)
        vol.dirty_super = True


def free_inode(vol, ino: int) -> None:
    if ino < vol.sb.first_ino:
        raise AllocError("예약된 inode는 해제할 수 없습니다.")
    g = (ino - 1) // vol.sb.inodes_per_group
    bit = (ino - 1) % vol.sb.inodes_per_group
    gd = vol.groups[g]
    bm = read_inode_bitmap(vol, gd)
    if not bm.test(bit):
        return
    bm.clear(bit)
    gd.free_inodes += 1
    vol.sb.free_inodes_count += 1
    write_inode_bitmap(vol, gd, bm)
    update_group_desc_fields(vol.sb, gd)
    vol.dirty_groups.add(g)
    vol.dirty_super = True
