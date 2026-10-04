"""Block/inode bitmap allocation and checksums."""

from __future__ import annotations

from ext4lib.fs import constants as C
from ext4lib.fs.crc32c import crc32c
from ext4lib.fs.superblock import GroupDesc, update_group_desc_fields


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

    def _skip_set(self, i: int, limit: int) -> int:
        data = self.data
        n = min(self.nbits, limit)
        while i < n and self.test(i):
            if (i & 7) == 0 and i + 8 <= n and data[i >> 3] == 0xFF:
                i += 8
                while i + 8 <= n and data[i >> 3] == 0xFF:
                    i += 8
                continue
            i += 1
        return i

    def _skip_clear(self, i: int, limit: int) -> int:
        data = self.data
        n = min(self.nbits, limit)
        while i < n and not self.test(i):
            if (i & 7) == 0 and i + 8 <= n and data[i >> 3] == 0:
                i += 8
                while i + 8 <= n and data[i >> 3] == 0:
                    i += 8
                continue
            i += 1
        return i

    def _find_run_from(self, first: int, last_start: int, count: int) -> int:
        n = self.nbits
        i = first
        while i < last_start:
            if self.test(i):
                nxt = self._skip_set(i, last_start)
                if nxt <= i:
                    break
                i = nxt
                continue
            free_end = self._skip_clear(i, n)
            if free_end - i >= count:
                return i
            if free_end <= i:
                break
            i = free_end
        return -1

    def find_run(self, count: int, hint: int = 0) -> int:
        n = self.nbits
        if count <= 0 or count > n:
            return -1
        if hint < 0 or hint >= n:
            hint = 0
        bit = self._find_run_from(hint, n, count)
        if bit >= 0:
            return bit
        if hint:
            return self._find_run_from(0, hint, count)
        return -1

    def find_one(self, hint: int = 0) -> int:
        return self.find_run(1, hint)

    def find_last_clear(self) -> int:
        """Highest free bit. Metadata blocks use this so the append cursor stays put."""
        data = self.data
        i = self.nbits - 1
        while i >= 0:
            if (i & 7) == 7 and data[i >> 3] == 0xFF:
                i -= 8
                continue
            if not self.test(i):
                return i
            i -= 1
        return -1

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
    if which == "block":
        # EXT4_CLUSTERS_PER_GROUP / 8. bigalloc is rejected by the writer,
        # therefore clusters == blocks here.
        csum_len = vol.sb.blocks_per_group // 8
    else:
        csum_len = vol.sb.inodes_per_group // 8
    crc = crc32c(vol.sb.csum_seed(), bitmap.data[:csum_len])
    if which == "block":
        # 0x18 low, 0x38 high. 0x34 is bg_exclude_bitmap_hi.
        gd.raw[0x18:0x1A] = (crc & 0xFFFF).to_bytes(2, "little")
        if vol.sb.desc_size >= 64:
            gd.raw[0x38:0x3A] = ((crc >> 16) & 0xFFFF).to_bytes(2, "little")
    else:
        gd.raw[0x1A:0x1C] = (crc & 0xFFFF).to_bytes(2, "little")
        if vol.sb.desc_size >= 64:
            gd.raw[0x3A:0x3C] = ((crc >> 16) & 0xFFFF).to_bytes(2, "little")
    update_group_desc_fields(vol.sb, gd)




def bitmap_checksum_values(
    vol, gd: GroupDesc, which: str, data: bytes
) -> tuple[int, int]:
    """Return (stored, calculated) using the Linux/e2fsprogs layout."""
    if which == "block":
        csum_len = vol.sb.blocks_per_group // 8
        low_off, high_off, hi_end = 0x18, 0x38, 0x3A
    elif which == "inode":
        csum_len = vol.sb.inodes_per_group // 8
        low_off, high_off, hi_end = 0x1A, 0x3A, 0x3C
    else:
        raise ValueError("which must be block or inode")
    crc = crc32c(vol.sb.csum_seed(), data[:csum_len])
    stored = int.from_bytes(gd.raw[low_off:low_off + 2], "little")
    if vol.sb.desc_size >= hi_end:
        stored |= int.from_bytes(gd.raw[high_off:high_off + 2], "little") << 16
        return stored, crc
    return stored, crc & 0xFFFF


def bitmap_checksum_valid(vol, gd: GroupDesc, which: str, data: bytes) -> bool:
    if not vol.sb.has_metadata_csum:
        return True
    stored, calculated = bitmap_checksum_values(vol, gd, which, data)
    return stored == calculated


def legacy_bitmap_checksum_signature(
    vol, gd: GroupDesc, which: str, data: bytes
) -> bool:
    """Detect the exact checksum-layout bug written by older Ext4Reader builds.

    Older builds put the high 16 bits inside bg_exclude_bitmap_hi:
      block: 0x34 instead of 0x38
      inode: 0x36 instead of 0x3A
    They also checksummed a full filesystem block for inode bitmaps.

    Requiring both the old low half and misplaced high half to match the
    calculated legacy CRC gives a 32-bit fingerprint.  We therefore repair
    only media produced by this known bug, not arbitrary checksum failures.
    """
    if not vol.sb.has_metadata_csum or vol.sb.desc_size < 64:
        return False
    legacy_crc = crc32c(
        vol.sb.csum_seed(),
        data[: vol.sb.block_size],
    )
    if which == "block":
        low_off, misplaced_hi_off = 0x18, 0x34
    elif which == "inode":
        low_off, misplaced_hi_off = 0x1A, 0x36
    else:
        raise ValueError("which must be block or inode")
    low = int.from_bytes(gd.raw[low_off:low_off + 2], "little")
    misplaced_hi = int.from_bytes(
        gd.raw[misplaced_hi_off:misplaced_hi_off + 2], "little"
    )
    return (
        low == (legacy_crc & 0xFFFF)
        and misplaced_hi == ((legacy_crc >> 16) & 0xFFFF)
    )


def apply_legacy_bitmap_checksum_repair(
    vol, gd: GroupDesc, which: str, data: bytes
) -> None:
    """Repair only the known pre-JBD2 Ext4Reader bitmap checksum layout bug."""
    if not legacy_bitmap_checksum_signature(vol, gd, which, data):
        raise ValueError("known legacy bitmap checksum signature not present")
    if which == "block":
        gd.raw[0x34:0x36] = b"\x00\x00"
        nbits = vol.sb.blocks_per_group
    elif which == "inode":
        gd.raw[0x36:0x38] = b"\x00\x00"
        nbits = vol.sb.inodes_per_group
    else:
        raise ValueError("which must be block or inode")
    apply_bitmap_csum(vol, gd, which, Bitmap(bytearray(data), nbits))


def bitmap_padding_is_set(data: bytes, used_bits: int, total_bits: int) -> bool:
    """Linux requires bitmap padding bits outside the real group to be set."""
    if used_bits < 0 or total_bits < used_bits or total_bits > len(data) * 8:
        return False
    for bit in range(used_bits, total_bits):
        if not (data[bit >> 3] & (1 << (bit & 7))):
            return False
    return True


def bitmap_free_count(data: bytes, nbits: int) -> int:
    if nbits <= 0:
        return 0
    full, rem = divmod(nbits, 8)
    used = sum(int(b).bit_count() for b in data[:full])
    if rem:
        used += (data[full] & ((1 << rem) - 1)).bit_count()
    return nbits - used

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


def _set_abs_block_if_in_group(
    bm: Bitmap, start: int, end: int, block: int
) -> None:
    if start <= block < end:
        bm.set(block - start)


def rebuild_block_bitmap_from_metadata(
    vol, group: int, progress=None
) -> Bitmap:
    """Reconstruct one corrupt block bitmap without trusting its old contents.

    Sources of truth:
      * every allocated inode from the inode bitmaps
      * all block/inode bitmap and inode-table locations from group descriptors
      * primary/backup superblock + GDT/reserved-GDT metadata

    The caller MUST compare both free-count and stored checksum before writing
    this candidate to disk.
    """
    if group < 0 or group >= len(vol.groups):
        raise ValueError(f"invalid block group: {group}")
    if vol.sb.feature_ro_compat & C.EXT4_FEATURE_RO_COMPAT_BIGALLOC:
        raise ValueError("BIGALLOC bitmap reconstruction is not supported")

    from ext4lib.fs.extents import inode_allocation_blocks
    from ext4lib.fs.inode import inode_checksum_valid

    gd = vol.groups[group]
    start, end = group_block_range(vol, group)
    group_blocks = max(0, end - start)
    data = bytearray(vol.sb.block_size)
    bm = Bitmap(data, vol.sb.blocks_per_group)

    # Linux requires bits beyond the real last group boundary to be set.
    for bit in range(group_blocks, vol.sb.blocks_per_group):
        bm.set(bit)

    # Group-descriptor declared metadata can live in another group with
    # flex_bg, so inspect every descriptor rather than only the target group.
    it_blocks = inode_table_blocks(vol)
    for meta_gd in vol.groups:
        _set_abs_block_if_in_group(bm, start, end, meta_gd.block_bitmap)
        _set_abs_block_if_in_group(bm, start, end, meta_gd.inode_bitmap)
        for block in range(meta_gd.inode_table, meta_gd.inode_table + it_blocks):
            _set_abs_block_if_in_group(bm, start, end, block)

    # Superblock/GDT/reserved-GDT blocks are fixed filesystem metadata.
    gdt_blocks = (
        vol.sb.groups_count * vol.sb.desc_size + vol.sb.block_size - 1
    ) // vol.sb.block_size
    for meta_group in range(vol.sb.groups_count):
        if not bg_has_super(vol, meta_group):
            continue
        meta_start, meta_end = group_block_range(vol, meta_group)
        _set_abs_block_if_in_group(bm, start, end, meta_start)
        for block in range(
            meta_start + 1,
            min(
                meta_end,
                meta_start
                + 1
                + gdt_blocks
                + int(getattr(vol.sb, "reserved_gdt_blocks", 0) or 0),
            ),
        ):
            _set_abs_block_if_in_group(bm, start, end, block)

    # Reconstruct all file-owned blocks from allocated inodes only. This does
    # not consult the corrupt block bitmap.
    total_groups = len(vol.groups)
    for inode_group, inode_gd in enumerate(vol.groups):
        if progress is not None and (
            inode_group % 64 == 0 or inode_group + 1 == total_groups
        ):
            progress(
                f"EXT4 block bitmap 재구성: inode group "
                f"{inode_group + 1}/{total_groups}"
            )
        ibm = read_inode_bitmap(vol, inode_gd)
        base_ino = inode_group * vol.sb.inodes_per_group + 1
        max_count = min(
            vol.sb.inodes_per_group,
            max(0, vol.sb.inodes_count - (base_ino - 1)),
        )
        for bit in range(max_count):
            if not ibm.test(bit):
                continue
            ino = base_ino + bit
            inode = vol.read_inode(ino)
            if not inode_checksum_valid(vol.sb, inode):
                raise ValueError(
                    f"allocated inode {ino} checksum mismatch during bitmap rebuild"
                )
            if inode.mode == 0 and ino >= vol.sb.first_ino:
                raise ValueError(
                    f"allocated inode {ino} has zero mode during bitmap rebuild"
                )
            for block in inode_allocation_blocks(vol, inode):
                _set_abs_block_if_in_group(bm, start, end, block)

    return bm


def read_block_bitmap(vol, gd: GroupDesc) -> Bitmap:
    cache = getattr(vol, "_block_bm_cache", None)
    if cache is not None and gd.group in cache:
        return cache[gd.group]
    start, end = group_block_range(vol, gd.group)
    nbits = end - start
    if gd.flags & C.BG_BLOCK_UNINIT:
        bm = _init_block_bitmap(vol, gd)
    else:
        bm = Bitmap(bytearray(vol.read_block(gd.block_bitmap)), nbits)
    if cache is not None:
        cache[gd.group] = bm
    return bm


def read_inode_bitmap(vol, gd: GroupDesc) -> Bitmap:
    cache = getattr(vol, "_inode_bm_cache", None)
    if cache is not None and gd.group in cache:
        return cache[gd.group]
    if gd.flags & C.BG_INODE_UNINIT:
        bm = _init_inode_bitmap(vol, gd)
    else:
        bm = Bitmap(bytearray(vol.read_block(gd.inode_bitmap)), vol.sb.inodes_per_group)
    if cache is not None:
        cache[gd.group] = bm
    return bm


def write_block_bitmap(vol, gd: GroupDesc, bm: Bitmap) -> None:
    apply_bitmap_csum(vol, gd, "block", bm)
    cache = getattr(vol, "_block_bm_cache", None)
    dirty = getattr(vol, "_dirty_block_bm", None)
    if cache is not None and dirty is not None:
        cache[gd.group] = bm
        dirty.add(gd.group)
        return
    (getattr(vol, "write_metadata_block", None) or vol.write_block)(gd.block_bitmap, bytes(bm.data[: vol.sb.block_size]).ljust(vol.sb.block_size, b"\x00"))


def write_inode_bitmap(vol, gd: GroupDesc, bm: Bitmap) -> None:
    apply_bitmap_csum(vol, gd, "inode", bm)
    cache = getattr(vol, "_inode_bm_cache", None)
    dirty = getattr(vol, "_dirty_inode_bm", None)
    if cache is not None and dirty is not None:
        cache[gd.group] = bm
        dirty.add(gd.group)
        return
    (getattr(vol, "write_metadata_block", None) or vol.write_block)(gd.inode_bitmap, bytes(bm.data[: vol.sb.block_size]).ljust(vol.sb.block_size, b"\x00"))


class AllocError(RuntimeError):
    pass


def alloc_blocks(vol, count: int, prefer_group: int | None = None, *, metadata: bool = False) -> list[int]:
    if count <= 0:
        return []
    ng = vol.sb.groups_count
    if metadata:
        # Extent index blocks come from the end of the disk. Taking them from
        # the append cursor splits every large sequential write into 1MB extents.
        order = list(range(ng - 1, -1, -1))
    else:
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
        hints = getattr(vol, "_alloc_hint", None)
        allocated_here = False
        # greedy: largest possible run then smaller
        while remaining > 0 and gd.free_blocks > 0:
            if metadata:
                bit = bm.find_last_clear()
                if bit < 0:
                    break
                got = 1
            else:
                want = min(remaining, gd.free_blocks, C.EXT_UNINIT_MAX_LEN)
                hint = hints.get(g, 0) if hints is not None else 0
                bit = -1
                got = want
                if hint and bm._skip_clear(hint, hint + want) == hint + want:
                    bit = hint
                else:
                    bit = bm.find_run(want)
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
            allocated_here = True
            if hints is not None and not metadata:
                hints[g] = bit + got
        if not allocated_here:
            continue
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


def _queue_block_frees(vol, runs: list[tuple[int, int]]) -> None:
    """Keep freed blocks unavailable until the current JBD2 transaction commits.

    File data is written to home blocks before metadata commit (ordered mode).
    Reusing a just-freed block before the transaction is durable could overwrite
    data or extent-tree metadata still referenced by the old on-disk inode.
    """
    pending = getattr(vol, "_pending_block_frees", None)
    if pending is None:
        pending = []
        vol._pending_block_frees = pending
    for phys, length in runs:
        if length > 0:
            pending.append((phys, length))


def _free_phys_runs_now(vol, runs: list[tuple[int, int]]) -> None:
    """Apply block frees to the in-memory bitmap/counts immediately."""
    by_group: dict[int, list[tuple[int, int]]] = {}
    for phys, length in runs:
        if length <= 0:
            continue
        end = phys + length
        cursor = phys
        while cursor < end:
            if cursor < vol.sb.first_data_block:
                cursor += 1
                continue
            g = (cursor - vol.sb.first_data_block) // vol.sb.blocks_per_group
            if g < 0 or g >= vol.sb.groups_count:
                cursor += 1
                continue
            _start, gend = group_block_range(vol, g)
            run_end = min(end, gend)
            by_group.setdefault(g, []).append((cursor, run_end - cursor))
            cursor = run_end
    for g, pieces in by_group.items():
        gd = vol.groups[g]
        bm = read_block_bitmap(vol, gd)
        start, _ = group_block_range(vol, g)
        freed = 0
        first_freed_bit: int | None = None
        for b, length in pieces:
            bit = b - start
            for i in range(length):
                idx = bit + i
                if 0 <= idx < bm.nbits and bm.test(idx):
                    bm.clear(idx)
                    freed += 1
                    if first_freed_bit is None or idx < first_freed_bit:
                        first_freed_bit = idx
        if not freed:
            continue
        gd.free_blocks += freed
        vol.sb.free_blocks_count += freed
        hints = getattr(vol, "_alloc_hint", None)
        if hints is not None and first_freed_bit is not None:
            prev = hints.get(g)
            if prev is None or first_freed_bit < prev:
                hints[g] = max(0, first_freed_bit)
        write_block_bitmap(vol, gd, bm)
        update_group_desc_fields(vol.sb, gd)
        vol.dirty_groups.add(g)
        vol.dirty_super = True


def apply_pending_block_frees(vol) -> int:
    """Apply JBD2-deferred frees immediately before a synchronous commit."""
    pending = getattr(vol, "_pending_block_frees", None)
    if not pending:
        return 0
    runs = list(pending)
    _free_phys_runs_now(vol, runs)
    # Clear only after the whole pass succeeds. Reapplying after a partial
    # failure is safe because _free_phys_runs_now checks the bitmap bit first.
    pending.clear()
    return sum(length for _phys, length in runs if length > 0)


def free_blocks(vol, blocks: list[int]) -> None:
    free_phys_runs(vol, [(b, 1) for b in blocks])


def free_phys_runs(vol, runs: list[tuple[int, int]]) -> None:
    """Free physical runs, deferring reuse while a JBD2 transaction is open."""
    if getattr(vol, "_journal_writer", None) is not None:
        _queue_block_frees(vol, runs)
        return
    _free_phys_runs_now(vol, runs)

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
