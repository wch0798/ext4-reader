"""EXT4 superblock and group descriptors."""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field

from ext4lib.fs import constants as C
from ext4lib.fs.crc32c import crc32c, crc32c_seed


def _u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def _u64(lo: int, hi: int) -> int:
    return (hi << 32) | lo


@dataclass
class GroupDesc:
    group: int
    block_bitmap: int
    inode_bitmap: int
    inode_table: int
    free_blocks: int
    free_inodes: int
    used_dirs: int
    flags: int
    itable_unused: int
    raw: bytearray

    def pack(self) -> bytes:
        return bytes(self.raw)


@dataclass
class Superblock:
    raw: bytearray
    inodes_count: int
    blocks_count: int
    free_blocks_count: int
    free_inodes_count: int
    first_data_block: int
    log_block_size: int
    blocks_per_group: int
    inodes_per_group: int
    mtime: int
    wtime: int
    magic: int
    state: int
    errors: int
    creator_os: int
    rev_level: int
    first_ino: int
    inode_size: int
    block_group_nr: int
    feature_compat: int
    feature_incompat: int
    feature_ro_compat: int
    uuid: bytes
    volume_name: str
    last_mounted: str
    desc_size: int
    hash_seed: bytes
    def_hash_version: int
    default_mount_opts: int
    first_meta_bg: int
    mkfs_time: int
    journal_inum: int
    want_extra_isize: int
    min_extra_isize: int
    checksum_seed: int
    last_orphan: int = 0
    orphan_file_inum: int = 0
    groups_count: int = 0
    block_size: int = 4096
    groups: list[GroupDesc] = field(default_factory=list)

    @property
    def has_64bit(self) -> bool:
        return bool(self.feature_incompat & C.EXT4_FEATURE_INCOMPAT_64BIT)

    @property
    def has_extents(self) -> bool:
        return bool(self.feature_incompat & C.EXT4_FEATURE_INCOMPAT_EXTENTS)

    @property
    def has_metadata_csum(self) -> bool:
        return bool(self.feature_ro_compat & C.EXT4_FEATURE_RO_COMPAT_METADATA_CSUM)

    @property
    def has_gdt_csum(self) -> bool:
        return bool(self.feature_ro_compat & C.EXT4_FEATURE_RO_COMPAT_GDT_CSUM)

    @property
    def has_journal(self) -> bool:
        return bool(self.feature_compat & C.EXT4_FEATURE_COMPAT_HAS_JOURNAL)

    @property
    def needs_recovery(self) -> bool:
        return bool(self.feature_incompat & C.EXT4_FEATURE_INCOMPAT_RECOVER)

    @property
    def has_dir_index(self) -> bool:
        return bool(self.feature_compat & C.EXT4_FEATURE_COMPAT_DIR_INDEX)

    @property
    def has_filetype(self) -> bool:
        return bool(self.feature_incompat & C.EXT4_FEATURE_INCOMPAT_FILETYPE)

    @property
    def fs_type(self) -> str:
        if self.feature_incompat & C.EXT4_FEATURE_INCOMPAT_EXTENTS:
            return "EXT4"
        if self.has_journal:
            return "EXT3"
        return "EXT2"

    @property
    def uuid_str(self) -> str:
        try:
            return str(uuid.UUID(bytes=self.uuid))
        except Exception:
            return self.uuid.hex()

    @property
    def clean(self) -> bool:
        return bool(self.state & C.EXT4_VALID_FS) and not self.needs_recovery

    def csum_seed(self) -> int:
        if self.feature_incompat & C.EXT4_FEATURE_INCOMPAT_CSUM_SEED:
            return self.checksum_seed
        return crc32c_seed(self.uuid)

    def update_counts(self) -> None:
        struct.pack_into("<I", self.raw, 0x0C, self.free_blocks_count & 0xFFFFFFFF)
        struct.pack_into("<I", self.raw, 0x10, self.free_inodes_count & 0xFFFFFFFF)
        if self.has_64bit:
            struct.pack_into("<I", self.raw, 0x150, self.free_blocks_count >> 32)
        import time as _t
        self.wtime = int(_t.time())
        struct.pack_into("<I", self.raw, 0x30, self.wtime)

    def write_checksum(self) -> None:
        if not self.has_metadata_csum:
            return
        struct.pack_into("<I", self.raw, 0x3FC, 0)
        # Linux ext4_superblock_csum() starts from ~0. Unlike inode,
        # bitmap and group-descriptor checksums, the superblock does not use
        # s_csum_seed / UUID as the initial CRC.
        crc = crc32c(0xFFFFFFFF, self.raw[:0x3FC])
        struct.pack_into("<I", self.raw, 0x3FC, crc)


def parse_superblock(data: bytes) -> Superblock:
    if len(data) < 1024:
        raise ValueError("슈퍼블록이 너무 짧습니다.")
    magic = _u16(data, 0x38)
    if magic != C.EXT4_SUPER_MAGIC:
        raise ValueError("EXT 매직(0xEF53)이 아닙니다.")
    incompat = _u32(data, 0x60)
    has64 = bool(incompat & C.EXT4_FEATURE_INCOMPAT_64BIT)
    blocks_lo = _u32(data, 0x04)
    blocks_hi = _u32(data, 0x150) if has64 else 0
    free_lo = _u32(data, 0x0C)
    free_hi = _u32(data, 0x154) if has64 else 0
    log_bs = _u32(data, 0x18)
    block_size = C.EXT4_MIN_BLOCK_SIZE << log_bs
    inodes_per_group = _u32(data, 0x28)
    blocks_per_group = _u32(data, 0x20)
    blocks_count = _u64(blocks_lo, blocks_hi)
    first_data = _u32(data, 0x14)
    groups = (blocks_count - first_data + blocks_per_group - 1) // blocks_per_group
    desc_size = _u16(data, 0xFE) if has64 else 32
    if desc_size == 0:
        desc_size = 32
    if desc_size < 32:
        desc_size = 32
    inode_size = _u16(data, 0x58) or C.EXT4_GOOD_OLD_INODE_SIZE
    raw_name = data[0x78 : 0x78 + 16].split(b"\x00", 1)[0]
    raw_mount = data[0x88 : 0x88 + 64].split(b"\x00", 1)[0]
    csum_seed = _u32(data, 0x270)
    sb = Superblock(
        raw=bytearray(data[:1024]),
        inodes_count=_u32(data, 0x00),
        blocks_count=blocks_count,
        free_blocks_count=_u64(free_lo, free_hi),
        free_inodes_count=_u32(data, 0x10),
        first_data_block=first_data,
        log_block_size=log_bs,
        blocks_per_group=blocks_per_group,
        inodes_per_group=inodes_per_group,
        mtime=_u32(data, 0x2C),
        wtime=_u32(data, 0x30),
        magic=magic,
        state=_u16(data, 0x3A),
        errors=_u16(data, 0x3C),
        creator_os=_u32(data, 0x48),
        rev_level=_u32(data, 0x4C),
        first_ino=_u32(data, 0x54) or C.EXT4_GOOD_OLD_FIRST_INO,
        inode_size=inode_size,
        block_group_nr=_u16(data, 0x5A),
        feature_compat=_u32(data, 0x5C),
        feature_incompat=incompat,
        feature_ro_compat=_u32(data, 0x64),
        uuid=bytes(data[0x68:0x78]),
        volume_name=raw_name.decode("utf-8", errors="replace"),
        last_mounted=raw_mount.decode("utf-8", errors="replace"),
        desc_size=desc_size,
        # 0xE8 is s_last_orphan. HTREE s_hash_seed starts at 0xEC.
        hash_seed=bytes(data[0xEC:0xFC]),
        def_hash_version=data[0xFC],
        default_mount_opts=_u32(data, 0x100),
        first_meta_bg=_u32(data, 0x104),
        mkfs_time=_u32(data, 0x108),
        journal_inum=_u32(data, 0xE0),
        want_extra_isize=_u16(data, 0x15C) or 32,
        min_extra_isize=_u16(data, 0x15A) or 32,
        checksum_seed=csum_seed,
        last_orphan=_u32(data, 0xE8),
        orphan_file_inum=_u32(data, 0x280),
        groups_count=groups,
        block_size=block_size,
    )
    return sb




def superblock_checksum_valid(sb: Superblock) -> bool:
    if not sb.has_metadata_csum:
        return True
    stored = _u32(sb.raw, 0x3FC)
    tmp = bytearray(sb.raw)
    struct.pack_into("<I", tmp, 0x3FC, 0)
    calc = crc32c(0xFFFFFFFF, tmp[:0x3FC])
    return stored == calc


def group_desc_checksum_valid(sb: Superblock, gd: GroupDesc) -> bool:
    if not (sb.has_metadata_csum or sb.has_gdt_csum):
        return True
    stored = _u16(gd.raw, 0x1E)
    tmp = GroupDesc(
        group=gd.group,
        block_bitmap=gd.block_bitmap,
        inode_bitmap=gd.inode_bitmap,
        inode_table=gd.inode_table,
        free_blocks=gd.free_blocks,
        free_inodes=gd.free_inodes,
        used_dirs=gd.used_dirs,
        flags=gd.flags,
        itable_unused=gd.itable_unused,
        raw=bytearray(gd.raw),
    )
    apply_gdt_checksum(sb, tmp)
    return stored == _u16(tmp.raw, 0x1E)


def superblock_error_info(sb: Superblock) -> dict[str, int | str]:
    raw = sb.raw
    def cstr(off: int, length: int) -> str:
        return bytes(raw[off:off + length]).split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    return {
        "count": _u32(raw, 0x194),
        "first_time": _u32(raw, 0x198),
        "first_ino": _u32(raw, 0x19C),
        "first_block": struct.unpack_from("<Q", raw, 0x1A0)[0],
        "first_func": cstr(0x1A8, 32),
        "first_line": _u32(raw, 0x1C8),
        "last_time": _u32(raw, 0x1CC),
        "last_ino": _u32(raw, 0x1D0),
        "last_line": _u32(raw, 0x1D4),
        "last_block": struct.unpack_from("<Q", raw, 0x1D8)[0],
        "last_func": cstr(0x1E0, 32),
    }

def _gdt_csum_old(sb: Superblock, group: int, raw: bytearray) -> int:
    """Original crc16 GDT checksum (RO_COMPAT_GDT_CSUM without metadata_csum)."""
    # crc16-itu-t of uuid + le16(group) [+ le16(group>>16) if 64bit] + desc with csum zero
    crc = 0xFFFF
    poly = 0x1021

    def crc16(crc: int, data: bytes) -> int:
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ poly) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF
        return crc

    crc = crc16(crc, sb.uuid)
    crc = crc16(crc, struct.pack("<H", group & 0xFFFF))
    if sb.has_64bit:
        crc = crc16(crc, struct.pack("<H", (group >> 16) & 0xFFFF))
    tmp = bytearray(raw)
    struct.pack_into("<H", tmp, 0x1E, 0)
    crc = crc16(crc, bytes(tmp))
    return crc


def apply_gdt_checksum(sb: Superblock, gd: GroupDesc) -> None:
    raw = gd.raw
    if sb.has_metadata_csum:
        struct.pack_into("<H", raw, 0x1E, 0)
        crc = crc32c(sb.csum_seed(), struct.pack("<I", gd.group))
        crc = crc32c(crc, raw)
        struct.pack_into("<H", raw, 0x1E, crc & 0xFFFF)
    elif sb.has_gdt_csum:
        struct.pack_into("<H", raw, 0x1E, 0)
        c = _gdt_csum_old(sb, gd.group, raw)
        struct.pack_into("<H", raw, 0x1E, c)


def parse_group_desc(sb: Superblock, group: int, raw: bytes) -> GroupDesc:
    buf = bytearray(raw[: sb.desc_size].ljust(sb.desc_size, b"\x00"))
    bb_lo = _u32(buf, 0x00)
    ib_lo = _u32(buf, 0x04)
    it_lo = _u32(buf, 0x08)
    free_blocks = _u16(buf, 0x0C)
    free_inodes = _u16(buf, 0x0E)
    used_dirs = _u16(buf, 0x10)
    flags = _u16(buf, 0x12)
    itable_unused = _u16(buf, 0x1C)
    if sb.has_64bit and sb.desc_size >= 64:
        bb_hi = _u32(buf, 0x20)
        ib_hi = _u32(buf, 0x24)
        it_hi = _u32(buf, 0x28)
        free_blocks |= _u16(buf, 0x2C) << 16
        free_inodes |= _u16(buf, 0x2E) << 16
        used_dirs |= _u16(buf, 0x30) << 16
        itable_unused |= _u16(buf, 0x32) << 16
    else:
        bb_hi = ib_hi = it_hi = 0
    return GroupDesc(
        group=group,
        block_bitmap=_u64(bb_lo, bb_hi),
        inode_bitmap=_u64(ib_lo, ib_hi),
        inode_table=_u64(it_lo, it_hi),
        free_blocks=free_blocks,
        free_inodes=free_inodes,
        used_dirs=used_dirs,
        flags=flags,
        itable_unused=itable_unused,
        raw=buf,
    )


def update_group_desc_fields(sb: Superblock, gd: GroupDesc) -> None:
    raw = gd.raw
    struct.pack_into("<I", raw, 0x00, gd.block_bitmap & 0xFFFFFFFF)
    struct.pack_into("<I", raw, 0x04, gd.inode_bitmap & 0xFFFFFFFF)
    struct.pack_into("<I", raw, 0x08, gd.inode_table & 0xFFFFFFFF)
    struct.pack_into("<H", raw, 0x0C, gd.free_blocks & 0xFFFF)
    struct.pack_into("<H", raw, 0x0E, gd.free_inodes & 0xFFFF)
    struct.pack_into("<H", raw, 0x10, gd.used_dirs & 0xFFFF)
    struct.pack_into("<H", raw, 0x12, gd.flags)
    struct.pack_into("<H", raw, 0x1C, gd.itable_unused & 0xFFFF)
    if sb.has_64bit and sb.desc_size >= 64:
        struct.pack_into("<I", raw, 0x20, gd.block_bitmap >> 32)
        struct.pack_into("<I", raw, 0x24, gd.inode_bitmap >> 32)
        struct.pack_into("<I", raw, 0x28, gd.inode_table >> 32)
        struct.pack_into("<H", raw, 0x2C, (gd.free_blocks >> 16) & 0xFFFF)
        struct.pack_into("<H", raw, 0x2E, (gd.free_inodes >> 16) & 0xFFFF)
        struct.pack_into("<H", raw, 0x30, (gd.used_dirs >> 16) & 0xFFFF)
        struct.pack_into("<H", raw, 0x32, (gd.itable_unused >> 16) & 0xFFFF)
    apply_gdt_checksum(sb, gd)
