"""EXT4 inode parse/pack and checksums."""

from __future__ import annotations

import os
import stat
import struct
import time
from dataclasses import dataclass

from ext4lib.fs import constants as C
from ext4lib.fs.crc32c import crc32c
from ext4lib.fs.superblock import Superblock


def _u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


@dataclass
class Inode:
    ino: int
    raw: bytearray
    mode: int
    uid: int
    gid: int
    size: int
    atime: int
    ctime: int
    mtime: int
    dtime: int
    links: int
    blocks: int
    flags: int
    generation: int
    extra_isize: int
    crtime: int
    file_acl: int

    @property
    def is_dir(self) -> bool:
        return stat.S_ISDIR(self.mode)

    @property
    def is_reg(self) -> bool:
        return stat.S_ISREG(self.mode)

    @property
    def is_lnk(self) -> bool:
        return stat.S_ISLNK(self.mode)

    @property
    def uses_extents(self) -> bool:
        return bool(self.flags & C.EXT4_EXTENTS_FL)

    @property
    def is_indexed(self) -> bool:
        return bool(self.flags & C.EXT4_INDEX_FL)

    @property
    def i_block(self) -> bytes:
        return bytes(self.raw[0x28:0x64])

    def set_i_block(self, data: bytes) -> None:
        if len(data) != 60:
            raise ValueError("i_block must be 60 bytes")
        self.raw[0x28:0x64] = data

    def set_size(self, size: int) -> None:
        self.size = size
        struct.pack_into("<I", self.raw, 0x04, size & 0xFFFFFFFF)
        struct.pack_into("<I", self.raw, 0x6C, (size >> 32) & 0xFFFFFFFF)

    def _put_time(self, sec_off: int, extra_off: int, ts: float | int | None) -> int:
        lo, extra, sec = encode_time(ts)
        struct.pack_into("<I", self.raw, sec_off, lo)
        # The *_extra word exists only when i_extra_isize covers it.
        if self.extra_isize >= extra_off + 4 - C.EXT4_GOOD_OLD_INODE_SIZE:
            struct.pack_into("<I", self.raw, extra_off, extra)
        return sec

    def set_times(self, now: float | int | None = None) -> None:
        # a/c/mtime only: i_crtime is the creation time and must not move.
        if now is None:
            now = time.time_ns() / 1e9
        self.atime = self._put_time(0x08, 0x8C, now)
        self.ctime = self._put_time(0x0C, 0x84, now)
        self.mtime = self._put_time(0x10, 0x88, now)

    def set_ctime(self) -> None:
        self.ctime = self._put_time(0x0C, 0x84, time.time_ns() / 1e9)

    def set_atime_mtime(self, atime: float | int, mtime: float | int) -> None:
        # Windows FILETIME may be before 1970 or after 2038; encode_time()
        # stores those with epoch bits instead of failing struct.pack.
        self.atime = self._put_time(0x08, 0x8C, atime)
        self.mtime = self._put_time(0x10, 0x88, mtime)
        self.set_ctime()

    def set_links(self, n: int) -> None:
        self.links = n
        struct.pack_into("<H", self.raw, 0x1A, n & 0xFFFF)

    def set_blocks(self, fs_blocks: int, block_size: int) -> None:
        # 512-byte units, 48-bit so a file is not capped at 2TiB.
        self.blocks = fs_blocks * (block_size // 512)
        struct.pack_into("<I", self.raw, 0x1C, self.blocks & 0xFFFFFFFF)
        if len(self.raw) >= 0x76:
            struct.pack_into("<H", self.raw, 0x74, (self.blocks >> 32) & 0xFFFF)
        if self.flags & C.EXT4_HUGE_FILE_FL:
            self.flags &= ~C.EXT4_HUGE_FILE_FL
            struct.pack_into("<I", self.raw, 0x20, self.flags)

    def set_owned_blocks(self, data_blocks: int, block_size: int) -> None:
        # i_blocks also counts the external xattr block (i_file_acl).
        self.set_blocks(data_blocks + (1 if self.file_acl else 0), block_size)

    def set_flags(self, flags: int) -> None:
        self.flags = flags
        struct.pack_into("<I", self.raw, 0x20, flags)

    def set_mode(self, mode: int) -> None:
        self.mode = mode
        struct.pack_into("<H", self.raw, 0x00, mode)

    def set_owner(self, uid: int, gid: int) -> None:
        uid = int(uid) & 0xFFFFFFFF
        gid = int(gid) & 0xFFFFFFFF
        self.uid = uid
        self.gid = gid
        struct.pack_into("<H", self.raw, 0x02, uid & 0xFFFF)
        struct.pack_into("<H", self.raw, 0x18, gid & 0xFFFF)
        if len(self.raw) >= 0x7C:
            struct.pack_into("<H", self.raw, 0x78, (uid >> 16) & 0xFFFF)
            struct.pack_into("<H", self.raw, 0x7A, (gid >> 16) & 0xFFFF)

    def apply_checksum(self, sb: Superblock) -> None:
        apply_inode_checksum(sb, self)

    def mode_str(self) -> str:
        return stat.filemode(self.mode)

    def type_label(self) -> str:
        if self.is_dir:
            return "폴더"
        if self.is_lnk:
            return "바로가기"
        if stat.S_ISCHR(self.mode):
            return "문자 장치"
        if stat.S_ISBLK(self.mode):
            return "블록 장치"
        if stat.S_ISFIFO(self.mode):
            return "FIFO"
        if stat.S_ISSOCK(self.mode):
            return "소켓"
        return "파일"


# Linux EXT4_INODE_CSUM_HI_EXTRA_END: i_checksum_hi ends 4 bytes into the
# extra area, so it exists only when i_extra_isize >= 4.
_CSUM_HI_EXTRA_END = 4


def encode_time(ts: float | int | None) -> tuple[int, int, int]:
    """Linux ext4_encode_extra_time(): (low 32 bits, epoch|ns<<2, seconds)."""
    if ts is None:
        ns_total = time.time_ns()
    elif isinstance(ts, int):
        ns_total = ts * 1_000_000_000
    else:
        ns_total = int(round(float(ts) * 1_000_000_000))
    sec, nsec = divmod(ns_total, 1_000_000_000)
    # Representable range is 1901-12-13 .. 2446-05-10.
    if sec < -0x80000000:
        sec, nsec = -0x80000000, 0
    elif sec > 0x37FFFFFFF:
        sec, nsec = 0x37FFFFFFF, 999_999_999
    epoch = ((sec + 0x80000000) >> 32) & 3
    return sec & 0xFFFFFFFF, epoch | (nsec << 2), sec


def apply_inode_checksum(sb: Superblock, inode: Inode) -> None:
    if not sb.has_metadata_csum:
        return
    raw = inode.raw
    struct.pack_into("<H", raw, 0x7C, 0)
    if inode.extra_isize >= _CSUM_HI_EXTRA_END and len(raw) >= 0x84:
        struct.pack_into("<H", raw, 0x82, 0)
    crc = crc32c(sb.csum_seed(), struct.pack("<I", inode.ino))
    crc = crc32c(crc, struct.pack("<I", inode.generation))
    crc = crc32c(crc, raw)
    struct.pack_into("<H", raw, 0x7C, crc & 0xFFFF)
    if inode.extra_isize >= _CSUM_HI_EXTRA_END and len(raw) >= 0x84:
        struct.pack_into("<H", raw, 0x82, (crc >> 16) & 0xFFFF)




def inode_checksum_valid(sb: Superblock, inode: Inode) -> bool:
    if not sb.has_metadata_csum:
        return True
    raw = bytearray(inode.raw)
    stored_lo = _u16(raw, 0x7C) if len(raw) >= 0x7E else 0
    stored_hi = (
        _u16(raw, 0x82)
        if inode.extra_isize >= _CSUM_HI_EXTRA_END and len(raw) >= 0x84
        else None
    )
    struct.pack_into("<H", raw, 0x7C, 0)
    if stored_hi is not None:
        struct.pack_into("<H", raw, 0x82, 0)
    crc = crc32c(sb.csum_seed(), struct.pack("<I", inode.ino))
    crc = crc32c(crc, struct.pack("<I", inode.generation))
    crc = crc32c(crc, raw)
    if stored_lo != (crc & 0xFFFF):
        return False
    if stored_hi is not None and stored_hi != ((crc >> 16) & 0xFFFF):
        return False
    return True

def parse_inode(sb: Superblock, ino: int, raw: bytes) -> Inode:
    size = max(int(sb.inode_size or 128), 128)
    buf = bytearray(raw[:size].ljust(size, b"\x00"))
    mode = _u16(buf, 0x00)
    uid = _u16(buf, 0x02)
    gid = _u16(buf, 0x18)
    if len(buf) >= 0x7C:
        uid |= _u16(buf, 0x78) << 16
        gid |= _u16(buf, 0x7A) << 16
    fsize = _u32(buf, 0x04)
    if len(buf) >= 0x70:
        fsize |= _u32(buf, 0x6C) << 32
    flags = _u32(buf, 0x20)
    blocks = _u32(buf, 0x1C)
    if (
        len(buf) >= 0x76
        and sb.feature_ro_compat & C.EXT4_FEATURE_RO_COMPAT_HUGE_FILE
    ):
        blocks |= _u16(buf, 0x74) << 32
        if flags & C.EXT4_HUGE_FILE_FL:
            blocks *= sb.block_size // 512
    extra = _u16(buf, 0x80) if len(buf) >= 0x82 else 0
    crtime = _u32(buf, 0x90) if extra >= 24 and len(buf) >= 0x94 else 0
    file_acl = _u32(buf, 0x68) if len(buf) >= 0x6C else 0
    if len(buf) >= 0x78:
        file_acl |= _u16(buf, 0x76) << 32
    return Inode(
        ino=ino,
        raw=buf,
        mode=mode,
        uid=uid,
        gid=gid,
        size=fsize,
        atime=_u32(buf, 0x08),
        ctime=_u32(buf, 0x0C),
        mtime=_u32(buf, 0x10),
        dtime=_u32(buf, 0x14),
        links=_u16(buf, 0x1A),
        blocks=blocks,
        flags=flags,
        generation=_u32(buf, 0x64) if len(buf) >= 0x68 else 0,
        extra_isize=extra,
        crtime=crtime,
        file_acl=file_acl,
    )


def new_inode_raw(sb: Superblock, ino: int, mode: int, uid: int = 0, gid: int = 0) -> Inode:
    raw = bytearray(sb.inode_size)
    extra = min(sb.want_extra_isize, sb.inode_size - 128)
    now_lo, now_extra, _ = encode_time(None)
    struct.pack_into("<H", raw, 0x00, mode)
    struct.pack_into("<H", raw, 0x02, uid & 0xFFFF)
    struct.pack_into("<H", raw, 0x18, gid & 0xFFFF)
    struct.pack_into("<H", raw, 0x78, (uid >> 16) & 0xFFFF)
    struct.pack_into("<H", raw, 0x7A, (gid >> 16) & 0xFFFF)
    struct.pack_into("<I", raw, 0x08, now_lo)
    struct.pack_into("<I", raw, 0x0C, now_lo)
    struct.pack_into("<I", raw, 0x10, now_lo)
    struct.pack_into("<H", raw, 0x1A, 1)
    flags = C.EXT4_EXTENTS_FL
    struct.pack_into("<I", raw, 0x20, flags)
    gen = int.from_bytes(os.urandom(4), "little") or 1
    struct.pack_into("<I", raw, 0x64, gen)
    if extra:
        struct.pack_into("<H", raw, 0x80, extra)
        # *_extra words hold nanoseconds + epoch bits; 0x90 is i_crtime.
        for off in (0x84, 0x88, 0x8C, 0x90, 0x94):
            if extra >= off + 4 - C.EXT4_GOOD_OLD_INODE_SIZE:
                struct.pack_into("<I", raw, off, now_lo if off == 0x90 else now_extra)
    inode = parse_inode(sb, ino, raw)
    # empty extent header
    hdr = struct.pack("<HHHHI", C.EXT4_EXT_MAGIC, 0, 4, 0, 0)
    inode.raw[0x28:0x28 + 12] = hdr
    inode.raw[0x34:0x64] = b"\x00" * (60 - 12)
    inode.flags = flags
    return inode


def file_type_from_mode(mode: int) -> int:
    if stat.S_ISREG(mode):
        return C.EXT4_FT_REG_FILE
    if stat.S_ISDIR(mode):
        return C.EXT4_FT_DIR
    if stat.S_ISLNK(mode):
        return C.EXT4_FT_SYMLINK
    if stat.S_ISCHR(mode):
        return C.EXT4_FT_CHRDEV
    if stat.S_ISBLK(mode):
        return C.EXT4_FT_BLKDEV
    if stat.S_ISFIFO(mode):
        return C.EXT4_FT_FIFO
    if stat.S_ISSOCK(mode):
        return C.EXT4_FT_SOCK
    return C.EXT4_FT_UNKNOWN
