"""Regression tests for write-path bugs found in the full write-path review.

Each case runs on a Steam Deck style image (tests/ext4_image_fixture.py) and
checks it with tests/ext4_fsck.py, so no WSL, mkfs or e2fsck is needed.
"""

from __future__ import annotations

import os
import shutil
import struct
import tempfile
import unittest
from types import SimpleNamespace

from ext4lib.fs import constants as C
from ext4lib.fs.bitmap import AllocError, group_block_range, read_block_bitmap
from ext4lib.fs.superblock import _gdt_csum_old, crc16
from ext4lib.fs.volume import Ext4Volume
from ext4lib.fs.writer import (
    create_empty_file,
    create_file,
    lookup_path,
    mkdir,
    read_range,
    set_file_size,
    write_range,
)
from ext4lib.io.backend import ImageDevice
from tests.ext4_fsck import check_image
from tests.ext4_image_fixture import make_steamdeck_image


def _open(path: str, writable: bool) -> Ext4Volume:
    return Ext4Volume(ImageDevice(path, writable=writable), 0, os.path.getsize(path), owns_device=True)


class _ImageCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ext4wi-")
        self.img = os.path.join(self.tmp, "sd.img")
        make_steamdeck_image(self.img)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def assertClean(self):
        errors, stats = check_image(self.img)
        self.assertEqual(errors, [], f"fsck: {stats}")


class EnospcRollbackTests(_ImageCase):
    """A copy that runs out of space must not leak inode or block bits."""

    def test_create_file_enospc_leaves_counts_and_bitmaps_clean(self):
        vol = _open(self.img, True)
        try:
            free_blocks = vol.sb.free_blocks_count
            free_inodes = vol.sb.free_inodes_count
            src = os.path.join(self.tmp, "too-big.bin")
            with open(src, "wb") as fp:
                fp.truncate((free_blocks + 16) * vol.sb.block_size)
            with self.assertRaises(AllocError):
                create_file(vol, lookup_path(vol, "/"), "too-big.bin", src)
            vol.flush_metadata()
            self.assertEqual(vol.sb.free_blocks_count, free_blocks)
            self.assertEqual(vol.sb.free_inodes_count, free_inodes)
        finally:
            vol.close()
        self.assertClean()

    def test_write_range_enospc_frees_blocks_of_earlier_holes(self):
        vol = _open(self.img, True)
        try:
            bs = vol.sb.block_size
            node = create_empty_file(vol, lookup_path(vol, "/"), "holes.bin")
            # lblk 1 mapped, so the big write below fills hole 0 first and
            # only then fails on the hole from lblk 2.
            write_range(vol, node, bs, b"x", flush=True)
            free_blocks = vol.sb.free_blocks_count
            node = lookup_path(vol, "/holes.bin")
            with self.assertRaises(AllocError):
                write_range(vol, node, 0, bytes((free_blocks + 16) * bs))
            vol.flush_metadata()
            self.assertEqual(vol.sb.free_blocks_count, free_blocks)
            self.assertEqual(lookup_path(vol, "/holes.bin").size, bs + 1)
        finally:
            vol.close()
        self.assertClean()

    def test_mkdir_enospc_frees_inode(self):
        vol = _open(self.img, True)
        try:
            # Use up every free block with one file.
            bs = vol.sb.block_size
            filler = create_empty_file(vol, lookup_path(vol, "/"), "filler.bin")
            write_range(vol, filler, 0, bytes(vol.sb.free_blocks_count * bs), flush=True)
            free_inodes = vol.sb.free_inodes_count
            self.assertEqual(vol.sb.free_blocks_count, 0)
            with self.assertRaises(AllocError):
                mkdir(vol, lookup_path(vol, "/"), "no-room")
            vol.flush_metadata()
            self.assertEqual(vol.sb.free_inodes_count, free_inodes)
        finally:
            vol.close()
        self.assertClean()


class StaleDataTests(_ImageCase):
    """Bytes a file never wrote must read back as zeros, as on Linux."""

    def _poison_free_blocks(self):
        vol = _open(self.img, False)
        try:
            bs = vol.sb.block_size
            free = []
            for gd in vol.groups:
                start, end = group_block_range(vol, gd.group)
                bm = read_block_bitmap(vol, gd)
                free.extend(start + bit for bit in range(end - start) if not bm.test(bit))
        finally:
            vol.close()
        with open(self.img, "r+b") as fp:
            for block in free:
                fp.seek(block * bs)
                fp.write(b"\xAA" * bs)

    def test_partial_write_into_new_block_does_not_expose_old_bytes(self):
        self._poison_free_blocks()
        vol = _open(self.img, True)
        try:
            node = create_empty_file(vol, lookup_path(vol, "/"), "a.bin")
            write_range(vol, node, 0, b"0123456789", flush=True)
            write_range(vol, lookup_path(vol, "/a.bin"), 100, b"Z" * 10, flush=True)
            # A write that starts mid-block in a brand new block.
            write_range(vol, lookup_path(vol, "/a.bin"), 5000, b"Q", flush=True)
            node = lookup_path(vol, "/a.bin")
            data = read_range(vol, node, 0, node.size)
            self.assertEqual(data[:10], b"0123456789")
            self.assertEqual(data[10:100], bytes(90))
            self.assertEqual(data[100:110], b"Z" * 10)
            self.assertEqual(data[110:5000], bytes(4890))
            self.assertEqual(data[5000:], b"Q")
        finally:
            vol.close()
        self.assertClean()

    def test_shrink_then_grow_reads_zeros(self):
        vol = _open(self.img, True)
        try:
            node = create_empty_file(vol, lookup_path(vol, "/"), "t.bin")
            write_range(vol, node, 0, b"\xBB" * 8192, flush=True)
            set_file_size(vol, lookup_path(vol, "/t.bin"), 100)
            set_file_size(vol, lookup_path(vol, "/t.bin"), 8192)
            node = lookup_path(vol, "/t.bin")
            data = read_range(vol, node, 0, node.size)
            self.assertEqual(data[:100], b"\xBB" * 100)
            self.assertEqual(data[100:], bytes(8092))

            # Write past EOF inside the EOF block: the gap reads zeros too.
            set_file_size(vol, node, 50)
            write_range(vol, lookup_path(vol, "/t.bin"), 200, b"E", flush=True)
            node = lookup_path(vol, "/t.bin")
            data = read_range(vol, node, 0, node.size)
            self.assertEqual(data[:50], b"\xBB" * 50)
            self.assertEqual(data[50:200], bytes(150))
            self.assertEqual(data[200:], b"E")
        finally:
            vol.close()
        self.assertClean()


class GdtCrc16Tests(unittest.TestCase):
    """gdt_csum without metadata_csum uses Linux crc16 (poly 0x8005, reflected)."""

    def test_crc16_matches_linux_lib_crc16(self):
        # CRC-16/ARC check value: Linux crc16(0, "123456789").
        self.assertEqual(crc16(0, b"123456789"), 0xBB3D)

    def test_group_desc_csum_layout(self):
        uuid = bytes(range(16))
        desc = bytearray(os.urandom(32))
        sb = SimpleNamespace(uuid=uuid, has_64bit=False)
        expected = crc16(crc16(crc16(0xFFFF, uuid), struct.pack("<I", 7)), bytes(desc[:0x1E]))
        self.assertEqual(_gdt_csum_old(sb, 7, desc), expected)
        # bg_checksum is skipped, so its old value does not matter.
        desc[0x1E:0x20] = b"\x12\x34"
        self.assertEqual(_gdt_csum_old(sb, 7, desc), expected)

        desc64 = bytearray(os.urandom(64))
        sb64 = SimpleNamespace(uuid=uuid, has_64bit=True)
        crc = crc16(crc16(crc16(0xFFFF, uuid), struct.pack("<I", 7)), bytes(desc64[:0x1E]))
        self.assertEqual(_gdt_csum_old(sb64, 7, desc64), crc16(crc, bytes(desc64[0x20:])))


class SparseSuper2BlockerTests(unittest.TestCase):
    def test_sparse_super2_blocks_write(self):
        sb = SimpleNamespace(
            feature_compat=C.EXT4_FEATURE_COMPAT_SPARSE_SUPER2,
            feature_incompat=C.EXT4_FEATURE_INCOMPAT_EXTENTS | C.EXT4_FEATURE_INCOMPAT_FILETYPE,
            feature_ro_compat=C.EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER,
            state=C.EXT4_VALID_FS,
            last_orphan=0,
            has_extents=True,
        )
        vol = SimpleNamespace(sb=sb, journal_needs_recovery=lambda: False)
        reasons = Ext4Volume.hard_write_blockers(vol)
        self.assertTrue(any("sparse_super2" in r for r in reasons), reasons)


if __name__ == "__main__":
    unittest.main()
