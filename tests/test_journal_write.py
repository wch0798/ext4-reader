import struct
import unittest
from collections import OrderedDict
from types import SimpleNamespace

from ext4lib.fs import constants as C
from ext4lib.fs.crc32c import crc32c
from ext4lib.fs.journal import (
    JBD2_FEATURE_INCOMPAT_64BIT,
    JBD2_FEATURE_INCOMPAT_CSUM_V3,
    JBD2_FLAG_ESCAPE,
    JBD2_FLAG_LAST_TAG,
    JBD2_CRC32C_CHKSUM,
    JournalInfo,
    _JournalLog,
)
from ext4lib.fs.volume import Ext4Volume


class JournalCodecTests(unittest.TestCase):
    def _log(self):
        log = _JournalLog.__new__(_JournalLog)
        log.fs_block_size = 1024
        log.info = JournalInfo(
            block_size=1024,
            maxlen=1024,
            first=1,
            sequence=7,
            start=0,
            feature_compat=0,
            feature_incompat=JBD2_FEATURE_INCOMPAT_64BIT | JBD2_FEATURE_INCOMPAT_CSUM_V3,
            feature_ro_compat=0,
            uuid=bytes(range(16)),
            checksum_type=JBD2_CRC32C_CHKSUM,
            nr_users=1,
        )
        log.csum_seed = crc32c(0xFFFFFFFF, log.info.uuid)
        return log

    def test_descriptor_roundtrip_with_escape_and_checksum(self):
        log = self._log()
        source = bytearray(b"x" * log.fs_block_size)
        struct.pack_into(">I", source, 0, C.JBD2_MAGIC_NUMBER)

        descriptor, stored = log.build_descriptor(
            sequence=8,
            target_block=0x1_00000012,
            block=bytes(source),
        )

        self.assertEqual(struct.unpack_from(">I", stored, 0)[0], 0)
        tags = log.parse_descriptor(descriptor)
        self.assertEqual(len(tags), 1)
        target, flags, checksum = tags[0]
        self.assertEqual(target, 0x1_00000012)
        self.assertTrue(flags & JBD2_FLAG_ESCAPE)
        self.assertTrue(flags & JBD2_FLAG_LAST_TAG)
        log.verify_data_checksum(8, stored, checksum)

    def test_commit_block_verifies_with_recovery_codec(self):
        log = self._log()
        commit = log.build_commit(9)
        self.assertEqual(
            struct.unpack_from(">III", commit, 0),
            (C.JBD2_MAGIC_NUMBER, 2, 9),
        )
        log._verify_commit_checksum(commit)


class MemoryDevice:
    writable = True

    def __init__(self, size=64 * 1024):
        self.data = bytearray(size)
        self.writes = []
        self.flushes = 0

    def read(self, offset, length):
        return bytes(self.data[offset : offset + length])

    def write(self, offset, data):
        blob = bytes(data)
        self.data[offset : offset + len(blob)] = blob
        self.writes.append((offset, blob))

    def flush(self):
        self.flushes += 1


class MetadataOverlayTests(unittest.TestCase):
    def _volume(self):
        vol = Ext4Volume.__new__(Ext4Volume)
        vol.dev = MemoryDevice()
        vol.part_offset = 0
        vol.sb = SimpleNamespace(block_size=1024, blocks_count=64)
        vol._metadata_overlay = {}
        vol._journal_writer = object()
        vol._block_cache = OrderedDict()
        vol._block_cache_cap = 16
        vol._data_dirty = False
        return vol

    def test_metadata_is_visible_before_checkpoint_but_not_written_home(self):
        vol = self._volume()
        home = 3 * 1024
        vol.dev.data[home : home + 1024] = b"a" * 1024

        vol.write_metadata_block(3, b"b" * 1024)

        self.assertEqual(vol.dev.data[home : home + 1024], b"a" * 1024)
        self.assertEqual(vol.read_bytes(home, 1024), b"b" * 1024)
        self.assertEqual(vol.dev.writes, [])

        snapshot = {3: bytes(vol._metadata_overlay[3])}
        vol._checkpoint_metadata_blocks(snapshot)
        self.assertEqual(vol.dev.data[home : home + 1024], b"b" * 1024)
        self.assertTrue(vol._data_dirty)

    def test_partial_metadata_overlay_preserves_surrounding_home_bytes(self):
        vol = self._volume()
        home = 5 * 1024
        vol.dev.data[home : home + 1024] = bytes(range(256)) * 4

        vol.write_metadata_bytes(home + 100, b"JBD2")

        result = vol.read_bytes(home + 96, 16)
        self.assertEqual(result[4:8], b"JBD2")
        self.assertEqual(vol.dev.writes, [])



    def test_64bit_bitmap_checksum_high_words_use_linux_offsets(self):
        from ext4lib.fs.bitmap import Bitmap, apply_bitmap_csum
        from ext4lib.fs.superblock import GroupDesc

        raw = bytearray(64)
        # Sentinel: exclude_bitmap_hi must not be clobbered by checksum writes.
        raw[0x34:0x38] = b"EXCL"
        gd = GroupDesc(
            group=0,
            block_bitmap=1,
            inode_bitmap=2,
            inode_table=3,
            free_blocks=10,
            free_inodes=10,
            used_dirs=1,
            flags=0,
            itable_unused=0,
            raw=raw,
        )
        sb = SimpleNamespace(
            has_metadata_csum=True,
            desc_size=64,
            blocks_per_group=32768,
            inodes_per_group=32768,
            csum_seed=lambda: 0x12345678,
            has_64bit=True,
            has_gdt_csum=False,
        )
        vol = SimpleNamespace(sb=sb)
        bm = Bitmap(bytearray(4096), 32768)

        apply_bitmap_csum(vol, gd, "block", bm)
        self.assertEqual(gd.raw[0x34:0x38], b"EXCL")
        self.assertNotEqual(gd.raw[0x38:0x3A], b"\x00\x00")

if __name__ == "__main__":
    unittest.main()
