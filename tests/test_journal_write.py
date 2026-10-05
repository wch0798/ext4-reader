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
    JournalWriter,
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


class JournalSequenceTests(unittest.TestCase):
    def test_clean_journal_persists_next_unused_transaction_sequence(self):
        class FakeLog:
            def __init__(self):
                self.calls = []

            def mark_clean(self, sequence, head=None):
                self.calls.append((sequence, head))

        class FakeDevice:
            def __init__(self):
                self.flushes = 0

            def flush(self):
                self.flushes += 1

        writer = JournalWriter.__new__(JournalWriter)
        writer.log = FakeLog()
        writer.vol = SimpleNamespace(
            sb=SimpleNamespace(needs_recovery=True),
            dev=FakeDevice(),
            _data_dirty=True,
        )
        writer.head = 17
        writer.last_sequence = 41
        writer.sequence = 42
        writer.committed = True

        writer.mark_clean()

        self.assertEqual(writer.log.calls, [(42, 17)])
        self.assertEqual(writer.vol.dev.flushes, 1)
        self.assertFalse(writer.vol._data_dirty)
        self.assertFalse(writer.committed)


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


class DeferredBlockFreeTests(unittest.TestCase):
    def test_journaled_free_is_not_reusable_before_sync_commit(self):
        from ext4lib.fs.bitmap import (
            AllocError,
            Bitmap,
            alloc_blocks,
            apply_pending_block_frees,
            free_phys_runs,
        )
        from ext4lib.fs.superblock import GroupDesc

        # One tiny group with every block allocated. Block 5 is freed while a
        # JBD2 transaction is open; it must remain unavailable to allocation
        # until the pending free is folded into the transaction at sync time.
        gd = GroupDesc(
            group=0,
            block_bitmap=1,
            inode_bitmap=2,
            inode_table=3,
            free_blocks=0,
            free_inodes=0,
            used_dirs=0,
            flags=0,
            itable_unused=0,
            raw=bytearray(32),
        )
        sb = SimpleNamespace(
            groups_count=1,
            first_data_block=0,
            blocks_per_group=8,
            blocks_count=8,
            free_blocks_count=0,
            block_size=1024,
            has_metadata_csum=False,
            has_64bit=False,
            desc_size=32,
            has_gdt_csum=False,
        )
        bm = Bitmap(bytearray([0xFF]), 8)
        vol = SimpleNamespace(
            sb=sb,
            groups=[gd],
            _block_bm_cache={0: bm},
            _dirty_block_bm=set(),
            _alloc_hint={},
            dirty_groups=set(),
            dirty_super=False,
            _journal_writer=object(),
            _pending_block_frees=[],
        )

        free_phys_runs(vol, [(5, 1)])
        self.assertTrue(bm.test(5))
        self.assertEqual(gd.free_blocks, 0)
        self.assertEqual(vol._pending_block_frees, [(5, 1)])
        with self.assertRaises(AllocError):
            alloc_blocks(vol, 1)

        apply_pending_block_frees(vol)
        self.assertFalse(bm.test(5))
        self.assertEqual(gd.free_blocks, 1)
        self.assertEqual(vol._pending_block_frees, [])
        self.assertEqual(alloc_blocks(vol, 1), [5])


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


class FreeCountReconcileTests(unittest.TestCase):
    def test_commit_reconciles_group_and_super_free_counts_from_bitmap(self):
        from ext4lib.fs.bitmap import Bitmap
        from ext4lib.fs.superblock import GroupDesc

        vol = Ext4Volume.__new__(Ext4Volume)
        gd = GroupDesc(
            group=0, block_bitmap=1, inode_bitmap=2, inode_table=3,
            free_blocks=16, free_inodes=0, used_dirs=0, flags=0,
            itable_unused=0, raw=bytearray(32),
        )
        # 8 real blocks; bits 0..3 allocated and 4..7 free => 4 free.
        bm = Bitmap(bytearray([0x0F]), 8)
        sb = SimpleNamespace(
            block_size=1024, blocks_count=8, first_data_block=0,
            blocks_per_group=8, desc_size=32, free_blocks_count=16,
            free_inodes_count=0, has_64bit=False, has_metadata_csum=False,
            has_gdt_csum=False,
            update_counts=lambda: None, write_checksum=lambda: None,
            raw=bytearray(1024),
        )
        vol.sb = sb
        vol.groups = [gd]
        vol._block_bm_cache = {0: bm}
        vol._inode_bm_cache = {}
        vol._dirty_block_bm = {0}
        vol._dirty_inode_bm = set()
        vol.dirty_groups = {0}
        vol.dirty_super = True
        vol._journal_writer = None
        vol._pending_block_frees = []
        vol._metadata_overlay = {}
        vol._data_dirty = False
        vol.write_metadata_block = lambda *args: None
        vol.write_metadata_bytes = lambda *args: None

        vol.commit_metadata(sync=False)

        self.assertEqual(gd.free_blocks, 4)
        self.assertEqual(vol.sb.free_blocks_count, 4)

if __name__ == "__main__":
    unittest.main()
