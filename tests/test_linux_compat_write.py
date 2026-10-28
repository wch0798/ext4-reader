"""Write-path rules a Linux (Steam Deck) mount and e2fsck depend on.

Runs on Windows without mkfs.ext4: each case drives one helper with a small
stub volume.
"""

import struct
import unittest
from types import SimpleNamespace

from ext4lib.fs import constants as C
from ext4lib.fs.bitmap import _init_block_bitmap
from ext4lib.fs.directory import DirError, _dx_hash_version
from ext4lib.fs.hashdir import dirhash
from ext4lib.fs.superblock import Superblock
from ext4lib.fs.volume import Ext4Volume
from ext4lib.fs.writer import _dec_dir_links, _inc_dir_links
from tests.ext4_fsck import INDEX_FL, RO_DIR_NLINK, pass4_dir_link_errors


def _sb_raw(s_flags: int) -> bytearray:
    raw = bytearray(1024)
    struct.pack_into("<I", raw, 0x160, s_flags)
    return raw


class HashSignednessTests(unittest.TestCase):
    def test_superblock_reads_unsigned_hash_flag(self):
        fget = Superblock.hash_unsigned.fget
        self.assertTrue(fget(SimpleNamespace(raw=_sb_raw(C.EXT2_FLAGS_UNSIGNED_HASH))))
        self.assertFalse(fget(SimpleNamespace(raw=_sb_raw(C.EXT2_FLAGS_SIGNED_HASH))))

    def test_root_version_follows_superblock_flag(self):
        root = bytearray(64)
        root[28] = C.DX_HASH_HALF_MD4
        unsigned = SimpleNamespace(sb=SimpleNamespace(hash_unsigned=True))
        signed = SimpleNamespace(sb=SimpleNamespace(hash_unsigned=False))
        self.assertEqual(_dx_hash_version(unsigned, root), C.DX_HASH_HALF_MD4_UNSIGNED)
        self.assertEqual(_dx_hash_version(signed, root), C.DX_HASH_HALF_MD4)

    def test_non_ascii_name_hash_depends_on_signedness(self):
        # Why the flag matters: Korean names hash to a different leaf.
        name = "세이브데이터.sav".encode("utf-8")
        seed = bytes(range(1, 17))
        self.assertNotEqual(
            dirhash(name, C.DX_HASH_HALF_MD4, seed),
            dirhash(name, C.DX_HASH_HALF_MD4_UNSIGNED, seed),
        )


class UninitBlockBitmapTests(unittest.TestCase):
    def test_backup_group_reserves_reserved_gdt_blocks(self):
        sb = SimpleNamespace(
            block_size=4096,
            blocks_per_group=32768,
            blocks_count=4 * 32768,
            first_data_block=0,
            groups_count=4,
            desc_size=64,
            reserved_gdt_blocks=255,
            inodes_per_group=8192,
            inode_size=256,
            feature_ro_compat=C.EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER,
        )
        # flex_bg: group 1 bitmaps and inode table live in group 0.
        gd = SimpleNamespace(
            group=1, block_bitmap=100, inode_bitmap=200, inode_table=300,
            flags=C.BG_BLOCK_UNINIT,
        )
        bm = _init_block_bitmap(SimpleNamespace(sb=sb), gd)
        # backup super + 1 GDT block + 255 reserved GDT blocks
        for bit in range(0, 1 + 1 + 255):
            self.assertTrue(bm.test(bit), bit)
        self.assertFalse(bm.test(257))
        self.assertFalse(gd.flags & C.BG_BLOCK_UNINIT)


class WriteBlockerTests(unittest.TestCase):
    def _vol(self, ro_compat: int):
        sb = SimpleNamespace(
            feature_incompat=C.EXT4_FEATURE_INCOMPAT_EXTENTS | C.EXT4_FEATURE_INCOMPAT_FILETYPE,
            feature_ro_compat=ro_compat,
            state=C.EXT4_VALID_FS,
            last_orphan=0,
            has_extents=True,
        )
        return SimpleNamespace(sb=sb, journal_needs_recovery=lambda: False)

    def test_supported_ro_compat_allows_write(self):
        ro = (
            C.EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER
            | C.EXT4_FEATURE_RO_COMPAT_LARGE_FILE
            | C.EXT4_FEATURE_RO_COMPAT_HUGE_FILE
            | C.EXT4_FEATURE_RO_COMPAT_DIR_NLINK
            | C.EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE
            | C.EXT4_FEATURE_RO_COMPAT_METADATA_CSUM
        )
        self.assertEqual(Ext4Volume.hard_write_blockers(self._vol(ro)), [])

    def test_quota_blocks_write(self):
        ro = C.EXT4_FEATURE_RO_COMPAT_METADATA_CSUM | C.EXT4_FEATURE_RO_COMPAT_QUOTA
        reasons = Ext4Volume.hard_write_blockers(self._vol(ro))
        self.assertTrue(any("ro_compat" in r for r in reasons), reasons)


class _Parent:
    def __init__(self, links, flags=0):
        self.links = links
        self.flags = flags

    def set_links(self, n):
        self.links = n


class DirNlinkTests(unittest.TestCase):
    def _vol(self, dir_nlink: bool, dir_index: bool = False):
        ro = C.EXT4_FEATURE_RO_COMPAT_DIR_NLINK if dir_nlink else 0
        compat = C.EXT4_FEATURE_COMPAT_DIR_INDEX if dir_index else 0
        return SimpleNamespace(
            sb=SimpleNamespace(feature_ro_compat=ro, feature_compat=compat)
        )

    def test_normal_increment(self):
        p = _Parent(2)
        _inc_dir_links(self._vol(True), p)
        self.assertEqual(p.links, 3)

    def test_exact_link_max_stays(self):
        # 64998 subdirectories: i_links_count becomes 65000 and Linux keeps it.
        # The following subdirectory (64999) is the first one stored as 1.
        p = _Parent(C.EXT4_LINK_MAX - 1, flags=C.EXT4_INDEX_FL)
        _inc_dir_links(self._vol(True, True), p)
        self.assertEqual(p.links, C.EXT4_LINK_MAX)
        p = _Parent(C.EXT4_LINK_MAX - 1)
        _inc_dir_links(self._vol(True), p)
        self.assertEqual(p.links, C.EXT4_LINK_MAX)

    def test_indexed_past_limit_becomes_one(self):
        p = _Parent(C.EXT4_LINK_MAX, flags=C.EXT4_INDEX_FL)
        vol = self._vol(True, True)
        _inc_dir_links(vol, p)
        self.assertEqual(p.links, 1)
        _inc_dir_links(vol, p)
        self.assertEqual(p.links, 1)

    def test_nonindexed_at_limit_is_refused_even_with_dir_nlink(self):
        with self.assertRaises(DirError):
            _inc_dir_links(self._vol(True), _Parent(C.EXT4_LINK_MAX))

    def test_overflow_without_dir_nlink_is_refused(self):
        p = _Parent(C.EXT4_LINK_MAX - 1)
        vol = self._vol(False)
        _inc_dir_links(vol, p)
        self.assertEqual(p.links, C.EXT4_LINK_MAX)
        self.assertEqual(vol.sb.feature_ro_compat, 0)
        with self.assertRaises(DirError):
            _inc_dir_links(self._vol(False), _Parent(C.EXT4_LINK_MAX))

    def test_indexed_without_dir_nlink_emlink_at_link_max(self):
        # Feature still off: the increment that lands on 65000 is allowed,
        # and the next one is EMLINK. The feature is not turned on here
        # because the count is not the sentinel.
        p = _Parent(C.EXT4_LINK_MAX - 1, flags=C.EXT4_INDEX_FL)
        vol = self._vol(False, True)
        _inc_dir_links(vol, p)
        self.assertEqual(p.links, C.EXT4_LINK_MAX)
        self.assertEqual(vol.sb.feature_ro_compat, 0)
        with self.assertRaises(DirError):
            _inc_dir_links(vol, p)

    def test_sentinel_enables_dir_nlink(self):
        p = _Parent(1, flags=C.EXT4_INDEX_FL)
        vol = self._vol(False, True)
        _inc_dir_links(vol, p)
        self.assertEqual(p.links, 1)
        self.assertTrue(vol.sb.feature_ro_compat & C.EXT4_FEATURE_RO_COMPAT_DIR_NLINK)

    def test_dec_count_leaves_one_and_two(self):
        # ext4_dec_count(): directories drop nlink only when it is above 2.
        p = _Parent(4)
        _dec_dir_links(p)
        self.assertEqual(p.links, 3)
        _dec_dir_links(p)
        self.assertEqual(p.links, 2)
        _dec_dir_links(p)
        self.assertEqual(p.links, 2)
        p = _Parent(1)
        _dec_dir_links(p)
        self.assertEqual(p.links, 1)

    def test_subdir_boundaries_and_delete_below_limit(self):
        # Directory entries are packed directly (no mkdir, no inodes) and each
        # subdirectory applies ext4_inc_count. 64998 subdirectories stay at
        # 65000; 64999, 65000 and 65001 are the sentinel 1. Deleting back
        # under the limit does not clear that 1.
        parent = _Parent(2, flags=C.EXT4_INDEX_FL)
        vol = self._vol(True, True)
        rec = 16
        want = {
            64998: C.EXT4_LINK_MAX,
            64999: 1,
            65000: 1,
            65001: 1,
        }
        seen = {}
        for i in range(65001):
            name = f"{i:05d}".encode()
            raw = bytearray(rec)
            struct.pack_into("<IHBB", raw, 0, 100, rec, len(name), C.EXT4_FT_DIR)
            raw[8 : 8 + len(name)] = name
            if i in (0, 64999, 65000):
                self.assertEqual(raw[7], C.EXT4_FT_DIR)
                self.assertEqual(raw[8 : 8 + len(name)], name)
            _inc_dir_links(vol, parent)
            n = i + 1
            if n in want:
                seen[n] = parent.links
        self.assertEqual(seen, want)
        # 65001 -> 64998 is back at the exact limit (counted links == 65000);
        # one more removal is under it. The stored count stays 1.
        for _ in range(65001 - 64998):
            _dec_dir_links(parent)
        self.assertEqual(parent.links, 1)
        _dec_dir_links(parent)
        self.assertEqual(parent.links, 1)


class Pass4LinkCountTests(unittest.TestCase):
    def test_above_limit_must_be_one(self):
        # 65000 subdirectories: counted links are 65002, stored value is 1.
        self.assertEqual(
            pass4_dir_link_errors(12, 1, 2 + 65000, INDEX_FL, RO_DIR_NLINK),
            [],
        )
        self.assertEqual(
            pass4_dir_link_errors(12, 65002, 2 + 65000, INDEX_FL, RO_DIR_NLINK),
            ["dir 12: i_links_count 65002 should be 1"],
        )

    def test_exact_limit_is_not_collapsed(self):
        # 64998 subdirectories: counted links are exactly 65000.
        self.assertEqual(
            pass4_dir_link_errors(12, 65000, 65000, INDEX_FL, RO_DIR_NLINK),
            [],
        )
        self.assertTrue(
            pass4_dir_link_errors(12, 1, 65000, INDEX_FL, RO_DIR_NLINK)
        )

    def test_missing_dir_nlink_and_cleared_overflow(self):
        missing = pass4_dir_link_errors(12, 1, 65001, INDEX_FL, 0)
        self.assertEqual(len(missing), 1)
        self.assertIn("DIR_NLINK", missing[0])
        # Real count fits again, but the inode is still the sentinel.
        cleared = pass4_dir_link_errors(12, 1, 100, INDEX_FL, RO_DIR_NLINK)
        self.assertEqual(
            cleared, ["dir 12: i_links_count is 1 but counted links are 100"]
        )


if __name__ == "__main__":
    unittest.main()
