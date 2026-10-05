import struct
import unittest

from ext4lib.fs import constants as C
from ext4lib.fs.superblock import parse_superblock


class SuperblockLayoutTests(unittest.TestCase):
    def _raw(self):
        raw = bytearray(1024)
        struct.pack_into("<I", raw, 0x00, 1024)  # inodes
        struct.pack_into("<I", raw, 0x04, 8192)  # blocks
        struct.pack_into("<I", raw, 0x0C, 4096)
        struct.pack_into("<I", raw, 0x10, 512)
        struct.pack_into("<I", raw, 0x14, 0)
        struct.pack_into("<I", raw, 0x18, 2)  # 4096-byte blocks
        struct.pack_into("<I", raw, 0x20, 8192)
        struct.pack_into("<I", raw, 0x28, 1024)
        struct.pack_into("<H", raw, 0x38, C.EXT4_SUPER_MAGIC)
        struct.pack_into("<H", raw, 0x3A, C.EXT4_VALID_FS)
        struct.pack_into("<I", raw, 0x5C, C.EXT4_FEATURE_COMPAT_DIR_INDEX | C.EXT4_FEATURE_COMPAT_ORPHAN_FILE)
        struct.pack_into("<I", raw, 0x60, C.EXT4_FEATURE_INCOMPAT_EXTENTS)
        struct.pack_into("<I", raw, 0x64, C.EXT4_FEATURE_RO_COMPAT_METADATA_CSUM)
        struct.pack_into("<H", raw, 0x58, 256)
        struct.pack_into("<I", raw, 0xE8, 0x11223344)
        raw[0xEC:0xFC] = bytes.fromhex("00112233445566778899aabbccddeeff")
        raw[0xFC] = C.DX_HASH_HALF_MD4
        struct.pack_into("<H", raw, 0xFE, 64)
        struct.pack_into("<I", raw, 0x100, 0xA1B2C3D4)
        struct.pack_into("<I", raw, 0x280, 1234)
        return raw

    def test_hash_seed_starts_after_last_orphan(self):
        sb = parse_superblock(self._raw())
        self.assertEqual(sb.last_orphan, 0x11223344)
        self.assertEqual(
            sb.hash_seed,
            bytes.fromhex("00112233445566778899aabbccddeeff"),
        )
        self.assertEqual(sb.orphan_file_inum, 1234)
        self.assertEqual(sb.def_hash_version, C.DX_HASH_HALF_MD4)
        self.assertEqual(sb.default_mount_opts, 0xA1B2C3D4)


    def test_update_counts_rejects_negative_free_blocks(self):
        sb = parse_superblock(self._raw())
        sb.free_blocks_count = -1
        with self.assertRaisesRegex(ValueError, "invalid EXT4 free block count"):
            sb.update_counts()

    def test_update_counts_rejects_free_blocks_above_total(self):
        sb = parse_superblock(self._raw())
        sb.free_blocks_count = sb.blocks_count + 1
        with self.assertRaisesRegex(ValueError, "invalid EXT4 free block count"):
            sb.update_counts()


    def test_update_counts_preserves_64bit_total_and_writes_free_hi(self):
        raw = self._raw()
        struct.pack_into("<I", raw, 0x60, C.EXT4_FEATURE_INCOMPAT_EXTENTS | C.EXT4_FEATURE_INCOMPAT_64BIT)
        struct.pack_into("<I", raw, 0x04, 0x12345678)
        struct.pack_into("<I", raw, 0x150, 0x00000001)
        struct.pack_into("<I", raw, 0x0C, 0x89ABCDEF)
        struct.pack_into("<I", raw, 0x154, 0x00000002)

        sb = parse_superblock(raw)
        total_before = sb.blocks_count
        sb.free_blocks_count = 0x00000003FEDCBA98
        sb.update_counts()

        self.assertEqual(struct.unpack_from("<I", sb.raw, 0x150)[0], 0x00000001)
        self.assertEqual(struct.unpack_from("<I", sb.raw, 0x154)[0], 0x00000003)
        reparsed = parse_superblock(bytes(sb.raw))
        self.assertEqual(reparsed.blocks_count, total_before)
        self.assertEqual(reparsed.free_blocks_count, 0x00000003FEDCBA98)


if __name__ == "__main__":
    unittest.main()
