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


if __name__ == "__main__":
    unittest.main()
