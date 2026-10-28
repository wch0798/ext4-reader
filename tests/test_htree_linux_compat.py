"""Indexed (HTREE) directories handled like Linux fs/ext4/namei.c and dir.c.

Each class covers one defect found on folders that Linux had already indexed:
depth limit, '..' lookup, equal-hash split, readdir fallback and rollback of
a failed directory grow.
"""

from __future__ import annotations

import os
import shutil
import struct
import tempfile
import unittest
from types import SimpleNamespace

import ext4lib.fs.directory as D
from ext4lib.fs import constants as C
from ext4lib.fs.directory import (
    DirError,
    DxCorrupt,
    _dx_entries,
    _dx_insert_pointer,
    _dx_root_levels,
    _dx_split_point,
    _format_dx_node,
    _is_dx_node_block,
    _new_dx_hash_version,
    _write_dx_entries,
    dir_parent_ino,
    list_dir,
    logical_to_phys,
    lookup_dir_name,
    read_dir_lblock,
)
from ext4lib.fs.volume import Ext4Volume
from ext4lib.fs.writer import create_empty_file, lookup_path, mkdir, move_entry
from ext4lib.io.backend import ImageDevice
from tests.ext4_fsck import check_image
from tests.ext4_image_fixture import make_steamdeck_image

SA_INO = 12  # the fixture's indexed "steamapps" folder


def _open(path: str, writable: bool) -> Ext4Volume:
    return Ext4Volume(ImageDevice(path, writable=writable), 0, os.path.getsize(path), owns_device=True)


def _fake_vol(largedir: bool, bs: int = 4096):
    incompat = C.EXT4_FEATURE_INCOMPAT_LARGEDIR if largedir else 0
    return SimpleNamespace(
        sb=SimpleNamespace(feature_incompat=incompat, block_size=bs, has_metadata_csum=False)
    )


def _rewrite_root(vol, ino: int, edit) -> None:
    inode = vol.read_inode(ino)
    block = bytearray(read_dir_lblock(vol, inode, 0))
    edit(block)
    vol.write_metadata_block(logical_to_phys(vol, inode, 0), bytes(block))
    vol.drop_dir_cache(ino)


class _ImageCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ext4htree-")
        self.img = os.path.join(self.tmp, "sd.img")
        make_steamdeck_image(self.img, casefold_htree_dir="steamapps")
        self.vol = _open(self.img, True)

    def tearDown(self):
        try:
            self.vol.close()
        except Exception:
            pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def names(self, ino: int) -> set[str]:
        return {e.name for e in list_dir(self.vol, self.vol.read_inode(ino))}


class DepthLimitTests(_ImageCase):
    def test_root_levels_follow_largedir(self):
        root = bytearray(4096)
        root[29] = 8
        for largedir, allowed in ((False, (0, 1)), (True, (0, 1, 2))):
            for levels in range(4):
                root[30] = levels
                if levels in allowed:
                    self.assertEqual(_dx_root_levels(_fake_vol(largedir), root), (32, levels))
                else:
                    with self.assertRaises(DxCorrupt):
                        _dx_root_levels(_fake_vol(largedir), root)

    def test_no_third_level_without_largedir(self):
        bs = 64
        root = bytearray(bs)
        root[28], root[29], root[30] = 1, 8, 0
        _write_dx_entries(root, 32, 3, [(0, 1)])
        blocks = {0: root}
        nxt = [2]

        def alloc():
            nxt[0] += 1
            return nxt[0] - 1

        with self.assertRaises(DirError):
            for i in range(400):
                dirty = _dx_insert_pointer(
                    lambda lb: blocks[lb], blocks[0], (i + 1) * 10, 1000 + i, bs, 0, alloc, 2
                )
                blocks.update(dirty)
        self.assertEqual(blocks[0][30], 1)

    def test_too_deep_index_on_disk_is_corruption(self):
        create_empty_file(self.vol, self.vol.read_inode(SA_INO), "keep.txt")
        _rewrite_root(self.vol, SA_INO, lambda b: b.__setitem__(30, 2))
        self.assertEqual(self.names(SA_INO), {".", "..", "keep.txt"})
        with self.assertRaises(DirError):
            create_empty_file(self.vol, self.vol.read_inode(SA_INO), "new.txt")


class DotDotTests(_ImageCase):
    def test_dotdot_comes_from_dx_root(self):
        top = mkdir(self.vol, lookup_path(self.vol, "/"), "top")
        move_entry(self.vol, "/steamapps", "/top/steamapps")
        sa = lookup_path(self.vol, "/top/steamapps")
        self.assertTrue(sa.is_indexed)
        self.assertEqual(dir_parent_ino(self.vol, sa), top.ino)
        self.assertIn("..", self.names(SA_INO))

        # The ancestor walk passes the indexed folder; both moves must fail.
        with self.assertRaises(DirError):
            move_entry(self.vol, "/top", "/top/steamapps/top")
        mkdir(self.vol, lookup_path(self.vol, "/top/steamapps"), "Common")
        with self.assertRaises(DirError):
            move_entry(self.vol, "/top", "/top/steamapps/Common/top")
        self.assertIsNotNone(lookup_path(self.vol, "/top/steamapps/Common"))
        self.vol.close()
        errors, stats = check_image(self.img)
        self.assertEqual(errors, [], f"fsck: {stats}")

    def test_unreadable_dotdot_refuses_move(self):
        mkdir(self.vol, lookup_path(self.vol, "/"), "dst")
        mkdir(self.vol, lookup_path(self.vol, "/"), "src")
        # Break the second fake dirent of steamapps' dx_root.
        _rewrite_root(self.vol, SA_INO, lambda b: b.__setitem__(slice(20, 22), b"xx"))
        with self.assertRaises(DirError):
            dir_parent_ino(self.vol, self.vol.read_inode(SA_INO))
        with self.assertRaises(DirError):
            move_entry(self.vol, "/src", "/steamapps/src")


class EqualHashSplitTests(unittest.TestCase):
    def test_continued_bit_when_run_crosses_split(self):
        hashes = [10, 20, 20, 20, 20, 30]
        sizes = [600] * 6
        split, index_hash = _dx_split_point(hashes, sizes, 4096)
        self.assertEqual(hashes[split], 20)
        self.assertEqual(hashes[split - 1], 20)
        self.assertEqual(index_hash, 21)

    def test_no_continued_bit_on_hash_boundary(self):
        hashes = [10, 12, 14, 16]
        split, index_hash = _dx_split_point(hashes, [1024] * 4, 4096)
        self.assertEqual(index_hash, hashes[split])
        self.assertEqual(index_hash & 1, 0)

    def test_scan_stopping_at_first_entry_uses_count_minus_move(self):
        # CVE-2025-23150 (Linux 6.12.24+): "if (i >= 0) split = count - move".
        # The first entry's on-disk rec_len holds most of the block, so the
        # size scan stops at i == 0 and the split is count-move, not count/2.
        split, index_hash = _dx_split_point([2, 4, 6, 8], [4040, 12, 12, 12], 4096)
        self.assertEqual((split, index_hash), (1, 4))

    def test_split_points_match_linux_do_split(self):
        # Linux 6.12 namei.c do_split(): from the hash-sorted tail, stop when
        # size + rec_len/2 > blocksize/2. If that stop is i >= 0 (including
        # i == 0), split = count - move. count/2 is only for i == -1.
        cases = (
            # i == 0: 12+12+12 move, then 4040/2 crosses the middle.
            # count - move = 1. The old i > 0 test used count/2 = 2.
            ([2, 4, 6, 8], [4040, 12, 12, 12], 4096, 1, 4),
            # General stop at i == 1: two 1024-byte entries move.
            # split = 4 - 2 = 2, and the hashes differ so no continued bit.
            ([10, 12, 14, 16], [1024, 1024, 1024, 1024], 4096, 2, 14),
        )
        for hashes, sizes, bs, linux_split, linux_hash in cases:
            split, index_hash = _dx_split_point(hashes, sizes, bs)
            self.assertEqual(split, linux_split)
            self.assertEqual(index_hash, linux_hash)

    def test_all_equal_hashes(self):
        split, index_hash = _dx_split_point([40] * 8, [512] * 8, 4096)
        self.assertEqual((split, index_hash), (4, 41))


class ReaddirFallbackTests(_ImageCase):
    def test_bad_index_falls_back_without_reading_index_blocks(self):
        for n in ("a1", "a2", "a3"):
            create_empty_file(self.vol, self.vol.read_inode(SA_INO), n)
        # indirect_levels 1: the root now claims leaf block 1 is a dx_node.
        _rewrite_root(self.vol, SA_INO, lambda b: b.__setitem__(30, 1))
        self.assertEqual(self.names(SA_INO), {".", "..", "a1", "a2", "a3"})

    def test_bad_leaf_pointer_is_an_error_not_a_linear_scan(self):
        def point_far(b: bytearray) -> None:
            struct.pack_into("<I", b, 32 + 4, 7)

        _rewrite_root(self.vol, SA_INO, point_far)
        with self.assertRaises(DirError) as ctx:
            list_dir(self.vol, self.vol.read_inode(SA_INO))
        self.assertNotIsInstance(ctx.exception, DxCorrupt)

    def test_dx_node_block_is_recognised(self):
        node = _format_dx_node(4096, True, [(0, 1), (100, 2)])
        self.assertTrue(_is_dx_node_block(node, 4096))
        leaf = bytearray(4096)
        struct.pack_into("<IHBB", leaf, 0, 12, 4096, 1, 1)
        self.assertFalse(_is_dx_node_block(leaf, 4096))


class GrowRollbackTests(_ImageCase):
    def test_failed_split_leaves_parent_unchanged(self):
        vol = self.vol
        real = D._dx_csum_set

        def boom(*_a, **_k):
            raise OSError("injected write failure")

        D._dx_csum_set = boom
        try:
            for i in range(400):
                sa = vol.read_inode(SA_INO)
                before = (sa.size, sa.blocks, sa.i_block)
                free = vol.sb.free_blocks_count
                try:
                    create_empty_file(vol, sa, f"file_{i:04d}_with_a_long_padding_name")
                except OSError:
                    break
            else:
                self.fail("the leaf never needed a split")
        finally:
            D._dx_csum_set = real
        created = i
        after = vol.read_inode(SA_INO)
        self.assertEqual((after.size, after.blocks, after.i_block), before)
        self.assertEqual(vol.sb.free_blocks_count, free)

        vol.flush_metadata()
        vol.close()
        errors, stats = check_image(self.img)
        self.assertEqual(errors, [], f"fsck: {stats}")
        self.vol = _open(self.img, True)
        sa = self.vol.read_inode(SA_INO)
        self.assertEqual(sa.size, before[0])
        self.assertEqual(len(self.names(SA_INO)), created + 2)
        # The same insert works once writes succeed again.
        create_empty_file(self.vol, sa, f"file_{created:04d}_with_a_long_padding_name")
        self.assertGreater(self.vol.read_inode(SA_INO).size, before[0])
        self.vol.close()
        errors, stats = check_image(self.img)
        self.assertEqual(errors, [], f"fsck: {stats}")


def _long_name(i: int) -> str:
    # 200 bytes fills a 4KiB directory block in about twenty creates.
    stem = f"f{i:04d}"
    return stem + ("n" * (200 - len(stem)))


class MakeIndexedDirTests(_ImageCase):
    def test_hash_version_comes_from_the_superblock(self):
        signed = SimpleNamespace(
            sb=SimpleNamespace(def_hash_version=C.DX_HASH_HALF_MD4, hash_unsigned=False)
        )
        unsigned = SimpleNamespace(
            sb=SimpleNamespace(def_hash_version=C.DX_HASH_HALF_MD4, hash_unsigned=True)
        )
        self.assertEqual(_new_dx_hash_version(signed), (C.DX_HASH_HALF_MD4, C.DX_HASH_HALF_MD4))
        self.assertEqual(
            _new_dx_hash_version(unsigned),
            (C.DX_HASH_HALF_MD4, C.DX_HASH_HALF_MD4_UNSIGNED),
        )

    def _fill(self, parent_ino: int, extra: list[str] | None = None) -> tuple[int, list[str]]:
        names = list(extra or [])
        for name in names:
            create_empty_file(self.vol, self.vol.read_inode(parent_ino), name, flush=False)
        for i in range(40):
            name = _long_name(i)
            create_empty_file(self.vol, self.vol.read_inode(parent_ino), name, flush=False)
            names.append(name)
            if self.vol.read_inode(parent_ino).is_indexed:
                return i, names
        self.fail("directory never grew past one block")

    def test_full_linear_directory_becomes_htree(self):
        vol = self.vol
        parent = mkdir(vol, lookup_path(vol, "/"), "plain")
        self.assertFalse(parent.is_indexed)
        free_before = vol.sb.free_blocks_count
        _i, names = self._fill(parent.ino, ["GameSave", "Straße"])
        node = vol.read_inode(parent.ino)
        self.assertTrue(node.flags & C.EXT4_INDEX_FL)
        self.assertEqual(node.size, 3 * vol.sb.block_size)
        # Two new leaves, and no file data blocks.
        self.assertEqual(vol.sb.free_blocks_count, free_before - 2)
        root = read_dir_lblock(vol, node, 0)
        self.assertEqual(root[8:9], b".")
        self.assertEqual(root[20:22], b"..")
        self.assertEqual(struct.unpack_from("<H", root, 4)[0], 12)
        self.assertEqual(struct.unpack_from("<H", root, 16)[0], vol.sb.block_size - 12)
        self.assertEqual(root[28], vol.sb.def_hash_version)
        self.assertEqual(root[29], 8)
        self.assertEqual(root[30], 0)
        limit, count = struct.unpack_from("<HH", root, 32)
        self.assertEqual(limit, (vol.sb.block_size - 32 - 8) // 8)
        self.assertEqual(count, 2)
        self.assertEqual(struct.unpack_from("<I", root, 36)[0], 1)
        self.assertEqual(struct.unpack_from("<I", root, 44)[0], 2)
        listed = self.names(parent.ino)
        self.assertEqual(listed, {".", "..", *names})
        self.assertEqual(lookup_dir_name(vol, node, "gamesave"), lookup_dir_name(vol, node, "GameSave"))
        vol.close()
        errors, stats = check_image(self.img)
        self.assertEqual(errors, [], f"fsck: {stats}")

    def test_casefold_directory_indexes_folded_names(self):
        vol = self.vol
        parent = mkdir(vol, lookup_path(vol, "/steamapps"), "Saves")
        self.assertTrue(parent.flags & C.EXT4_CASEFOLD_FL)
        self.assertFalse(parent.is_indexed)
        _i, names = self._fill(parent.ino, ["Straße"])
        node = vol.read_inode(parent.ino)
        self.assertTrue(node.is_indexed)
        self.assertEqual(root_hash_version(vol, node), vol.sb.def_hash_version)
        self.assertIsNotNone(lookup_dir_name(vol, node, "straße"))
        self.assertEqual(self.names(parent.ino), {".", "..", *names})
        vol.close()
        errors, stats = check_image(self.img)
        self.assertEqual(errors, [], f"fsck: {stats}")

    def test_without_dir_index_stays_linear(self):
        vol = self.vol
        saved = vol.sb.feature_compat
        vol.sb.feature_compat = saved & ~C.EXT4_FEATURE_COMPAT_DIR_INDEX
        try:
            parent = mkdir(vol, lookup_path(vol, "/"), "linear")
            for i in range(40):
                create_empty_file(vol, vol.read_inode(parent.ino), _long_name(i), flush=False)
            node = vol.read_inode(parent.ino)
            self.assertGreater(node.size, vol.sb.block_size)
            self.assertFalse(node.is_indexed)
        finally:
            vol.sb.feature_compat = saved

    def test_created_directory_link_count_becomes_one(self):
        # The folder is one this program created. Once it is indexed, the next
        # subdirectory past EXT4_LINK_MAX is stored as nlink 1 (dir_nlink).
        vol = self.vol
        parent = mkdir(vol, lookup_path(vol, "/"), "wide")
        self._fill(parent.ino)
        node = vol.read_inode(parent.ino)
        self.assertTrue(node.is_indexed)
        node.set_links(C.EXT4_LINK_MAX)
        vol.write_inode(node)
        mkdir(vol, vol.read_inode(parent.ino), "past-limit")
        self.assertEqual(vol.read_inode(parent.ino).links, 1)
        mkdir(vol, vol.read_inode(parent.ino), "still-one")
        self.assertEqual(vol.read_inode(parent.ino).links, 1)
        self.assertTrue(vol.sb.feature_ro_compat & C.EXT4_FEATURE_RO_COMPAT_DIR_NLINK)

    def test_failed_conversion_rolls_back(self):
        vol = self.vol
        parent = mkdir(vol, lookup_path(vol, "/"), "again")
        real = D._dx_csum_set

        def boom(*_a, **_k):
            raise OSError("injected write failure")

        D._dx_csum_set = boom
        try:
            for i in range(40):
                before_node = vol.read_inode(parent.ino)
                before = (before_node.size, before_node.blocks, before_node.i_block, before_node.flags)
                free = vol.sb.free_blocks_count
                inodes = vol.sb.free_inodes_count
                try:
                    create_empty_file(vol, before_node, _long_name(i), flush=False)
                except OSError:
                    break
            else:
                self.fail("conversion never ran")
        finally:
            D._dx_csum_set = real
        failed = i
        after = vol.read_inode(parent.ino)
        self.assertEqual((after.size, after.blocks, after.i_block, after.flags), before)
        self.assertFalse(after.is_indexed)
        self.assertEqual(vol.sb.free_blocks_count, free)
        self.assertEqual(vol.sb.free_inodes_count, inodes)
        self.assertNotIn(_long_name(failed), self.names(parent.ino))
        self.assertEqual(len(self.names(parent.ino)), failed + 2)
        D._dx_csum_set = real
        create_empty_file(vol, vol.read_inode(parent.ino), _long_name(failed), flush=False)
        self.assertTrue(vol.read_inode(parent.ino).is_indexed)
        vol.close()
        errors, stats = check_image(self.img)
        self.assertEqual(errors, [], f"fsck: {stats}")


def root_hash_version(vol, node) -> int:
    return read_dir_lblock(vol, node, 0)[28]


if __name__ == "__main__":
    unittest.main()
