"""Copy files from Windows into a Steam Deck style ext4 image, then fsck it.

No WSL, mkfs or e2fsck: the image comes from tests/ext4_image_fixture.py and
tests/ext4_fsck.py checks it the way ``e2fsck -fn`` would.
"""

from __future__ import annotations

import os
import shutil
import struct
import tempfile
import unittest

from ext4lib.fs import constants as C
from ext4lib.fs.directory import DirError, list_dir
from ext4lib.fs.volume import Ext4Volume
from ext4lib.fs.writer import (
    copy_tree_in,
    create_empty_file,
    lookup_path,
    mkdir,
    move_entry,
    read_range,
    set_file_size,
    unlink_checked,
    write_range,
)
from ext4lib.io.backend import ImageDevice
from tests.ext4_fsck import check_image
from tests.ext4_image_fixture import make_steamdeck_image


def _open(path: str, writable: bool) -> Ext4Volume:
    return Ext4Volume(ImageDevice(path, writable=writable), 0, os.path.getsize(path), owns_device=True)


class SteamDeckImageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ext4rd-")
        self.img = os.path.join(self.tmp, "sd.img")
        make_steamdeck_image(self.img, casefold_htree_dir="steamapps")
        self.src = os.path.join(self.tmp, "src")
        os.makedirs(os.path.join(self.src, "Game 게임", "Saves"))
        with open(os.path.join(self.src, "Game 게임", "readme.txt"), "wb") as fp:
            fp.write(b"hello deck\n")
        with open(os.path.join(self.src, "Game 게임", "Saves", "세이브01.sav"), "wb") as fp:
            fp.write(os.urandom(300_000))
        open(os.path.join(self.src, "Game 게임", "empty.bin"), "wb").close()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def assertClean(self):
        errors, stats = check_image(self.img)
        self.assertEqual(errors, [], f"fsck: {stats}")
        return stats

    def test_fresh_image_is_clean(self):
        self.assertClean()

    def test_copy_in_then_fsck(self):
        vol = _open(self.img, True)
        try:
            self.assertEqual(vol.hard_write_blockers(), [])
            root = lookup_path(vol, "/")
            copy_tree_in(vol, root, os.path.join(self.src, "Game 게임"))

            # Explorer-style copy: empty create, then 1 MiB writes.
            big = create_empty_file(vol, lookup_path(vol, "/"), "big.bin")
            payload = os.urandom(6 * 1024 * 1024 + 123)
            for off in range(0, len(payload), 1 << 20):
                write_range(vol, big, off, payload[off : off + (1 << 20)])
                big = lookup_path(vol, "/big.bin")
            vol.flush_metadata()

            # Steam library folder: casefold + already indexed. Enough names
            # to split leaves, so placement must use the casefolded hash.
            sa = lookup_path(vol, "/steamapps")
            for i in range(400):
                f = create_empty_file(vol, sa, f"Proton_{i:03d}_Save데이터.TXT")
                if i % 50 == 0:
                    write_range(vol, f, 0, b"x" * 5000, flush=True)
                sa = lookup_path(vol, "/steamapps")
            with self.assertRaises(DirError):
                create_empty_file(vol, sa, "proton_007_save데이터.txt")
            sub = mkdir(vol, sa, "Common")
            self.assertTrue(sub.flags & C.EXT4_CASEFOLD_FL)

            # Plain folder turned casefold while empty (chattr +F).
            cf = mkdir(vol, lookup_path(vol, "/"), "cf")
            cf.set_flags(cf.flags | C.EXT4_CASEFOLD_FL)
            vol.write_inode(cf)
            create_empty_file(vol, lookup_path(vol, "/cf"), "Straße")
            with self.assertRaises(DirError):
                create_empty_file(vol, lookup_path(vol, "/cf"), "STRASSE")

            for bad in ("a/b", "nul\x00name", "..", "x" * 256):
                with self.assertRaises(DirError):
                    create_empty_file(vol, lookup_path(vol, "/"), bad)

            move_entry(vol, "/Game 게임/readme.txt", "/readme.txt")
            set_file_size(vol, lookup_path(vol, "/big.bin"), 3 * 1024 * 1024 + 7)
            unlink_checked(vol, lookup_path(vol, "/steamapps"), "Proton_100_Save데이터.TXT")

            # Windows timestamps before 1970 and after 2038, with fractions.
            node = lookup_path(vol, "/big.bin")
            node.set_atime_mtime(-86400.25, 2_300_000_000.5)
            vol.write_inode(node)
        finally:
            vol.close()

        stats = self.assertClean()
        self.assertGreater(stats.get("htree_leaves", 0), 1)

        vol = _open(self.img, False)
        try:
            game = lookup_path(vol, "/Game 게임")
            sav = lookup_path(vol, "/Game 게임/Saves/세이브01.sav")
            for node, perm in ((game, C.DEFAULT_LINUX_DIR_MODE), (sav, C.DEFAULT_LINUX_FILE_MODE)):
                self.assertEqual((node.uid, node.gid), (1000, 1000))
                self.assertEqual(node.mode & 0o777, perm)
            with open(os.path.join(self.src, "Game 게임", "Saves", "세이브01.sav"), "rb") as fp:
                self.assertEqual(read_range(vol, sav, 0, sav.size), fp.read())
            big = lookup_path(vol, "/big.bin")
            self.assertEqual(read_range(vol, big, 0, big.size), payload[: 3 * 1024 * 1024 + 7])
            # mtime 2_300_000_000.5 -> epoch bit 1, 500000000 ns.
            self.assertEqual(struct.unpack_from("<I", big.raw, 0x88)[0], 1 | (500_000_000 << 2))
            self.assertEqual(struct.unpack_from("<I", big.raw, 0x10)[0], 2_300_000_000)
            # atime -86400.25 -> seconds -86401 (low 32 bits), 750000000 ns, epoch 0.
            self.assertEqual(struct.unpack_from("<i", big.raw, 0x08)[0], -86401)
            self.assertEqual(struct.unpack_from("<I", big.raw, 0x8C)[0], 750_000_000 << 2)
            names = {e.name for e in list_dir(vol, lookup_path(vol, "/steamapps"))}
            self.assertEqual(len(names - {".", ".."}), 400)
        finally:
            vol.close()

    def test_fsck_detects_corruption(self):
        vol = _open(self.img, True)
        try:
            create_empty_file(vol, lookup_path(vol, "/"), "a.txt")
        finally:
            vol.close()
        sb = vol.sb
        with open(self.img, "r+b") as fp:
            # Flip a byte in the group 0 descriptor's free-blocks count.
            fp.seek(sb.block_size + 0x0C)
            b = fp.read(1)
            fp.seek(sb.block_size + 0x0C)
            fp.write(bytes([b[0] ^ 1]))
        errors, _ = check_image(self.img)
        self.assertTrue(any("descriptor checksum" in e for e in errors), errors)
        self.assertTrue(any("free blocks" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
