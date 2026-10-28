"""ext4 casefold must match Linux utf8_casefold() with the Unicode 12.1 table.

Expected bytes were produced by running the kernel's own trie
(fs/unicode/utf8data.c_shipped) through a port of utf8byte(). Names are stored
as given; only lookup, duplicate checks and the htree hash use the fold.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from ext4lib.fs import ucd_12_1
from ext4lib.fs.casefold import utf8_casefold, utf8_validate
from ext4lib.fs.directory import DirError, list_dir
from ext4lib.fs.volume import Ext4Volume
from ext4lib.fs.writer import create_empty_file, lookup_path, rename_entry
from ext4lib.io.backend import ImageDevice
from tests.ext4_fsck import check_image
from tests.ext4_image_fixture import make_steamdeck_image

HANGUL_SAVE = "세이브"  # 세이브 as jamo


class Utf8CasefoldTest(unittest.TestCase):
    def fold(self, text: str) -> bytes | None:
        return utf8_casefold(text.encode("utf-8"))

    def test_version(self):
        self.assertEqual(ucd_12_1.UNICODE_VERSION, "12.1.0")

    def test_german_sharp_s(self):
        self.assertEqual(self.fold("Straße"), b"strasse")
        self.assertEqual(self.fold("STRASSE"), b"strasse")
        self.assertEqual(self.fold("ẞ"), b"ss")

    def test_turkish_dotted_i(self):
        # CaseFolding status F, not the Turkic T mapping.
        self.assertEqual(self.fold("İstanbul"), b"i\xcc\x87stanbul")
        self.assertEqual(self.fold("I"), b"i")
        self.assertNotEqual(self.fold("İstanbul"), self.fold("Istanbul"))

    def test_hangul(self):
        self.assertEqual(self.fold("세이브01"), (HANGUL_SAVE + "01").encode())
        self.assertEqual(self.fold("한글"), self.fold("한글"))

    def test_combining(self):
        self.assertEqual(self.fold("Café"), b"cafe\xcc\x81")
        self.assertEqual(self.fold("Café"), b"cafe\xcc\x81")
        self.assertEqual(self.fold("Å"), b"a\xcc\x8a")  # ANGSTROM SIGN
        self.assertEqual(self.fold("á̖"), "á̖".encode())
        self.assertEqual(self.fold("ΣΑΣ"), "σασ".encode())

    def test_newer_than_12_1_left_alone(self):
        # Python 3.12 (Unicode 15.0) folds these; Linux keeps them as is.
        self.assertEqual(self.fold("Ꟁ"), "Ꟁ".encode())  # Unicode 14
        self.assertEqual(self.fold("Ⱟ"), "Ⱟ".encode())  # Unicode 14
        self.assertEqual(self.fold("\U0001faf6"), "\U0001faf6".encode())
        # U+1DFA (Unicode 14) has class 0 for Linux, so no reordering.
        self.assertEqual(self.fold("á᷺"), "á᷺".encode())
        self.assertEqual(self.fold("͸"), "͸".encode())  # unassigned

    def test_default_ignorable_removed(self):
        self.assertEqual(self.fold("a​b"), b"ab")
        self.assertEqual(self.fold("x­y"), b"xy")
        self.assertEqual(self.fold("❤️"), "❤".encode())
        self.assertEqual(self.fold("​"), b"")
        # A removed ignorable still stops canonical reordering.
        self.assertEqual(self.fold("á​̖"), "á̖".encode())

    def test_invalid_utf8(self):
        for raw in (b"\xff", b"bad\xff", b"\x80A", b"\xc0\xaf", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xe2\x82"):
            self.assertIsNone(utf8_casefold(raw), raw)
            self.assertFalse(utf8_validate(raw), raw)
        # utf8byte() copies a stray continuation byte after a valid character.
        self.assertEqual(utf8_casefold(b"A\x80"), b"a\x80")
        self.assertFalse(utf8_validate(b"A\x80"))
        self.assertTrue(utf8_validate("Ꟁ".encode()))


def _open(path: str, writable: bool) -> Ext4Volume:
    return Ext4Volume(ImageDevice(path, writable=writable), 0, os.path.getsize(path), owns_device=True)


class CasefoldDirectoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ext4cf-")
        self.img = os.path.join(self.tmp, "sd.img")
        make_steamdeck_image(self.img, casefold_htree_dir="steamapps")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_names_hash_and_duplicates(self):
        stored = ["Straße", "İstanbul", "세이브01.sav", "Café", "Ꟁ.sav", "a​b", "bad\udcff"]
        clashes = ["STRASSE", "i̇stanbul", HANGUL_SAVE + "01.SAV", "CAFÉ", "ab"]
        vol = _open(self.img, True)
        try:
            sa = lookup_path(vol, "/steamapps")
            for i in range(300):  # enough to split htree leaves
                create_empty_file(vol, sa, f"Proton_{i:03d}.TXT")
                sa = lookup_path(vol, "/steamapps")
            for name in stored:
                create_empty_file(vol, sa, name)
                sa = lookup_path(vol, "/steamapps")
            for name in clashes:
                with self.assertRaises(DirError, msg=name):
                    create_empty_file(vol, sa, name)
            # Unicode 15 would fold U+A7C0 to U+A7C1; Linux 12.1 keeps both.
            create_empty_file(vol, sa, "ꟁ.sav")
            sa = lookup_path(vol, "/steamapps")
            self.assertEqual(
                lookup_path(vol, "/steamapps/STRASSE").ino, lookup_path(vol, "/steamapps/Straße").ino
            )
            # rename onto another case of an existing name must not drop the source.
            with self.assertRaises(DirError):
                rename_entry(vol, sa, "Café", "STRASSE")
            rename_entry(vol, lookup_path(vol, "/steamapps"), "Café", "CAFÉ")
        finally:
            vol.close()

        errors, stats = check_image(self.img)
        self.assertEqual(errors, [], f"fsck: {stats}")
        self.assertGreater(stats.get("htree_leaves", 0), 1)

        vol = _open(self.img, False)
        try:
            raw = {e.raw for e in list_dir(vol, lookup_path(vol, "/steamapps"))}
        finally:
            vol.close()
        # Stored exactly as given.
        for name in [*stored[:3], "CAFÉ", "Ꟁ.sav", "ꟁ.sav", "a​b"]:
            self.assertIn(name.encode("utf-8"), raw)
        self.assertIn(b"bad\xff", raw)
        self.assertNotIn("Café".encode(), raw)

    def test_strict_mode_rejects_invalid_utf8(self):
        vol = _open(self.img, True)
        try:
            vol.sb.raw[0x27E] |= 1  # SB_ENC_STRICT_MODE_FL, in memory only
            sa = lookup_path(vol, "/steamapps")
            with self.assertRaises(DirError):
                create_empty_file(vol, sa, "bad\udcff")
            create_empty_file(vol, sa, "Ꟁ ok")  # unassigned in 12.1 is still valid
            # Only casefold directories are checked.
            create_empty_file(vol, lookup_path(vol, "/"), "bad\udcff")
        finally:
            vol.close()


if __name__ == "__main__":
    unittest.main()
