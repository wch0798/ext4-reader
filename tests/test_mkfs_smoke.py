"""Smoke test: format a temp image with the system mkfs.ext4 and open it.

Skipped when no mkfs.ext4/mke2fs is on PATH. e2fsck validates the result
when it is installed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest

from ext4lib.fs import constants as C
from ext4lib.fs.directory import list_dir
from ext4lib.fs.volume import Ext4Volume
from ext4lib.fs.writer import create_empty_file, lookup_path, read_range, write_range
from ext4lib.io.backend import ImageDevice

MKFS = shutil.which("mkfs.ext4") or shutil.which("mke2fs")
E2FSCK = shutil.which("e2fsck")
IMAGE_SIZE = 32 * 1024 * 1024


def _open(path: str, writable: bool) -> Ext4Volume:
    return Ext4Volume(ImageDevice(path, writable=writable), 0, os.path.getsize(path), owns_device=True)


@unittest.skipUnless(MKFS, "mkfs.ext4/mke2fs not installed")
class MkfsSmokeTest(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".img")
        with os.fdopen(fd, "wb") as fp:
            fp.truncate(IMAGE_SIZE)
        subprocess.run(
            [MKFS, "-F", "-q", "-t", "ext4", "-b", "4096",
             # e2fsprogs < 1.47 rejects ^orphan_file; it is off there anyway.
             "-O", "64bit,metadata_csum", self.path],
            check=True, capture_output=True, timeout=60,
        )

    def tearDown(self):
        os.unlink(self.path)

    def test_format_open_write_check(self):
        vol = _open(self.path, False)
        try:
            self.assertEqual(vol.sb.block_size, 4096)
            self.assertTrue(vol.sb.has_metadata_csum)
            names = {e.name for e in list_dir(vol, vol.read_inode(C.EXT4_ROOT_INO))}
            self.assertIn("lost+found", names)
        finally:
            vol.close()

        vol = _open(self.path, True)
        self.assertEqual(vol.hard_write_blockers(), [])
        vol.begin_write_session()
        node = create_empty_file(vol, lookup_path(vol, "/"), "smoke.bin")
        payload = b"mkfs-smoke" * 1000
        write_range(vol, node, 0, payload, flush=True)
        vol.finish_write_session()
        vol.close()

        vol = _open(self.path, False)
        try:
            node = lookup_path(vol, "/smoke.bin")
            self.assertEqual(read_range(vol, node, 0, len(payload)), payload)
        finally:
            vol.close()

        if E2FSCK:
            res = subprocess.run([E2FSCK, "-fn", self.path], capture_output=True, timeout=60)
            self.assertEqual(res.returncode, 0, res.stdout.decode(errors="replace"))


if __name__ == "__main__":
    unittest.main()
