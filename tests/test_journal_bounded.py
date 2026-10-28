"""Bounded JBD2 transactions: a long fragmented copy must fit a tiny journal.

The fast cases use tests/ext4_image_fixture.py (1024-block journal, 8 MiB
groups) and tests/ext4_fsck.py. The heavy cases format a real image with
mkfs.ext4 -J size=1 in WSL (or a native mkfs on PATH), write it ONLY through
ext4lib on an ImageDevice, and check it with e2fsck -fn from the same Linux.
They are skipped when no mkfs.ext4/e2fsck is reachable.
"""

from __future__ import annotations

import hashlib
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest

from ext4lib.fs import constants as C
from ext4lib.fs.crc32c import crc32c
from ext4lib.fs.extents import file_extents
from ext4lib.fs.journal import (
    JBD2_FEATURE_INCOMPAT_64BIT,
    JBD2_FEATURE_INCOMPAT_CSUM_V2,
    JBD2_FEATURE_INCOMPAT_CSUM_V3,
    JBD2_FLAG_LAST_TAG,
    JBD2_FLAG_SAME_UUID,
    JBD2_CRC32C_CHKSUM,
    JournalInfo,
    _JournalLog,
)
from ext4lib.fs.volume import Ext4Error, Ext4Volume
from ext4lib.fs.writer import (
    create_empty_file,
    create_file,
    lookup_path,
    read_range,
    set_file_size,
    unlink,
    write_range,
)
from ext4lib.io.backend import ImageDevice
from tests.ext4_fsck import check_image
from tests.ext4_image_fixture import make_steamdeck_image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIB = 1024 * 1024


def _open(path: str, writable: bool) -> Ext4Volume:
    return Ext4Volume(ImageDevice(path, writable=writable), 0, os.path.getsize(path), owns_device=True)


def _chunk(index: int, size: int = MIB) -> bytes:
    """Deterministic, position-tagged test data."""
    rnd = random.Random(index)
    return struct.pack("<Q", index) + rnd.randbytes(size - 8)


class _CommitSpy:
    """Record every JBD2 commit: metadata blocks and the ring head."""

    def __init__(self, vol: Ext4Volume):
        self.writer = vol._journal_writer
        self.sizes: list[int] = []
        self.wraps = 0
        orig = self.writer.commit

        def commit():
            before = self.writer.head
            n = orig()
            if n:
                self.sizes.append(n)
                if self.writer.head < before:
                    self.wraps += 1
            return n

        self.writer.commit = commit


def _fragment(vol: Ext4Volume, hole_blocks: int, holes: int) -> None:
    """Leave ``holes`` free runs of ``hole_blocks`` blocks: interleave two
    files, then delete one of them. Everything goes through ext4lib."""
    bs = vol.sb.block_size
    root = lookup_path(vol, "/")
    keep = create_empty_file(vol, root, "comb.bin")
    gone = create_empty_file(vol, lookup_path(vol, "/"), "gap.bin")
    filler = b"\xA5" * (hole_blocks * bs)
    for i in range(holes):
        write_range(vol, gone, i * hole_blocks * bs, filler)
        write_range(vol, keep, i * bs, b"\x5A" * bs)
    vol.flush_metadata()
    unlink(vol, lookup_path(vol, "/"), "gap.bin")


class DescriptorPackingTests(unittest.TestCase):
    def _log(self, block_size: int, incompat: int) -> _JournalLog:
        log = _JournalLog.__new__(_JournalLog)
        log.fs_block_size = block_size
        log.info = JournalInfo(
            block_size=block_size, maxlen=1024, first=1, sequence=7, start=0,
            feature_compat=0, feature_incompat=incompat, feature_ro_compat=0,
            uuid=bytes(range(16)),
            checksum_type=JBD2_CRC32C_CHKSUM if incompat & 0x18 else 0,
            nr_users=1,
        )
        log.csum_seed = crc32c(0xFFFFFFFF, log.info.uuid)
        return log

    def test_full_descriptor_roundtrips_for_every_tag_format(self):
        variants = [
            0,
            JBD2_FEATURE_INCOMPAT_64BIT,
            JBD2_FEATURE_INCOMPAT_CSUM_V2,
            JBD2_FEATURE_INCOMPAT_CSUM_V2 | JBD2_FEATURE_INCOMPAT_64BIT,
            JBD2_FEATURE_INCOMPAT_CSUM_V3,
            JBD2_FEATURE_INCOMPAT_CSUM_V3 | JBD2_FEATURE_INCOMPAT_64BIT,
        ]
        for bs in (1024, 4096):
            for incompat in variants:
                with self.subTest(bs=bs, incompat=incompat):
                    log = self._log(bs, incompat)
                    per = log.tags_per_descriptor()
                    tail = 4 if log.has_csum else 0
                    # Fills the block: one more tag would not fit.
                    self.assertLessEqual(12 + 16 + per * log._tag_bytes() + tail, bs)
                    self.assertGreater(12 + 16 + (per + 1) * log._tag_bytes() + tail, bs)
                    hi = (1 << 32) if log.has_64bit else 0
                    blocks = [(hi + 100 + i, bytes([i % 251]) * bs) for i in range(per)]
                    desc, images = log.build_descriptor_tags(9, blocks)
                    tags = log.parse_descriptor(desc)
                    self.assertEqual([t for t, _f, _c in tags], [b for b, _d in blocks])
                    for i, (_t, flags, csum) in enumerate(tags):
                        self.assertEqual(bool(flags & JBD2_FLAG_SAME_UUID), i > 0)
                        self.assertEqual(bool(flags & JBD2_FLAG_LAST_TAG), i == per - 1)
                        log.verify_data_checksum(9, images[i], csum)

    def test_log_space_counts_descriptor_and_commit_overhead(self):
        log = self._log(1024, JBD2_FEATURE_INCOMPAT_CSUM_V3 | JBD2_FEATURE_INCOMPAT_64BIT)
        per = log.tags_per_descriptor()
        self.assertEqual(per, 62)
        self.assertEqual(log.log_blocks_for(0), 0)
        self.assertEqual(log.log_blocks_for(1), 3)
        self.assertEqual(log.log_blocks_for(per), per + 2)
        self.assertEqual(log.log_blocks_for(per + 1), per + 4)


class FixtureBoundedTransactionTests(unittest.TestCase):
    """No WSL needed: 1024-block journal, 8 MiB groups, many bitmaps."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ext4jb-")
        self.img = os.path.join(self.tmp, "sd.img")
        make_steamdeck_image(self.img, groups=24, last_group_blocks=2048)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def assertClean(self):
        errors, stats = check_image(self.img)
        self.assertEqual(errors, [], f"fsck: {stats}")

    def test_fragmented_copy_commits_in_bounded_transactions(self):
        # The old writer rebuilt every extent leaf on each write_range() call
        # (13 fresh leaves here) and overflowed this journal after ~80 MiB.
        _shrink_journal(self.img, maxlen=520)
        vol = _open(self.img, True)
        vol.begin_write_session()
        spy = _CommitSpy(vol)
        limit = spy.writer.max_transaction_blocks
        _fragment(vol, hole_blocks=8, holes=4096)
        node = create_empty_file(vol, lookup_path(vol, "/"), "big.bin")
        total = 120
        for i in range(total):
            write_range(vol, node, i * MIB, _chunk(i))
            if i >= 60:
                vol.flush_metadata()  # many small commits: the ring wraps
        set_file_size(vol, lookup_path(vol, "/big.bin"), 64 * MIB + 5)
        vol.finish_write_session()
        vol.close()

        self.assertGreater(len(spy.sizes), 3)
        self.assertLessEqual(max(spy.sizes), limit, spy.sizes)
        self.assertGreater(spy.wraps, 0)
        vol = _open(self.img, False)
        try:
            node = lookup_path(vol, "/big.bin")
            self.assertGreater(len(file_extents(vol, node)), 2000)
            for i in range(64):
                self.assertEqual(read_range(vol, node, i * MIB, MIB), _chunk(i), i)
            self.assertEqual(read_range(vol, node, 64 * MIB, 16), _chunk(64)[:5])
        finally:
            vol.close()
        self.assertClean()

    def test_power_cut_inside_commit_replays_to_a_consistent_volume(self):
        # Cut once while journal blocks are written (transaction discarded)
        # and once during checkpoint (transaction replayed).
        for phase in ("log", "checkpoint"):
            with self.subTest(phase=phase):
                make_steamdeck_image(self.img, groups=24, last_group_blocks=2048)
                self._power_cut(phase)

    def _power_cut(self, phase: str) -> None:
        class PowerCut(Exception):
            pass

        vol = _open(self.img, True)
        vol.begin_write_session()
        _fragment(vol, hole_blocks=8, holes=1024)
        node = create_empty_file(vol, lookup_path(vol, "/"), "cut.bin")
        dev = vol.dev
        state = {"dead": False, "commits": 0}
        real_write, real_flush = dev.write, dev.flush

        def write(offset, data):
            if state["dead"]:
                raise PowerCut()
            real_write(offset, data)

        def flush():
            if state["dead"]:
                raise PowerCut()
            real_flush()

        dev.write, dev.flush = write, flush
        writer = vol._journal_writer
        if phase == "log":
            orig = writer._write_log_block
            seen = {"n": 0}

            def log_block(logical, data):
                seen["n"] += 1
                if state["commits"] >= 3 and seen["n"] % 7 == 0:
                    state["dead"] = True
                orig(logical, data)

            writer._write_log_block = log_block
        else:
            orig_cp = vol._checkpoint_metadata_blocks

            def checkpoint(metadata):
                if state["commits"] >= 3:
                    items = sorted(metadata.items())
                    orig_cp(dict(items[: len(items) // 2]))
                    state["dead"] = True
                    raise PowerCut()
                orig_cp(metadata)

            vol._checkpoint_metadata_blocks = checkpoint
        orig_commit = writer.commit

        def commit():
            n = orig_commit()
            state["commits"] += 1
            return n

        writer.commit = commit
        written = 0
        with self.assertRaises(PowerCut):
            for i in range(100):
                write_range(vol, node, i * MIB, _chunk(i))
                written = i + 1
                if i % 4 == 3:
                    vol.flush_metadata()  # an application fsync()
        dev.close()

        vol = _open(self.img, True)
        vol.recover_pending_journal()
        vol.close()
        vol = _open(self.img, True)
        vol.begin_write_session()
        vol.finish_write_session()
        node = lookup_path(vol, "/cut.bin")
        self.assertGreater(node.size, 0)
        self.assertLessEqual(node.size, (written + 1) * MIB)
        for i in range(node.size // MIB):
            self.assertEqual(read_range(vol, node, i * MIB, MIB), _chunk(i), i)
        vol.close()
        self.assertClean()

    def test_reserve_commits_before_a_step_would_pass_the_limit(self):
        vol = _open(self.img, True)
        try:
            vol.begin_write_session()
            spy = _CommitSpy(vol)
            limit = spy.writer.max_transaction_blocks
            create_empty_file(vol, lookup_path(vol, "/"), "a", flush=False)
            pending = vol.journal_pending_blocks()
            self.assertGreater(pending, 1)
            vol.journal_reserve(limit - pending)
            self.assertEqual(spy.sizes, [])
            vol.journal_reserve(limit - pending + 1)
            self.assertEqual(len(spy.sizes), 1)
            self.assertEqual(spy.sizes[0], pending)
            self.assertEqual(vol._metadata_overlay, {})
        finally:
            vol.close()
        self.assertClean()

    def test_oversized_extent_conversion_fails_before_writing_anything(self):
        # A block-mapped (ext3) file is converted to extents in one handle; a
        # file too fragmented for the journal must be refused up front.
        from unittest import mock
        from ext4lib.fs import extents as X
        from ext4lib.fs.extents import Extent, ensure_extent_layout

        vol = _open(self.img, True)
        try:
            vol.begin_write_session()
            node = create_empty_file(vol, lookup_path(vol, "/"), "old.bin")
            before = _sha(self.img)
            node.set_flags(node.flags & ~C.EXT4_EXTENTS_FL)  # in memory only
            frag = [Extent(i, 1, 5000 + 2 * i, False) for i in range(200000)]
            with mock.patch.object(X, "walk_indirect", return_value=frag), \
                    mock.patch.object(X, "_collect_indirect_pointer_blocks", return_value=[]):
                with self.assertRaisesRegex(Ext4Error, "extent 변환"):
                    ensure_extent_layout(vol, node)
            self.assertEqual(vol._metadata_overlay, {})
            self.assertEqual(_sha(self.img), before)
            vol.finish_write_session()
        finally:
            vol.close()
        self.assertClean()

    def test_too_small_journal_fails_before_writing_anything(self):
        _shrink_journal(self.img, maxlen=64)
        before = _sha(self.img)
        vol = _open(self.img, True)
        try:
            with self.assertRaises(Ext4Error):
                vol.begin_write_session()
        finally:
            vol.close()
        self.assertEqual(_sha(self.img), before)


def _sha(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fp:
        for block in iter(lambda: fp.read(MIB), b""):
            h.update(block)
    return h.hexdigest()


def _shrink_journal(path: str, maxlen: int) -> None:
    """Test fixture tampering: claim a smaller JBD2 s_maxlen (still valid)."""
    vol = _open(path, False)
    try:
        jino = vol.read_inode(vol.sb.journal_inum)
        phys = file_extents(vol, jino)[0].physical
        off = phys * vol.sb.block_size
    finally:
        vol.close()
    with open(path, "r+b") as fp:
        fp.seek(off)
        raw = bytearray(fp.read(1024))
        struct.pack_into(">I", raw, 0x10, maxlen)
        struct.pack_into(">I", raw, 0xFC, 0)
        struct.pack_into(">I", raw, 0xFC, crc32c(0xFFFFFFFF, bytes(raw)))
        fp.seek(off)
        fp.write(raw)


# --- real mkfs.ext4 / e2fsck (WSL on Windows) --------------------------------

_WSL = shutil.which("wsl.exe") if os.name == "nt" else None


def _linux(args: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
    # wsl -e does not search /usr/sbin, where mkfs.ext4 and e2fsck live.
    shell = ["sh", "-c", 'PATH="/usr/sbin:/sbin:$PATH"; exec "$@"', "sh", *args]
    argv = [_WSL, "-e", *shell] if _WSL else args
    return subprocess.run(argv, capture_output=True, timeout=timeout)


def _linux_path(path: str) -> str:
    if not _WSL:
        return path
    res = _linux(["wslpath", "-a", path], timeout=60)
    return res.stdout.decode().strip()


def _have_linux_tools() -> bool:
    if os.name != "nt" and not (shutil.which("mkfs.ext4") and shutil.which("e2fsck")):
        return False
    if os.name == "nt" and not _WSL:
        return False
    try:
        res = _linux(["sh", "-c", "command -v mkfs.ext4 && command -v e2fsck"], timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return res.returncode == 0


LINUX_TOOLS = _have_linux_tools()


@unittest.skipUnless(LINUX_TOOLS, "mkfs.ext4/e2fsck (native or WSL) not available")
class MkfsTinyJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ext4jb-mkfs-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mkfs(self, name: str, size_mib: int) -> str:
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as fp:
            fp.truncate(size_mib * MIB)
        # 1 KiB blocks: -J size=1 is the 1024-block minimum and groups are
        # 8 MiB, so a 1 GiB copy touches ~130 bitmaps.
        res = _linux(
            ["mkfs.ext4", "-F", "-q", "-b", "1024", "-J", "size=1", "-N", "2048",
             "-O", "64bit,metadata_csum", _linux_path(path)],
            timeout=600,
        )
        self.assertEqual(res.returncode, 0, res.stderr.decode(errors="replace"))
        return path

    def _e2fsck(self, path: str) -> None:
        res = _linux(["e2fsck", "-fn", _linux_path(path)], timeout=1200)
        self.assertEqual(
            res.returncode, 0,
            res.stdout.decode(errors="replace") + res.stderr.decode(errors="replace"),
        )

    def test_1gib_fragmented_copy_on_1024_block_journal(self):
        img = self._mkfs("tiny-journal.img", 1400)
        vol = _open(img, True)
        vol.begin_write_session()
        spy = _CommitSpy(vol)
        self.assertEqual(spy.writer.log.info.maxlen, 1024)
        limit = spy.writer.max_transaction_blocks
        bs = vol.sb.block_size
        total = 1040  # MiB
        hole = 128
        _fragment(vol, hole_blocks=hole, holes=total * MIB // (hole * bs) + 64)
        node = create_empty_file(vol, lookup_path(vol, "/"), "big.bin")
        digest = hashlib.sha256()
        for i in range(total):
            data = _chunk(i)
            digest.update(data)
            # Explorer/WinFsp style: many 1 MiB writes, no fsync in between.
            write_range(vol, node, i * MIB, data)
        # Freeing the comb (~8400 one-block extents in ~130 groups) runs in
        # bounded truncate steps and takes the log around the ring.
        unlink(vol, lookup_path(vol, "/"), "comb.bin")
        vol.finish_write_session()
        vol.close()

        self.assertGreater(len(spy.sizes), 3)
        self.assertLessEqual(max(spy.sizes), limit, spy.sizes)
        self.assertGreater(spy.wraps, 0, spy.sizes)
        vol = _open(img, False)
        try:
            node = lookup_path(vol, "/big.bin")
            self.assertEqual(node.size, total * MIB)
            self.assertGreater(len(file_extents(vol, node)), 8000)
            back = hashlib.sha256()
            for i in range(total):
                back.update(read_range(vol, node, i * MIB, MIB))
            self.assertEqual(back.hexdigest(), digest.hexdigest())
        finally:
            vol.close()
        self._e2fsck(img)

    def test_create_file_from_host_on_tiny_journal(self):
        img = self._mkfs("host-copy.img", 200)
        src = os.path.join(self.tmp, "src.bin")
        with open(src, "wb") as fp:
            for i in range(96):
                fp.write(_chunk(i))
        vol = _open(img, True)
        vol.begin_write_session()
        spy = _CommitSpy(vol)
        _fragment(vol, hole_blocks=64, holes=96 * MIB // (64 * 1024) + 16)
        create_file(vol, lookup_path(vol, "/"), "src.bin", src)
        vol.finish_write_session()
        vol.close()
        self.assertLessEqual(max(spy.sizes), spy.writer.max_transaction_blocks)
        vol = _open(img, False)
        try:
            node = lookup_path(vol, "/src.bin")
            for i in range(96):
                self.assertEqual(read_range(vol, node, i * MIB, MIB), _chunk(i), i)
        finally:
            vol.close()
        self._e2fsck(img)

    def test_killed_copy_replays_to_a_consistent_volume(self):
        img = self._mkfs("killed.img", 320)
        vol = _open(img, True)
        vol.begin_write_session()
        _fragment(vol, hole_blocks=64, holes=4000)
        vol.finish_write_session()
        vol.close()

        # A separate process copies and is hard-killed (TerminateProcess /
        # SIGKILL) part way, as when the app or Windows dies mid-copy.
        child = (
            "import sys\n"
            "from tests.test_journal_bounded import _open, _chunk, MIB\n"
            "from ext4lib.fs.writer import create_empty_file, lookup_path, write_range\n"
            "vol = _open(sys.argv[1], True)\n"
            "vol.begin_write_session()\n"
            "node = create_empty_file(vol, lookup_path(vol, '/'), 'killed.bin')\n"
            "for i in range(240):\n"
            "    write_range(vol, node, i * MIB, _chunk(i))\n"
            "    if i % 16 == 15:\n"
            "        vol.flush_metadata()\n"
            "    print(i, flush=True)\n"
        )
        env = dict(os.environ, PYTHONPATH=ROOT)
        proc = subprocess.Popen(
            [sys.executable, "-c", child, img], cwd=ROOT, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            for line in proc.stdout:
                if int(line) >= 150:
                    break
            time.sleep(0.05)
        finally:
            proc.kill()
            proc.wait(timeout=60)
            proc.stdout.close()
            proc.stderr.close()

        vol = _open(img, True)
        self.assertTrue(vol.sb.needs_recovery or vol.journal_needs_recovery())
        vol.recover_pending_journal()
        vol.close()
        vol = _open(img, True)
        vol.begin_write_session()
        vol.finish_write_session()
        node = lookup_path(vol, "/killed.bin")
        self.assertGreaterEqual(node.size, 144 * MIB)
        for i in range(node.size // MIB):
            self.assertEqual(read_range(vol, node, i * MIB, MIB), _chunk(i), i)
        vol.close()
        self._e2fsck(img)


if __name__ == "__main__":
    unittest.main()
