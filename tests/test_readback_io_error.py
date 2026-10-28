"""Mock-only tests: a read-back I/O error after write+flush is post-write.

Each route must write exactly once and never hand the payload to another
route or partition candidate.
"""

import unittest
from unittest.mock import Mock, patch

from ext4lib.io.backend import IoError
from ext4lib.windows import disk
from ext4lib.windows.disk import PostWriteError, _LockedVolume

from tests.test_windows_disk_io import FakeKernel32, make_dev
from tests.test_windows_lock_flush_failures import DeniedK32, FakeNt, PartitionK32

READ_ERRORS = (
    lambda: IoError("read-back ReadFile 실패", winerr=1117),
    lambda: OSError(1117, "read failed"),
)


def _failing_read(make_exc):
    def read(absolute, n):
        raise make_exc()

    return read


def _writes(k32):
    return [c for c in k32.calls if c[0] == "write"]


class NtWriteAtReadBackErrorTests(unittest.TestCase):
    def test_nt_write_at_read_error_stops_fallback_chain(self):
        for make_exc in READ_ERRORS:
            with self.subTest(exc=type(make_exc()).__name__):
                k32 = FakeKernel32()
                nt = FakeNt()
                dev = make_dev(k32)
                dev._partition_offset = 4096
                dev._write_blockers = []
                dev._nt_handle = 55
                dev._read_at = _failing_read(make_exc)
                dev._write_locked_partition_device = Mock(side_effect=IoError("denied", winerr=5))
                dev._write_at_flushed = Mock(side_effect=IoError("denied", winerr=5))
                dev._prepare_system_helper_handle = Mock()
                dev._write_unbuffered_physical = Mock()
                dev._scsi_write10 = Mock()
                dev._activate_whole_disk_offline = Mock(return_value=(True, 0))
                with patch.object(disk, "ntdll", nt):
                    with self.assertRaises(PostWriteError) as ctx:
                        dev._fallback_after_volume_access_denied(0, b"n" * 512)
                self.assertIsInstance(ctx.exception.__cause__, (IoError, OSError))
                self.assertEqual(nt.log.count("write"), 1)
                self.assertEqual(dev._write_unbuffered_physical.call_count, 0)
                self.assertEqual(dev._scsi_write10.call_count, 0)
                self.assertEqual(dev._activate_whole_disk_offline.call_count, 0)


class PartitionReadBackErrorTests(unittest.TestCase):
    def _dev(self, k32, make_exc):
        dev = make_dev(k32)
        dev._partition_number = 1
        dev._partition_offset = 4096
        dev._partition_size = 1 << 16
        dev._write_blockers = []
        dev._read_at = _failing_read(make_exc)
        dev._write_at_flushed = Mock()
        dev._nt_write_at = Mock()
        dev._scsi_write10 = Mock()
        return dev

    def _run(self, dev, k32, nt):
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "ntdll", nt), \
             patch.object(disk, "_allow_extended_io", lambda h: None), \
             patch.object(disk, "_nt_open_raw_handle", lambda p: 55):
            with self.assertRaises(PostWriteError) as ctx:
                dev._fallback_after_volume_access_denied(512, b"z" * 512)
        self.assertIsInstance(ctx.exception.__cause__, (IoError, OSError))
        self.assertEqual(dev._write_at_flushed.call_count, 0)
        self.assertEqual(dev._nt_write_at.call_count, 0)
        self.assertEqual(dev._scsi_write10.call_count, 0)

    def test_win32_partition_read_error_skips_physicaldrive(self):
        for make_exc in READ_ERRORS:
            with self.subTest(exc=type(make_exc()).__name__):
                k32 = PartitionK32()
                nt = FakeNt()
                self._run(self._dev(k32, make_exc), k32, nt)
                self.assertEqual(len(_writes(k32)), 1)
                self.assertEqual(nt.log.count("write"), 0)

    def test_native_partition_read_error_skips_next_candidate(self):
        for make_exc in READ_ERRORS:
            with self.subTest(exc=type(make_exc()).__name__):
                k32 = PartitionK32(open_ok=False)
                nt = FakeNt()
                self._run(self._dev(k32, make_exc), k32, nt)
                self.assertEqual(nt.log.count("write"), 1)
                self.assertEqual(nt.flushes, 1)


class VolumeHandleReadBackErrorTests(unittest.TestCase):
    def test_volume_handle_read_error_skips_fallback(self):
        for make_exc in READ_ERRORS:
            with self.subTest(exc=type(make_exc()).__name__):
                k32 = DeniedK32()
                nt = FakeNt()
                dev = make_dev(k32)
                dev._partition_offset = 4096
                dev._read_at = _failing_read(make_exc)
                dev._fallback_after_volume_access_denied = Mock()
                item = _LockedVolume(handle=22, name="vol", partition_number=1, locked=True)
                with patch.object(disk, "kernel32", k32), patch.object(disk, "ntdll", nt):
                    with self.assertRaises(PostWriteError) as ctx:
                        dev._write_volume_seek(item, 0, b"q" * 1024)
                self.assertIsInstance(ctx.exception.__cause__, (IoError, OSError))
                self.assertEqual(nt.log.count("write"), 1)
                self.assertEqual(dev._fallback_after_volume_access_denied.call_count, 0)


if __name__ == "__main__":
    unittest.main()
