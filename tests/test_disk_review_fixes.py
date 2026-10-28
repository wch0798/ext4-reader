"""Mock-only tests for the windows/disk.py line review fixes (no real disk I/O)."""

import unittest
from unittest.mock import patch

from ext4lib.io.backend import IoError
from ext4lib.windows import disk
from ext4lib.windows.disk import _LockedVolume

from tests.test_windows_disk_io import FakeKernel32, make_dev


def _raise(err):
    def fn(*_a, **_k):
        raise IoError("fail", winerr=err)

    return fn


class PhysicalIndexTests(unittest.TestCase):
    def test_only_trailing_digits_name_the_disk(self):
        self.assertEqual(disk._physical_index(r"\\.\PhysicalDrive3"), 3)
        self.assertEqual(disk._physical_index(r"\\.\PHYSICALDRIVE12\\"), 12)
        self.assertIsNone(disk._physical_index(r"\\.\PhysicalDrive1\x2"))
        self.assertIsNone(disk._physical_index(r"\\.\PhysicalDrive"))
        self.assertIsNone(disk._physical_index(r"\\.\C:"))


class ReopenIdentityTests(unittest.TestCase):
    def _dev(self, k32):
        dev = make_dev(k32, writable=True)
        dev._expected_size = 1 << 20
        dev._expected_serial = "CARD-A"
        dev._expected_ext_uuid = b"\x11" * 16
        return dev

    def test_reopen_refuses_different_medium_before_locking_volumes(self):
        k32 = FakeKernel32()
        dev = self._dev(k32)
        locked = []

        def verify(path, offset, **kw):
            self.assertEqual(kw["expected_serial"], "CARD-A")
            self.assertEqual(kw["expected_ext_uuid"], b"\x11" * 16)
            raise IoError("serial changed", winerr=1167)

        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "_verify_expected_medium", verify), \
             patch.object(disk, "_lock_volumes_for_disk", lambda idx, *a: locked.append(idx) or []), \
             patch.object(disk, "_open_handle", lambda *a: self.fail("opened by index")):
            with self.assertRaises(IoError) as ctx:
                dev._reopen_locked()
        self.assertEqual(ctx.exception.winerr, 1167)
        self.assertEqual(locked, [])
        self.assertIsNone(dev._handle)

    def test_retried_write_never_reaches_swapped_card(self):
        k32 = FakeKernel32()
        dev = self._dev(k32)
        writes = []

        def write_once(offset, data):
            writes.append(offset)
            raise IoError("unplugged", winerr=1167)

        dev._raw_write_once = write_once
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "_verify_expected_medium", _raise(1167)):
            with self.assertRaises(IoError):
                dev._raw_write(0, b"x" * 512)
        self.assertEqual(writes, [0])


class ReopenScsiVerdictTests(unittest.TestCase):
    def test_reopen_forgets_route_verdicts_and_keeps_dirty(self):
        k32 = FakeKernel32()
        dev = make_dev(k32, writable=True)
        dev._scsi_fua_supported = False
        dev._scsi_sync_cache_supported = False
        dev._fallback_write_route = "scsi"
        dev._scsi_dirty = True
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "_enable_storage_privileges", lambda: None), \
             patch.object(disk, "_lock_volumes_for_disk", lambda idx, *a: []), \
             patch.object(disk, "_open_handle", lambda *a: 77), \
             patch.object(disk, "_query_disk_size", lambda h: (len(k32.media), 512)):
            dev._reopen_locked()
        self.assertEqual(dev._handle, 77)
        self.assertIsNone(dev._scsi_fua_supported)
        self.assertIsNone(dev._scsi_sync_cache_supported)
        self.assertIsNone(dev._fallback_write_route)
        self.assertTrue(dev._scsi_dirty)


class DeviceGoneFallbackTests(unittest.TestCase):
    def test_removal_mid_write_stops_the_fallback_chain(self):
        for err in (21, 1167, 1617):
            dev = make_dev(FakeKernel32())
            escalated = []
            dev._write_locked_partition_device = _raise(5)
            dev._write_at = _raise(err)
            dev._nt_write_at = lambda *a: escalated.append("nt")
            dev._prepare_system_helper_handle = lambda: escalated.append("helper")
            dev._scsi_write10 = lambda *a: escalated.append("scsi")
            dev._activate_whole_disk_offline = lambda: escalated.append("offline")
            with self.assertRaises(IoError) as ctx:
                dev._fallback_after_volume_access_denied(0, b"x" * 512)
            self.assertEqual(ctx.exception.winerr, err)
            self.assertEqual(escalated, [])

    def test_removal_during_scsi_skips_offline_and_localsystem(self):
        dev = make_dev(FakeKernel32())
        dev._write_blockers = []
        escalated = []
        dev._write_locked_partition_device = _raise(5)
        dev._write_at = _raise(5)
        dev._nt_write_at = _raise(5)
        dev._prepare_system_helper_handle = lambda: None
        dev._write_unbuffered_physical = _raise(5)
        dev._scsi_write10 = _raise(1167)
        dev._activate_whole_disk_offline = lambda: escalated.append("offline") or (False, 5)
        with self.assertRaises(IoError) as ctx:
            dev._fallback_after_volume_access_denied(0, b"x" * 512)
        self.assertEqual(ctx.exception.winerr, 1167)
        self.assertEqual(escalated, [])

    def test_access_denied_still_walks_the_chain(self):
        dev = make_dev(FakeKernel32())
        dev._write_locked_partition_device = _raise(5)
        dev._write_at = _raise(5)
        done = []
        dev._nt_write_at = lambda off, data: done.append(off)
        dev._fallback_after_volume_access_denied(512, b"x" * 512)
        self.assertEqual(done, [512])


class ReadOnlyTests(unittest.TestCase):
    def test_raw_write_on_read_only_device_never_calls_writefile(self):
        k32 = FakeKernel32()
        dev = make_dev(k32, writable=False)
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(IoError) as ctx:
                dev._raw_write(0, b"x" * 512)
        self.assertEqual(ctx.exception.winerr, disk.ERROR_ACCESS_DENIED)
        self.assertFalse([c for c in k32.calls if c[0] == "write"])

    def test_read_only_flush_is_a_no_op(self):
        k32 = FakeKernel32(flush_err=5)
        dev = make_dev(k32, writable=False)
        with patch.object(disk, "kernel32", k32):
            dev.flush()
        self.assertEqual(k32.calls, [])


class NtFlushTests(unittest.TestCase):
    def test_fatal_native_flush_failure_is_reported(self):
        class FakeNt:
            def NtFlushBuffersFile(self, handle, iosb):
                return -1073741810  # any failing NTSTATUS

            def RtlNtStatusToDosError(self, status):
                return 1167

        k32 = FakeKernel32()
        dev = make_dev(k32)
        dev._nt_handle = 33
        with patch.object(disk, "kernel32", k32), patch.object(disk, "ntdll", FakeNt()):
            with self.assertRaises(IoError) as ctx:
                dev.flush()
        self.assertEqual(ctx.exception.winerr, 1167)


class PartitionTargetTests(unittest.TestCase):
    def test_volume_with_different_base_is_not_used_for_relative_write(self):
        dev = make_dev(FakeKernel32())
        dev._partition_offset = 0
        dev._partition_size = 0
        dev._partition_volume = _LockedVolume(
            handle=22, name="vol", partition_number=1, locked=True,
            partition_offset=1 << 20, partition_size=1 << 20,
        )
        self.assertIsNone(dev._partition_write_target(4096, 512))
        dev._partition_offset = 1 << 20
        dev._partition_size = 1 << 20
        self.assertEqual(dev._partition_write_target((1 << 20) + 4096, 512)[1], 4096)


class HelperHandleTests(unittest.TestCase):
    def test_helper_reopen_compares_length_info_not_geometry(self):
        k32 = FakeKernel32()
        k32.CreateFileW = lambda *a: 44
        dev = make_dev(k32, size=31_914_983_424)
        dev._serial = "CARD-A"
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "_query_geometry", lambda h: (31_914_000_000, 512)), \
             patch.object(disk, "_query_disk_size", lambda h: (31_914_983_424, 512)), \
             patch.object(disk, "_query_storage", lambda h: ("", "", 12, True)), \
             patch.object(disk, "_query_storage_serial", lambda h: "CARD-A"), \
             patch.object(disk, "_allow_extended_io", lambda h: None):
            dev._prepare_system_helper_handle()
        self.assertEqual(dev._handle, 44)
        self.assertEqual(dev._size, 31_914_983_424)

    def test_helper_reopen_rejects_changed_serial(self):
        k32 = FakeKernel32()
        k32.CreateFileW = lambda *a: 44
        dev = make_dev(k32)
        dev._serial = "CARD-A"
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "_query_disk_size", lambda h: (len(k32.media), 512)), \
             patch.object(disk, "_query_storage", lambda h: ("", "", 12, True)), \
             patch.object(disk, "_query_storage_serial", lambda h: "CARD-B"), \
             patch.object(disk, "_allow_extended_io", lambda h: None):
            with self.assertRaises(IoError) as ctx:
                dev._prepare_system_helper_handle()
        self.assertEqual(ctx.exception.winerr, 1167)
        self.assertIn(("close", 44), k32.calls)
        self.assertIsNone(dev._handle)


class LockCleanupTests(unittest.TestCase):
    def test_interrupted_volume_scan_releases_already_locked_volumes(self):
        class K32(FakeKernel32):
            def FindFirstVolumeW(self, buf, n):
                buf.value = "\\\\?\\Volume{a}\\"
                return 5

            def FindNextVolumeW(self, find, buf, n):
                raise KeyboardInterrupt

            def FindVolumeClose(self, find):
                return True

            def CreateFileW(self, *a):
                return 70

        def fake_ioctl(handle, code, inbuf=None, out_cb=0):
            if code == disk.IOCTL_STORAGE_GET_DEVICE_NUMBER:
                return (7).to_bytes(4, "little") + (9).to_bytes(4, "little") + (1).to_bytes(4, "little")
            return b""

        released = []
        with patch.object(disk, "kernel32", K32()), \
             patch.object(disk, "_ioctl", fake_ioctl), \
             patch.object(disk, "_take_volume_offline", lambda h, n: True), \
             patch.object(disk, "_query_partition_extent", lambda h: (1 << 20, 1 << 20, 1)), \
             patch.object(disk, "_release_locked_volume", released.append):
            with self.assertRaises(KeyboardInterrupt):
                disk._lock_volumes_for_disk(9)
        self.assertEqual([item.handle for item in released], [70])


if __name__ == "__main__":
    unittest.main()
