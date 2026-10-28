"""Mock-only tests: Windows lock and flush failures are errors, never success.

Four paths in ext4lib.windows.disk are covered, each with a success and a
failure case:

1. lock/dismount/offline all failing on a mounted volume -> VolumeLockError
   before any write (opt-in ``allow_unlocked_volume_write`` bypasses; a raw
   disk with no mounted volume proceeds as before);
2. NtFlushBuffersFile NTSTATUS failure in ``_nt_write_volume_handle``;
3. any FlushFileBuffers failure in ``flush()`` (dirty flag kept);
4. SCSI SYNCHRONIZE CACHE unsupported -> FlushFileBuffers fallback, dirty
   cleared only when some flush path really succeeded.

No real disk is touched: kernel32/ntdll are replaced by in-memory fakes.
"""

import inspect
import unittest
from unittest.mock import Mock, patch

from ext4lib.io.backend import IoError
from ext4lib.windows import disk
from ext4lib.windows.disk import (
    PostWriteError,
    VolumeLockError,
    WindowsPhysicalDevice,
    _LockedVolume,
)

from tests.test_windows_disk_io import FakeKernel32, make_dev
from tests.test_windows_lock_flush_failures import (
    ALL_SECURING,
    NT_FAIL,
    FakeNt,
    VolumeK32,
    _volume_ioctl,
)

UNSUPPORTED = [
    (False, (0x05, 0x20, 0x00), "DIRECT invalid opcode"),
    (False, (0x05, 0x24, 0x00), "BUFFERED invalid field"),
]


class NoVolumeK32(FakeKernel32):
    """A raw disk Windows has not mounted at all."""

    def FindFirstVolumeW(self, buf, n):
        self.SetLastError(disk.ERROR_NO_MORE_FILES)
        return disk.INVALID_HANDLE_VALUE


class HandleFlushK32(FakeKernel32):
    """FlushFileBuffers fails only for the handles in ``bad``."""

    def __init__(self, bad, err=1, **kw):
        super().__init__(**kw)
        self.bad = set(bad)
        self.err = err

    def FlushFileBuffers(self, handle):
        self.calls.append(("flush", handle))
        if handle in self.bad:
            self.SetLastError(self.err)
            return False
        return True


def _writes(k32):
    return [c for c in k32.calls if c[0] == "write"]


def _flushes(k32):
    return [c for c in k32.calls if c[0] == "flush"]


# --------------------------------------------------------------------------
# 1) lock / dismount / offline all failing
# --------------------------------------------------------------------------
class VolumeLockTests(unittest.TestCase):
    def _lock(self, failing, k32=None, **kwargs):
        k32 = VolumeK32() if k32 is None else k32
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "_ioctl", _volume_ioctl(failing)), \
             patch.object(disk, "LOCK_VOLUME_RETRIES", 1), \
             patch.object(disk, "_query_partition_extent", lambda h: (1 << 20, 1 << 20, 1)), \
             patch.object(disk, "_volume_guid_for_fve", lambda n: None):
            return k32, disk._lock_volumes_for_disk(9, **kwargs)

    def test_all_failing_raises_volume_lock_error_and_writes_nothing(self):
        with self.assertRaises(VolumeLockError) as ctx:
            k32, _ = self._lock(ALL_SECURING)
        self.assertIsInstance(ctx.exception, IoError)
        self.assertEqual(ctx.exception.winerr, disk.ERROR_ACCESS_DENIED)
        self.assertIn("Volume{a}", str(ctx.exception))

    def test_all_failing_closes_handle_without_write(self):
        k32 = VolumeK32()
        with self.assertRaises(VolumeLockError):
            self._lock(ALL_SECURING, k32=k32)
        self.assertIn(("close", 70), k32.calls)
        self.assertFalse(_writes(k32))

    def test_opt_in_flag_continues_with_unsecured_volume(self):
        _k32, locked = self._lock(ALL_SECURING, allow_unlocked=True)
        self.assertEqual(len(locked), 1)
        item = locked[0]
        self.assertFalse(item.locked)
        self.assertFalse(item.dismounted)
        self.assertFalse(item.offline)
        self.assertFalse(item.secured)

    def test_lock_success_is_unchanged(self):
        _k32, locked = self._lock(set())
        self.assertEqual(len(locked), 1)
        self.assertTrue(locked[0].locked)
        self.assertTrue(locked[0].dismounted)
        self.assertTrue(locked[0].offline)
        self.assertTrue(locked[0].secured)

    def test_dismount_only_counts_as_secured(self):
        _k32, locked = self._lock({disk.FSCTL_LOCK_VOLUME, disk.IOCTL_VOLUME_OFFLINE})
        self.assertFalse(locked[0].locked)
        self.assertTrue(locked[0].dismounted)
        self.assertTrue(locked[0].secured)

    def test_raw_disk_without_any_volume_proceeds(self):
        k32, locked = self._lock(ALL_SECURING, k32=NoVolumeK32())
        self.assertEqual(locked, [])
        dev = make_dev(k32)
        with patch.object(disk, "kernel32", k32):
            dev._raw_write_once(4096, b"r" * 512)
        self.assertEqual(bytes(k32.media[4096:4608]), b"r" * 512)

    def test_opt_in_flag_defaults_to_false(self):
        param = inspect.signature(WindowsPhysicalDevice._open).parameters[
            "allow_unlocked_volume_write"
        ]
        self.assertIs(param.default, False)
        for fn in (disk._lock_volumes_for_disk, disk._open_hidden_volume_alias,
                   disk._open_partition_device, disk._secure_exclusive_access):
            self.assertIs(inspect.signature(fn).parameters["allow_unlocked"].default, False)

    def test_reopen_passes_opt_in_flag_through(self):
        k32 = FakeKernel32()
        dev = make_dev(k32)
        dev._allow_unlocked_volume_write = True
        dev._expected_size = 0
        dev._expected_serial = ""
        dev._expected_ext_uuid = None
        locker = Mock(return_value=[])
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "_verify_expected_medium", lambda *a, **k: None), \
             patch.object(disk, "_enable_storage_privileges", lambda: True), \
             patch.object(disk, "_open_handle", lambda *a: 11), \
             patch.object(disk, "_query_disk_size", lambda h: (1 << 20, 512)), \
             patch.object(disk, "_lock_volumes_for_disk", locker):
            dev._reopen_locked()
        locker.assert_called_once_with(9, True)


class WriteTimeGuardTests(unittest.TestCase):
    def _dev(self, k32, **item_kw):
        dev = make_dev(k32)
        dev._partition_number = 1
        dev._partition_offset = 4096
        dev._partition_size = 1 << 16
        kw = dict(handle=70, name="vol", partition_number=1, locked=False,
                  partition_offset=4096, partition_size=1 << 16)
        kw.update(item_kw)
        dev._partition_volume = _LockedVolume(**kw)
        return dev

    def test_unsecured_volume_write_is_refused_before_any_byte(self):
        k32 = FakeKernel32()
        dev = self._dev(k32)
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(VolumeLockError) as ctx:
                dev._raw_write_once(4096 + 512, b"g" * 512)
        self.assertIn("vol", str(ctx.exception))
        self.assertFalse(_writes(k32))
        self.assertEqual(bytes(k32.media[512:1024]), b"\x00" * 512)

    def test_opt_in_flag_lets_unsecured_write_through(self):
        k32 = FakeKernel32()
        dev = self._dev(k32)
        dev._allow_unlocked_volume_write = True
        with patch.object(disk, "kernel32", k32):
            dev._raw_write_once(4096 + 512, b"g" * 512)
        self.assertEqual([c[1] for c in _writes(k32)], [70])
        self.assertEqual(bytes(k32.media[512:1024]), b"g" * 512)

    def test_locked_volume_write_is_unchanged(self):
        k32 = FakeKernel32()
        dev = self._dev(k32, locked=True)
        with patch.object(disk, "kernel32", k32):
            dev._raw_write_once(4096 + 512, b"g" * 512)
        self.assertEqual(bytes(k32.media[512:1024]), b"g" * 512)

    def test_dismounted_only_volume_write_is_allowed(self):
        k32 = FakeKernel32()
        dev = self._dev(k32, dismounted=True)
        with patch.object(disk, "kernel32", k32):
            dev._raw_write_once(4096 + 512, b"g" * 512)
        self.assertEqual(bytes(k32.media[512:1024]), b"g" * 512)


# --------------------------------------------------------------------------
# 2) NtFlushBuffersFile NTSTATUS in _nt_write_volume_handle
# --------------------------------------------------------------------------
class NtVolumeWriteFlushTests(unittest.TestCase):
    def _run(self, nt):
        k32 = FakeKernel32()
        dev = make_dev(k32)
        dev._read_at = lambda absolute, n: nt.log.append("read") or b"v" * n
        item = _LockedVolume(handle=22, name="vol", partition_number=1, locked=True)
        with patch.object(disk, "kernel32", k32), patch.object(disk, "ntdll", nt):
            dev._nt_write_volume_handle(item, 0, b"v" * 512)
        return nt

    def test_negative_ntstatus_raises_post_write_error_before_read_back(self):
        nt = FakeNt(flush_status=NT_FAIL)
        with self.assertRaises(PostWriteError) as ctx:
            self._run(nt)
        self.assertEqual(ctx.exception.winerr, 31)
        self.assertIn("NtFlushBuffersFile", str(ctx.exception))
        self.assertIn("NTSTATUS=0xC0000001", str(ctx.exception))
        # A good read-back must not be able to mask the flush verdict.
        self.assertEqual(nt.log, ["write", "flush"])

    def test_zero_ntstatus_passes_and_reads_back(self):
        nt = self._run(FakeNt(flush_status=0))
        self.assertEqual(nt.log, ["write", "flush", "read"])

    def test_informational_positive_ntstatus_is_success(self):
        # STATUS_PENDING-like non-negative codes are not failures.
        nt = self._run(FakeNt(flush_status=0x103))
        self.assertEqual(nt.flushes, 1)
        self.assertIn("read", nt.log)


# --------------------------------------------------------------------------
# 3) every FlushFileBuffers failure in flush()
# --------------------------------------------------------------------------
class FlushFileBuffersTests(unittest.TestCase):
    def _dev(self, k32):
        dev = make_dev(k32)
        dev._scsi_dirty = True
        dev._scsi_sync_cache_supported = True
        dev._scsi_sync_cache_once = Mock(return_value=(True, None, "DIRECT"))
        return dev

    def test_any_win32_code_raises_and_keeps_dirty(self):
        # 50 (NOT_SUPPORTED), 1 (INVALID_FUNCTION) and 6 (INVALID_HANDLE) used to
        # be tolerated; 31 (GEN_FAILURE) always was fatal. All must raise now.
        for err in (50, 1, 6, 31, 1117):
            with self.subTest(err=err):
                k32 = FakeKernel32(flush_err=err)
                dev = self._dev(k32)
                with patch.object(disk, "kernel32", k32):
                    with self.assertRaises(IoError) as ctx:
                        dev.flush()
                self.assertIsInstance(ctx.exception, PostWriteError)
                self.assertEqual(ctx.exception.winerr, err)
                self.assertTrue(dev._scsi_dirty)

    def test_partition_volume_handle_flush_failure_raises(self):
        k32 = HandleFlushK32(bad={70}, err=50)
        dev = self._dev(k32)
        dev._partition_volume = _LockedVolume(handle=70, name="vol", partition_number=1, locked=True)
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(PostWriteError) as ctx:
                dev.flush()
        self.assertEqual(ctx.exception.winerr, 50)
        self.assertIn("vol", str(ctx.exception))
        self.assertEqual([c[1] for c in _flushes(k32)], [11, 70])
        self.assertTrue(dev._scsi_dirty)

    def test_flush_success_clears_dirty(self):
        k32 = FakeKernel32()
        dev = self._dev(k32)
        dev._partition_volume = _LockedVolume(handle=70, name="vol", partition_number=1, locked=True)
        with patch.object(disk, "kernel32", k32):
            dev.flush()
        self.assertEqual([c[1] for c in _flushes(k32)], [11, 70])
        self.assertFalse(dev._scsi_dirty)

    def test_read_only_or_closed_device_skips_flush(self):
        k32 = FakeKernel32(flush_err=50)
        dev = self._dev(k32)
        dev._writable = False
        with patch.object(disk, "kernel32", k32):
            dev.flush()
        self.assertFalse(_flushes(k32))


# --------------------------------------------------------------------------
# 4) SCSI SYNCHRONIZE CACHE unsupported -> FlushFileBuffers fallback
# --------------------------------------------------------------------------
class ScsiSyncCacheFallbackTests(unittest.TestCase):
    def _dev(self, k32, supported=None, results=None):
        dev = make_dev(k32)
        dev._scsi_dirty = True
        dev._scsi_sync_cache_supported = supported
        dev._scsi_sync_cache_once = Mock(side_effect=list(results or UNSUPPORTED))
        return dev

    def test_unsupported_falls_back_to_flush_file_buffers_and_clears_dirty(self):
        k32 = FakeKernel32()
        dev = self._dev(k32)
        with patch.object(disk, "kernel32", k32):
            dev._scsi_synchronize_cache()
        self.assertEqual(dev._scsi_sync_cache_once.call_count, 2)
        self.assertEqual([c[1] for c in _flushes(k32)], [11])
        self.assertFalse(dev._scsi_dirty)
        self.assertIs(dev._scsi_sync_cache_supported, False)

    def test_unsupported_and_fallback_failure_raises_and_keeps_dirty(self):
        k32 = FakeKernel32(flush_err=1)
        dev = self._dev(k32)
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(IoError) as ctx:
                dev._scsi_synchronize_cache()
        self.assertIsInstance(ctx.exception, PostWriteError)
        self.assertEqual(ctx.exception.winerr, 1)
        self.assertIn("FlushFileBuffers", str(ctx.exception))
        self.assertEqual([c[1] for c in _flushes(k32)], [11])
        self.assertTrue(dev._scsi_dirty)
        self.assertIs(dev._scsi_sync_cache_supported, False)

    def test_learned_unsupported_still_runs_fallback_flush(self):
        k32 = FakeKernel32()
        dev = self._dev(k32, supported=False)
        with patch.object(disk, "kernel32", k32):
            dev._scsi_synchronize_cache()
        dev._scsi_sync_cache_once.assert_not_called()
        self.assertEqual([c[1] for c in _flushes(k32)], [11])
        self.assertFalse(dev._scsi_dirty)

    def test_learned_unsupported_fallback_failure_raises(self):
        k32 = FakeKernel32(flush_err=50)
        dev = self._dev(k32, supported=False)
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(PostWriteError) as ctx:
                dev._scsi_synchronize_cache()
        self.assertEqual(ctx.exception.winerr, 50)
        self.assertTrue(dev._scsi_dirty)

    def test_os_flush_already_failed_raises_without_clearing(self):
        k32 = FakeKernel32()
        dev = self._dev(k32)
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(PostWriteError):
                dev._scsi_synchronize_cache(os_flush_ok=False)
        self.assertFalse(_flushes(k32))  # no second attempt hides the first failure
        self.assertTrue(dev._scsi_dirty)

    def test_supported_sync_cache_without_os_flush_still_flushes_handle(self):
        k32 = FakeKernel32()
        dev = self._dev(k32, results=[(True, None, "DIRECT")])
        with patch.object(disk, "kernel32", k32):
            dev._scsi_synchronize_cache()
        self.assertEqual([c[1] for c in _flushes(k32)], [11])
        self.assertFalse(dev._scsi_dirty)
        self.assertIs(dev._scsi_sync_cache_supported, True)

    def test_supported_sync_cache_with_failing_handle_flush_keeps_dirty(self):
        k32 = FakeKernel32(flush_err=1)
        dev = self._dev(k32, results=[(True, None, "DIRECT")])
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(PostWriteError):
                dev._scsi_synchronize_cache()
        self.assertTrue(dev._scsi_dirty)

    def test_real_sync_cache_failure_is_still_post_write_error(self):
        k32 = FakeKernel32()
        dev = self._dev(
            k32,
            results=[(False, (0x04, 0x00, 0x00), "DIRECT hw"), (False, None, "BUFFERED Win32=31")],
        )
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(PostWriteError):
                dev._scsi_synchronize_cache()
        self.assertTrue(dev._scsi_dirty)
        self.assertIsNone(dev._scsi_sync_cache_supported)

    def test_flush_entry_point_unsupported_device_success(self):
        k32 = FakeKernel32()
        dev = self._dev(k32)
        with patch.object(disk, "kernel32", k32):
            dev.flush()
        # flush() already drained the handle; no duplicate fallback flush.
        self.assertEqual([c[1] for c in _flushes(k32)], [11])
        self.assertFalse(dev._scsi_dirty)

    def test_flush_entry_point_unsupported_device_flush_failure(self):
        k32 = FakeKernel32(flush_err=50)
        dev = self._dev(k32)
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(PostWriteError) as ctx:
                dev.flush()
        self.assertEqual(ctx.exception.winerr, 50)
        self.assertTrue(dev._scsi_dirty)

    def test_clean_device_does_nothing(self):
        k32 = FakeKernel32(flush_err=1)
        dev = self._dev(k32)
        dev._scsi_dirty = False
        with patch.object(disk, "kernel32", k32):
            dev._scsi_synchronize_cache()
        dev._scsi_sync_cache_once.assert_not_called()
        self.assertFalse(_flushes(k32))


if __name__ == "__main__":
    unittest.main()
