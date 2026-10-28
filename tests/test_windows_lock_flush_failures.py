"""Mock-only tests: Windows lock/flush failures must never count as success."""

import base64
import ctypes
import hashlib
import unittest
from unittest.mock import Mock, patch

from ext4lib.io.backend import IoError
from ext4lib.windows import disk
from ext4lib.windows import system_raw as helper
from ext4lib.windows.disk import PostWriteError, _LockedVolume

from tests.test_windows_disk_io import FakeKernel32, _set_out, make_dev

NT_FAIL = -1073741823  # STATUS_UNSUCCESSFUL
ALL_SECURING = {disk.FSCTL_LOCK_VOLUME, disk.FSCTL_DISMOUNT_VOLUME, disk.IOCTL_VOLUME_OFFLINE}


def _devno(disk_number, part=1, dev_type=7):
    return (
        dev_type.to_bytes(4, "little")
        + disk_number.to_bytes(4, "little")
        + part.to_bytes(4, "little")
    )


class VolumeK32(FakeKernel32):
    """One volume on PhysicalDrive9 whose handle is 70."""

    def FindFirstVolumeW(self, buf, n):
        buf.value = "\\\\?\\Volume{a}\\"
        return 5

    def FindNextVolumeW(self, find, buf, n):
        self.SetLastError(disk.ERROR_NO_MORE_FILES)
        return False

    def FindVolumeClose(self, find):
        return True

    def CreateFileW(self, *a):
        return 70


def _volume_ioctl(failing, calls=None):
    def fake_ioctl(handle, code, inbuf=None, out_cb=0):
        if calls is not None:
            calls.append(code)
        if code == disk.IOCTL_STORAGE_GET_DEVICE_NUMBER:
            return _devno(9)
        if code in failing:
            raise OSError(disk.ERROR_ACCESS_DENIED)
        return b""

    return fake_ioctl


class LockFailureTests(unittest.TestCase):
    def _lock(self, failing):
        k32 = VolumeK32()
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "_ioctl", _volume_ioctl(failing)), \
             patch.object(disk, "LOCK_VOLUME_RETRIES", 1), \
             patch.object(disk, "_query_partition_extent", lambda h: (1 << 20, 1 << 20, 1)), \
             patch.object(disk, "_volume_guid_for_fve", lambda n: None):
            return k32, disk._lock_volumes_for_disk(9)

    def test_lock_dismount_offline_all_failing_aborts_without_write(self):
        with self.assertRaises(IoError) as ctx:
            self._lock(ALL_SECURING)
        self.assertEqual(ctx.exception.winerr, disk.ERROR_ACCESS_DENIED)
        self.assertIn("다른 프로세스", str(ctx.exception))
        self.assertIn("Volume{a}", str(ctx.exception))
        self.assertIn("Win32 5", str(ctx.exception))

    def test_abort_closes_volume_handle_and_writes_nothing(self):
        k32 = VolumeK32()
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "_ioctl", _volume_ioctl(ALL_SECURING)), \
             patch.object(disk, "LOCK_VOLUME_RETRIES", 1):
            with self.assertRaises(IoError):
                disk._lock_volumes_for_disk(9)
        self.assertIn(("close", 70), k32.calls)
        self.assertFalse([c for c in k32.calls if c[0] == "write"])

    def test_open_aborts_before_any_write_when_volume_is_held(self):
        k32 = FakeKernel32()
        dev = make_dev(k32)
        dev._raw_write = Mock(side_effect=AssertionError("must not write"))
        dev._expected_size = 0
        dev._expected_serial = ""
        dev._expected_ext_uuid = None
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "_verify_expected_medium", lambda *a, **k: None), \
             patch.object(disk, "_enable_storage_privileges", lambda: True), \
             patch.object(disk, "_open_handle", lambda *a: 11), \
             patch.object(disk, "_lock_volumes_for_disk", Mock(side_effect=IoError("held", winerr=5))):
            with self.assertRaises(IoError):
                dev._reopen_locked()
        dev._raw_write.assert_not_called()
        self.assertFalse([c for c in k32.calls if c[0] == "write"])
        self.assertEqual(dev._volume_locks, [])

    def test_dismount_alone_is_still_enough(self):
        _k32, locked = self._lock({disk.FSCTL_LOCK_VOLUME})
        self.assertEqual(len(locked), 1)
        self.assertFalse(locked[0].locked)
        self.assertTrue(locked[0].offline)

    def test_normal_lock_success_is_unchanged(self):
        _k32, locked = self._lock(set())
        self.assertEqual(len(locked), 1)
        self.assertTrue(locked[0].locked)
        self.assertTrue(locked[0].offline)
        self.assertEqual(locked[0].handle, 70)


class HiddenAliasLockTests(unittest.TestCase):
    def test_all_securing_steps_failing_raises_and_closes_handle(self):
        k32 = FakeKernel32()
        k32.CreateFileW = lambda *a: 40
        fve_calls = []
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "_ioctl", _volume_ioctl(ALL_SECURING)), \
             patch.object(disk, "LOCK_VOLUME_RETRIES", 1), \
             patch.object(disk, "_volume_alias_candidates",
                          lambda: [("\\\\.\\HarddiskVolume27", "guid", "target")]), \
             patch.object(disk, "_query_partition_extent", lambda h: (1 << 20, 1 << 20, 1)), \
             patch.object(disk, "_try_enable_fve_raw_access", lambda *a: "guid"), \
             patch.object(disk, "_fve_raw_access", lambda n, on: fve_calls.append((n, on)) or (True, 0)), \
             patch.object(disk, "_is_writable_ioctl", lambda h: (True, 0)):
            with self.assertRaises(IoError) as ctx:
                disk._open_hidden_volume_alias(9, 1, 1 << 20, 1 << 20)
        self.assertIn("HarddiskVolume27", str(ctx.exception))
        self.assertIn(("close", 40), k32.calls)
        self.assertIn(("guid", False), fve_calls)

    def test_lock_success_returns_writable_handle(self):
        k32 = FakeKernel32()
        k32.CreateFileW = lambda *a: 40
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "_ioctl", _volume_ioctl(set())), \
             patch.object(disk, "_volume_alias_candidates",
                          lambda: [("\\\\.\\HarddiskVolume27", None, "target")]), \
             patch.object(disk, "_query_partition_extent", lambda h: (1 << 20, 1 << 20, 1)), \
             patch.object(disk, "_try_enable_fve_raw_access", lambda *a: None), \
             patch.object(disk, "_is_writable_ioctl", lambda h: (True, 0)):
            item = disk._open_hidden_volume_alias(9, 1, 1 << 20, 1 << 20)
        self.assertEqual(item.handle, 40)
        self.assertTrue(item.locked)
        self.assertTrue(item.offline)


class PartitionDeviceLockTests(unittest.TestCase):
    def _open(self, failing):
        k32 = FakeKernel32()
        k32.CreateFileW = lambda *a: 40
        codes = []
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "_ioctl", _volume_ioctl(failing, codes)), \
             patch.object(disk, "LOCK_VOLUME_RETRIES", 1), \
             patch.object(disk, "_query_partition_extent", lambda h: (1 << 20, 1 << 20, 1)), \
             patch.object(disk, "_is_writable_ioctl", lambda h: (True, 0)):
            return k32, codes, disk._open_partition_device(9, 1, 1 << 20, 1 << 20)

    def test_all_securing_steps_failing_raises_and_closes_handle(self):
        k32 = FakeKernel32()
        k32.CreateFileW = lambda *a: 40
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "_ioctl", _volume_ioctl(ALL_SECURING)), \
             patch.object(disk, "LOCK_VOLUME_RETRIES", 1), \
             patch.object(disk, "_query_partition_extent", lambda h: (1 << 20, 1 << 20, 1)), \
             patch.object(disk, "_is_writable_ioctl", lambda h: (True, 0)):
            with self.assertRaises(IoError) as ctx:
                disk._open_partition_device(9, 1, 1 << 20, 1 << 20)
        self.assertIn("Harddisk9Partition1", str(ctx.exception))
        self.assertIn("Win32 5", str(ctx.exception))
        self.assertIn(("close", 40), k32.calls)

    def test_lock_then_dismount_then_offline(self):
        _k32, codes, item = self._open(set())
        order = [c for c in codes if c in ALL_SECURING]
        self.assertEqual(
            order,
            [disk.FSCTL_LOCK_VOLUME, disk.FSCTL_DISMOUNT_VOLUME, disk.IOCTL_VOLUME_OFFLINE],
        )
        self.assertTrue(item.locked)
        self.assertTrue(item.offline)

    def test_lock_failure_with_dismount_still_takes_offline(self):
        _k32, _codes, item = self._open({disk.FSCTL_LOCK_VOLUME})
        self.assertFalse(item.locked)
        self.assertTrue(item.offline)

    def test_dismount_failure_skips_offline_but_lock_is_enough(self):
        _k32, codes, item = self._open({disk.FSCTL_DISMOUNT_VOLUME})
        self.assertNotIn(disk.IOCTL_VOLUME_OFFLINE, codes)
        self.assertTrue(item.locked)
        self.assertFalse(item.offline)


class ScanK32(FakeKernel32):
    """Volumes a, b, ...; handle 70+i for read/write opens, 170+i for probes."""

    def __init__(self, count=1, first_err=0, next_err=disk.ERROR_NO_MORE_FILES,
                 open_fail=(), probe_fail=()):
        super().__init__()
        self.names = [f"\\\\?\\Volume{{{chr(97 + i)}}}" for i in range(count)]
        self.first_err = first_err
        self.next_err = next_err
        self.open_fail = set(open_fail)
        self.probe_fail = set(probe_fail)
        self.i = 0

    def FindFirstVolumeW(self, buf, n):
        if self.first_err:
            self.SetLastError(self.first_err)
            return disk.INVALID_HANDLE_VALUE
        self.i = 0
        buf.value = self.names[0] + "\\"
        return 5

    def FindNextVolumeW(self, find, buf, n):
        self.i += 1
        if self.i < len(self.names):
            buf.value = self.names[self.i] + "\\"
            return True
        self.SetLastError(self.next_err)
        return False

    def FindVolumeClose(self, find):
        return True

    def CreateFileW(self, path, access, *a):
        i = self.names.index(path)
        if access and i in self.open_fail:
            self.SetLastError(disk.ERROR_ACCESS_DENIED)
            return disk.INVALID_HANDLE_VALUE
        if not access and i in self.probe_fail:
            self.SetLastError(disk.ERROR_ACCESS_DENIED)
            return disk.INVALID_HANDLE_VALUE
        return (70 if access else 170) + i


def _scan_ioctl(disks, extents=None):
    """disks[i]: PhysicalDrive number of volume i, or None if unanswered."""
    extents = extents or {}

    def fake_ioctl(handle, code, inbuf=None, out_cb=0):
        i = int(handle) % 100 - 70
        if code == disk.IOCTL_STORAGE_GET_DEVICE_NUMBER:
            if disks[i] is None:
                raise OSError(1)
            return _devno(disks[i])
        if code == disk.IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS:
            if i not in extents:
                raise OSError(1)
            nums = extents[i]
            out = len(nums).to_bytes(4, "little") + b"\0" * 4
            for num in nums:
                out += num.to_bytes(4, "little") + b"\0" * 20
            return out
        return b""

    return fake_ioctl


class VolumeScanTests(unittest.TestCase):
    def _scan(self, k32, disks, extents=None):
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "_ioctl", _scan_ioctl(disks, extents)), \
             patch.object(disk, "_query_partition_extent", lambda h: None), \
             patch.object(disk, "_volume_guid_for_fve", lambda n: None):
            return disk._lock_volumes_for_disk(9)

    def test_find_first_volume_failure_aborts(self):
        with self.assertRaises(IoError) as ctx:
            self._scan(ScanK32(first_err=disk.ERROR_ACCESS_DENIED), [9])
        self.assertIn("FindFirstVolumeW", str(ctx.exception))
        self.assertEqual(ctx.exception.winerr, disk.ERROR_ACCESS_DENIED)

    def test_find_first_volume_no_more_files_is_an_empty_list(self):
        self.assertEqual(self._scan(ScanK32(first_err=disk.ERROR_NO_MORE_FILES), [9]), [])

    def test_find_next_volume_failure_aborts_and_releases_locks(self):
        released = []
        with patch.object(disk, "_release_locked_volume", released.append):
            with self.assertRaises(IoError) as ctx:
                self._scan(ScanK32(next_err=21), [9])
        self.assertIn("FindNextVolumeW", str(ctx.exception))
        self.assertEqual(ctx.exception.winerr, 21)
        self.assertEqual([item.handle for item in released], [70])

    def test_open_failure_on_target_disk_aborts(self):
        with self.assertRaises(IoError) as ctx:
            self._scan(ScanK32(count=2, open_fail={1}), [3, 9])
        self.assertIn("Volume{b}", str(ctx.exception))
        self.assertEqual(ctx.exception.winerr, disk.ERROR_ACCESS_DENIED)

    def test_open_failure_on_unidentifiable_volume_aborts(self):
        with self.assertRaises(IoError):
            self._scan(ScanK32(count=2, open_fail={1}, probe_fail={1}), [3, 9])

    def test_open_failure_on_other_disk_is_skipped(self):
        k32 = ScanK32(count=2, open_fail={0})
        locked = self._scan(k32, [3, 9])
        self.assertEqual([item.handle for item in locked], [71])
        self.assertIn(("close", 170), k32.calls)

    def test_unidentified_volume_aborts(self):
        with self.assertRaises(IoError) as ctx:
            self._scan(ScanK32(count=2), [3, None])
        self.assertIn("Volume{b}", str(ctx.exception))

    def test_spanned_volume_on_target_disk_is_locked_via_extents(self):
        locked = self._scan(ScanK32(count=2), [3, None], extents={1: [2, 9]})
        self.assertEqual([item.handle for item in locked], [71])

    def test_spanned_volume_on_other_disks_is_skipped(self):
        k32 = ScanK32(count=1)
        self.assertEqual(self._scan(k32, [None], extents={0: [2, 3]}), [])
        self.assertIn(("close", 70), k32.calls)


class PartitionK32(FakeKernel32):
    def __init__(self, open_ok=True, **kw):
        super().__init__(**kw)
        self.open_ok = open_ok

    def CreateFileW(self, path, *a):
        if not self.open_ok:
            self.SetLastError(2)
            return disk.INVALID_HANDLE_VALUE
        return 40


class FakeNt:
    def __init__(self, flush_status=0, media=None, log=None):
        self.flush_status = flush_status
        self.flushes = 0
        self.media = media
        self.log = log if log is not None else []

    def NtWriteFile(self, handle, ev, apc, ctx, iosb, buf, length, off, key):
        self.log.append("write")
        if self.media is not None:
            start = off._obj.value
            self.media[start : start + length] = bytes(buf)[:length]
        iosb._obj.Information = length
        return 0

    def NtFlushBuffersFile(self, handle, iosb):
        self.log.append("flush")
        self.flushes += 1
        return self.flush_status

    def RtlNtStatusToDosError(self, status):
        return 31

    def NtClose(self, handle):
        return 0


class WritePathFlushTests(unittest.TestCase):
    def _dev(self, k32):
        dev = make_dev(k32)
        dev._partition_number = 1
        dev._partition_offset = 4096
        dev._partition_size = 1 << 16
        dev._read_at = lambda absolute, n: bytes(k32.media[absolute - 4096 : absolute - 4096 + n])
        return dev

    def _run_partition(self, k32, nt):
        dev = self._dev(k32)
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "ntdll", nt), \
             patch.object(disk, "_allow_extended_io", lambda h: None), \
             patch.object(disk, "_nt_open_raw_handle", lambda p: 55):
            dev._write_locked_partition_device(512, b"z" * 512)

    def test_partition_win32_flush_failure_raises_despite_good_readback(self):
        k32 = PartitionK32(flush_err=1)
        with self.assertRaises(PostWriteError) as ctx:
            self._run_partition(k32, FakeNt())
        self.assertEqual(ctx.exception.winerr, 1)
        self.assertIn("FlushFileBuffers", str(ctx.exception))
        # The data itself landed, so only the flush result caused the error.
        self.assertEqual(bytes(k32.media[512:1024]), b"z" * 512)

    def test_partition_native_flush_failure_raises_at_once(self):
        k32 = PartitionK32(open_ok=False)
        nt = FakeNt(flush_status=NT_FAIL)
        with self.assertRaises(PostWriteError) as ctx:
            self._run_partition(k32, nt)
        self.assertIn("NtFlushBuffersFile", str(ctx.exception))
        # The second partition alias must not be tried after a written-but-unflushed payload.
        self.assertEqual(nt.flushes, 1)

    def test_partition_success_path_is_unchanged(self):
        k32 = PartitionK32()
        self._run_partition(k32, FakeNt())
        self.assertEqual(bytes(k32.media[512:1024]), b"z" * 512)
        self.assertIn(("flush", 40), k32.calls)

    def test_partition_native_success_path_is_unchanged(self):
        k32 = PartitionK32(open_ok=False)
        nt = FakeNt(media=k32.media)
        self._run_partition(k32, nt)
        self.assertEqual(bytes(k32.media[512:1024]), b"z" * 512)
        self.assertEqual(nt.flushes, 1)

    def _run_volume(self, nt):
        k32 = FakeKernel32()
        dev = self._dev(k32)
        dev._read_at = lambda absolute, n: b"v" * n
        item = _LockedVolume(handle=22, name="vol", partition_number=1, locked=True)
        with patch.object(disk, "kernel32", k32), patch.object(disk, "ntdll", nt):
            dev._nt_write_volume_handle(item, 0, b"v" * 512)

    def test_volume_handle_flush_failure_raises_despite_good_readback(self):
        with self.assertRaises(PostWriteError) as ctx:
            self._run_volume(FakeNt(flush_status=NT_FAIL))
        self.assertEqual(ctx.exception.winerr, 31)
        self.assertIn("NtFlushBuffersFile", str(ctx.exception))
        self.assertIn("vol", str(ctx.exception))

    def test_volume_handle_success_path_is_unchanged(self):
        nt = FakeNt()
        self._run_volume(nt)
        self.assertEqual(nt.flushes, 1)

    def _run_nt_write_at(self, nt):
        k32 = FakeKernel32()
        dev = make_dev(k32)
        dev._nt_handle = 55
        dev._read_at = lambda absolute, n: nt.log.append("read") or b"n" * n
        with patch.object(disk, "ntdll", nt):
            dev._nt_write_at(4096, b"n" * 512)

    def test_nt_write_at_flushes_before_read_back(self):
        nt = FakeNt()
        self._run_nt_write_at(nt)
        self.assertEqual(nt.log, ["write", "flush", "read"])

    def test_nt_write_at_flush_failure_raises_without_read_back(self):
        nt = FakeNt(flush_status=NT_FAIL)
        with self.assertRaises(PostWriteError) as ctx:
            self._run_nt_write_at(nt)
        self.assertEqual(ctx.exception.winerr, 31)
        self.assertIn("PhysicalDrive9", str(ctx.exception))
        self.assertEqual(nt.log, ["write", "flush"])


class DeniedK32(FakeKernel32):
    """WriteFile writes ``first_chunk`` bytes once, then fails with Win32 5."""

    def __init__(self, first_chunk=0, **kw):
        super().__init__(**kw)
        self.first_chunk = first_chunk

    def WriteFile(self, handle, buf, length, done, ov):
        if self.first_chunk:
            n, self.first_chunk = self.first_chunk, 0
            self.calls.append(("write", handle, self.pos[handle], n))
            _set_out(done, n)
            return True
        _set_out(done, 0)
        ctypes.set_last_error(disk.ERROR_ACCESS_DENIED)
        return False


class VolumeSeekFallbackTests(unittest.TestCase):
    def _run(self, k32, nt_write):
        dev = make_dev(k32)
        dev._partition_offset = 4096
        dev._nt_write_volume_handle = nt_write
        dev._fallback_after_volume_access_denied = Mock()
        item = _LockedVolume(handle=22, name="vol", partition_number=1, locked=True)
        with patch.object(disk, "kernel32", k32):
            dev._write_volume_seek(item, 0, b"q" * 1024)
        return dev

    def test_flush_error_after_nt_write_propagates_without_fallback(self):
        k32 = DeniedK32()
        nt_write = Mock(side_effect=PostWriteError("vol NtFlushBuffersFile 실패", winerr=31))
        dev = make_dev(k32)
        dev._nt_write_volume_handle = nt_write
        dev._fallback_after_volume_access_denied = Mock()
        item = _LockedVolume(handle=22, name="vol", partition_number=1, locked=True)
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(PostWriteError) as ctx:
                dev._write_volume_seek(item, 0, b"q" * 1024)
        self.assertEqual(ctx.exception.winerr, 31)
        dev._fallback_after_volume_access_denied.assert_not_called()

    def test_error_before_any_byte_may_fall_back(self):
        dev = self._run(DeniedK32(), Mock(side_effect=IoError("nt denied", winerr=5)))
        dev._fallback_after_volume_access_denied.assert_called_once()

    def test_denied_after_partial_write_raises_without_fallback(self):
        k32 = DeniedK32(first_chunk=512)
        nt_write = Mock()
        dev = make_dev(k32)
        dev._nt_write_volume_handle = nt_write
        dev._fallback_after_volume_access_denied = Mock()
        item = _LockedVolume(handle=22, name="vol", partition_number=1, locked=True)
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(PostWriteError) as ctx:
                dev._write_volume_seek(item, 0, b"q" * 1024)
        self.assertIn("vol", str(ctx.exception))
        nt_write.assert_not_called()
        dev._fallback_after_volume_access_denied.assert_not_called()

    def test_fallback_physicaldrive_flush_failure_stops_the_chain(self):
        k32 = FakeKernel32(flush_err=1)
        dev = make_dev(k32)
        dev._partition_offset = 4096
        dev._write_blockers = []
        dev._write_locked_partition_device = Mock(side_effect=IoError("denied", winerr=5))
        dev._nt_write_at = Mock()
        dev._scsi_write10 = Mock()
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(PostWriteError) as ctx:
                dev._fallback_after_volume_access_denied(0, b"p" * 512)
        self.assertEqual(ctx.exception.winerr, 1)
        self.assertIn("PhysicalDrive9", str(ctx.exception))
        dev._nt_write_at.assert_not_called()
        dev._scsi_write10.assert_not_called()


class DirtyFlagTests(unittest.TestCase):
    def _dev(self, k32):
        dev = make_dev(k32)
        dev._scsi_dirty = True
        dev._scsi_sync_cache_supported = None
        return dev

    def test_flush_failure_on_known_no_sync_cache_device_keeps_dirty(self):
        k32 = FakeKernel32(flush_err=1)  # ERROR_INVALID_FUNCTION
        dev = self._dev(k32)
        dev._scsi_sync_cache_supported = False
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(IoError):
                dev.flush()
        self.assertTrue(dev._scsi_dirty)

    def test_flush_failure_when_sync_cache_turns_out_unsupported_keeps_dirty(self):
        k32 = FakeKernel32(flush_err=1)
        dev = self._dev(k32)
        dev._scsi_sync_cache_once = Mock(
            side_effect=[
                (False, (0x05, 0x20, 0x00), "DIRECT invalid opcode"),
                (False, (0x05, 0x20, 0x00), "BUFFERED invalid opcode"),
            ]
        )
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(IoError) as ctx:
                dev.flush()
        # The Windows flush error is reported, not the SCSI fallback message.
        self.assertEqual(ctx.exception.winerr, 1)
        self.assertTrue(dev._scsi_dirty)
        self.assertFalse(dev._scsi_sync_cache_supported)

    def test_native_flush_failure_keeps_dirty(self):
        k32 = FakeKernel32()
        dev = self._dev(k32)
        dev._scsi_sync_cache_supported = False
        dev._nt_handle = 33
        nt = FakeNt(flush_status=NT_FAIL)  # Win32 31: formerly only a warning
        with patch.object(disk, "kernel32", k32), patch.object(disk, "ntdll", nt):
            with self.assertRaises(IoError) as ctx:
                dev.flush()
        self.assertEqual(ctx.exception.winerr, 31)
        self.assertIn("NtFlushBuffersFile", str(ctx.exception))
        self.assertTrue(dev._scsi_dirty)

    def test_successful_os_flush_still_clears_dirty_without_sync_cache(self):
        k32 = FakeKernel32()
        dev = self._dev(k32)
        dev._scsi_sync_cache_supported = False
        with patch.object(disk, "kernel32", k32):
            dev.flush()
        self.assertFalse(dev._scsi_dirty)

    def test_successful_sync_cache_and_os_flush_clear_dirty(self):
        k32 = FakeKernel32()
        dev = self._dev(k32)
        dev._scsi_sync_cache_once = Mock(return_value=(True, None, "DIRECT"))
        with patch.object(disk, "kernel32", k32):
            dev.flush()
        self.assertFalse(dev._scsi_dirty)

    def test_working_sync_cache_does_not_clear_dirty_when_os_flush_failed(self):
        k32 = FakeKernel32(flush_err=1)
        dev = self._dev(k32)
        dev._scsi_sync_cache_once = Mock(return_value=(True, None, "DIRECT"))
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(PostWriteError) as ctx:
                dev.flush()
        self.assertEqual(ctx.exception.winerr, 1)
        dev._scsi_sync_cache_once.assert_called_once()
        self.assertTrue(dev._scsi_dirty)


class HelperK32:
    def __init__(self, flush_err=0):
        self.flush_err = flush_err

    def SetLastError(self, err):
        ctypes.set_last_error(err)

    def SetFilePointerEx(self, *a):
        return True

    def WriteFile(self, handle, buf, length, done, ov):
        _set_out(done, length)
        return True

    def FlushFileBuffers(self, handle):
        if self.flush_err:
            ctypes.set_last_error(self.flush_err)
            return False
        return True


class SystemHelperFlushTests(unittest.TestCase):
    def test_write_win32_flush_failure_raises(self):
        with patch.object(disk, "kernel32", HelperK32(flush_err=1)):
            with self.assertRaises(PostWriteError) as ctx:
                helper._write_win32(77, 4096, b"w" * 512)
        self.assertEqual(ctx.exception.winerr, 1)
        self.assertIn("FlushFileBuffers", str(ctx.exception))

    def test_write_win32_success(self):
        with patch.object(disk, "kernel32", HelperK32()):
            helper._write_win32(77, 4096, b"w" * 512)

    def test_write_nt_flush_failure_raises(self):
        with patch.object(disk, "ntdll", FakeNt(flush_status=NT_FAIL)):
            with self.assertRaises(PostWriteError) as ctx:
                helper._write_nt(77, 4096, b"w" * 512)
        self.assertEqual(ctx.exception.winerr, 31)
        self.assertIn("NtFlushBuffersFile", str(ctx.exception))

    def test_execute_request_stops_after_post_write_failure(self):
        data = b"x" * 4096
        req = {
            "physical_path": r"\\.\PhysicalDrive1",
            "parent_pid": 1234,
            "physical_handle": 5678,
            "volume_handle": 9012,
            "relative_offset": 4755456,
            "absolute_offset": 5804032,
            "partition_offset": 1048576,
            "partition_size": 1023869452288,
            "sector_size": 512,
            "data_b64": base64.b64encode(data).decode("ascii"),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        devno = disk.STORAGE_DEVICE_NUMBER()
        devno.DeviceType = 7
        devno.DeviceNumber = 1
        write_nt = Mock()
        unbuffered = Mock()
        with patch.object(helper, "_duplicate_handle", side_effect=lambda pid, h: h), \
             patch.object(disk, "_query_storage", return_value=("", "Reader", 7, True)), \
             patch.object(disk, "_enable_storage_privileges", lambda: True), \
             patch.object(disk, "_ioctl", return_value=bytes(devno)), \
             patch.object(disk, "kernel32", HelperK32()), \
             patch.object(helper, "_write_win32",
                          side_effect=PostWriteError("SYSTEM FlushFileBuffers 실패 (Win32 1)", winerr=1)), \
             patch.object(helper, "_write_nt", write_nt), \
             patch.object(disk, "_write_unbuffered_raw_path", unbuffered):
            result = helper._execute_request(req)
        self.assertFalse(result["ok"])
        self.assertTrue(result["post_write"])
        self.assertIn("Win32 1", result["error"])
        write_nt.assert_not_called()
        unbuffered.assert_not_called()


if __name__ == "__main__":
    unittest.main()
