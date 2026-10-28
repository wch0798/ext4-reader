"""Mock-only tests: post-write failures are never retried or rerouted."""

import base64
import hashlib
import unittest
from unittest.mock import Mock, patch

from ext4lib.io.backend import IoError
from ext4lib.windows import disk
from ext4lib.windows import system_raw as helper
from ext4lib.windows.disk import PostWriteError

from tests.test_windows_disk_io import FakeKernel32, make_dev
from tests.test_windows_lock_flush_failures import NT_FAIL, FakeNt, HelperK32


def _write_calls(k32):
    return [c for c in k32.calls if c[0] == "write"]


class RetryPostWriteTests(unittest.TestCase):
    def test_flush_failure_with_gen_failure_is_not_retried(self):
        # Win32 31 is a retry code, but on a flush it follows a real write.
        k32 = FakeKernel32(flush_err=31)
        dev = make_dev(k32, writable=True)
        reopened = []
        dev._reopen_locked = lambda: reopened.append(1)

        def write_once(offset, data):
            dev._write_at(offset, data)
            disk._flush_handle_checked(dev._handle, dev.path)

        dev._raw_write_once = write_once
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(PostWriteError) as ctx:
                dev._raw_write(4096, b"a" * 512)
        self.assertEqual(ctx.exception.winerr, 31)
        self.assertEqual(len(_write_calls(k32)), 1)
        self.assertEqual(reopened, [])

    def test_retry_code_write_error_is_still_retried(self):
        k32 = FakeKernel32()
        dev = make_dev(k32, writable=True)
        reopened = []
        dev._reopen_locked = lambda: reopened.append(1)
        attempts = []

        def write_once(offset, data):
            attempts.append(offset)
            if len(attempts) == 1:
                raise IoError("gen failure", winerr=31)
            dev._write_at(offset, data)

        dev._raw_write_once = write_once
        with patch.object(disk, "kernel32", k32):
            dev._raw_write(4096, b"b" * 512)
        self.assertEqual(attempts, [4096, 4096])
        self.assertEqual(reopened, [1])
        self.assertEqual(bytes(k32.media[4096:4608]), b"b" * 512)


class RawWriteRetryPathTests(unittest.TestCase):
    def test_transient_failure_then_real_write_succeeds(self):
        k32 = FakeKernel32()
        dev = make_dev(k32, writable=True)
        dev._reopen_locked = Mock()
        real_write_at = dev._write_at
        failures = [IoError("aborted", winerr=995)]

        def write_at(offset, data):
            if failures:
                raise failures.pop()
            real_write_at(offset, data)

        dev._write_at = write_at
        with patch.object(disk, "kernel32", k32):
            dev._raw_write(8192, b"c" * 1024)
        dev._reopen_locked.assert_called_once()
        self.assertEqual(len(_write_calls(k32)), 1)
        self.assertEqual(bytes(k32.media[8192:9216]), b"c" * 1024)

    def test_post_write_error_propagates_through_raw_write(self):
        k32 = FakeKernel32()
        dev = make_dev(k32, writable=True)
        dev._reopen_locked = Mock()
        dev._write_at = Mock(side_effect=PostWriteError("short write", winerr=31))
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(PostWriteError):
                dev._raw_write(8192, b"d" * 512)
        dev._write_at.assert_called_once()
        dev._reopen_locked.assert_not_called()


class ScsiReadBackTests(unittest.TestCase):
    def _dev(self, read_back):
        dev = make_dev(FakeKernel32(), writable=True)
        dev._scsi_fua_supported = None
        dev._scsi_sync_cache_supported = None
        dev._read_at = read_back
        dev._scsi_write10_buffered = Mock()
        return dev

    def test_direct_read_back_mismatch_is_post_write_without_fallback(self):
        dev = self._dev(Mock(return_value=b"\x00" * 512))
        with patch.object(disk.kernel32, "DeviceIoControl", return_value=True):
            with self.assertRaises(PostWriteError) as ctx:
                dev._scsi_write10(0, b"e" * 512)
        self.assertEqual(ctx.exception.winerr, 23)
        dev._scsi_write10_buffered.assert_not_called()

    def test_direct_read_back_io_error_is_post_write_without_fallback(self):
        dev = self._dev(Mock(side_effect=IoError("read fail", winerr=31)))
        with patch.object(disk.kernel32, "DeviceIoControl", return_value=True):
            with self.assertRaises(PostWriteError):
                dev._scsi_write10(0, b"e" * 512)
        dev._scsi_write10_buffered.assert_not_called()

    def test_buffered_read_back_mismatch_is_post_write(self):
        dev = self._dev(Mock(return_value=b"\x00" * 512))
        with patch.object(disk.kernel32, "DeviceIoControl", return_value=True):
            with self.assertRaises(PostWriteError):
                disk.WindowsPhysicalDevice._scsi_write10_buffered(dev, 0, b"e" * 512)

    def test_scsi_post_write_error_stops_fallback_chain(self):
        dev = make_dev(FakeKernel32(), writable=True)
        dev._write_blockers = []
        escalated = []
        fail5 = Mock(side_effect=IoError("denied", winerr=5))
        dev._write_locked_partition_device = fail5
        dev._write_at = fail5
        dev._nt_write_at = fail5
        dev._prepare_system_helper_handle = lambda: None
        dev._write_unbuffered_physical = fail5
        dev._scsi_write10 = Mock(side_effect=PostWriteError("mismatch", winerr=23))
        dev._activate_whole_disk_offline = lambda: escalated.append("offline") or (False, 5)
        with self.assertRaises(PostWriteError):
            dev._fallback_after_volume_access_denied(0, b"x" * 512)
        dev._scsi_write10.assert_called_once()
        self.assertEqual(escalated, [])


class PartialWriteGapTests(unittest.TestCase):
    """Failures after some bytes reached the device are PostWriteError."""

    def test_overlapped_short_write_continuation_failure_is_post_write(self):
        k32 = FakeKernel32(max_chunk=256)
        k32.pos[11] = 0  # the fake ignores OVERLAPPED offsets
        dev = make_dev(k32, writable=True)
        dev._use_overlapped = True
        dev._write_seek = Mock(side_effect=IoError("seek fail", winerr=5))
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(PostWriteError):
                dev._write_at(0, b"a" * 512)

    def test_overlapped_failure_after_partial_completion_is_post_write(self):
        k32 = FakeKernel32()
        k32.pos[11] = 0
        dev = make_dev(k32, writable=True)
        dev._use_overlapped = True
        dev._finish_overlapped = Mock(side_effect=IoError("pending fail", winerr=31))
        dev._write_seek = Mock()
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(PostWriteError):
                dev._write_at(0, b"a" * 512)
        dev._write_seek.assert_not_called()

    def test_raw_write_later_chunk_failure_is_not_retried(self):
        k32 = FakeKernel32()
        dev = make_dev(k32, writable=True)
        dev._reopen_locked = Mock()
        dev._write_at = Mock(side_effect=[None, IoError("gen failure", winerr=31)])
        with patch.object(disk, "kernel32", k32), patch.object(disk, "IO_CHUNK", 512):
            with self.assertRaises(PostWriteError):
                dev._raw_write(0, b"f" * 1024)
        self.assertEqual(dev._write_at.call_count, 2)
        dev._reopen_locked.assert_not_called()

    def test_volume_seek_failure_after_short_write_is_post_write(self):
        class SeekFailK32(FakeKernel32):
            seeks = 0

            def SetFilePointerEx(self, handle, offset, new_pos, whence):
                self.seeks += 1
                if self.seeks > 1:
                    disk.ctypes.set_last_error(5)
                    return False
                return super().SetFilePointerEx(handle, offset, new_pos, whence)

        k32 = SeekFailK32(max_chunk=256)
        dev = make_dev(k32, writable=True)
        item = Mock(handle=21, offline=False)
        item.name = "HarddiskVolume9"
        dev._fallback_after_volume_access_denied = Mock()
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(PostWriteError):
                dev._write_volume_seek(item, 0, b"g" * 512)
        dev._fallback_after_volume_access_denied.assert_not_called()

    def test_partition_device_partial_write_then_device_gone_is_post_write(self):
        gone = next(iter(disk.DEVICE_GONE_ERRORS))

        class GoneK32(FakeKernel32):
            def CreateFileW(self, *args):
                return 21

            def WriteFile(self, handle, buf, length, done, ov):
                super().WriteFile(handle, buf, 256, done, ov)
                disk.ctypes.set_last_error(gone)
                return False

        k32 = GoneK32()
        dev = make_dev(k32, writable=True)
        dev._partition_number = 1
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "_allow_extended_io", lambda h: None):
            with self.assertRaises(PostWriteError):
                dev._write_locked_partition_device(0, b"h" * 512)

    def test_scsi_later_chunk_failure_is_post_write(self):
        dev = make_dev(FakeKernel32(), writable=True)
        dev._scsi_max_transfer = 512
        dev._scsi_write10_one = Mock(side_effect=[None, IoError("denied", winerr=5)])
        with self.assertRaises(PostWriteError):
            dev._scsi_write10(0, b"i" * 1024)

    def test_scsi_first_chunk_failure_stays_plain_io_error(self):
        dev = make_dev(FakeKernel32(), writable=True)
        dev._scsi_max_transfer = 512
        dev._scsi_write10_one = Mock(side_effect=IoError("denied", winerr=5))
        with self.assertRaises(IoError) as ctx:
            dev._scsi_write10(0, b"i" * 1024)
        self.assertNotIsInstance(ctx.exception, PostWriteError)

    def test_scsi_cache_sync_failure_is_post_write(self):
        dev = make_dev(FakeKernel32(), writable=True)
        dev._scsi_dirty = True
        dev._scsi_sync_cache_supported = None
        dev._scsi_sync_cache_once = Mock(return_value=(False, None, "DIRECT Win32=31"))
        with self.assertRaises(PostWriteError):
            dev._scsi_synchronize_cache()
        self.assertTrue(dev._scsi_dirty)

    def test_usbdk_post_write_error_is_not_rewrapped(self):
        dev = make_dev(FakeKernel32(), writable=True)
        dev._write_blockers = []
        dev._removable = True
        dev._bus_type = 7
        fail5 = Mock(side_effect=IoError("denied", winerr=5))
        dev._write_locked_partition_device = fail5
        dev._write_at = fail5
        dev._nt_write_at = fail5
        dev._prepare_system_helper_handle = lambda: None
        dev._write_unbuffered_physical = fail5
        dev._scsi_write10 = fail5
        dev._activate_whole_disk_offline = lambda: (False, 5)
        usbdk = Mock()
        usbdk.write.side_effect = PostWriteError("usb verify", winerr=23)
        dev._activate_usbdk_backend = lambda: setattr(dev, "_usbdk", usbdk)
        with patch.object(helper, "run_system_raw_write",
                          return_value={"ok": False, "error": "denied"}):
            with self.assertRaises(PostWriteError) as ctx:
                dev._fallback_after_volume_access_denied(0, b"j" * 512)
        self.assertEqual(ctx.exception.winerr, 23)


class HelperReadBackTests(unittest.TestCase):
    def test_read_back_io_error_stops_helper_routes(self):
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
        write_win32 = Mock()
        write_nt = Mock()
        unbuffered = Mock()
        with patch.object(helper, "_duplicate_handle", side_effect=lambda pid, h: h), \
             patch.object(disk, "_query_storage", return_value=("", "Reader", 7, True)), \
             patch.object(disk, "_enable_storage_privileges", lambda: True), \
             patch.object(disk, "_ioctl", return_value=bytes(devno)), \
             patch.object(disk, "kernel32", HelperK32()), \
             patch.object(helper, "_write_win32", write_win32), \
             patch.object(helper, "_read_win32",
                          side_effect=IoError("SYSTEM read-back 실패", winerr=31)), \
             patch.object(helper, "_write_nt", write_nt), \
             patch.object(disk, "_write_unbuffered_raw_path", unbuffered):
            result = helper._execute_request(req)
        self.assertFalse(result["ok"])
        self.assertTrue(result["post_write"])
        write_win32.assert_called_once()
        write_nt.assert_not_called()
        unbuffered.assert_not_called()


class PartialNt(FakeNt):
    """NtWriteFile that transfers half the payload, then fails."""

    def NtWriteFile(self, handle, ev, apc, ctx, iosb, buf, length, off, key):
        self.log.append("write")
        iosb._obj.Information = length // 2
        return NT_FAIL


def _nt_writes(nt):
    return [c for c in nt.log if c == "write"]


class RemainingPostWriteGapTests(unittest.TestCase):
    """Failures after a write reached the device: no retry, no other route."""

    def test_write_seek_reseek_failure_after_short_write_is_not_retried(self):
        class SeekFailK32(FakeKernel32):
            seeks = 0

            def SetFilePointerEx(self, handle, offset, new_pos, whence):
                self.seeks += 1
                if self.seeks > 1:
                    disk.ctypes.set_last_error(31)
                    return False
                return super().SetFilePointerEx(handle, offset, new_pos, whence)

        k32 = SeekFailK32(max_chunk=256)
        dev = make_dev(k32, writable=True)
        dev._reopen_locked = Mock()
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(PostWriteError) as ctx:
                dev._raw_write(0, b"j" * 512)
        self.assertEqual(ctx.exception.winerr, 31)
        self.assertEqual(len(_write_calls(k32)), 1)
        dev._reopen_locked.assert_not_called()

    def test_volume_partial_write_with_access_denied_is_not_rerouted(self):
        class DeniedK32(FakeKernel32):
            def WriteFile(self, handle, buf, length, done, ov):
                super().WriteFile(handle, buf, length // 2, done, ov)
                disk.ctypes.set_last_error(5)
                return False

        k32 = DeniedK32()
        dev = make_dev(k32, writable=True)
        item = Mock(handle=21, offline=False)
        item.name = "HarddiskVolume9"
        dev._nt_write_volume_handle = Mock()
        dev._fallback_after_volume_access_denied = Mock()
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(PostWriteError):
                dev._write_volume_seek(item, 0, b"k" * 512)
        self.assertEqual(len(_write_calls(k32)), 1)
        dev._nt_write_volume_handle.assert_not_called()
        dev._fallback_after_volume_access_denied.assert_not_called()

    def test_volume_nt_partial_failure_stops_fallback(self):
        class DeniedK32(FakeKernel32):
            def WriteFile(self, handle, buf, length, done, ov):
                disk.ctypes.set_last_error(5)
                return False

        k32 = DeniedK32()
        nt = PartialNt(log=[])
        dev = make_dev(k32, writable=True)
        item = Mock(handle=21, offline=False)
        item.name = "HarddiskVolume9"
        dev._fallback_after_volume_access_denied = Mock()
        with patch.object(disk, "kernel32", k32), patch.object(disk, "ntdll", nt):
            with self.assertRaises(PostWriteError):
                dev._write_volume_seek(item, 0, b"l" * 512)
        self.assertEqual(len(_nt_writes(nt)), 1)
        dev._fallback_after_volume_access_denied.assert_not_called()

    def test_physical_nt_partial_failure_stops_fallback_chain(self):
        nt = PartialNt(log=[])
        dev = make_dev(FakeKernel32(), writable=True)
        dev._write_blockers = []
        dev._nt_handle = 33
        dev._write_locked_partition_device = Mock(side_effect=IoError("denied", winerr=5))
        dev._write_at_flushed = Mock(side_effect=IoError("denied", winerr=5))
        dev._prepare_system_helper_handle = Mock()
        dev._write_unbuffered_physical = Mock()
        dev._scsi_write10 = Mock()
        with patch.object(disk, "ntdll", nt):
            with self.assertRaises(PostWriteError):
                dev._fallback_after_volume_access_denied(0, b"m" * 512)
        self.assertEqual(len(_nt_writes(nt)), 1)
        dev._write_unbuffered_physical.assert_not_called()
        dev._scsi_write10.assert_not_called()

    def test_partition_nt_partial_failure_skips_next_candidate(self):
        class NoOpenK32(FakeKernel32):
            def CreateFileW(self, *args):
                disk.ctypes.set_last_error(5)
                return disk.INVALID_HANDLE_VALUE

        k32 = NoOpenK32()
        nt = PartialNt(log=[])
        dev = make_dev(k32, writable=True)
        dev._partition_number = 1
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "ntdll", nt), \
             patch.object(disk, "_nt_open_raw_handle", lambda path: 44):
            with self.assertRaises(PostWriteError):
                dev._write_locked_partition_device(0, b"n" * 512)
        self.assertEqual(len(_nt_writes(nt)), 1)

    def test_system_helper_timeout_after_start_is_post_write(self):
        import tempfile

        ran = Mock(return_value=Mock(returncode=0, stdout="", stderr=""))
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(helper, "_program_data_dir", lambda: tmp), \
             patch.object(helper, "_system_helper_exe", lambda exe: exe), \
             patch.object(helper, "_task_run_command", lambda exe, req: "x"), \
             patch.object(helper, "_run_hidden", ran), \
             patch("ext4lib.host.app_exe", lambda: "app.exe"):
            with self.assertRaises(PostWriteError):
                helper.run_system_raw_write(
                    physical_path=r"\\.\PhysicalDrive9",
                    parent_pid=1,
                    physical_handle=11,
                    volume_handle=None,
                    relative_offset=0,
                    absolute_offset=0,
                    partition_offset=0,
                    partition_size=0,
                    data=b"o" * 512,
                    sector_size=512,
                    timeout=0.05,
                )
        runs = [c for c in ran.call_args_list if "/Run" in c.args[0]]
        self.assertEqual(len(runs), 1)

    def test_system_helper_post_write_error_skips_usbdk(self):
        dev = make_dev(FakeKernel32(), writable=True)
        dev._write_blockers = []
        dev._removable = True
        dev._bus_type = 7
        fail5 = Mock(side_effect=IoError("denied", winerr=5))
        dev._write_locked_partition_device = fail5
        dev._write_at_flushed = fail5
        dev._nt_write_at = fail5
        dev._prepare_system_helper_handle = Mock()
        dev._write_unbuffered_physical = fail5
        dev._scsi_write10 = fail5
        dev._activate_whole_disk_offline = lambda: (False, 5)
        dev._activate_usbdk_backend = Mock()
        helper_write = Mock(side_effect=PostWriteError("timeout", winerr=1460))
        with patch.object(helper, "run_system_raw_write", helper_write):
            with self.assertRaises(PostWriteError):
                dev._fallback_after_volume_access_denied(0, b"p" * 512)
        helper_write.assert_called_once()
        dev._activate_usbdk_backend.assert_not_called()

    def test_usbdk_flush_failure_is_post_write(self):
        dev = make_dev(FakeKernel32(), writable=True)
        dev._usbdk = Mock()
        dev._usbdk.flush.side_effect = IoError("bot flush", winerr=31)
        dev._raw_write(0, b"q" * 512)
        with self.assertRaises(PostWriteError) as ctx:
            dev.flush()
        self.assertEqual(ctx.exception.winerr, 31)
        dev._usbdk.write.assert_called_once()


class PendingK32(FakeKernel32):
    """Overlapped WriteFile that is queued, then fails in GetOverlappedResult."""

    def __init__(self, result_err, **kw):
        super().__init__(**kw)
        self.result_err = result_err

    def WriteFile(self, handle, buf, length, done, ov):
        self.calls.append(("write", handle, 0, length))
        disk.ctypes.set_last_error(disk.ERROR_IO_PENDING)
        return False

    def GetOverlappedResult(self, handle, ov, done, wait):
        disk.ctypes.set_last_error(self.result_err)
        return False


def _usbdk_backend():
    from ext4lib.windows.usbdk import UsbDkBotBackend

    dev = UsbDkBotBackend.__new__(UsbDkBotBackend)
    dev.sector_size = 512
    dev.size = 1024 * 1024
    dev.partition_offset = 4096
    dev.partition_size = 512 * 16
    return dev


class FinalPostWriteGapTests(unittest.TestCase):
    """Queued overlapped writes, UsbDk BOT writes and helper NtWriteFile."""

    def test_pending_overlapped_write_failure_is_not_rewritten(self):
        # 87 used to switch to _write_seek and rewrite; 31 used to hit _retry.
        for err in (disk.ERROR_INVALID_PARAMETER, 31):
            with self.subTest(err=err):
                k32 = PendingK32(err)
                dev = make_dev(k32, writable=True)
                dev._use_overlapped = True
                dev._reopen_locked = Mock()
                dev._write_seek = Mock()
                with patch.object(disk, "kernel32", k32):
                    with self.assertRaises(PostWriteError) as ctx:
                        dev._raw_write(0, b"r" * 512)
                self.assertEqual(ctx.exception.winerr, err)
                self.assertEqual(len(_write_calls(k32)), 1)
                dev._write_seek.assert_not_called()
                dev._reopen_locked.assert_not_called()

    def test_immediate_overlapped_write_rejection_stays_plain_io_error(self):
        class DeniedK32(FakeKernel32):
            def WriteFile(self, handle, buf, length, done, ov):
                disk.ctypes.set_last_error(5)
                return False

        k32 = DeniedK32()
        dev = make_dev(k32, writable=True)
        dev._use_overlapped = True
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(IoError) as ctx:
                dev._write_at(0, b"r" * 512)
        self.assertNotIsInstance(ctx.exception, PostWriteError)

    def test_usbdk_later_chunk_failure_is_post_write(self):
        from ext4lib.windows.usbdk import UsbDkError

        dev = _usbdk_backend()
        dev._write_blocks = Mock(side_effect=[None, UsbDkError("bot", winerr=31)])
        dev._read_blocks = lambda lba, blocks: b"s" * (blocks * 512)
        with patch("ext4lib.windows.usbdk.IO_CHUNK", 512):
            with self.assertRaises(PostWriteError):
                dev.write(4096, b"s" * 1024)

    def test_usbdk_first_chunk_failure_stays_plain_usbdk_error(self):
        from ext4lib.windows.usbdk import UsbDkError

        dev = _usbdk_backend()
        dev._write_blocks = Mock(side_effect=UsbDkError("bot", winerr=31))
        with self.assertRaises(UsbDkError):
            dev.write(4096, b"s" * 512)

    def test_usbdk_read_back_io_error_is_post_write(self):
        from ext4lib.windows.usbdk import UsbDkError

        dev = _usbdk_backend()
        dev._write_blocks = Mock()
        dev._read_blocks = Mock(side_effect=UsbDkError("bot read", winerr=31))
        with self.assertRaises(PostWriteError):
            dev.write(4096, b"s" * 512)

    def test_usbdk_read_back_mismatch_is_not_rewrapped_by_fallback(self):
        dev = make_dev(FakeKernel32(), writable=True)
        dev._write_blockers = []
        dev._removable = True
        dev._bus_type = 7
        dev._partition_size = 512 * 16
        fail5 = Mock(side_effect=IoError("denied", winerr=5))
        dev._write_locked_partition_device = fail5
        dev._write_at_flushed = fail5
        dev._nt_write_at = fail5
        dev._prepare_system_helper_handle = lambda: None
        dev._write_unbuffered_physical = fail5
        dev._scsi_write10 = fail5
        dev._activate_whole_disk_offline = lambda: (False, 5)
        backend = _usbdk_backend()
        backend.partition_offset = 0
        backend._write_blocks = Mock()
        backend._read_blocks = lambda lba, blocks: b"\x00" * (blocks * 512)
        dev._activate_usbdk_backend = lambda: setattr(dev, "_usbdk", backend)
        with patch.object(helper, "run_system_raw_write",
                          return_value={"ok": False, "error": "denied"}):
            with self.assertRaises(PostWriteError) as ctx:
                dev._fallback_after_volume_access_denied(0, b"t" * 512)
        self.assertEqual(ctx.exception.winerr, 23)

    def test_helper_nt_partial_failure_is_post_write(self):
        nt = PartialNt(log=[])
        with patch.object(disk, "ntdll", nt):
            with self.assertRaises(PostWriteError):
                helper._write_nt(77, 4096, b"u" * 512)
        self.assertEqual(_nt_writes(nt), ["write"])

    def test_helper_nt_failure_without_bytes_stays_plain_io_error(self):
        class FailNt(FakeNt):
            def NtWriteFile(self, handle, ev, apc, ctx, iosb, buf, length, off, key):
                iosb._obj.Information = 0
                return NT_FAIL

        with patch.object(disk, "ntdll", FailNt()):
            with self.assertRaises(IoError) as ctx:
                helper._write_nt(77, 4096, b"u" * 512)
        self.assertNotIsInstance(ctx.exception, PostWriteError)

    def test_helper_nt_partial_failure_stops_later_methods(self):
        data = b"v" * 4096
        req = {
            "physical_path": r"\\.\PhysicalDrive1",
            "parent_pid": 1234,
            "physical_handle": 5678,
            "volume_handle": None,
            "relative_offset": 0,
            "absolute_offset": 1048576,
            "partition_offset": 1048576,
            "partition_size": 1 << 30,
            "sector_size": 512,
            "data_b64": base64.b64encode(data).decode("ascii"),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        devno = disk.STORAGE_DEVICE_NUMBER()
        devno.DeviceType = 7
        devno.DeviceNumber = 1
        nt = PartialNt(log=[])
        unbuffered = Mock()
        with patch.object(helper, "_duplicate_handle", side_effect=lambda pid, h: h), \
             patch.object(disk, "_query_storage", return_value=("", "Reader", 7, True)), \
             patch.object(disk, "_enable_storage_privileges", lambda: True), \
             patch.object(disk, "_ioctl", return_value=bytes(devno)), \
             patch.object(disk, "kernel32", HelperK32()), \
             patch.object(disk, "ntdll", nt), \
             patch.object(helper, "_write_win32",
                          side_effect=IoError("denied", winerr=5)), \
             patch.object(disk, "_write_unbuffered_raw_path", unbuffered):
            result = helper._execute_request(req)
        self.assertFalse(result["ok"])
        self.assertTrue(result["post_write"])
        self.assertEqual(_nt_writes(nt), ["write"])
        unbuffered.assert_not_called()


class PartialFailK32(FakeKernel32):
    """WriteFile that transfers half the payload, then reports failure."""

    def __init__(self, err, **kw):
        super().__init__(**kw)
        self.err = err

    def WriteFile(self, handle, buf, length, done, ov):
        super().WriteFile(handle, buf, length // 2, done, ov)
        disk.ctypes.set_last_error(self.err)
        return False


def _scsi_ioctl(status, sense_key):
    """DeviceIoControl stub that completes a WRITE(10) with a SCSI status."""

    def ioctl(handle, code, packet, *args):
        if code == disk.IOCTL_SCSI_PASS_THROUGH_DIRECT:
            hdr = disk.SCSI_PASS_THROUGH_DIRECT.from_buffer(packet)
        else:
            hdr = disk.SCSI_PASS_THROUGH.from_buffer(packet)
        hdr.ScsiStatus = status
        off = int(hdr.SenseInfoOffset)
        sense = bytes([0x70, 0, sense_key]) + b"\x00" * 9 + bytes([0x11, 0])
        disk.ctypes.memmove(disk.ctypes.addressof(packet) + off, sense, len(sense))
        return True

    return ioctl


class AuditPostWriteGapTests(unittest.TestCase):
    """Bytes reached the device before the failure: no retry, no other route."""

    def test_write_seek_failed_write_with_bytes_is_not_retried(self):
        k32 = PartialFailK32(31)
        dev = make_dev(k32, writable=True)
        dev._reopen_locked = Mock()
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(PostWriteError) as ctx:
                dev._raw_write(0, b"w" * 512)
        self.assertEqual(ctx.exception.winerr, 31)
        self.assertEqual(len(_write_calls(k32)), 1)
        dev._reopen_locked.assert_not_called()

    def test_write_seek_failed_write_without_bytes_stays_plain_io_error(self):
        class FailK32(FakeKernel32):
            def WriteFile(self, handle, buf, length, done, ov):
                disk.ctypes.set_last_error(5)
                return False

        k32 = FailK32()
        dev = make_dev(k32, writable=True)
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(IoError) as ctx:
                dev._write_seek(0, b"w" * 512)
        self.assertNotIsInstance(ctx.exception, PostWriteError)

    def test_overlapped_fallback_to_seek_partial_write_is_post_write(self):
        class K32(PartialFailK32):
            def WriteFile(self, handle, buf, length, done, ov):
                if ov is not None:
                    disk.ctypes.set_last_error(disk.ERROR_INVALID_PARAMETER)
                    return False
                return super().WriteFile(handle, buf, length, done, ov)

        k32 = K32(31)
        dev = make_dev(k32, writable=True)
        dev._use_overlapped = True
        dev._reopen_locked = Mock()
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(PostWriteError):
                dev._raw_write(0, b"w" * 512)
        self.assertEqual(len(_write_calls(k32)), 1)
        dev._reopen_locked.assert_not_called()

    def _scsi_dev(self):
        dev = make_dev(FakeKernel32(), writable=True)
        dev._scsi_fua_supported = None
        dev._scsi_sync_cache_supported = None
        dev._read_at = Mock(return_value=b"x" * 512)
        return dev

    def test_scsi_medium_error_is_post_write_without_buffered_retry(self):
        for key in (0x03, 0x04, 0x0B):
            with self.subTest(key=key):
                dev = self._scsi_dev()
                dev._scsi_write10_buffered = Mock()
                with patch.object(disk.kernel32, "DeviceIoControl", _scsi_ioctl(2, key)):
                    with self.assertRaises(PostWriteError):
                        dev._scsi_write10(0, b"x" * 512)
                dev._scsi_write10_buffered.assert_not_called()

    def test_scsi_buffered_medium_error_is_post_write(self):
        dev = self._scsi_dev()
        with patch.object(disk.kernel32, "DeviceIoControl", _scsi_ioctl(2, 0x03)):
            with self.assertRaises(PostWriteError):
                disk.WindowsPhysicalDevice._scsi_write10_buffered(dev, 0, b"x" * 512)

    def test_scsi_illegal_request_still_falls_back(self):
        dev = self._scsi_dev()
        dev._scsi_write10_buffered = Mock()
        with patch.object(disk.kernel32, "DeviceIoControl", _scsi_ioctl(2, 0x05)):
            dev._scsi_write10(0, b"x" * 512)
        dev._scsi_write10_buffered.assert_called_once()

    def test_scsi_ioctl_timeout_is_post_write_without_buffered_retry(self):
        dev = self._scsi_dev()
        dev._scsi_write10_buffered = Mock()

        def timeout(*args):
            disk.ctypes.set_last_error(121)
            return False

        with patch.object(disk.kernel32, "DeviceIoControl", timeout):
            with self.assertRaises(PostWriteError):
                dev._scsi_write10(0, b"x" * 512)
        dev._scsi_write10_buffered.assert_not_called()

    def test_scsi_executed_error_stops_fallback_chain(self):
        dev = make_dev(FakeKernel32(), writable=True)
        dev._write_blockers = []
        dev._scsi_fua_supported = None
        dev._read_at = Mock(return_value=b"x" * 512)
        fail5 = Mock(side_effect=IoError("denied", winerr=5))
        dev._write_locked_partition_device = fail5
        dev._write_at_flushed = fail5
        dev._nt_write_at = fail5
        dev._prepare_system_helper_handle = lambda: None
        dev._write_unbuffered_physical = fail5
        dev._activate_whole_disk_offline = Mock(return_value=(False, 5))
        helper_write = Mock()
        with patch.object(disk.kernel32, "DeviceIoControl", _scsi_ioctl(2, 0x03)), \
             patch.object(helper, "run_system_raw_write", helper_write):
            with self.assertRaises(PostWriteError):
                dev._fallback_after_volume_access_denied(0, b"x" * 512)
        dev._activate_whole_disk_offline.assert_not_called()
        helper_write.assert_not_called()

    def test_helper_success_then_offline_adopt_failure_is_post_write(self):
        dev = make_dev(FakeKernel32(), writable=True)
        dev._write_blockers = []
        dev._disk_offline = False
        fail5 = Mock(side_effect=IoError("denied", winerr=5))
        dev._write_locked_partition_device = fail5
        dev._write_at_flushed = fail5
        dev._nt_write_at = fail5
        dev._prepare_system_helper_handle = lambda: None
        dev._write_unbuffered_physical = fail5
        dev._scsi_write10 = fail5
        dev._activate_whole_disk_offline = lambda: (False, 5)
        dev._adopt_whole_disk_offline = Mock(side_effect=IoError("close", winerr=31))
        dev._verify_readback = Mock()
        reopened = []
        dev._reopen_locked = lambda: reopened.append(1)
        helper_write = Mock(return_value={"ok": True, "disk_offline": True})
        with patch.object(helper, "run_system_raw_write", helper_write):
            with self.assertRaises(PostWriteError):
                dev._fallback_after_volume_access_denied(0, b"y" * 512)
        helper_write.assert_called_once()
        dev._verify_readback.assert_not_called()

    def test_helper_unexpected_error_after_write_is_post_write(self):
        data = b"z" * 4096
        req = {
            "physical_path": r"\\.\PhysicalDrive1",
            "parent_pid": 1234,
            "physical_handle": 5678,
            "volume_handle": None,
            "relative_offset": 0,
            "absolute_offset": 1048576,
            "partition_offset": 1048576,
            "partition_size": 1 << 30,
            "sector_size": 512,
            "data_b64": base64.b64encode(data).decode("ascii"),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        devno = disk.STORAGE_DEVICE_NUMBER()
        devno.DeviceType = 7
        devno.DeviceNumber = 1
        write_nt = Mock()
        with patch.object(helper, "_duplicate_handle", side_effect=lambda pid, h: h), \
             patch.object(disk, "_query_storage", return_value=("", "Reader", 7, True)), \
             patch.object(disk, "_enable_storage_privileges", lambda: True), \
             patch.object(disk, "_ioctl", return_value=bytes(devno)), \
             patch.object(disk, "kernel32", HelperK32()), \
             patch.object(helper, "_write_win32", side_effect=OSError(31, "ctypes")), \
             patch.object(helper, "_write_nt", write_nt):
            result = helper._execute_request(req)
        self.assertFalse(result["ok"])
        self.assertTrue(result["post_write"])
        write_nt.assert_not_called()

    def test_helper_timeout_with_failing_query_is_still_post_write(self):
        import subprocess
        import tempfile

        def run(cmd, timeout=None):
            if "/Query" in cmd:
                raise subprocess.TimeoutExpired(cmd, timeout)
            return Mock(returncode=0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(helper, "_program_data_dir", lambda: tmp), \
             patch.object(helper, "_system_helper_exe", lambda exe: exe), \
             patch.object(helper, "_task_run_command", lambda exe, req: "x"), \
             patch.object(helper, "_run_hidden", run), \
             patch("ext4lib.host.app_exe", lambda: "app.exe"):
            with self.assertRaises(PostWriteError) as ctx:
                helper.run_system_raw_write(
                    physical_path=r"\\.\PhysicalDrive9",
                    parent_pid=1,
                    physical_handle=11,
                    volume_handle=None,
                    relative_offset=0,
                    absolute_offset=0,
                    partition_offset=0,
                    partition_size=0,
                    data=b"o" * 512,
                    sector_size=512,
                    timeout=0.05,
                )
        self.assertEqual(ctx.exception.winerr, 1460)


class _BotApi:
    """UsbDk transfer stub: CBW accepted, then the given phase fails."""

    def __init__(self, fail_phase=None, csw_status=0, sense_key=0):
        self.fail_phase = fail_phase
        self.csw_status = csw_status
        self.sense_key = sense_key
        self.tag = 0
        self.data_out = 0

    def transfer(self, handle, endpoint, data, read_len=0):
        from ext4lib.windows.usbdk import CBW_SIGNATURE, CSW_SIGNATURE, UsbDkError

        if data is not None:
            blob = bytes(data)
            if len(blob) == 31 and blob[:4] == CBW_SIGNATURE.to_bytes(4, "little"):
                self.tag = int.from_bytes(blob[4:8], "little")
                self.cdb0 = blob[15]
                return b""
            self.data_out += 1
            if self.fail_phase == "data":
                raise UsbDkError("bulk-out stall", winerr=31)
            return b""
        if read_len == 13:
            if self.fail_phase == "csw":
                raise UsbDkError("csw timeout", winerr=121)
            status = self.csw_status if self.cdb0 != 0x03 else 0
            return (CSW_SIGNATURE.to_bytes(4, "little") + self.tag.to_bytes(4, "little")
                    + (0).to_bytes(4, "little") + bytes([status]))
        return bytes([0x70, 0, self.sense_key]) + b"\x00" * 9 + bytes([0x11, 0]) + b"\x00" * 4

    def reset_pipe(self, handle, endpoint):
        pass


class UsbDkFirstChunkTests(unittest.TestCase):
    def _backend(self, api):
        dev = _usbdk_backend()
        dev._api = api
        dev._redirect = 1
        dev._tag = 1
        dev._closed = False
        dev.bulk_in = 0x81
        dev.bulk_out = 0x02
        dev.lun = 0
        dev._recover_pipes = lambda: None
        dev._read_blocks = Mock()
        return dev

    def test_first_chunk_failure_after_data_phase_is_post_write(self):
        for kw in ({"fail_phase": "data"}, {"fail_phase": "csw"},
                   {"csw_status": 1, "sense_key": 0x03}):
            with self.subTest(**kw):
                dev = self._backend(_BotApi(**kw))
                with self.assertRaises(PostWriteError):
                    dev.write(4096, b"s" * 512)
                dev._read_blocks.assert_not_called()

    def test_first_chunk_rejected_command_stays_plain_usbdk_error(self):
        from ext4lib.windows.usbdk import UsbDkError

        api = _BotApi(csw_status=1, sense_key=0x05)
        dev = self._backend(api)
        with self.assertRaises(UsbDkError) as ctx:
            dev.write(4096, b"s" * 512)
        self.assertNotIsInstance(ctx.exception, PostWriteError)
        self.assertEqual(api.data_out, 1)


if __name__ == "__main__":
    unittest.main()
