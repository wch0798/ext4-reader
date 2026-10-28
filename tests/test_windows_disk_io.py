"""Win32-mocked tests for ext4lib.windows.disk raw I/O, locking and close."""

import ctypes
import threading
import unittest
from unittest.mock import patch

from ext4lib.io.backend import IoError
from ext4lib.windows import disk
from ext4lib.windows.disk import WindowsPhysicalDevice, _LockedVolume


def _set_out(ref, value):
    """Store into a ctypes.byref(DWORD) argument."""
    ref._obj.value = value


class FakeKernel32:
    """Sector device backed by a bytearray; records every call in order."""

    def __init__(self, size=1 << 20, max_chunk=None, flush_err=0):
        self.media = bytearray(size)
        self.pos = {}
        self.max_chunk = max_chunk
        self.flush_err = flush_err
        self.calls = []
        self.write_addrs = []

    def SetLastError(self, err):
        ctypes.set_last_error(err)

    def SetFilePointerEx(self, handle, offset, new_pos, whence):
        self.pos[handle] = int(offset)
        return True

    def _n(self, length):
        return min(length, self.max_chunk) if self.max_chunk else length

    def ReadFile(self, handle, buf, length, done, ov):
        start = self.pos[handle]
        n = max(0, min(self._n(length), len(self.media) - start))
        ctypes.memmove(buf, bytes(self.media[start : start + n]), n)
        self.pos[handle] = start + n
        _set_out(done, n)
        return True

    def WriteFile(self, handle, buf, length, done, ov):
        addr = buf.value if isinstance(buf, ctypes.c_void_p) else ctypes.addressof(buf)
        self.write_addrs.append(addr)
        start = self.pos[handle]
        n = self._n(length)
        self.media[start : start + n] = ctypes.string_at(addr, n)
        self.pos[handle] = start + n
        _set_out(done, n)
        self.calls.append(("write", handle, start, n))
        return True

    def FlushFileBuffers(self, handle):
        self.calls.append(("flush", handle))
        if self.flush_err:
            ctypes.set_last_error(self.flush_err)
            return False
        return True

    def CloseHandle(self, handle):
        self.calls.append(("close", handle))
        return True


def make_dev(k32, writable=True, size=None):
    dev = WindowsPhysicalDevice.__new__(WindowsPhysicalDevice)
    dev.path = r"\\.\PhysicalDrive9"
    dev._handle = 11
    dev._size = len(k32.media) if size is None else size
    dev.sector_size = 512
    dev._writable = writable
    dev._io_lock = threading.RLock()
    dev._closed = False
    dev._stop_ka = threading.Event()
    dev._use_overlapped = False
    dev._partition_number = None
    dev._partition_offset = 0
    dev._partition_size = 0
    dev._partition_volume = None
    dev._volume_locks = []
    dev._nt_handle = None
    dev._usbdk = None
    dev._disk_offline = False
    dev._scsi_dirty = False
    return dev


class PartialIoTests(unittest.TestCase):
    def test_short_reads_are_continued_not_zero_filled(self):
        k32 = FakeKernel32(max_chunk=512)
        k32.media[0:4096] = bytes(range(256)) * 16
        dev = make_dev(k32)
        with patch.object(disk, "kernel32", k32):
            got = dev._raw_read_once(0, 4096)
        self.assertEqual(got, bytes(k32.media[0:4096]))

    def test_zero_byte_read_inside_device_raises(self):
        k32 = FakeKernel32()
        k32.ReadFile = lambda h, b, n, done, ov: (_set_out(done, 0), True)[1]
        dev = make_dev(k32)
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(IoError) as ctx:
                dev._raw_read_once(4096, 512)
        self.assertEqual(ctx.exception.winerr, disk.ERROR_HANDLE_EOF)

    def test_read_past_end_of_medium_is_zero_padded(self):
        k32 = FakeKernel32(size=4096)
        k32.media[3584:4096] = b"\xAA" * 512
        dev = make_dev(k32)
        with patch.object(disk, "kernel32", k32):
            got = dev._raw_read_once(3584, 1024)
            beyond = dev._raw_read_once(8192, 512)
        self.assertEqual(got, b"\xAA" * 512 + b"\x00" * 512)
        self.assertEqual(beyond, b"\x00" * 512)

    def test_short_writes_are_continued_at_the_right_offset(self):
        k32 = FakeKernel32(max_chunk=1000)
        dev = make_dev(k32)
        payload = bytes(range(256)) * 16
        with patch.object(disk, "kernel32", k32):
            dev._write_seek(8192, payload)
        self.assertEqual(bytes(k32.media[8192 : 8192 + 4096]), payload)
        starts = [c[2] for c in k32.calls if c[0] == "write"]
        self.assertEqual(starts, [8192, 9192, 10192, 11192, 12192])

    def test_zero_byte_write_raises_instead_of_looping(self):
        k32 = FakeKernel32()
        k32.WriteFile = lambda h, b, n, done, ov: (_set_out(done, 0), True)[1]
        dev = make_dev(k32)
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(IoError) as ctx:
                dev._write_seek(0, b"x" * 512)
        self.assertEqual(ctx.exception.winerr, disk.ERROR_WRITE_FAULT)

    def test_write_past_end_of_disk_is_rejected(self):
        k32 = FakeKernel32(size=1 << 16)
        dev = make_dev(k32)
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(IoError):
                dev._raw_write_once((1 << 16) - 512, b"x" * 1024)
            with self.assertRaises(IoError):
                dev._raw_write_once(-512, b"x" * 512)
        self.assertFalse([c for c in k32.calls if c[0] == "write"])

    def test_offsets_above_4gib_are_not_truncated(self):
        dev = make_dev(FakeKernel32())
        ov = dev._overlapped(0x1_2345_6000)
        self.assertEqual(ov.Offset, 0x2345_6000)
        self.assertEqual(ov.OffsetHigh, 0x1)


class UnbufferedAlignmentTests(unittest.TestCase):
    def _alignment_raw(self, logical, physical):
        raw = bytearray(28)
        raw[16:20] = logical.to_bytes(4, "little")
        raw[20:24] = physical.to_bytes(4, "little")
        return bytes(raw)

    def _run(self, k32, offset, data, logical=512, physical=4096):
        backing = ctypes.create_string_buffer(len(data) + 2 * 65536)
        k32.CreateFileW = lambda *a: 77
        # Deliberately misaligned base so the code must align it itself.
        k32.VirtualAlloc = lambda *a: ctypes.addressof(backing) + 1
        k32.VirtualFree = lambda *a: k32.calls.append(("free",)) or True
        raw = self._alignment_raw(logical, physical)

        def fake_ioctl(handle, code, inbuf=None, out_cb=0):
            if code == disk.IOCTL_STORAGE_QUERY_PROPERTY:
                return raw
            return b""

        with patch.object(disk, "kernel32", k32), patch.object(disk, "_ioctl", fake_ioctl):
            return disk._write_unbuffered_raw_path(r"\\.\PhysicalDrive9", offset, data), backing

    def test_misaligned_offset_or_length_is_rejected_and_handle_closed(self):
        for offset, length in ((100, 512), (512, 100), (-512, 512)):
            k32 = FakeKernel32()
            with self.assertRaises(IoError) as ctx:
                self._run(k32, offset, b"x" * length)
            self.assertEqual(ctx.exception.winerr, 87)
            self.assertIn(("close", 77), k32.calls)
            self.assertFalse(k32.write_addrs)

    def test_buffer_is_physically_aligned_and_written_back(self):
        k32 = FakeKernel32()
        payload = bytes(range(256)) * 32
        (logical, physical), _backing = self._run(k32, 8192, payload)
        self.assertEqual((logical, physical), (512, 4096))
        self.assertEqual(k32.write_addrs[0] % 4096, 0)
        self.assertEqual(bytes(k32.media[8192 : 8192 + len(payload)]), payload)
        # Flush happens after the write, and the handle and buffer are always released.
        kinds = [c[0] for c in k32.calls]
        self.assertLess(kinds.index("write"), kinds.index("flush"))
        self.assertIn("free", kinds)
        self.assertEqual(kinds[-1], "close")


class LockRetryTests(unittest.TestCase):
    def test_access_denied_lock_is_retried_then_succeeds(self):
        attempts = []

        def fake_ioctl(handle, code, inbuf=None, out_cb=0):
            attempts.append(code)
            if len(attempts) < 3:
                raise OSError(5)
            return b""

        with patch.object(disk, "_ioctl", fake_ioctl), patch.object(disk.time, "sleep") as sleep:
            self.assertTrue(disk._lock_volume_with_retry(5, "vol"))
        self.assertEqual(attempts, [disk.FSCTL_LOCK_VOLUME] * 3)
        self.assertEqual(sleep.call_count, 2)

    def test_lock_gives_up_after_bounded_retries(self):
        def fake_ioctl(handle, code, inbuf=None, out_cb=0):
            raise OSError(5)

        with patch.object(disk, "_ioctl", fake_ioctl), patch.object(disk.time, "sleep") as sleep:
            self.assertFalse(disk._lock_volume_with_retry(5, "vol"))
        self.assertEqual(sleep.call_count, disk.LOCK_VOLUME_RETRIES - 1)

    def test_non_transient_lock_error_is_not_retried(self):
        calls = []

        def fake_ioctl(handle, code, inbuf=None, out_cb=0):
            calls.append(code)
            raise OSError(1)  # ERROR_INVALID_FUNCTION

        with patch.object(disk, "_ioctl", fake_ioctl), patch.object(disk.time, "sleep") as sleep:
            self.assertFalse(disk._lock_volume_with_retry(5, "vol"))
        self.assertEqual(len(calls), 1)
        sleep.assert_not_called()

    def test_failed_open_releases_every_locked_volume(self):
        item = _LockedVolume(handle=42, name="vol", partition_number=1, locked=True, offline=True)
        released = []

        def open_handle(path, writable):
            raise IoError("denied", winerr=5)

        with patch.object(disk, "_enable_storage_privileges", lambda: True), \
             patch.object(disk, "_lock_volumes_for_disk", lambda idx, *a: [item]), \
             patch.object(disk, "_open_handle", open_handle), \
             patch.object(disk, "_release_locked_volume", released.append):
            with self.assertRaises(IoError):
                WindowsPhysicalDevice(
                    r"\\.\PhysicalDrive9", writable=True, partition_number=1
                )
        self.assertEqual(released, [item])

    def test_write_protect_after_lock_releases_volumes(self):
        item = _LockedVolume(handle=42, name="vol", partition_number=1, locked=True)
        released = []
        k32 = FakeKernel32()

        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "_enable_storage_privileges", lambda: True), \
             patch.object(disk, "_lock_volumes_for_disk", lambda idx, *a: [item]), \
             patch.object(disk, "_open_handle", lambda path, writable: 11), \
             patch.object(disk, "_query_storage", lambda h: ("", "", 12, True)), \
             patch.object(disk, "_query_storage_serial", lambda h: ""), \
             patch.object(disk, "_log_write_environment", lambda *a: []), \
             patch.object(disk, "_is_writable_ioctl", lambda h: (False, 19)), \
             patch.object(disk, "_release_locked_volume", released.append):
            with self.assertRaises(IoError) as ctx:
                WindowsPhysicalDevice(
                    r"\\.\PhysicalDrive9", writable=True, partition_number=1
                )
        self.assertEqual(ctx.exception.winerr, 19)
        self.assertEqual(released, [item])
        self.assertIn(("close", 11), k32.calls)


class FlushCloseOrderTests(unittest.TestCase):
    def _dev_with_volume(self, k32):
        dev = make_dev(k32)
        vol = _LockedVolume(handle=22, name="vol", partition_number=1, locked=True)
        dev._partition_volume = vol
        dev._volume_locks = [vol]
        return dev, vol

    def test_close_flushes_before_closing_and_unlocking(self):
        k32 = FakeKernel32()
        dev, vol = self._dev_with_volume(k32)
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "_release_locked_volume", lambda item: k32.calls.append(("release", item.handle))):
            dev.close()
        self.assertEqual(
            k32.calls,
            [("flush", 11), ("flush", 22), ("close", 11), ("release", 22)],
        )
        self.assertTrue(dev._closed)

    def test_read_only_close_does_not_flush(self):
        k32 = FakeKernel32()
        dev = make_dev(k32, writable=False)
        with patch.object(disk, "kernel32", k32):
            dev.close()
        self.assertEqual(k32.calls, [("close", 11)])

    def test_flush_reports_media_gone(self):
        for err in (21, 1167, 19):
            k32 = FakeKernel32(flush_err=err)
            dev, _vol = self._dev_with_volume(k32)
            with patch.object(disk, "kernel32", k32):
                with self.assertRaises(IoError) as ctx:
                    dev.flush()
            self.assertEqual(ctx.exception.winerr, err)

    def test_flush_failure_is_fatal_even_when_bridge_lacks_flush(self):
        k32 = FakeKernel32(flush_err=1)  # ERROR_INVALID_FUNCTION
        dev, _vol = self._dev_with_volume(k32)
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(IoError) as ctx:
                dev.flush()
        self.assertEqual(ctx.exception.winerr, 1)
        self.assertIn("FlushFileBuffers", str(ctx.exception))
        self.assertIn("Win32 1", str(ctx.exception))

    def test_close_still_unlocks_when_final_flush_fails(self):
        k32 = FakeKernel32(flush_err=21)
        dev, vol = self._dev_with_volume(k32)
        released = []
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "_release_locked_volume", released.append):
            with self.assertRaises(IoError) as ctx:
                dev.close()
        self.assertEqual(ctx.exception.winerr, 21)
        self.assertEqual(released, [vol])
        self.assertIn(("close", 11), k32.calls)
        self.assertTrue(dev._closed)
        dev.close()  # second close is a no-op


class ReviewFixTests(unittest.TestCase):
    def test_unbuffered_write_reports_fatal_flush_failure(self):
        k32 = FakeKernel32(flush_err=21)
        with self.assertRaises(IoError) as ctx:
            UnbufferedAlignmentTests()._run(k32, 4096, b"x" * 4096)
        self.assertEqual(ctx.exception.winerr, 21)
        kinds = [c[0] for c in k32.calls]
        self.assertIn("free", kinds)
        self.assertEqual(kinds[-1], "close")

    def test_unbuffered_write_fails_on_any_flush_error(self):
        k32 = FakeKernel32(flush_err=1)
        with self.assertRaises(disk.PostWriteError) as ctx:
            UnbufferedAlignmentTests()._run(k32, 4096, b"y" * 4096)
        self.assertEqual(ctx.exception.winerr, 1)
        # The bytes landed, so only the flush result caused the failure.
        self.assertEqual(bytes(k32.media[4096:8192]), b"y" * 4096)
        self.assertEqual([c[0] for c in k32.calls][-1], "close")

    def test_disk_size_prefers_get_length_info(self):
        def fake_ioctl(handle, code, inbuf=None, out_cb=0):
            self.assertEqual(code, disk.IOCTL_DISK_GET_LENGTH_INFO)
            return (31_914_983_424).to_bytes(8, "little")

        with patch.object(disk, "_query_geometry", lambda h: (31_914_000_000, 512)), \
             patch.object(disk, "_ioctl", fake_ioctl):
            self.assertEqual(disk._query_disk_size(5), (31_914_983_424, 512))

    def test_disk_size_falls_back_to_geometry(self):
        def fake_ioctl(handle, code, inbuf=None, out_cb=0):
            raise OSError(1)

        with patch.object(disk, "_query_geometry", lambda h: (1 << 30, 4096)), \
             patch.object(disk, "_ioctl", fake_ioctl):
            self.assertEqual(disk._query_disk_size(5), (1 << 30, 4096))

    def test_failed_reopen_does_not_leave_stale_handle(self):
        k32 = FakeKernel32()
        dev = make_dev(k32, writable=False)

        def open_handle(path, writable):
            raise IoError("gone", winerr=1167)

        with patch.object(disk, "kernel32", k32), patch.object(disk, "_open_handle", open_handle):
            with self.assertRaises(IoError):
                dev._reopen_locked()
            self.assertIsNone(dev._handle)
            dev.close()
        self.assertEqual(k32.calls.count(("close", 11)), 1)

    def test_close_releases_everything_when_online_restore_raises(self):
        k32 = FakeKernel32()
        dev = make_dev(k32, writable=False)
        vol = _LockedVolume(handle=22, name="vol", partition_number=1, locked=True)
        dev._volume_locks = [vol]
        dev._disk_offline = True
        released = []

        def boom():
            raise OSError(31)

        dev._restore_whole_disk_online = boom
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk, "_release_locked_volume", released.append):
            with self.assertRaises(OSError):
                dev.close()
        self.assertIn(("close", 11), k32.calls)
        self.assertEqual(released, [vol])

    def test_short_volume_write_is_continued(self):
        k32 = FakeKernel32(max_chunk=1000)
        dev = make_dev(k32)
        vol = _LockedVolume(handle=22, name="vol", partition_number=1, locked=True)
        payload = bytes(range(256)) * 16
        with patch.object(disk, "kernel32", k32):
            dev._write_volume_seek(vol, 4096, payload)
        self.assertEqual(bytes(k32.media[4096 : 4096 + 4096]), payload)
        starts = [c[2] for c in k32.calls if c[0] == "write"]
        self.assertEqual(starts, [4096, 5096, 6096, 7096, 8096])

    def test_zero_byte_volume_write_raises_write_fault(self):
        k32 = FakeKernel32()
        k32.WriteFile = lambda h, b, n, done, ov: (_set_out(done, 0), True)[1]
        dev = make_dev(k32)
        vol = _LockedVolume(handle=22, name="vol", partition_number=1, locked=True)
        with patch.object(disk, "kernel32", k32):
            with self.assertRaises(IoError) as ctx:
                dev._write_volume_seek(vol, 0, b"x" * 512)
        self.assertEqual(ctx.exception.winerr, disk.ERROR_WRITE_FAULT)

    def test_short_overlapped_write_is_continued(self):
        k32 = FakeKernel32()
        payload = bytes(range(256)) * 8
        state = {"first": True}
        orig_write = k32.WriteFile

        def write_file(handle, buf, length, done, ov):
            if ov is not None:
                o = ov._obj
                k32.pos[handle] = o.Offset | (o.OffsetHigh << 32)
                if state.pop("first", False):
                    length = 512
            return orig_write(handle, buf, length, done, None)

        k32.WriteFile = write_file
        dev = make_dev(k32)
        dev._use_overlapped = True
        with patch.object(disk, "kernel32", k32):
            dev._write_at(8192, payload)
        self.assertEqual(bytes(k32.media[8192 : 8192 + len(payload)]), payload)

    def test_access_denied_open_mentions_admin(self):
        k32 = FakeKernel32()
        k32.CreateFileW = lambda *a: disk.INVALID_HANDLE_VALUE
        with patch.object(disk, "kernel32", k32), \
             patch.object(disk.ctypes, "get_last_error", lambda: 5), \
             patch.object(disk, "is_admin", lambda: False):
            with self.assertRaises(IoError) as ctx:
                disk._open_handle(r"\\.\PhysicalDrive9", False)
        self.assertEqual(ctx.exception.winerr, 5)
        self.assertIn("관리자", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
