import unittest
from unittest.mock import Mock, patch

from ext4lib.io.backend import IoError
from ext4lib.windows import disk as diskmod
from ext4lib.windows.disk import _LockedVolume, _partition_extent_matches, WindowsPhysicalDevice


class PhysicalPartitionBoundaryTests(unittest.TestCase):
    def _device(self):
        dev = WindowsPhysicalDevice.__new__(WindowsPhysicalDevice)
        dev._partition_offset = 4096
        dev._partition_size = 8192
        dev._partition_volume = None
        dev._use_overlapped = False
        dev._write_at = Mock()
        return dev

    def test_write_before_selected_partition_is_rejected(self):
        dev = self._device()
        with self.assertRaises(IoError):
            dev._raw_write_once(0, b"x" * 512)
        dev._write_at.assert_not_called()

    def test_write_after_selected_partition_is_rejected(self):
        dev = self._device()
        with self.assertRaises(IoError):
            dev._raw_write_once(4096 + 8192 - 256, b"x" * 512)
        dev._write_at.assert_not_called()

    def test_write_inside_selected_partition_is_allowed(self):
        dev = self._device()
        dev._raw_write_once(4096, b"x" * 512)
        dev._write_at.assert_called_once_with(4096, b"x" * 512)


class PartitionExtentMatchTests(unittest.TestCase):
    def _item(self, number=3, offset=1048576, size=64 * 1024 * 1024):
        return _LockedVolume(
            handle=1,
            name="test",
            partition_number=number,
            locked=True,
            partition_offset=offset,
            partition_size=size,
        )

    def test_exact_partition_extent_matches(self):
        item = self._item()
        self.assertTrue(
            _partition_extent_matches(item, 3, 1048576, 64 * 1024 * 1024)
        )

    def test_same_number_wrong_offset_is_rejected(self):
        item = self._item()
        self.assertFalse(
            _partition_extent_matches(item, 3, 2097152, 64 * 1024 * 1024)
        )

    def test_same_number_wrong_size_is_rejected(self):
        item = self._item()
        self.assertFalse(
            _partition_extent_matches(item, 3, 1048576, 32 * 1024 * 1024)
        )


class ScsiDurabilityTests(unittest.TestCase):
    def _device(self):
        dev = WindowsPhysicalDevice.__new__(WindowsPhysicalDevice)
        dev.sector_size = 512
        dev._handle = 123
        dev._scsi_dirty = False
        dev._closed = False
        dev._usbdk = None
        dev._partition_volume = None
        dev._nt_handle = None
        import threading
        dev._io_lock = threading.RLock()
        return dev

    def test_successful_scsi_write_marks_device_cache_dirty(self):
        dev = self._device()
        payload = b"x" * 512
        dev._read_at = Mock(return_value=payload)
        with patch.object(diskmod.kernel32, "DeviceIoControl", return_value=True):
            dev._scsi_write10_direct(0, payload)
        self.assertTrue(dev._scsi_dirty)

    def test_sync_cache_success_clears_dirty_marker(self):
        dev = self._device()
        dev._scsi_dirty = True
        with patch.object(diskmod.kernel32, "DeviceIoControl", return_value=True):
            dev._scsi_synchronize_cache()
        self.assertFalse(dev._scsi_dirty)

    def test_sync_cache_failure_keeps_dirty_marker_and_fails_closed(self):
        dev = self._device()
        dev._scsi_dirty = True
        with (
            patch.object(diskmod.kernel32, "DeviceIoControl", return_value=False),
            patch.object(diskmod.ctypes, "get_last_error", return_value=21),
        ):
            with self.assertRaises(IoError):
                dev._scsi_synchronize_cache()
        self.assertTrue(dev._scsi_dirty)

    def test_flush_invokes_scsi_cache_barrier(self):
        dev = self._device()
        dev._scsi_dirty = True
        dev._scsi_synchronize_cache = Mock()
        with patch.object(diskmod.kernel32, "FlushFileBuffers", return_value=True):
            dev.flush()
        dev._scsi_synchronize_cache.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
