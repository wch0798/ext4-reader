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
        dev._scsi_fua_supported = None
        dev._scsi_sync_cache_supported = None
        dev._fallback_write_route = None
        dev._closed = False
        dev._usbdk = None
        dev._partition_volume = None
        dev._nt_handle = None
        import threading
        dev._io_lock = threading.RLock()
        return dev

    def test_successful_scsi_fua_write_needs_no_later_cache_flush(self):
        dev = self._device()
        payload = b"x" * 512
        dev._read_at = Mock(return_value=payload)
        with patch.object(diskmod.kernel32, "DeviceIoControl", return_value=True):
            dev._scsi_write10_direct(0, payload, fua=True)
        self.assertTrue(dev._scsi_fua_supported)
        self.assertFalse(dev._scsi_dirty)

    def test_plain_scsi_write_marks_device_cache_dirty(self):
        dev = self._device()
        payload = b"x" * 512
        dev._read_at = Mock(return_value=payload)
        with patch.object(diskmod.kernel32, "DeviceIoControl", return_value=True):
            dev._scsi_write10_direct(0, payload, fua=False)
        self.assertTrue(dev._scsi_dirty)

    def test_fua_illegal_field_falls_back_to_plain_write_once(self):
        dev = self._device()
        unsupported = IoError("FUA unsupported", winerr=5)
        unsupported.scsi_sense = (0x05, 0x24, 0x00)
        dev._scsi_write10_direct = Mock(side_effect=[unsupported, None])

        dev._scsi_write10(0, b"x" * 512)

        self.assertFalse(dev._scsi_fua_supported)
        self.assertEqual(
            dev._scsi_write10_direct.call_args_list,
            [
                unittest.mock.call(0, b"x" * 512, fua=True),
                unittest.mock.call(0, b"x" * 512, fua=False),
            ],
        )

    def test_sync_cache_success_clears_dirty_marker(self):
        dev = self._device()
        dev._scsi_dirty = True
        dev._scsi_sync_cache_once = Mock(return_value=(True, None, "DIRECT"))

        dev._scsi_synchronize_cache()

        self.assertFalse(dev._scsi_dirty)
        self.assertTrue(dev._scsi_sync_cache_supported)
        dev._scsi_sync_cache_once.assert_called_once_with(True)

    def test_unsupported_sync_cache_enters_compatibility_mode(self):
        dev = self._device()
        dev._scsi_dirty = True
        dev._scsi_sync_cache_once = Mock(
            side_effect=[
                (False, (0x00, 0x00, 0x00), "DIRECT status=0x02"),
                (False, (0x05, 0x24, 0x00), "BUFFERED illegal field"),
            ]
        )

        dev._scsi_synchronize_cache()

        self.assertFalse(dev._scsi_dirty)
        self.assertFalse(dev._scsi_sync_cache_supported)

    def test_real_sync_cache_failure_still_fails_closed(self):
        dev = self._device()
        dev._scsi_dirty = True
        dev._scsi_sync_cache_once = Mock(
            side_effect=[
                (False, (0x03, 0x11, 0x00), "DIRECT medium error"),
                (False, (0x03, 0x11, 0x00), "BUFFERED medium error"),
            ]
        )

        with self.assertRaises(IoError):
            dev._scsi_synchronize_cache()
        self.assertTrue(dev._scsi_dirty)

    def test_flush_invokes_scsi_cache_barrier_only_for_dirty_plain_writes(self):
        dev = self._device()
        dev._scsi_dirty = True
        dev._scsi_synchronize_cache = Mock()
        with patch.object(diskmod.kernel32, "FlushFileBuffers", return_value=True):
            dev.flush()
        dev._scsi_synchronize_cache.assert_called_once_with()

    def test_sticky_scsi_route_skips_known_failing_windows_paths(self):
        dev = self._device()
        dev._partition_offset = 4096
        dev._fallback_write_route = "scsi"
        dev._scsi_write10 = Mock()
        dev._write_locked_partition_device = Mock(
            side_effect=AssertionError("must not reprobe partition path")
        )

        dev._fallback_after_volume_access_denied(512, b"x" * 512)

        dev._scsi_write10.assert_called_once_with(4608, b"x" * 512)
        dev._write_locked_partition_device.assert_not_called()


if __name__ == "__main__":
    unittest.main()
