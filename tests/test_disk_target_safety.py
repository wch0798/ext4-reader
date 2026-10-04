import unittest
from unittest.mock import Mock

from ext4lib.io.backend import IoError
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


if __name__ == "__main__":
    unittest.main()
