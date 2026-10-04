import unittest
from unittest.mock import Mock

from ext4lib.io.backend import IoError
from ext4lib.windows.disk import WindowsPhysicalDevice


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


if __name__ == "__main__":
    unittest.main()
