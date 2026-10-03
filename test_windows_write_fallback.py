import unittest

from ext4reader.io_backend import IoError
from ext4reader.windows_disk import WindowsPhysicalDevice


class WriteFallbackTests(unittest.TestCase):
    def make_dev(self):
        dev = WindowsPhysicalDevice.__new__(WindowsPhysicalDevice)
        dev._partition_offset = 1048576
        dev._partition_size = 1023869452288
        dev._size = 1023871549440
        return dev

    def test_physicaldrive_retry_uses_absolute_offset_and_stops_on_success(self):
        dev = self.make_dev()
        calls = []

        def write_at(offset, data):
            calls.append(("physical", offset, bytes(data)))

        def scsi(offset, data):
            calls.append(("scsi", offset, bytes(data)))

        dev._write_at = write_at
        dev._scsi_write10 = scsi

        payload = b"x" * 4096
        dev._fallback_after_volume_access_denied(4755456, payload)

        self.assertEqual(
            calls,
            [("physical", 1048576 + 4755456, payload)],
        )

    def test_scsi_runs_only_after_physicaldrive_retry_fails(self):
        dev = self.make_dev()
        calls = []

        def write_at(offset, data):
            calls.append(("physical", offset, bytes(data)))
            raise IoError("access denied", winerr=5)

        def scsi(offset, data):
            calls.append(("scsi", offset, bytes(data)))

        dev._write_at = write_at
        dev._scsi_write10 = scsi

        payload = b"y" * 4096
        dev._fallback_after_volume_access_denied(4755456, payload)

        absolute = 1048576 + 4755456
        self.assertEqual(
            calls,
            [
                ("physical", absolute, payload),
                ("scsi", absolute, payload),
            ],
        )

    def test_partition_write_target_is_relative_to_partition_start(self):
        dev = self.make_dev()
        item = object()
        dev._partition_volume = item

        target = dev._partition_write_target(1048576 + 4096, 4096)
        self.assertEqual(target, (item, 4096))

    def test_partition_write_target_rejects_out_of_partition_range(self):
        dev = self.make_dev()
        dev._partition_volume = object()

        self.assertIsNone(dev._partition_write_target(0, 4096))
        self.assertIsNone(
            dev._partition_write_target(
                dev._partition_offset + dev._partition_size - 2048,
                4096,
            )
        )


if __name__ == "__main__":
    unittest.main()
