import unittest
from unittest.mock import patch

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

        def nt_write(offset, data):
            calls.append(("nt", offset, bytes(data)))

        def scsi(offset, data):
            calls.append(("scsi", offset, bytes(data)))

        dev._write_at = write_at
        dev._nt_write_at = nt_write
        dev._scsi_write10 = scsi

        payload = b"x" * 4096
        dev._fallback_after_volume_access_denied(4755456, payload)

        self.assertEqual(
            calls,
            [("physical", 1048576 + 4755456, payload)],
        )

    def test_native_nt_runs_after_physicaldrive_retry_fails(self):
        dev = self.make_dev()
        calls = []

        def write_at(offset, data):
            calls.append(("physical", offset, bytes(data)))
            raise IoError("access denied", winerr=5)

        def nt_write(offset, data):
            calls.append(("nt", offset, bytes(data)))

        def scsi(offset, data):
            calls.append(("scsi", offset, bytes(data)))

        dev._write_at = write_at
        dev._nt_write_at = nt_write
        dev._scsi_write10 = scsi

        payload = b"y" * 4096
        dev._fallback_after_volume_access_denied(4755456, payload)

        absolute = 1048576 + 4755456
        self.assertEqual(
            calls,
            [
                ("physical", absolute, payload),
                ("nt", absolute, payload),
            ],
        )

    def test_scsi_runs_only_after_physical_and_native_nt_fail(self):
        dev = self.make_dev()
        calls = []

        def write_at(offset, data):
            calls.append(("physical", offset, bytes(data)))
            raise IoError("access denied", winerr=5)

        def nt_write(offset, data):
            calls.append(("nt", offset, bytes(data)))
            raise IoError("nt access denied", winerr=5)

        def scsi(offset, data):
            calls.append(("scsi", offset, bytes(data)))

        dev._write_at = write_at
        dev._nt_write_at = nt_write
        dev._scsi_write10 = scsi

        payload = b"z" * 4096
        dev._fallback_after_volume_access_denied(4755456, payload)

        absolute = 1048576 + 4755456
        self.assertEqual(
            calls,
            [
                ("physical", absolute, payload),
                ("nt", absolute, payload),
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


class RawOpenTests(unittest.TestCase):
    def test_writable_open_prefers_share_read_and_normal_attribute(self):
        import ext4reader.windows_disk as wd

        calls = []

        class FakeKernel32:
            def CreateFileW(self, path, access, share, sec, creation, flags, template):
                calls.append((path, access, share, creation, flags))
                return 12345

        with patch.object(wd, "kernel32", FakeKernel32()), patch.object(
            wd, "_allow_extended_io", lambda handle: None
        ):
            handle = wd._open_handle(r"\\.\PhysicalDrive9", True)

        self.assertEqual(handle, 12345)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][2], wd.FILE_SHARE_READ)
        self.assertEqual(calls[0][4], wd.FILE_ATTRIBUTE_NORMAL)

    def test_writable_open_falls_back_to_share_write(self):
        import ext4reader.windows_disk as wd

        calls = []

        class FakeKernel32:
            def CreateFileW(self, path, access, share, sec, creation, flags, template):
                calls.append((share, flags))
                if len(calls) == 1:
                    return wd.INVALID_HANDLE_VALUE
                return 54321

        errors = iter([5])

        with patch.object(wd, "kernel32", FakeKernel32()), patch.object(
            wd, "_allow_extended_io", lambda handle: None
        ), patch.object(wd.ctypes, "get_last_error", lambda: next(errors, 5)):
            handle = wd._open_handle(r"\\.\PhysicalDrive9", True)

        self.assertEqual(handle, 54321)
        self.assertEqual(calls[0], (wd.FILE_SHARE_READ, wd.FILE_ATTRIBUTE_NORMAL))
        self.assertEqual(
            calls[1],
            (wd.FILE_SHARE_READ | wd.FILE_SHARE_WRITE, wd.FILE_ATTRIBUTE_NORMAL),
        )


class NativePathTests(unittest.TestCase):
    def test_win32_physicaldrive_path_converts_to_nt_dos_device(self):
        import ext4reader.windows_disk as wd
        self.assertEqual(
            wd._nt_native_path(r"\\.\PhysicalDrive1"),
            r"\??\PhysicalDrive1",
        )

    def test_globalroot_path_converts_to_device_path(self):
        import ext4reader.windows_disk as wd
        self.assertEqual(
            wd._nt_native_path(r"\\?\GLOBALROOT\Device\HarddiskVolume26"),
            r"\Device\HarddiskVolume26",
        )
