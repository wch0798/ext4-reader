import unittest
from unittest.mock import patch

from ext4reader.io_backend import IoError
from ext4reader.windows_disk import WindowsPhysicalDevice, _LockedVolume


class WriteFallbackTests(unittest.TestCase):
    def make_dev(self):
        dev = WindowsPhysicalDevice.__new__(WindowsPhysicalDevice)
        dev.path = r"\\.\PhysicalDrive1"
        dev._partition_number = 1
        dev._partition_offset = 1048576
        dev._partition_size = 1023869452288
        dev._size = 1023871549440
        dev._write_blockers = []
        dev._write_locked_partition_device = lambda offset, data: (_ for _ in ()).throw(
            IoError("partition access denied", winerr=5)
        )
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

        dev._write_locked_partition_device = lambda offset, data: (_ for _ in ()).throw(
            IoError("partition access denied", winerr=5)
        )
        dev._write_locked_partition_device = lambda offset, data: (_ for _ in ()).throw(
            IoError("partition access denied", winerr=5)
        )
        dev._write_locked_partition_device = lambda offset, data: (_ for _ in ()).throw(
            IoError("partition access denied", winerr=5)
        )
        dev._write_at = write_at
        dev._nt_write_at = nt_write
        dev._scsi_write10 = scsi

        payload = b"x" * 4096
        dev._fallback_after_volume_access_denied(4755456, payload)

        self.assertEqual(
            calls,
            [("physical", 1048576 + 4755456, payload)],
        )

    def test_locked_partition_device_is_first_fallback_and_stops_on_success(self):
        dev = self.make_dev()
        calls = []

        def part_write(offset, data):
            calls.append(("partition", offset, bytes(data)))

        def write_at(offset, data):
            calls.append(("physical", offset, bytes(data)))

        dev._write_locked_partition_device = part_write
        dev._write_at = write_at
        dev._nt_write_at = lambda offset, data: calls.append(("nt", offset, bytes(data)))
        dev._scsi_write10 = lambda offset, data: calls.append(("scsi", offset, bytes(data)))

        payload = b"p" * 4096
        dev._fallback_after_volume_access_denied(4755456, payload)

        self.assertEqual(calls, [("partition", 4755456, payload)])

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


    def test_offline_volume_skips_volume_write_and_uses_physical_fallback(self):
        dev = self.make_dev()
        calls = []
        item = _LockedVolume(
            handle=123,
            name=r"\\.\HarddiskVolume26",
            partition_number=1,
            locked=True,
            offline=True,
        )

        def fallback(relative, data):
            calls.append((relative, bytes(data)))

        dev._fallback_after_volume_access_denied = fallback
        payload = b"o" * 4096
        dev._write_volume_seek(item, 4755456, payload)

        self.assertEqual(calls, [(4755456, payload)])


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


class VolumeOfflineTests(unittest.TestCase):
    def test_take_volume_offline_uses_documented_ioctl(self):
        import ext4reader.windows_disk as wd

        calls = []
        with patch.object(wd, "_ioctl", lambda handle, code: calls.append((handle, code)) or b""):
            self.assertTrue(wd._take_volume_offline(77, r"\\.\HarddiskVolume26"))

        self.assertEqual(calls, [(77, wd.IOCTL_VOLUME_OFFLINE)])

    def test_bring_volume_online_clears_offline_state(self):
        import ext4reader.windows_disk as wd

        item = _LockedVolume(
            handle=88,
            name=r"\\.\HarddiskVolume26",
            partition_number=1,
            locked=True,
            offline=True,
        )
        calls = []
        with patch.object(wd, "_ioctl", lambda handle, code: calls.append((handle, code)) or b""):
            wd._bring_volume_online(item)

        self.assertFalse(item.offline)
        self.assertEqual(calls, [(88, wd.IOCTL_VOLUME_ONLINE)])


class StoragePrivilegeTests(unittest.TestCase):
    def test_storage_privilege_requests_manage_volume(self):
        import ext4reader.windows_disk as wd

        calls = []
        with patch.object(
            wd,
            "_enable_privilege",
            lambda name: calls.append(name) or (True, 0),
        ):
            self.assertTrue(wd._enable_storage_privileges())

        self.assertEqual(calls, [wd.SE_MANAGE_VOLUME_NAME])

    def test_storage_privilege_failure_is_reported(self):
        import ext4reader.windows_disk as wd

        with patch.object(wd, "_enable_privilege", return_value=(False, wd.ERROR_NOT_ALL_ASSIGNED)):
            self.assertFalse(wd._enable_storage_privileges())


class WindowsWritePolicyTests(unittest.TestCase):
    def test_policy_detector_reports_removable_disk_deny_write(self):
        import ext4reader.windows_disk as wd

        values = {
            ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}", "Deny_Write"): 1,
        }

        def fake_read(root, path, name):
            root_name = "HKLM" if root == wd.winreg.HKEY_LOCAL_MACHINE else "HKCU"
            return values.get((root_name, path, name))

        with patch.object(wd, "_read_reg_dword", side_effect=fake_read):
            blockers = wd._windows_write_policy_blockers()

        self.assertTrue(any("이동식 디스크 쓰기 액세스 거부" in x for x in blockers))

    def test_policy_detector_reports_bitlocker_removable_write_policy(self):
        import ext4reader.windows_disk as wd

        def fake_read(root, path, name):
            if (
                root == wd.winreg.HKEY_LOCAL_MACHINE
                and path == r"SYSTEM\CurrentControlSet\Policies\Microsoft\FVE"
                and name == "RDVDenyWriteAccess"
            ):
                return 1
            return None

        with patch.object(wd, "_read_reg_dword", side_effect=fake_read):
            blockers = wd._windows_write_policy_blockers()

        self.assertTrue(any("BitLocker 정책" in x for x in blockers))

    def test_disk_attribute_parser_detects_read_only(self):
        import ext4reader.windows_disk as wd

        raw = (
            (16).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
            + wd.DISK_ATTRIBUTE_READ_ONLY.to_bytes(8, "little")
        )
        with patch.object(wd, "_ioctl", return_value=raw):
            attrs, err = wd._query_disk_attributes(123)

        self.assertEqual(err, 0)
        self.assertEqual(attrs, wd.DISK_ATTRIBUTE_READ_ONLY)

    def test_gpt_attribute_parser_detects_read_only(self):
        import ext4reader.windows_disk as wd

        raw = bytearray(160)
        raw[0:4] = wd.PARTITION_STYLE_GPT.to_bytes(4, "little")
        raw[64:72] = wd.GPT_ATTRIBUTE_READ_ONLY.to_bytes(8, "little")
        with patch.object(wd, "_ioctl", return_value=bytes(raw)):
            attrs, err = wd._query_partition_gpt_attributes(123)

        self.assertEqual(err, 0)
        self.assertEqual(attrs, wd.GPT_ATTRIBUTE_READ_ONLY)

    def test_final_access_denied_reports_detected_policy(self):
        dev = WriteFallbackTests().make_dev()
        dev._write_blockers = ["컴퓨터 정책: 이동식 디스크 쓰기 액세스 거부 [Deny_Write=1]"]

        dev._write_locked_partition_device = lambda offset, data: (_ for _ in ()).throw(
            IoError("partition", winerr=5)
        )
        dev._write_at = lambda offset, data: (_ for _ in ()).throw(IoError("win32", winerr=5))
        dev._nt_write_at = lambda offset, data: (_ for _ in ()).throw(IoError("nt", winerr=5))
        dev._scsi_write10 = lambda offset, data: (_ for _ in ()).throw(IoError("scsi", winerr=5))

        with self.assertRaises(IoError) as cm:
            dev._fallback_after_volume_access_denied(4755456, b"x" * 4096)

        self.assertIn("Windows가 저장장치 쓰기를 정책/속성으로 차단", str(cm.exception))
        self.assertIn("Deny_Write=1", str(cm.exception))
