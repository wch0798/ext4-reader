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
        dev._handle = 888
        dev.sector_size = 512
        dev._removable = True
        dev._bus_type = 7
        dev._disk_offline = False
        dev._usbdk = None
        dev._nt_handle = None
        dev._use_overlapped = False
        dev._partition_volume = _LockedVolume(
            handle=999,
            name=r"\\.\HarddiskVolume27",
            partition_number=1,
            locked=True,
            offline=False,
        )
        dev._volume_locks = [dev._partition_volume]
        dev._write_locked_partition_device = lambda offset, data: (_ for _ in ()).throw(
            IoError("partition access denied", winerr=5)
        )
        # Most fallback-ordering tests focus on pre-existing routes. Dedicated
        # tests below enable the new whole-disk OFFLINE stage explicitly.
        dev._activate_whole_disk_offline = lambda: (False, 5)
        dev._prepare_system_helper_handle = lambda: None
        dev._write_unbuffered_physical = lambda offset, data: (_ for _ in ()).throw(
            IoError("unbuffered denied", winerr=5)
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

    def test_unbuffered_runs_after_native_nt_before_scsi(self):
        dev = self.make_dev()
        calls = []
        absolute = dev._partition_offset + 4755456
        payload = b"u" * 4096

        dev._write_at = lambda offset, data: (
            calls.append(("physical", offset)),
            (_ for _ in ()).throw(IoError("physical denied", winerr=5)),
        )[1]
        dev._nt_write_at = lambda offset, data: (
            calls.append(("nt", offset)),
            (_ for _ in ()).throw(IoError("nt denied", winerr=5)),
        )[1]

        def unbuffered(offset, data):
            calls.append(("unbuffered", offset, bytes(data)))

        dev._write_unbuffered_physical = unbuffered
        dev._scsi_write10 = lambda offset, data: calls.append(("scsi", offset))

        dev._fallback_after_volume_access_denied(4755456, payload)

        self.assertEqual(
            calls,
            [
                ("physical", absolute),
                ("nt", absolute),
                ("unbuffered", absolute, payload),
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

    def test_whole_disk_offline_stage_runs_before_localsystem(self):
        dev = self.make_dev()
        payload = b"d" * 4096
        absolute = dev._partition_offset + 4755456
        calls = []
        physical_attempts = {"count": 0}

        def write_at(offset, data):
            physical_attempts["count"] += 1
            calls.append(("physical", physical_attempts["count"], offset))
            if physical_attempts["count"] == 1:
                raise IoError("physical denied", winerr=5)

        dev._write_at = write_at
        dev._nt_write_at = lambda offset, data: (_ for _ in ()).throw(
            IoError("native denied", winerr=5)
        )
        dev._scsi_write10 = lambda offset, data: (_ for _ in ()).throw(
            IoError("scsi denied", winerr=5)
        )

        def activate():
            calls.append(("offline",))
            dev._disk_offline = True
            dev._partition_volume = None
            return True, 0

        dev._activate_whole_disk_offline = activate

        with patch(
            "ext4reader.system_raw_helper.run_system_raw_write",
            side_effect=AssertionError("LocalSystem must not run after offline write succeeds"),
        ):
            dev._fallback_after_volume_access_denied(4755456, payload)

        self.assertEqual(
            calls,
            [
                ("physical", 1, absolute),
                ("offline",),
                ("physical", 2, absolute),
            ],
        )

    def test_localsystem_helper_runs_only_after_all_admin_paths_fail(self):
        dev = self.make_dev()
        payload = b"s" * 4096
        absolute = dev._partition_offset + 4755456

        dev._write_at = lambda offset, data: (_ for _ in ()).throw(
            IoError("physical denied", winerr=5)
        )
        dev._nt_write_at = lambda offset, data: (_ for _ in ()).throw(
            IoError("native denied", winerr=5)
        )
        dev._scsi_write10 = lambda offset, data: (_ for _ in ()).throw(
            IoError("scsi denied", winerr=5)
        )
        dev._prepare_system_helper_handle = lambda: None
        dev._read_at = lambda offset, length: payload if (offset, length) == (absolute, len(payload)) else b""

        with patch(
            "ext4reader.system_raw_helper.run_system_raw_write",
            return_value={"ok": True, "method": "SYSTEM duplicated-volume NtWriteFile"},
        ) as helper:
            dev._fallback_after_volume_access_denied(4755456, payload)

        helper.assert_called_once()
        kwargs = helper.call_args.kwargs
        self.assertEqual(kwargs["physical_path"], r"\\.\PhysicalDrive1")
        self.assertEqual(kwargs["physical_handle"], 888)
        self.assertEqual(kwargs["volume_handle"], 999)
        self.assertEqual(kwargs["relative_offset"], 4755456)
        self.assertEqual(kwargs["absolute_offset"], absolute)
        self.assertEqual(kwargs["partition_offset"], 1048576)
        self.assertEqual(kwargs["partition_size"], 1023869452288)
        self.assertEqual(kwargs["sector_size"], 512)
        self.assertTrue(kwargs["try_disk_offline"])
        self.assertEqual(kwargs["data"], payload)

    def test_usbdk_runs_only_after_localsystem_failure_on_usb_reader(self):
        dev = self.make_dev()
        payload = b"b" * 4096
        absolute = dev._partition_offset + 4755456
        calls = []

        dev._write_at = lambda offset, data: (_ for _ in ()).throw(
            IoError("physical denied", winerr=5)
        )
        dev._nt_write_at = lambda offset, data: (_ for _ in ()).throw(
            IoError("native denied", winerr=5)
        )
        dev._scsi_write10 = lambda offset, data: (_ for _ in ()).throw(
            IoError("scsi denied", winerr=5)
        )
        dev._prepare_system_helper_handle = lambda: None

        class FakeUsb:
            def write(self, offset, data):
                calls.append(("usbdk", offset, bytes(data)))

        def activate():
            calls.append(("activate",))
            dev._usbdk = FakeUsb()

        dev._activate_usbdk_backend = activate

        with patch(
            "ext4reader.system_raw_helper.run_system_raw_write",
            return_value={"ok": False, "error": "SYSTEM denied"},
        ):
            dev._fallback_after_volume_access_denied(4755456, payload)

        self.assertEqual(
            calls,
            [
                ("activate",),
                ("usbdk", absolute, payload),
            ],
        )

    def test_non_usb_reader_does_not_use_usbdk_after_localsystem_failure(self):
        dev = self.make_dev()
        dev._bus_type = 12
        dev._write_at = lambda offset, data: (_ for _ in ()).throw(
            IoError("physical denied", winerr=5)
        )
        dev._nt_write_at = lambda offset, data: (_ for _ in ()).throw(
            IoError("native denied", winerr=5)
        )
        dev._scsi_write10 = lambda offset, data: (_ for _ in ()).throw(
            IoError("scsi denied", winerr=5)
        )
        dev._prepare_system_helper_handle = lambda: None
        dev._activate_usbdk_backend = lambda: (_ for _ in ()).throw(
            AssertionError("UsbDk must not run for native SD/MMC bus")
        )

        with patch(
            "ext4reader.system_raw_helper.run_system_raw_write",
            return_value={"ok": False, "error": "SYSTEM denied"},
        ):
            with self.assertRaises(IoError) as cm:
                dev._fallback_after_volume_access_denied(4755456, b"x" * 4096)

        self.assertIn("LocalSystem raw helper 실패", str(cm.exception))

    def test_usbdk_failure_restore_retries_during_pnp_reenumeration(self):
        import ext4reader.windows_disk as wd

        dev = WindowsPhysicalDevice.__new__(WindowsPhysicalDevice)
        dev.path = r"\\.\PhysicalDrive1"
        dev._size = 0
        dev._usbdk = object()
        attempts = {"count": 0}

        def reopen():
            attempts["count"] += 1
            if attempts["count"] < 3:
                raise IoError("PhysicalDrive not back yet", winerr=1167)

        dev._reopen_locked = reopen

        with patch.object(wd.time, "sleep") as sleep:
            dev._restore_windows_after_usbdk_failure()

        self.assertIsNone(dev._usbdk)
        self.assertEqual(attempts["count"], 3)
        self.assertEqual(sleep.call_count, 2)
        sleep.assert_called_with(0.25)

    def test_usbdk_activation_preserves_original_probe_error_after_restore(self):
        import threading
        import ext4reader.windows_disk as wd

        dev = WindowsPhysicalDevice.__new__(WindowsPhysicalDevice)
        dev.path = r"\\.\PhysicalDrive1"
        dev._writable = True
        dev._removable = True
        dev._bus_type = 7
        dev._partition_offset = 1048576
        dev._partition_size = 1023869452288
        dev._size = 1023871549440
        dev.sector_size = 512
        dev._usbdk = None
        dev._disk_offline = False
        dev._stop_ka = threading.Event()
        dev._nt_handle = None
        dev._volume_locks = []
        dev._partition_volume = None
        dev._handle = 888
        dev._raw_read_once = lambda offset, length: b"x" * length
        restored = []
        dev._restore_windows_after_usbdk_failure = lambda: restored.append(True)

        with patch("ext4reader.usbdk_setup.usbdk_ready", return_value=True), patch(
            "ext4reader.usbdk_backend.UsbDkBotBackend",
            side_effect=IoError("BOT probe failed", winerr=31),
        ), patch.object(wd.kernel32, "CloseHandle", return_value=True):
            with self.assertRaises(IoError) as cm:
                dev._activate_usbdk_backend()

        self.assertEqual(str(cm.exception), "BOT probe failed")
        self.assertEqual(restored, [True])

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

    def test_volume_access_denied_tries_native_nt_on_same_handle_first(self):
        import ext4reader.windows_disk as wd

        dev = self.make_dev()
        calls = []
        item = _LockedVolume(
            handle=321,
            name=r"\\.\HarddiskVolume27",
            partition_number=1,
            locked=True,
            offline=False,
        )

        class FakeKernel32:
            def SetLastError(self, value):
                wd.ctypes.set_last_error(value)

            def SetFilePointerEx(self, handle, offset, new_pos, origin):
                return True

            def WriteFile(self, handle, buf, length, done, overlapped):
                wd.ctypes.set_last_error(5)
                return False

        dev._nt_write_volume_handle = lambda vol, offset, data: calls.append(
            ("native-volume", vol.handle, offset, bytes(data))
        )
        dev._fallback_after_volume_access_denied = lambda offset, data: calls.append(
            ("fallback", offset, bytes(data))
        )

        payload = b"n" * 4096
        with patch.object(wd, "kernel32", FakeKernel32()):
            dev._write_volume_seek(item, 4755456, payload)

        self.assertEqual(
            calls,
            [("native-volume", 321, 4755456, payload)],
        )

    def test_volume_native_nt_failure_continues_to_other_raw_paths(self):
        import ext4reader.windows_disk as wd

        dev = self.make_dev()
        calls = []
        item = _LockedVolume(
            handle=322,
            name=r"\\.\HarddiskVolume27",
            partition_number=1,
            locked=True,
            offline=False,
        )

        class FakeKernel32:
            def SetLastError(self, value):
                wd.ctypes.set_last_error(value)

            def SetFilePointerEx(self, handle, offset, new_pos, origin):
                return True

            def WriteFile(self, handle, buf, length, done, overlapped):
                wd.ctypes.set_last_error(5)
                return False

        def native_fail(vol, offset, data):
            calls.append(("native-volume", offset))
            raise IoError("native volume denied", winerr=5)

        dev._nt_write_volume_handle = native_fail
        dev._fallback_after_volume_access_denied = lambda offset, data: calls.append(
            ("fallback", offset)
        )

        with patch.object(wd, "kernel32", FakeKernel32()):
            dev._write_volume_seek(item, 4755456, b"f" * 4096)

        self.assertEqual(
            calls,
            [("native-volume", 4755456), ("fallback", 4755456)],
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


class UnbufferedRawIoTests(unittest.TestCase):
    def test_access_alignment_parser_prefers_device_values(self):
        import ext4reader.windows_disk as wd

        raw = bytearray(28)
        raw[0:4] = (28).to_bytes(4, "little")
        raw[4:8] = (28).to_bytes(4, "little")
        raw[16:20] = (512).to_bytes(4, "little")
        raw[20:24] = (4096).to_bytes(4, "little")

        with patch.object(wd, "_ioctl", return_value=bytes(raw)):
            logical, physical = wd._query_access_alignment(123, 512)

        self.assertEqual(logical, 512)
        self.assertEqual(physical, 4096)

    def test_access_alignment_falls_back_when_query_fails(self):
        import ext4reader.windows_disk as wd

        with patch.object(wd, "_ioctl", side_effect=OSError(5)):
            logical, physical = wd._query_access_alignment(123, 4096)

        self.assertEqual((logical, physical), (4096, 4096))


class WholeDiskOfflineTests(unittest.TestCase):
    def test_set_disk_offline_uses_nonpersistent_attribute_mask_and_verifies(self):
        import ext4reader.windows_disk as wd

        calls = []

        def fake_ioctl(handle, code, inbuf=None, out_cb=0):
            calls.append((handle, code, bytes(inbuf) if inbuf is not None else None, out_cb))
            return b""

        with patch.object(wd, "_ioctl", side_effect=fake_ioctl), patch.object(
            wd,
            "_query_disk_attributes",
            return_value=(wd.DISK_ATTRIBUTE_OFFLINE, 0),
        ):
            ok, err = wd._set_disk_offline_state(123, True)

        self.assertTrue(ok)
        self.assertEqual(err, 0)
        self.assertEqual(calls[0][1], wd.IOCTL_DISK_SET_DISK_ATTRIBUTES)
        raw = calls[0][2]
        self.assertEqual(len(raw), 40)
        self.assertEqual(int.from_bytes(raw[0:4], "little"), 16)
        self.assertEqual(raw[4], 0)
        self.assertEqual(
            int.from_bytes(raw[8:16], "little"),
            wd.DISK_ATTRIBUTE_OFFLINE,
        )
        self.assertEqual(
            int.from_bytes(raw[16:24], "little"),
            wd.DISK_ATTRIBUTE_OFFLINE,
        )

    def test_set_disk_online_clears_only_offline_attribute(self):
        import ext4reader.windows_disk as wd

        sent = []

        def fake_ioctl(handle, code, inbuf=None, out_cb=0):
            sent.append(bytes(inbuf))
            return b""

        with patch.object(wd, "_ioctl", side_effect=fake_ioctl), patch.object(
            wd,
            "_query_disk_attributes",
            return_value=(0, 0),
        ):
            ok, err = wd._set_disk_offline_state(123, False)

        self.assertTrue(ok)
        self.assertEqual(err, 0)
        self.assertEqual(int.from_bytes(sent[0][8:16], "little"), 0)
        self.assertEqual(
            int.from_bytes(sent[0][16:24], "little"),
            wd.DISK_ATTRIBUTE_OFFLINE,
        )


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



class ReaderCompatibilityTests(unittest.TestCase):
    VOLUME_GUID = "\\\\?\\Volume{01234567-89ab-cdef-0123-456789abcdef}\\"

    def test_volume_guid_normalization_for_fve(self):
        import ext4reader.windows_disk as wd

        self.assertEqual(
            wd._volume_guid_for_fve("Volume{01234567-89ab-cdef-0123-456789abcdef}"),
            self.VOLUME_GUID,
        )
        self.assertEqual(
            wd._volume_guid_for_fve("\\\\.\\Volume{01234567-89ab-cdef-0123-456789abcdef}"),
            self.VOLUME_GUID,
        )
        self.assertIsNone(wd._volume_guid_for_fve("\\\\.\\HarddiskVolume27"))

    def test_hidden_volume_fve_candidates_include_globalroot_and_nt_target(self):
        import ext4reader.windows_disk as wd

        values = wd._fve_raw_candidates(
            r"\\.\HarddiskVolume27",
            None,
            r"\Device\HarddiskVolume27",
        )

        self.assertIn(r"\\?\GLOBALROOT\Device\HarddiskVolume27", values)
        self.assertIn(r"\Device\HarddiskVolume27", values)
        self.assertIn(r"\\.\HarddiskVolume27", values)

    def test_hidden_volume_fve_tries_multiple_identifiers_until_one_works(self):
        import ext4reader.windows_disk as wd

        calls = []

        def fake_access(name, enabled):
            calls.append((name, enabled))
            return (name == r"\\?\GLOBALROOT\Device\HarddiskVolume27", 0 if name == r"\\?\GLOBALROOT\Device\HarddiskVolume27" else 0x80070057)

        with patch.object(wd, "_FveEnableRawAccessW", object()), patch.object(
            wd, "_fve_raw_access", side_effect=fake_access
        ):
            selected = wd._try_enable_fve_raw_access(
                r"\\.\HarddiskVolume27",
                None,
                r"\Device\HarddiskVolume27",
            )

        self.assertEqual(
            selected,
            r"\\?\GLOBALROOT\Device\HarddiskVolume27",
        )
        self.assertEqual(calls[0][1], True)

    def test_fve_raw_access_success_and_hresult(self):
        import ext4reader.windows_disk as wd

        calls = []

        def fake_fve(name, enabled):
            calls.append((name, bool(enabled)))
            return 0

        with patch.object(wd, "_FveEnableRawAccessW", fake_fve):
            ok, hr = wd._fve_raw_access(self.VOLUME_GUID, True)

        self.assertTrue(ok)
        self.assertEqual(hr, 0)
        self.assertEqual(calls, [(self.VOLUME_GUID, True)])

    def test_fve_raw_access_reports_access_denied_hresult(self):
        import ext4reader.windows_disk as wd

        with patch.object(wd, "_FveEnableRawAccessW", lambda name, enabled: -2147024891):
            ok, hr = wd._fve_raw_access(self.VOLUME_GUID, True)

        self.assertFalse(ok)
        self.assertEqual(hr, 0x80070005)

    def test_release_disables_fve_raw_access_after_closing_volume(self):
        import ext4reader.windows_disk as wd

        hidden_fve_name = r"\\?\GLOBALROOT\Device\HarddiskVolume27"
        item = _LockedVolume(
            handle=91,
            name="\\\\.\\HarddiskVolume27",
            partition_number=1,
            locked=True,
            offline=False,
            volume_guid=self.VOLUME_GUID,
            fve_name=hidden_fve_name,
            fve_raw=True,
        )
        calls = []
        with patch.object(wd, "_bring_volume_online", lambda v: calls.append(("online", v.handle))), patch.object(
            wd.kernel32, "CloseHandle", lambda h: calls.append(("close", int(h))) or True
        ), patch.object(
            wd, "_fve_raw_access", lambda name, enabled: calls.append(("fve", name, enabled)) or (True, 0)
        ):
            wd._release_locked_volume(item)

        self.assertEqual(calls[0], ("online", 91))
        self.assertEqual(calls[1], ("close", 91))
        self.assertEqual(calls[2], ("fve", hidden_fve_name, False))
        self.assertFalse(item.fve_raw)

    def test_bus_names_cover_usb_sd_and_mmc_readers(self):
        import ext4reader.windows_disk as wd

        self.assertEqual(wd.BUS_NAMES[7], "USB")
        self.assertEqual(wd.BUS_NAMES[12], "SD")
        self.assertEqual(wd.BUS_NAMES[13], "MMC")

