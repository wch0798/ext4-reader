import base64
import hashlib
import os
import tempfile
import unittest
from unittest.mock import patch

from ext4reader.io_backend import IoError
from ext4reader import system_raw_helper as helper


class SystemRawHelperTests(unittest.TestCase):
    def make_request(self):
        data = b"x" * 4096
        return {
            "version": 1,
            "physical_path": r"\\.\PhysicalDrive1",
            "parent_pid": 1234,
            "physical_handle": 5678,
            "volume_handle": 9012,
            "relative_offset": 4755456,
            "absolute_offset": 5804032,
            "partition_offset": 1048576,
            "partition_size": 1023869452288,
            "sector_size": 512,
            "try_disk_offline": False,
            "data_b64": base64.b64encode(data).decode("ascii"),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    def test_task_command_quotes_executable_and_request(self):
        cmd = helper._task_run_command(
            r"C:\Program Files\Ext4 Reader\Ext4Reader.exe",
            r"C:\ProgramData\Ext4Reader\RawHelper\raw-1.json",
        )
        self.assertEqual(
            cmd,
            '"C:\\Program Files\\Ext4 Reader\\Ext4Reader.exe" '
            '--raw-helper-request '
            '"C:\\ProgramData\\Ext4Reader\\RawHelper\\raw-1.json"',
        )

    def test_system_helper_exe_uses_verified_copy(self):
        with tempfile.TemporaryDirectory() as td:
            source = os.path.join(td, "Ext4Reader.exe")
            out = os.path.join(td, "helper")
            os.mkdir(out)
            with open(source, "wb") as fp:
                fp.write(b"fake-pyinstaller-image")

            with patch.object(helper, "_program_data_dir", return_value=out):
                copied = helper._system_helper_exe(source)

            self.assertNotEqual(os.path.normcase(copied), os.path.normcase(source))
            with open(copied, "rb") as fp:
                self.assertEqual(fp.read(), b"fake-pyinstaller-image")

    def test_execute_uses_system_unbuffered_before_normal_fresh_write(self):
        import ext4reader.windows_disk as wd

        req = self.make_request()
        devno = wd.STORAGE_DEVICE_NUMBER()
        devno.DeviceType = 7
        devno.DeviceNumber = 1
        devno.PartitionNumber = 0
        raw_devno = bytes(devno)
        calls = []

        def duplicate(pid, handle):
            return 101 if handle == req["physical_handle"] else 102

        def unbuffered(path, offset, data, sector, **kwargs):
            calls.append((path, offset, len(data), sector, kwargs))
            return 512, 4096

        with patch.object(helper, "_duplicate_handle", side_effect=duplicate), patch.object(
            wd, "_query_storage", return_value=("", "Generic Reader", 7, True)
        ), patch.object(
            wd, "_ioctl", return_value=raw_devno
        ), patch.object(
            helper, "_write_win32", side_effect=IoError("duplicated denied", winerr=5)
        ), patch.object(
            helper, "_write_nt", side_effect=IoError("duplicated nt denied", winerr=5)
        ), patch.object(
            wd, "_write_unbuffered_raw_path", side_effect=unbuffered
        ):
            result = helper._execute_request(req)

        self.assertTrue(result["ok"])
        self.assertEqual(result["method"], "SYSTEM fresh-PhysicalDrive NO_BUFFERING")
        self.assertFalse(result["disk_offline"])
        self.assertEqual(result["logical_sector"], 512)
        self.assertEqual(result["physical_sector"], 4096)
        self.assertEqual(calls[0][0], r"\\.\PhysicalDrive1")
        self.assertEqual(calls[0][1], 5804032)
        self.assertEqual(calls[0][3], 512)
        self.assertEqual(calls[0][4]["expected_device_number"], 1)
        self.assertEqual(calls[0][4]["expected_device_type"], 7)

    def test_execute_uses_fresh_system_physicaldrive_after_duplicated_handles_fail(self):
        import ext4reader.windows_disk as wd

        req = self.make_request()
        data = base64.b64decode(req["data_b64"])
        devno = wd.STORAGE_DEVICE_NUMBER()
        devno.DeviceType = 7
        devno.DeviceNumber = 1
        devno.PartitionNumber = 0
        raw_devno = bytes(devno)

        def duplicate(pid, handle):
            return 101 if handle == req["physical_handle"] else 102

        def write_win32(handle, offset, payload):
            if handle == 303:
                return
            raise IoError("duplicated denied", winerr=5)

        with patch.object(helper, "_duplicate_handle", side_effect=duplicate), patch.object(
            wd, "_query_storage", return_value=("", "Generic Reader", 7, True)
        ), patch.object(
            wd, "_ioctl", return_value=raw_devno
        ), patch.object(
            wd, "_open_handle", return_value=303
        ), patch.object(
            wd,
            "_write_unbuffered_raw_path",
            side_effect=IoError("unbuffered denied", winerr=5),
        ), patch.object(
            helper, "_write_win32", side_effect=write_win32
        ), patch.object(
            helper, "_write_nt", side_effect=IoError("nt denied", winerr=5)
        ), patch.object(
            helper, "_read_win32", return_value=data
        ):
            result = helper._execute_request(req)

        self.assertTrue(result["ok"])
        self.assertEqual(result["method"], "SYSTEM fresh-PhysicalDrive WriteFile")

    def test_execute_can_set_whole_disk_offline_before_fresh_system_write(self):
        import ext4reader.windows_disk as wd

        req = self.make_request()
        req["try_disk_offline"] = True
        data = base64.b64decode(req["data_b64"])
        devno = wd.STORAGE_DEVICE_NUMBER()
        devno.DeviceType = 7
        devno.DeviceNumber = 1
        devno.PartitionNumber = 0
        raw_devno = bytes(devno)
        offline_calls = []

        def duplicate(pid, handle):
            return 101 if handle == req["physical_handle"] else 102

        def write_win32(handle, offset, payload):
            if handle == 303:
                return
            raise IoError("duplicated denied", winerr=5)

        def set_offline(handle, offline):
            offline_calls.append((int(getattr(handle, "value", handle)), bool(offline)))
            return True, 0

        with patch.object(helper, "_duplicate_handle", side_effect=duplicate), patch.object(
            wd, "_query_storage", return_value=("", "Generic Reader", 7, True)
        ), patch.object(
            wd, "_ioctl", return_value=raw_devno
        ), patch.object(
            wd, "_open_handle", return_value=303
        ), patch.object(
            wd, "_set_disk_offline_state", side_effect=set_offline
        ), patch.object(
            wd,
            "_write_unbuffered_raw_path",
            side_effect=IoError("unbuffered denied", winerr=5),
        ), patch.object(
            helper, "_write_win32", side_effect=write_win32
        ), patch.object(
            helper, "_write_nt", side_effect=IoError("nt denied", winerr=5)
        ), patch.object(
            helper, "_read_win32", return_value=data
        ):
            result = helper._execute_request(req)

        self.assertTrue(result["ok"])
        self.assertTrue(result["disk_offline"])
        self.assertEqual(result["method"], "SYSTEM fresh-PhysicalDrive WriteFile")
        self.assertEqual(offline_calls, [(101, True)])

    def test_execute_rejects_absolute_relative_offset_mismatch_before_handle_use(self):
        req = self.make_request()
        req["absolute_offset"] += 512

        with patch.object(
            helper,
            "_duplicate_handle",
            side_effect=AssertionError("handle duplication must not run"),
        ):
            with self.assertRaises(IoError) as cm:
                helper._execute_request(req)

        self.assertIn("오프셋 불일치", str(cm.exception))

    def test_execute_rejects_write_outside_partition_before_handle_use(self):
        req = self.make_request()
        req["relative_offset"] = req["partition_size"] - 2048
        req["absolute_offset"] = req["partition_offset"] + req["relative_offset"]

        with patch.object(
            helper,
            "_duplicate_handle",
            side_effect=AssertionError("handle duplication must not run"),
        ):
            with self.assertRaises(IoError) as cm:
                helper._execute_request(req)

        self.assertIn("파티션 밖", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
