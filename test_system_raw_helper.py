import base64
import hashlib
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
