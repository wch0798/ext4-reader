import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from ext4lib.io.backend import IoError
from ext4lib.mount import fuse as fm


class DummyVolume:
    def __init__(self, *, fail_sync=False, active=False):
        self.fail_sync = fail_sync
        self.sync_calls = []
        self.closed = False
        self.finished = False
        self._write_session_active = active

    def commit_metadata(self, sync=True):
        self.sync_calls.append(bool(sync))
        if self.fail_sync:
            raise IoError("simulated device flush failure", winerr=31)

    def read_inode(self, ino):
        return SimpleNamespace(ino=ino)

    def finish_write_session(self):
        self.finished = True
        self._write_session_active = False

    def close(self):
        self.closed = True


class WriteSafetyTests(unittest.TestCase):
    def test_sync_failure_is_latched_and_write_mount_fails_closed(self):
        vol = DummyVolume(fail_sync=True)
        ops = fm.Ext4FuseOps(vol, read_only=False)

        with self.assertRaises(IoError):
            ops.sync_pending()

        self.assertTrue(ops.read_only)
        self.assertIsNotNone(ops._write_failure)
        self.assertEqual(vol.sync_calls, [True])

        # Once a real write/flush failure has happened, do not silently retry
        # later writes as if the mount were healthy.
        with self.assertRaises(IoError) as cm:
            ops.sync_pending()
        self.assertIn("이전 디스크 쓰기/flush 오류", str(cm.exception))
        self.assertEqual(vol.sync_calls, [True])

    def test_sync_finishes_active_session_to_leave_media_clean(self):
        vol = DummyVolume(active=True)
        ops = fm.Ext4FuseOps(vol, read_only=False)

        ops.sync_pending()

        self.assertTrue(vol.finished)
        self.assertFalse(vol._write_session_active)
        self.assertEqual(vol.sync_calls, [])

    def test_buffered_write_failure_keeps_buffer_and_latches_error(self):
        vol = DummyVolume()
        ops = fm.Ext4FuseOps(vol, read_only=False)
        ops._wb = [12, 0, bytearray(b"abc")]

        with patch(
            "ext4lib.mount.fuse.write_range",
            side_effect=IoError("media disappeared", winerr=1167),
        ):
            with self.assertRaises(IoError):
                ops._wb_flush()

        self.assertIsNotNone(ops._wb)
        self.assertTrue(ops.read_only)
        self.assertIn("media disappeared", str(ops._write_failure))

    def test_unmount_reports_final_sync_failure_after_cleanup(self):
        class Ops:
            def __init__(self):
                self._stop = threading.Event()

            def sync_pending(self):
                raise IoError("final flush failed", winerr=31)

        class Thread:
            def is_alive(self):
                return False

        vol = DummyVolume()
        session = fm.MountSession("E:", vol, Thread(), read_only=False)
        session.ops = Ops()
        fm._SESSIONS["E:"] = session

        with (
            patch("ext4lib.mount.fuse._stop_winfsp_volume"),
            patch("ext4lib.mount.fuse._remove_drive_letter"),
            patch("ext4lib.mount.fuse._letter_present", return_value=False),
            patch("ext4lib.mount.fuse._forget"),
        ):
            with self.assertRaises(IoError) as cm:
                fm.unmount("E:")

        self.assertIn("마지막 디스크 반영이 실패", str(cm.exception))
        self.assertFalse(vol.finished)
        self.assertTrue(vol.closed)
        self.assertNotIn("E:", fm._SESSIONS)


class WriteSessionStateTests(unittest.TestCase):
    def _make_volume(self):
        class Device:
            writable = True

            def __init__(self):
                self.writes = []
                self.flushes = 0

            def write(self, offset, data):
                self.writes.append((offset, bytes(data)))

            def flush(self):
                self.flushes += 1

        raw = bytearray(1024)
        state = fm.C.EXT4_VALID_FS if hasattr(fm, "C") else 1
        # Import here to keep this test focused on volume state transitions.
        from ext4lib.fs import constants as C
        from ext4lib.fs.volume import Ext4Volume

        sb = SimpleNamespace(
            raw=raw,
            state=C.EXT4_VALID_FS,
            write_checksum=lambda: None,
        )
        vol = Ext4Volume.__new__(Ext4Volume)
        vol.dev = Device()
        vol.owns_device = False
        vol.part_offset = 1048576
        vol.sb = sb
        vol._data_dirty = False
        vol._write_session_active = False
        vol.commit_metadata = lambda sync=True: vol.dev.flush() if sync else None
        return vol, C

    def test_write_session_marks_unclean_then_restores_clean(self):
        vol, C = self._make_volume()

        vol.begin_write_session()
        self.assertTrue(vol._write_session_active)
        self.assertFalse(vol.sb.state & C.EXT4_VALID_FS)
        self.assertGreaterEqual(vol.dev.flushes, 1)

        vol.finish_write_session()
        self.assertFalse(vol._write_session_active)
        self.assertTrue(vol.sb.state & C.EXT4_VALID_FS)
        self.assertGreaterEqual(vol.dev.flushes, 3)


if __name__ == "__main__":
    unittest.main()
