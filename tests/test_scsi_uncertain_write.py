"""Mock-only tests: an ambiguous SCSI WRITE(10) failure never rewrites a range.

A WRITE(10) that fails without proof either way (no sense data, or a
DeviceIoControl error that does not carry sense proving pre-data-phase
rejection) is a PostWriteError. Win32 1/5/6/50/87 are not that proof by
themselves. Fallback to another variant or to plain WRITE(10) is allowed only
when the device explicitly rejected the command (ILLEGAL REQUEST + invalid CDB
field/opcode, including when that sense is attached to a failed ioctl) or when
an unbuffered device read shows the range still holds the snapshot taken
before the write. A cached ReadFile match is not proof.
"""

import unittest
from unittest.mock import Mock, patch

from ext4lib.io.backend import IoError
from ext4lib.windows import disk
from ext4lib.windows.disk import PostWriteError, UncertainWriteError

from tests.test_windows_disk_io import FakeKernel32, make_dev

PAYLOAD = b"n" * 512
OLD = b"o" * 512


def _scsi_ioctl(status, sense_key, asc=0x00, ascq=0x00, fua_only=False):
    """DeviceIoControl stub completing WRITE(10) with a SCSI status + sense.

    With fua_only=True only commands carrying the FUA bit fail; plain
    WRITE(10) completes GOOD, like a bridge that rejects the FUA field.
    """
    seen = []

    def ioctl(handle, code, packet, *args):
        if code == disk.IOCTL_SCSI_PASS_THROUGH_DIRECT:
            hdr = disk.SCSI_PASS_THROUGH_DIRECT.from_buffer(packet)
        else:
            hdr = disk.SCSI_PASS_THROUGH.from_buffer(packet)
        fua = bool(hdr.Cdb[1] & disk.SCSI_WRITE_FUA)
        seen.append((code, fua))
        if fua_only and not fua:
            hdr.ScsiStatus = disk.SCSI_STATUS_GOOD
            return True
        hdr.ScsiStatus = status
        off = int(hdr.SenseInfoOffset)
        sense = bytes([0x70, 0, sense_key]) + b"\x00" * 9 + bytes([asc, ascq])
        disk.ctypes.memmove(disk.ctypes.addressof(packet) + off, sense, len(sense))
        return True

    ioctl.seen = seen
    return ioctl


def _ioctl_fail(err):
    """DeviceIoControl stub that fails with a Win32 error code."""

    def ioctl(*args):
        disk.ctypes.set_last_error(err)
        return False

    return ioctl


class _Base(unittest.TestCase):
    def _dev(self, read_at):
        dev = make_dev(FakeKernel32(), writable=True)
        dev._scsi_fua_supported = None
        dev._scsi_sync_cache_supported = None
        dev._read_at = read_at
        return dev

    def _untouched_dev(self):
        """Unbuffered pre-image and compare both return the old content.

        The cached session read is a different channel and must not be what
        the untouched proof consults.
        """
        dev = self._dev(Mock(return_value=OLD))
        dev._read_device_unbuffered = Mock(return_value=OLD)
        return dev

    def _no_compare_dev(self):
        """Neither an unbuffered pre-image nor a compare is available."""
        dev = self._dev(Mock(side_effect=IoError("read fail", winerr=31)))
        dev._read_device_unbuffered = Mock(side_effect=IoError("no raw read", winerr=5))
        return dev


class SenseKeyZeroTests(_Base):
    def test_no_sense_without_comparison_is_post_write(self):
        dev = self._no_compare_dev()
        dev._scsi_write10_buffered = Mock()
        with patch.object(disk.kernel32, "DeviceIoControl", _scsi_ioctl(2, 0x00)):
            with self.assertRaises(PostWriteError) as ctx:
                dev._scsi_write10(0, PAYLOAD)
        self.assertIsInstance(ctx.exception, UncertainWriteError)
        self.assertIn("판단 불가로 보수적으로 중단", str(ctx.exception))
        dev._scsi_write10_buffered.assert_not_called()

    def test_no_sense_with_changed_range_is_post_write(self):
        # Pre-image is OLD, but after the failure the device reads differently:
        # some sectors may have landed, so no other route may touch it.
        dev = self._dev(Mock(return_value=OLD))
        dev._read_device_unbuffered = Mock(
            side_effect=[OLD, OLD[:256] + PAYLOAD[256:]]
        )
        dev._scsi_write10_buffered = Mock()
        with patch.object(disk.kernel32, "DeviceIoControl", _scsi_ioctl(2, 0x00)):
            with self.assertRaises(PostWriteError):
                dev._scsi_write10(0, PAYLOAD)
        dev._scsi_write10_buffered.assert_not_called()

    def test_error_builder_classifies_sense_keys(self):
        build = disk.WindowsPhysicalDevice._scsi_write_error
        self.assertIsInstance(build("w", 2, (0x00, 0, 0)), UncertainWriteError)
        self.assertIsInstance(build("w", 2, (0x03, 0x11, 0)), PostWriteError)
        self.assertNotIsInstance(build("w", 2, (0x03, 0x11, 0)), UncertainWriteError)
        for key in (0x02, 0x05, 0x06, 0x07):
            with self.subTest(key=key):
                exc = build("w", 2, (key, 0x24, 0))
                self.assertIsInstance(exc, IoError)
                self.assertNotIsInstance(exc, PostWriteError)
                self.assertEqual(exc.scsi_sense, (key, 0x24, 0))

    def test_uncertain_error_stops_fallback_chain(self):
        dev = self._no_compare_dev()
        dev._write_blockers = []
        fail5 = Mock(side_effect=IoError("denied", winerr=5))
        dev._write_locked_partition_device = fail5
        dev._write_at_flushed = fail5
        dev._nt_write_at = fail5
        dev._prepare_system_helper_handle = lambda: None
        dev._write_unbuffered_physical = fail5
        dev._activate_whole_disk_offline = Mock(return_value=(False, 5))
        with patch.object(disk.kernel32, "DeviceIoControl", _scsi_ioctl(2, 0x00)):
            with self.assertRaises(PostWriteError):
                dev._fallback_after_volume_access_denied(0, PAYLOAD)
        dev._activate_whole_disk_offline.assert_not_called()


class DeviceIoControlFailureTests(_Base):
    def test_unexplained_ioctl_error_without_comparison_is_post_write(self):
        for err in (31, 19, 1167, 433):
            with self.subTest(err=err):
                dev = self._no_compare_dev()
                dev._scsi_write10_buffered = Mock()
                with patch.object(disk.kernel32, "DeviceIoControl", _ioctl_fail(err)):
                    with self.assertRaises(PostWriteError) as ctx:
                        dev._scsi_write10(0, PAYLOAD)
                self.assertIsInstance(ctx.exception, UncertainWriteError)
                self.assertEqual(ctx.exception.winerr, err)
                self.assertIn("판단 불가로 보수적으로 중단", str(ctx.exception))
                dev._scsi_write10_buffered.assert_not_called()

    def test_buffered_unexplained_ioctl_error_is_post_write(self):
        dev = self._no_compare_dev()
        with patch.object(disk.kernel32, "DeviceIoControl", _ioctl_fail(31)):
            with self.assertRaises(UncertainWriteError):
                disk.WindowsPhysicalDevice._scsi_write10_buffered(dev, 0, PAYLOAD)

    def test_in_flight_errors_stay_post_write_even_with_comparison(self):
        # Timeout / I/O device errors: the command may still complete later,
        # so a read-back cannot prove anything.
        for err in (121, 1117):
            with self.subTest(err=err):
                dev = self._untouched_dev()
                dev._scsi_write10_buffered = Mock()
                with patch.object(disk.kernel32, "DeviceIoControl", _ioctl_fail(err)):
                    with self.assertRaises(PostWriteError) as ctx:
                        dev._scsi_write10(0, PAYLOAD)
                self.assertNotIsInstance(ctx.exception, UncertainWriteError)
                dev._scsi_write10_buffered.assert_not_called()

    def test_win32_without_sense_or_unbuffered_proof_is_post_write(self):
        # 1/5/6/50/87 do not prove the SRB was never built. Without sense and
        # without an unbuffered unchanged read, no other route may run.
        for err in (1, 5, 6, 50, 87):
            with self.subTest(err=err):
                dev = self._no_compare_dev()
                dev._scsi_write10_buffered = Mock()
                with patch.object(disk.kernel32, "DeviceIoControl", _ioctl_fail(err)):
                    with self.assertRaises(PostWriteError) as ctx:
                        dev._scsi_write10(0, PAYLOAD)
                self.assertIsInstance(ctx.exception, UncertainWriteError)
                self.assertEqual(ctx.exception.winerr, err)
                dev._scsi_write10_buffered.assert_not_called()

    def test_invalid_parameter_with_unbuffered_proof_halves_transfer_size(self):
        dev = self._no_compare_dev()
        dev._scsi_max_transfer = 1024
        dev._read_device_unbuffered = lambda _off, n: b"o" * n
        sizes = []

        def ioctl(handle, code, packet, *args):
            hdr = disk.SCSI_PASS_THROUGH_DIRECT.from_buffer(packet)
            if code == disk.IOCTL_SCSI_PASS_THROUGH:
                hdr = disk.SCSI_PASS_THROUGH.from_buffer(packet)
            sizes.append(int(hdr.DataTransferLength))
            if int(hdr.DataTransferLength) > 512:
                disk.ctypes.set_last_error(87)
                return False
            hdr.ScsiStatus = disk.SCSI_STATUS_GOOD
            return True

        dev._read_at = Mock(return_value=PAYLOAD)
        with patch.object(disk.kernel32, "DeviceIoControl", ioctl):
            dev._scsi_write10(0, PAYLOAD * 2)
        self.assertEqual(dev._scsi_max_transfer, 512)
        self.assertIn(1024, sizes)
        self.assertEqual(sizes[-1], 512)

    def test_invalid_parameter_with_illegal_request_sense_needs_no_read(self):
        # Sense attached to a failed ioctl is pre-data-phase proof. The cached
        # and unbuffered reads are both unavailable and must not be required.
        dev = self._no_compare_dev()
        seen = []

        def ioctl(handle, code, packet, *args):
            if code == disk.IOCTL_SCSI_PASS_THROUGH_DIRECT:
                hdr = disk.SCSI_PASS_THROUGH_DIRECT.from_buffer(packet)
            else:
                hdr = disk.SCSI_PASS_THROUGH.from_buffer(packet)
            fua = bool(hdr.Cdb[1] & disk.SCSI_WRITE_FUA)
            seen.append(fua)
            if not fua:
                hdr.ScsiStatus = disk.SCSI_STATUS_GOOD
                return True
            disk.ctypes.set_last_error(87)
            off = int(hdr.SenseInfoOffset)
            sense = bytes([0x70, 0, 0x05]) + b"\x00" * 9 + bytes([0x24, 0x00])
            disk.ctypes.memmove(disk.ctypes.addressof(packet) + off, sense, len(sense))
            return False

        dev._read_at = Mock(return_value=PAYLOAD)
        with patch.object(disk.kernel32, "DeviceIoControl", ioctl):
            dev._scsi_write10(0, PAYLOAD)
        self.assertEqual(seen, [True, False])
        self.assertFalse(dev._scsi_fua_supported)


class ExplicitRejectionFallbackTests(_Base):
    def test_illegal_request_invalid_field_allows_plain_write(self):
        dev = self._untouched_dev()
        ioctl = _scsi_ioctl(2, 0x05, asc=0x24, fua_only=True)
        with patch.object(disk.kernel32, "DeviceIoControl", ioctl):
            dev._read_at = Mock(return_value=PAYLOAD)
            dev._scsi_write10(0, PAYLOAD)
        self.assertEqual(
            ioctl.seen,
            [
                (disk.IOCTL_SCSI_PASS_THROUGH_DIRECT, True),
                (disk.IOCTL_SCSI_PASS_THROUGH_DIRECT, False),
            ],
        )
        self.assertFalse(dev._scsi_fua_supported)
        self.assertTrue(dev._scsi_dirty)

    def test_illegal_request_fallback_needs_no_read_comparison(self):
        # The explicit rejection is proof by itself: even without a usable
        # pre-image the plain WRITE(10) may run.
        dev = self._no_compare_dev()
        ioctl = _scsi_ioctl(2, 0x05, asc=0x24, fua_only=True)
        with patch.object(disk.kernel32, "DeviceIoControl", ioctl):
            dev._read_at = Mock(return_value=PAYLOAD)
            dev._scsi_write10(0, PAYLOAD)
        self.assertEqual([fua for _code, fua in ioctl.seen], [True, False])
        self.assertFalse(dev._scsi_fua_supported)

    def test_illegal_request_verdict_is_cached_per_device(self):
        dev = self._untouched_dev()
        ioctl = _scsi_ioctl(2, 0x05, asc=0x24, fua_only=True)
        dev._read_at = Mock(return_value=PAYLOAD)
        with patch.object(disk.kernel32, "DeviceIoControl", ioctl):
            dev._scsi_write10(0, PAYLOAD)
            dev._scsi_write10(512, PAYLOAD)
        # Second write skips the FUA probe entirely.
        self.assertEqual([fua for _code, fua in ioctl.seen], [True, False, False])

    def test_other_illegal_request_asc_does_not_disable_fua(self):
        dev = self._untouched_dev()
        dev._scsi_write10_buffered = Mock()
        ioctl = _scsi_ioctl(2, 0x05, asc=0x26)
        with patch.object(disk.kernel32, "DeviceIoControl", ioctl):
            dev._scsi_write10(0, PAYLOAD)
        self.assertEqual([fua for _code, fua in ioctl.seen], [True])
        self.assertIsNone(dev._scsi_fua_supported)
        dev._scsi_write10_buffered.assert_called_once_with(0, PAYLOAD, fua=True)


class ReadComparisonFallbackTests(_Base):
    def test_untouched_range_allows_plain_write_after_no_sense_failure(self):
        dev = self._dev(Mock(return_value=PAYLOAD))
        dev._read_device_unbuffered = Mock(return_value=OLD)
        ioctl = _scsi_ioctl(2, 0x00, fua_only=True)
        with patch.object(disk.kernel32, "DeviceIoControl", ioctl):
            dev._scsi_write10(0, PAYLOAD)
        self.assertEqual([fua for _code, fua in ioctl.seen], [True, False])
        self.assertFalse(dev._scsi_fua_supported)
        self.assertGreaterEqual(dev._read_device_unbuffered.call_count, 2)
        dev._read_at.assert_called_once()

    def test_cached_read_match_does_not_prove_untouched(self):
        # The session handle still returns the old bytes. That cache hit must
        # not disable FUA or open the buffered route.
        dev = self._dev(Mock(return_value=OLD))
        dev._read_device_unbuffered = Mock(side_effect=IoError("uncached", winerr=5))
        dev._scsi_write10_buffered = Mock()
        with patch.object(disk.kernel32, "DeviceIoControl", _scsi_ioctl(2, 0x00)):
            with self.assertRaises(UncertainWriteError):
                dev._scsi_write10(0, PAYLOAD)
        self.assertIsNone(dev._scsi_fua_supported)
        dev._scsi_write10_buffered.assert_not_called()
        dev._read_at.assert_not_called()

    def test_untouched_range_allows_buffered_variant_after_ioctl_failure(self):
        calls = []

        def ioctl(handle, code, packet, *args):
            calls.append(code)
            if code == disk.IOCTL_SCSI_PASS_THROUGH_DIRECT:
                disk.ctypes.set_last_error(31)
                return False
            hdr = disk.SCSI_PASS_THROUGH.from_buffer(packet)
            hdr.ScsiStatus = disk.SCSI_STATUS_GOOD
            return True

        # Unbuffered: pre-image, compare after DIRECT(FUA), compare after
        # DIRECT(plain). Cached _read_at only verifies the BUFFERED success.
        dev = self._dev(Mock(return_value=PAYLOAD))
        dev._read_device_unbuffered = Mock(return_value=OLD)
        with patch.object(disk.kernel32, "DeviceIoControl", ioctl):
            dev._scsi_write10(0, PAYLOAD)
        self.assertEqual(
            calls,
            [
                disk.IOCTL_SCSI_PASS_THROUGH_DIRECT,
                disk.IOCTL_SCSI_PASS_THROUGH_DIRECT,
                disk.IOCTL_SCSI_PASS_THROUGH,
            ],
        )

    def test_proven_fua_device_does_not_downgrade_on_uncertain_failure(self):
        dev = self._untouched_dev()
        dev._scsi_fua_supported = True
        dev._scsi_write10_buffered = Mock()
        ioctl = _scsi_ioctl(2, 0x00)
        with patch.object(disk.kernel32, "DeviceIoControl", ioctl):
            dev._scsi_write10(0, PAYLOAD)
        self.assertEqual([fua for _code, fua in ioctl.seen], [True])
        self.assertTrue(dev._scsi_fua_supported)
        dev._scsi_write10_buffered.assert_called_once_with(0, PAYLOAD, fua=True)

    def test_missing_pre_image_blocks_fallback(self):
        dev = self._dev(Mock(return_value=OLD))
        dev._read_device_unbuffered = Mock(side_effect=IoError("pre", winerr=31))
        dev._scsi_write10_buffered = Mock()
        with patch.object(disk.kernel32, "DeviceIoControl", _scsi_ioctl(2, 0x00)):
            with self.assertRaises(UncertainWriteError):
                dev._scsi_write10(0, PAYLOAD)
        dev._scsi_write10_buffered.assert_not_called()

    def test_failed_read_back_blocks_fallback(self):
        dev = self._dev(Mock(return_value=OLD))
        dev._read_device_unbuffered = Mock(
            side_effect=[OLD, IoError("cmp", winerr=31)]
        )
        dev._scsi_write10_buffered = Mock()
        with patch.object(disk.kernel32, "DeviceIoControl", _scsi_ioctl(2, 0x00)):
            with self.assertRaises(UncertainWriteError):
                dev._scsi_write10(0, PAYLOAD)
        dev._scsi_write10_buffered.assert_not_called()

    def test_later_chunk_uncertain_failure_is_post_write(self):
        dev = self._dev(Mock(return_value=OLD))
        dev._scsi_max_transfer = 512
        dev._scsi_write10_one = Mock(
            side_effect=[None, UncertainWriteError("no sense", winerr=5)]
        )
        with self.assertRaises(PostWriteError):
            dev._scsi_write10(0, PAYLOAD * 2)
        self.assertEqual(dev._scsi_write10_one.call_count, 2)


if __name__ == "__main__":
    unittest.main()
