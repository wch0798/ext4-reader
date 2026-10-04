import struct
import unittest
from unittest.mock import patch

from io_backend import IoError
from usbdk_backend import (
    CBW_SIGNATURE,
    CSW_SIGNATURE,
    UsbDkBotBackend,
    UsbDkError,
    parse_bulk_only_endpoints,
    parse_capacity10,
    parse_capacity16,
    parse_usb_identity,
)


class UsbDkParsingTests(unittest.TestCase):
    def test_parse_usb_identity_matches_realtek_reader_parent(self):
        ident = parse_usb_identity(r"USB\VID_0BDA&PID_0177\20121112761000000")
        self.assertEqual(ident.vid, 0x0BDA)
        self.assertEqual(ident.pid, 0x0177)
        self.assertEqual(ident.device_id, r"USB\VID_0BDA&PID_0177")
        self.assertEqual(ident.instance_id, "20121112761000000")
        self.assertEqual(ident.lun, 0)

    def test_parse_bulk_only_endpoints(self):
        config = bytes([9, 2, 32, 0, 1, 1, 0, 0x80, 50])
        interface = bytes([9, 4, 0, 0, 2, 0x08, 0x06, 0x50, 0])
        ep_out = bytes([7, 5, 0x02, 0x02, 0x00, 0x02, 0])
        ep_in = bytes([7, 5, 0x81, 0x02, 0x00, 0x02, 0])
        endpoints = parse_bulk_only_endpoints(config + interface + ep_out + ep_in)
        self.assertEqual(endpoints.interface_number, 0)
        self.assertEqual(endpoints.bulk_out, 0x02)
        self.assertEqual(endpoints.bulk_in, 0x81)

    def test_parse_bulk_only_endpoints_rejects_non_storage_interface(self):
        config = bytes([9, 2, 18, 0, 1, 1, 0, 0x80, 50])
        interface = bytes([9, 4, 0, 0, 0, 0x03, 0x01, 0x01, 0])
        with self.assertRaises(UsbDkError):
            parse_bulk_only_endpoints(config + interface)

    def test_capacity10(self):
        cap = parse_capacity10(struct.pack(">II", 1999, 512))
        self.assertEqual(cap.last_lba, 1999)
        self.assertEqual(cap.block_size, 512)
        self.assertEqual(cap.size, 2000 * 512)

    def test_capacity16(self):
        cap = parse_capacity16(struct.pack(">QI", 0x1_0000_0000, 4096) + b"\x00" * 20)
        self.assertEqual(cap.last_lba, 0x1_0000_0000)
        self.assertEqual(cap.block_size, 4096)


class _FakeApi:
    def __init__(self, read_payload: bytes):
        self.read_payload = read_payload
        self.writes = []
        self.last_tag = 0

    def transfer(self, handle, endpoint, data, read_len=0):
        if data is not None:
            blob = bytes(data)
            self.writes.append((endpoint, blob))
            if len(blob) == 31 and struct.unpack_from("<I", blob, 0)[0] == CBW_SIGNATURE:
                self.last_tag = struct.unpack_from("<I", blob, 4)[0]
            return b""
        if read_len == 13:
            return struct.pack("<IIIB", CSW_SIGNATURE, self.last_tag, 0, 0)
        return self.read_payload[:read_len]

    def reset_pipe(self, handle, endpoint):
        pass


class UsbDkBotTests(unittest.TestCase):
    def make_backend(self):
        dev = UsbDkBotBackend.__new__(UsbDkBotBackend)
        dev._api = _FakeApi(b"R" * 36)
        dev._redirect = 123
        dev._tag = 10
        dev._closed = False
        dev._sync_cache_supported = None
        dev.bulk_in = 0x81
        dev.bulk_out = 0x02
        dev.lun = 0
        dev.sector_size = 512
        dev.size = 1024 * 1024
        dev.partition_offset = 4096
        dev.partition_size = 512 * 16
        return dev

    def test_bot_builds_cbw_and_reads_csw(self):
        dev = self.make_backend()
        cdb = bytes([0x12, 0, 0, 0, 36, 0])
        payload = dev._bot(cdb, data_in_len=36)
        self.assertEqual(payload, b"R" * 36)
        cbw = dev._api.writes[0][1]
        sig, tag, transfer_len, flags, lun, cdb_len = struct.unpack_from("<IIIBBB", cbw, 0)
        self.assertEqual(sig, CBW_SIGNATURE)
        self.assertEqual(transfer_len, 36)
        self.assertEqual(flags, 0x80)
        self.assertEqual(lun, 0)
        self.assertEqual(cdb_len, 6)
        self.assertEqual(cbw[15:21], cdb)

    def test_write_is_partition_bounded_and_readback_verified(self):
        dev = self.make_backend()
        writes = []
        payload = b"x" * 1024

        def write_blocks(lba, blocks, data):
            writes.append((lba, blocks, bytes(data)))

        dev._write_blocks = write_blocks
        dev._read_blocks = lambda lba, blocks: payload
        dev.write(4096, payload)
        self.assertEqual(writes, [(8, 2, payload)])

        with self.assertRaises(UsbDkError):
            dev.write(0, b"x" * 512)

        with self.assertRaises(UsbDkError):
            dev.write(4096 + dev.partition_size - 512, b"x" * 1024)

    def test_write_detects_readback_mismatch(self):
        dev = self.make_backend()
        dev._write_blocks = lambda lba, blocks, data: None
        dev._read_blocks = lambda lba, blocks: b"z" * (blocks * 512)
        with self.assertRaises(UsbDkError) as cm:
            dev.write(4096, b"x" * 512)
        self.assertIn("read-back", str(cm.exception))

    def test_wait_until_ready_retries_transient_bot_errors(self):
        dev = self.make_backend()
        attempts = {"count": 0}

        def tur():
            attempts["count"] += 1
            if attempts["count"] < 3:
                raise UsbDkError("reader still re-enumerating", winerr=31)

        dev.test_unit_ready = tur
        with patch("usbdk_backend.time.sleep") as sleep:
            dev.wait_until_ready(timeout=1.0)

        self.assertEqual(attempts["count"], 3)
        self.assertEqual(sleep.call_count, 2)
        sleep.assert_called_with(0.20)

    def test_wait_until_ready_reports_last_usb_error_on_timeout(self):
        dev = self.make_backend()
        dev.test_unit_ready = lambda: (_ for _ in ()).throw(
            UsbDkError("reader not ready", winerr=31)
        )

        with patch(
            "usbdk_backend.time.monotonic",
            side_effect=[0.0, 2.0],
        ):
            with self.assertRaises(UsbDkError) as cm:
                dev.wait_until_ready(timeout=1.0)

        self.assertIn("장치 준비 시간 초과", str(cm.exception))
        self.assertIn("reader not ready", str(cm.exception))

    def test_flush_ignores_unsupported_synchronize_cache_and_health_checks(self):
        dev = self.make_backend()
        calls = []

        def bot(cdb, **kwargs):
            calls.append(cdb[0])
            if cdb[0] == 0x35:
                exc = UsbDkError(
                    "USB BOT SCSI 명령 실패 opcode=0x35 status=1 residue=0 "
                    "sense_key=0x05 asc=0x24 ascq=0x00",
                    winerr=31,
                )
                exc.scsi_status = 1
                exc.sense_key = 0x05
                exc.asc = 0x24
                exc.ascq = 0
                raise exc
            return b""

        dev._bot = bot
        dev.flush()

        self.assertFalse(dev._sync_cache_supported)
        self.assertEqual(calls, [0x35, 0x00])

        # Once capability absence is known, do not resend opcode 0x35.
        dev.flush()
        self.assertEqual(calls, [0x35, 0x00, 0x00])

    def test_flush_keeps_unexpected_scsi_errors_fatal(self):
        dev = self.make_backend()

        def bot(cdb, **kwargs):
            exc = UsbDkError("medium error", winerr=31)
            exc.scsi_status = 1
            exc.sense_key = 0x03
            exc.asc = 0x11
            exc.ascq = 0
            raise exc

        dev._bot = bot
        with self.assertRaises(UsbDkError):
            dev.flush()

    def test_read10_and_read16_cdb_selection(self):
        dev = self.make_backend()
        seen = []

        def bot(cdb, **kwargs):
            seen.append(bytes(cdb))
            return b"\x00" * kwargs["data_in_len"]

        dev._bot = bot
        dev._read_blocks(100, 2)
        self.assertEqual(seen[-1][0], 0x28)
        self.assertEqual(struct.unpack_from(">I", seen[-1], 2)[0], 100)

        dev._read_blocks(0x1_0000_0000, 1)
        self.assertEqual(seen[-1][0], 0x88)
        self.assertEqual(struct.unpack_from(">Q", seen[-1], 2)[0], 0x1_0000_0000)


if __name__ == "__main__":
    unittest.main()
