"""Direct USB Mass-Storage BOT backend using the optional UsbDk runtime.

This backend is deliberately a last resort. Normal card readers continue to use
Windows volume/PhysicalDrive I/O. When Windows rejects every raw-write route on
an USB removable reader, this module can temporarily redirect exactly that USB
device through UsbDk and issue SCSI Bulk-Only Transport commands directly.

No UsbDk driver binary is bundled here. The official runtime supplies
UsbDkHelper.dll/UsbDk.sys; see ext4reader.usbdk_setup.
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import struct
import subprocess
import time
from ctypes import wintypes
from dataclasses import dataclass

from ext4reader.io_backend import IO_CHUNK, IoError
from ext4reader.usbdk_setup import UsbDkRequiredError, find_usbdk_helper, usbdk_ready

MAX_DEVICE_ID_LEN = 200
TRANSFER_FAILURE = 0
TRANSFER_SUCCESS = 1
BULK_TRANSFER_TYPE = 1
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

CBW_SIGNATURE = 0x43425355
CSW_SIGNATURE = 0x53425355
SCSI_TEST_UNIT_READY = 0x00
SCSI_REQUEST_SENSE = 0x03
SCSI_INQUIRY = 0x12
SCSI_READ_CAPACITY10 = 0x25
SCSI_READ10 = 0x28
SCSI_WRITE10 = 0x2A
SCSI_SYNCHRONIZE_CACHE10 = 0x35
SCSI_SERVICE_ACTION_IN16 = 0x9E
SCSI_READ_CAPACITY16_SA = 0x10
SCSI_READ16 = 0x88
SCSI_WRITE16 = 0x8A

USB_DESCRIPTOR_TYPE_INTERFACE = 4
USB_DESCRIPTOR_TYPE_ENDPOINT = 5
USB_CLASS_MASS_STORAGE = 0x08
USB_SUBCLASS_SCSI = 0x06
USB_PROTOCOL_BULK_ONLY = 0x50
USB_ENDPOINT_BULK = 0x02

_USB_ID_RE = re.compile(
    r"^USB\\VID_([0-9A-F]{4})&PID_([0-9A-F]{4})(?:&[^\\]+)?\\(.+)$",
    re.IGNORECASE,
)
_PHYSICAL_RE = re.compile(r"^\\\\\.\\PhysicalDrive(\d+)$", re.IGNORECASE)


class UsbDkError(IoError):
    pass


class UsbDkDeviceNotFound(UsbDkError):
    pass


class _USB_DEVICE_DESCRIPTOR(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("bLength", ctypes.c_ubyte),
        ("bDescriptorType", ctypes.c_ubyte),
        ("bcdUSB", ctypes.c_ushort),
        ("bDeviceClass", ctypes.c_ubyte),
        ("bDeviceSubClass", ctypes.c_ubyte),
        ("bDeviceProtocol", ctypes.c_ubyte),
        ("bMaxPacketSize0", ctypes.c_ubyte),
        ("idVendor", ctypes.c_ushort),
        ("idProduct", ctypes.c_ushort),
        ("bcdDevice", ctypes.c_ushort),
        ("iManufacturer", ctypes.c_ubyte),
        ("iProduct", ctypes.c_ubyte),
        ("iSerialNumber", ctypes.c_ubyte),
        ("bNumConfigurations", ctypes.c_ubyte),
    ]


class _USB_DK_DEVICE_ID(ctypes.Structure):
    _fields_ = [
        ("DeviceID", ctypes.c_wchar * MAX_DEVICE_ID_LEN),
        ("InstanceID", ctypes.c_wchar * MAX_DEVICE_ID_LEN),
    ]


class _USB_DK_DEVICE_INFO(ctypes.Structure):
    _fields_ = [
        ("ID", _USB_DK_DEVICE_ID),
        ("FilterID", ctypes.c_uint64),
        ("Port", ctypes.c_uint64),
        ("Speed", ctypes.c_uint64),
        ("DeviceDescriptor", _USB_DEVICE_DESCRIPTOR),
    ]


class _USB_DK_CONFIG_DESCRIPTOR_REQUEST(ctypes.Structure):
    _fields_ = [
        ("ID", _USB_DK_DEVICE_ID),
        ("Index", ctypes.c_uint64),
    ]


class _USB_DK_GEN_TRANSFER_RESULT(ctypes.Structure):
    _fields_ = [
        ("BytesTransferred", ctypes.c_uint64),
        ("UsbdStatus", ctypes.c_uint64),
    ]


class _USB_DK_TRANSFER_RESULT(ctypes.Structure):
    _fields_ = [
        ("GenResult", _USB_DK_GEN_TRANSFER_RESULT),
        ("IsochronousResultsArray", ctypes.c_uint64),
    ]


class _USB_DK_TRANSFER_REQUEST(ctypes.Structure):
    _fields_ = [
        ("EndpointAddress", ctypes.c_uint64),
        ("Buffer", ctypes.c_uint64),
        ("BufferLength", ctypes.c_uint64),
        ("TransferType", ctypes.c_uint64),
        ("IsochronousPacketsArraySize", ctypes.c_uint64),
        ("IsochronousPacketsArray", ctypes.c_uint64),
        ("Result", _USB_DK_TRANSFER_RESULT),
    ]


@dataclass(frozen=True)
class UsbIdentity:
    device_id: str
    instance_id: str
    vid: int
    pid: int


@dataclass(frozen=True)
class BulkEndpoints:
    interface_number: int
    bulk_in: int
    bulk_out: int


@dataclass(frozen=True)
class Capacity:
    last_lba: int
    block_size: int

    @property
    def size(self) -> int:
        return (self.last_lba + 1) * self.block_size


def parse_usb_identity(parent_instance_id: str) -> UsbIdentity:
    text = (parent_instance_id or "").strip()
    m = _USB_ID_RE.match(text)
    if not m:
        raise UsbDkDeviceNotFound(
            f"USB 부모 장치 ID를 해석할 수 없습니다: {text or '(없음)'}",
            winerr=1167,
        )
    vid = int(m.group(1), 16)
    pid = int(m.group(2), 16)
    instance = m.group(3)
    device_id = f"USB\\VID_{vid:04X}&PID_{pid:04X}"
    return UsbIdentity(device_id, instance, vid, pid)


def resolve_usb_identity_for_physicaldrive(path: str) -> UsbIdentity:
    """Resolve PhysicalDriveN -> parent USB VID/PID/instance via built-in PowerShell."""
    m = _PHYSICAL_RE.match(path or "")
    if not m:
        raise UsbDkDeviceNotFound(f"잘못된 PhysicalDrive 경로: {path}", winerr=87)
    index = int(m.group(1))

    script = rf"""
$ErrorActionPreference = 'Stop'
$disk = Get-CimInstance Win32_DiskDrive -Filter "Index = {index}"
if ($null -eq $disk) {{ throw "PhysicalDrive{index} not found" }}
$cur = [string]$disk.PNPDeviceID
$found = $null
for ($i = 0; $i -lt 6 -and $cur; $i++) {{
    if ($cur -match '^USB\\VID_[0-9A-Fa-f]{{4}}&PID_[0-9A-Fa-f]{{4}}') {{
        $found = $cur
        break
    }}
    try {{
        $cur = [string](Get-PnpDeviceProperty -InstanceId $cur -KeyName 'DEVPKEY_Device_Parent').Data
    }} catch {{
        break
    }}
}}
if (-not $found) {{ throw "USB parent not found for PhysicalDrive{index}" }}
@{{ parent = $found; pnp = [string]$disk.PNPDeviceID }} | ConvertTo-Json -Compress
"""
    try:
        proc = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as exc:
        raise UsbDkDeviceNotFound(
            f"PhysicalDrive의 USB 부모 장치를 확인하지 못했습니다: {exc}",
            winerr=1167,
        ) from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise UsbDkDeviceNotFound(
            f"PhysicalDrive의 USB 부모 장치를 확인하지 못했습니다: {detail}",
            winerr=1167,
        )
    try:
        obj = json.loads((proc.stdout or "").strip())
        return parse_usb_identity(str(obj["parent"]))
    except Exception as exc:
        raise UsbDkDeviceNotFound(
            f"USB 부모 장치 결과를 해석하지 못했습니다: {(proc.stdout or '').strip()}",
            winerr=1167,
        ) from exc


def parse_bulk_only_endpoints(raw: bytes) -> BulkEndpoints:
    """Find a Mass-Storage/SCSI/Bulk-Only interface and its bulk endpoints."""
    pos = 0
    active_interface: int | None = None
    active_bot = False
    bulk_in: int | None = None
    bulk_out: int | None = None

    while pos + 2 <= len(raw):
        length = raw[pos]
        dtype = raw[pos + 1]
        if length < 2 or pos + length > len(raw):
            break
        desc = raw[pos : pos + length]

        if dtype == USB_DESCRIPTOR_TYPE_INTERFACE and length >= 9:
            if active_bot and bulk_in is not None and bulk_out is not None:
                return BulkEndpoints(active_interface or 0, bulk_in, bulk_out)
            active_interface = desc[2]
            alt = desc[3]
            klass = desc[5]
            subclass = desc[6]
            protocol = desc[7]
            active_bot = (
                alt == 0
                and klass == USB_CLASS_MASS_STORAGE
                and subclass == USB_SUBCLASS_SCSI
                and protocol == USB_PROTOCOL_BULK_ONLY
            )
            bulk_in = None
            bulk_out = None
        elif dtype == USB_DESCRIPTOR_TYPE_ENDPOINT and length >= 7 and active_bot:
            address = desc[2]
            attributes = desc[3] & 0x03
            if attributes == USB_ENDPOINT_BULK:
                if address & 0x80:
                    bulk_in = address
                else:
                    bulk_out = address

        pos += length

    if active_bot and bulk_in is not None and bulk_out is not None:
        return BulkEndpoints(active_interface or 0, bulk_in, bulk_out)
    raise UsbDkError(
        "UsbDk 장치에서 USB Mass Storage Bulk-Only endpoint를 찾지 못했습니다.",
        winerr=50,
    )


def parse_capacity10(data: bytes) -> Capacity:
    if len(data) != 8:
        raise UsbDkError("READ CAPACITY(10) 응답 길이가 잘못되었습니다.", winerr=23)
    last_lba, block_size = struct.unpack(">II", data)
    if block_size <= 0:
        raise UsbDkError("READ CAPACITY 블록 크기가 0입니다.", winerr=23)
    return Capacity(last_lba, block_size)


def parse_capacity16(data: bytes) -> Capacity:
    if len(data) < 12:
        raise UsbDkError("READ CAPACITY(16) 응답 길이가 잘못되었습니다.", winerr=23)
    last_lba = struct.unpack(">Q", data[:8])[0]
    block_size = struct.unpack(">I", data[8:12])[0]
    if block_size <= 0:
        raise UsbDkError("READ CAPACITY(16) 블록 크기가 0입니다.", winerr=23)
    return Capacity(last_lba, block_size)


class _UsbDkApi:
    def __init__(self, helper_path: str):
        self.path = helper_path
        try:
            self.dll = ctypes.WinDLL(helper_path, use_last_error=True)
        except Exception as exc:
            raise UsbDkRequiredError(
                f"UsbDkHelper.dll을 불러오지 못했습니다: {helper_path}\n{exc}",
                manual_install=True,
            ) from exc

        self.dll.UsbDk_GetDevicesList.argtypes = [
            ctypes.POINTER(ctypes.POINTER(_USB_DK_DEVICE_INFO)),
            ctypes.POINTER(wintypes.ULONG),
        ]
        self.dll.UsbDk_GetDevicesList.restype = wintypes.BOOL
        self.dll.UsbDk_ReleaseDevicesList.argtypes = [ctypes.POINTER(_USB_DK_DEVICE_INFO)]
        self.dll.UsbDk_ReleaseDevicesList.restype = None
        self.dll.UsbDk_GetConfigurationDescriptor.argtypes = [
            ctypes.POINTER(_USB_DK_CONFIG_DESCRIPTOR_REQUEST),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.ULONG),
        ]
        self.dll.UsbDk_GetConfigurationDescriptor.restype = wintypes.BOOL
        self.dll.UsbDk_ReleaseConfigurationDescriptor.argtypes = [ctypes.c_void_p]
        self.dll.UsbDk_ReleaseConfigurationDescriptor.restype = None
        self.dll.UsbDk_StartRedirect.argtypes = [ctypes.POINTER(_USB_DK_DEVICE_ID)]
        self.dll.UsbDk_StartRedirect.restype = wintypes.HANDLE
        self.dll.UsbDk_StopRedirect.argtypes = [wintypes.HANDLE]
        self.dll.UsbDk_StopRedirect.restype = wintypes.BOOL
        self.dll.UsbDk_WritePipe.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_USB_DK_TRANSFER_REQUEST),
            ctypes.c_void_p,
        ]
        self.dll.UsbDk_WritePipe.restype = ctypes.c_int
        self.dll.UsbDk_ReadPipe.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_USB_DK_TRANSFER_REQUEST),
            ctypes.c_void_p,
        ]
        self.dll.UsbDk_ReadPipe.restype = ctypes.c_int
        self.dll.UsbDk_ResetPipe.argtypes = [wintypes.HANDLE, ctypes.c_uint64]
        self.dll.UsbDk_ResetPipe.restype = wintypes.BOOL
        self.dll.UsbDk_ResetDevice.argtypes = [wintypes.HANDLE]
        self.dll.UsbDk_ResetDevice.restype = wintypes.BOOL

    def devices(self) -> list[_USB_DK_DEVICE_INFO]:
        ptr = ctypes.POINTER(_USB_DK_DEVICE_INFO)()
        count = wintypes.ULONG(0)
        if not self.dll.UsbDk_GetDevicesList(ctypes.byref(ptr), ctypes.byref(count)):
            raise UsbDkError("UsbDk USB 장치 열거에 실패했습니다.", winerr=31)
        try:
            out: list[_USB_DK_DEVICE_INFO] = []
            for i in range(int(count.value)):
                item = _USB_DK_DEVICE_INFO()
                ctypes.memmove(ctypes.byref(item), ctypes.byref(ptr[i]), ctypes.sizeof(item))
                out.append(item)
            return out
        finally:
            self.dll.UsbDk_ReleaseDevicesList(ptr)

    def configuration_descriptor(self, info: _USB_DK_DEVICE_INFO, index: int = 0) -> bytes:
        req = _USB_DK_CONFIG_DESCRIPTOR_REQUEST()
        req.ID = info.ID
        req.Index = int(index)
        ptr = ctypes.c_void_p()
        length = wintypes.ULONG(0)
        if not self.dll.UsbDk_GetConfigurationDescriptor(
            ctypes.byref(req),
            ctypes.byref(ptr),
            ctypes.byref(length),
        ):
            raise UsbDkError(
                f"UsbDk configuration descriptor #{index} 읽기 실패",
                winerr=31,
            )
        try:
            return ctypes.string_at(ptr.value, int(length.value))
        finally:
            self.dll.UsbDk_ReleaseConfigurationDescriptor(ptr)

    def start_redirect(self, device_id: _USB_DK_DEVICE_ID):
        handle = self.dll.UsbDk_StartRedirect(ctypes.byref(device_id))
        raw = int(handle) if handle else 0
        if not raw or raw == INVALID_HANDLE_VALUE:
            raise UsbDkError("UsbDk 장치 redirect 시작에 실패했습니다.", winerr=5)
        return handle

    def stop_redirect(self, handle) -> None:
        if handle and int(handle) != INVALID_HANDLE_VALUE:
            if not self.dll.UsbDk_StopRedirect(handle):
                raise UsbDkError("UsbDk 장치 redirect 해제에 실패했습니다.", winerr=31)

    def transfer(self, handle, endpoint: int, data: bytes | None, read_len: int = 0) -> bytes:
        if data is not None and read_len:
            raise ValueError("USB transfer direction is ambiguous")

        if data is not None:
            buf = ctypes.create_string_buffer(data, len(data))
            length = len(data)
            fn = self.dll.UsbDk_WritePipe
        else:
            length = int(read_len)
            buf = ctypes.create_string_buffer(length)
            fn = self.dll.UsbDk_ReadPipe

        req = _USB_DK_TRANSFER_REQUEST()
        req.EndpointAddress = int(endpoint)
        req.Buffer = ctypes.addressof(buf)
        req.BufferLength = length
        req.TransferType = BULK_TRANSFER_TYPE
        req.IsochronousPacketsArraySize = 0
        req.IsochronousPacketsArray = 0

        result = int(fn(handle, ctypes.byref(req), None))
        transferred = int(req.Result.GenResult.BytesTransferred)
        usbd_status = int(req.Result.GenResult.UsbdStatus)
        if result != TRANSFER_SUCCESS or usbd_status != 0:
            raise UsbDkError(
                f"UsbDk bulk transfer 실패 endpoint=0x{endpoint:02X} "
                f"result={result} usbd=0x{usbd_status:08X} "
                f"bytes={transferred}/{length}",
                winerr=31,
            )
        if transferred != length:
            raise UsbDkError(
                f"UsbDk bulk transfer 짧은 전송 endpoint=0x{endpoint:02X} "
                f"{transferred}/{length}",
                winerr=23,
            )
        if data is None:
            return bytes(buf.raw[:length])
        return b""

    def reset_pipe(self, handle, endpoint: int) -> None:
        try:
            self.dll.UsbDk_ResetPipe(handle, int(endpoint))
        except Exception:
            pass


def _copy_device_id(src: _USB_DK_DEVICE_ID) -> _USB_DK_DEVICE_ID:
    out = _USB_DK_DEVICE_ID()
    out.DeviceID = str(src.DeviceID)
    out.InstanceID = str(src.InstanceID)
    return out


class UsbDkBotBackend:
    """Raw block I/O over USB Mass Storage Bulk-Only Transport."""

    def __init__(
        self,
        physical_path: str,
        *,
        expected_size: int,
        expected_sector_size: int,
        partition_offset: int,
        partition_size: int,
        expected_prefix: bytes,
    ):
        from ext4reader.debuglog import LOG

        if not usbdk_ready():
            raise UsbDkRequiredError(
                "일반 Windows raw-write 경로가 모두 거부됐고 UsbDk가 설치되어 있지 않습니다. "
                "이 USB 카드리더에만 선택적 UsbDk direct-USB 백엔드를 사용할 수 있습니다.",
                manual_install=True,
            )

        helper = find_usbdk_helper()
        if not helper:
            raise UsbDkRequiredError(
                "UsbDk 서비스는 있지만 UsbDkHelper.dll을 찾지 못했습니다.",
                manual_install=True,
            )

        self.path = physical_path
        self.partition_offset = int(partition_offset)
        self.partition_size = int(partition_size)
        self.expected_size = int(expected_size)
        self.expected_sector_size = int(expected_sector_size or 512)
        self._api = _UsbDkApi(helper)
        self._redirect = None
        self._tag = 0x45585434
        self._closed = False

        identity = resolve_usb_identity_for_physicaldrive(physical_path)
        info = self._select_device(identity)
        endpoints = self._find_endpoints(info)
        self.identity = identity
        self.bulk_in = endpoints.bulk_in
        self.bulk_out = endpoints.bulk_out
        self.interface_number = endpoints.interface_number

        LOG.warning(
            "UsbDk 후보 확인 path=%s usb=%04X:%04X instance=%s "
            "bulk_in=0x%02X bulk_out=0x%02X",
            physical_path,
            identity.vid,
            identity.pid,
            identity.instance_id,
            self.bulk_in,
            self.bulk_out,
        )

        self._redirect = self._api.start_redirect(_copy_device_id(info.ID))
        try:
            time.sleep(0.25)
            inquiry = self.inquiry()
            self.capacity = self.read_capacity()
            self.sector_size = self.capacity.block_size
            self.size = self.capacity.size

            if self.expected_size and self.size != self.expected_size:
                raise UsbDkError(
                    f"UsbDk 장치 크기 불일치 expected={self.expected_size} actual={self.size}",
                    winerr=1167,
                )
            if self.expected_sector_size and self.sector_size != self.expected_sector_size:
                raise UsbDkError(
                    "UsbDk sector size 불일치 "
                    f"expected={self.expected_sector_size} actual={self.sector_size}",
                    winerr=1167,
                )
            if expected_prefix:
                actual = self.read(0, len(expected_prefix))
                if actual != expected_prefix:
                    raise UsbDkError(
                        "UsbDk redirect 장치의 시작 섹터가 기존 PhysicalDrive와 다릅니다.",
                        winerr=1167,
                    )

            vendor = inquiry[8:16].decode("ascii", "replace").strip() if len(inquiry) >= 16 else ""
            product = inquiry[16:32].decode("ascii", "replace").strip() if len(inquiry) >= 32 else ""
            LOG.warning(
                "UsbDk direct-USB BOT 활성화 성공 usb=%04X:%04X "
                "size=%s sector=%s inquiry=%s %s",
                identity.vid,
                identity.pid,
                self.size,
                self.sector_size,
                vendor,
                product,
            )
        except Exception:
            try:
                self.close()
            except Exception:
                pass
            raise

    def _select_device(self, identity: UsbIdentity) -> _USB_DK_DEVICE_INFO:
        matches: list[_USB_DK_DEVICE_INFO] = []
        serial_matches: list[_USB_DK_DEVICE_INFO] = []
        for info in self._api.devices():
            vid = int(info.DeviceDescriptor.idVendor)
            pid = int(info.DeviceDescriptor.idProduct)
            if vid != identity.vid or pid != identity.pid:
                continue
            matches.append(info)
            if str(info.ID.InstanceID).casefold() == identity.instance_id.casefold():
                serial_matches.append(info)

        if len(serial_matches) == 1:
            return serial_matches[0]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise UsbDkDeviceNotFound(
                f"UsbDk에서 대상 USB 카드리더 {identity.vid:04X}:{identity.pid:04X}를 찾지 못했습니다.",
                winerr=1167,
            )
        raise UsbDkDeviceNotFound(
            f"동일한 VID:PID USB 장치가 {len(matches)}개라 안전하게 대상을 결정할 수 없습니다.",
            winerr=1167,
        )

    def _find_endpoints(self, info: _USB_DK_DEVICE_INFO) -> BulkEndpoints:
        count = int(info.DeviceDescriptor.bNumConfigurations)
        failures: list[str] = []
        for index in range(max(1, count)):
            try:
                raw = self._api.configuration_descriptor(info, index)
                return parse_bulk_only_endpoints(raw)
            except UsbDkError as exc:
                failures.append(str(exc))
        raise UsbDkError(
            "UsbDk Mass Storage BOT endpoint 검색 실패: " + " | ".join(failures),
            winerr=50,
        )

    def _next_tag(self) -> int:
        self._tag = (self._tag + 1) & 0xFFFFFFFF
        if self._tag == 0:
            self._tag = 1
        return self._tag

    def _recover_pipes(self) -> None:
        self._api.reset_pipe(self._redirect, self.bulk_out)
        self._api.reset_pipe(self._redirect, self.bulk_in)

    def _bot(
        self,
        cdb: bytes,
        *,
        data_out: bytes | None = None,
        data_in_len: int = 0,
        sense_on_error: bool = True,
    ) -> bytes:
        if self._closed or not self._redirect:
            raise UsbDkError("UsbDk 장치가 닫혀 있습니다.", winerr=6)
        if not 1 <= len(cdb) <= 16:
            raise ValueError("SCSI CDB length must be 1..16")
        if data_out is not None and data_in_len:
            raise ValueError("SCSI command cannot read and write simultaneously")

        tag = self._next_tag()
        transfer_len = len(data_out) if data_out is not None else int(data_in_len)
        flags = 0x80 if data_in_len else 0x00
        cbw = struct.pack(
            "<IIIBBB16s",
            CBW_SIGNATURE,
            tag,
            transfer_len,
            flags,
            0,
            len(cdb),
            cdb.ljust(16, b"\x00"),
        )

        try:
            self._api.transfer(self._redirect, self.bulk_out, cbw)
            payload = b""
            if data_out is not None and data_out:
                self._api.transfer(self._redirect, self.bulk_out, data_out)
            elif data_in_len:
                payload = self._api.transfer(
                    self._redirect,
                    self.bulk_in,
                    None,
                    data_in_len,
                )

            csw = self._api.transfer(self._redirect, self.bulk_in, None, 13)
        except UsbDkError:
            self._recover_pipes()
            raise

        sig, csw_tag, residue, status = struct.unpack("<IIIB", csw)
        if sig != CSW_SIGNATURE or csw_tag != tag:
            self._recover_pipes()
            raise UsbDkError(
                f"USB BOT CSW 불일치 sig=0x{sig:08X} tag=0x{csw_tag:08X}/{tag:08X}",
                winerr=23,
            )
        if status != 0:
            detail = f"status={status} residue={residue}"
            if sense_on_error and cdb[0] != SCSI_REQUEST_SENSE:
                try:
                    sense = self.request_sense()
                    if len(sense) >= 14:
                        detail += (
                            f" sense_key=0x{sense[2] & 0x0F:02X}"
                            f" asc=0x{sense[12]:02X} ascq=0x{sense[13]:02X}"
                        )
                except Exception:
                    pass
            if status == 2:
                self._recover_pipes()
            raise UsbDkError(f"USB BOT SCSI 명령 실패 opcode=0x{cdb[0]:02X} {detail}", winerr=31)
        if residue:
            raise UsbDkError(
                f"USB BOT 데이터 residue={residue} opcode=0x{cdb[0]:02X}",
                winerr=23,
            )
        return payload

    def request_sense(self) -> bytes:
        cdb = bytes([SCSI_REQUEST_SENSE, 0, 0, 0, 18, 0])
        return self._bot(cdb, data_in_len=18, sense_on_error=False)

    def inquiry(self) -> bytes:
        cdb = bytes([SCSI_INQUIRY, 0, 0, 0, 36, 0])
        for attempt in range(3):
            try:
                return self._bot(cdb, data_in_len=36)
            except UsbDkError:
                if attempt == 2:
                    raise
                time.sleep(0.15)
        raise AssertionError("unreachable")

    def read_capacity(self) -> Capacity:
        cap10 = parse_capacity10(
            self._bot(bytes([SCSI_READ_CAPACITY10]) + b"\x00" * 9, data_in_len=8)
        )
        if cap10.last_lba != 0xFFFFFFFF:
            return cap10

        cdb = bytearray(16)
        cdb[0] = SCSI_SERVICE_ACTION_IN16
        cdb[1] = SCSI_READ_CAPACITY16_SA
        struct.pack_into(">I", cdb, 10, 32)
        return parse_capacity16(self._bot(bytes(cdb), data_in_len=32))

    def _check_aligned(self, offset: int, length: int) -> tuple[int, int]:
        if offset < 0 or length < 0 or offset % self.sector_size or length % self.sector_size:
            raise UsbDkError(
                f"UsbDk block I/O 정렬 오류 offset={offset} len={length} sector={self.sector_size}",
                winerr=87,
            )
        lba = offset // self.sector_size
        blocks = length // self.sector_size
        return lba, blocks

    def _read_blocks(self, lba: int, blocks: int) -> bytes:
        if blocks <= 0:
            return b""
        if lba <= 0xFFFFFFFF and blocks <= 0xFFFF and lba + blocks - 1 <= 0xFFFFFFFF:
            cdb = bytearray(10)
            cdb[0] = SCSI_READ10
            struct.pack_into(">I", cdb, 2, lba)
            struct.pack_into(">H", cdb, 7, blocks)
        else:
            cdb = bytearray(16)
            cdb[0] = SCSI_READ16
            struct.pack_into(">Q", cdb, 2, lba)
            struct.pack_into(">I", cdb, 10, blocks)
        return self._bot(bytes(cdb), data_in_len=blocks * self.sector_size)

    def _write_blocks(self, lba: int, blocks: int, data: bytes) -> None:
        if blocks <= 0:
            return
        if lba <= 0xFFFFFFFF and blocks <= 0xFFFF and lba + blocks - 1 <= 0xFFFFFFFF:
            cdb = bytearray(10)
            cdb[0] = SCSI_WRITE10
            struct.pack_into(">I", cdb, 2, lba)
            struct.pack_into(">H", cdb, 7, blocks)
        else:
            cdb = bytearray(16)
            cdb[0] = SCSI_WRITE16
            struct.pack_into(">Q", cdb, 2, lba)
            struct.pack_into(">I", cdb, 10, blocks)
        self._bot(bytes(cdb), data_out=data)

    def read(self, offset: int, length: int) -> bytes:
        if offset + length > self.size:
            length = max(0, self.size - offset)
        if length <= 0:
            return b""
        lba, blocks = self._check_aligned(offset, length)
        out: list[bytes] = []
        max_blocks = max(1, min(0xFFFF, IO_CHUNK // self.sector_size))
        done = 0
        while done < blocks:
            n = min(max_blocks, blocks - done)
            out.append(self._read_blocks(lba + done, n))
            done += n
        return b"".join(out)

    def write(self, offset: int, data: bytes) -> None:
        if not data:
            return
        end = offset + len(data)
        part_end = self.partition_offset + self.partition_size
        if (
            self.partition_size <= 0
            or offset < self.partition_offset
            or end > part_end
        ):
            raise UsbDkError(
                "UsbDk direct write가 선택한 EXT4 파티션 범위를 벗어났습니다.",
                winerr=5,
            )

        lba, blocks = self._check_aligned(offset, len(data))
        max_blocks = max(1, min(0xFFFF, IO_CHUNK // self.sector_size))
        done = 0
        while done < blocks:
            n = min(max_blocks, blocks - done)
            byte_start = done * self.sector_size
            byte_end = byte_start + n * self.sector_size
            chunk = data[byte_start:byte_end]
            self._write_blocks(lba + done, n, chunk)
            verify = self._read_blocks(lba + done, n)
            if verify != chunk:
                raise UsbDkError(
                    f"UsbDk direct write read-back 불일치 lba={lba + done} blocks={n}",
                    winerr=23,
                )
            done += n

    def flush(self) -> None:
        cdb = bytes([SCSI_SYNCHRONIZE_CACHE10]) + b"\x00" * 9
        self._bot(cdb)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        handle = self._redirect
        self._redirect = None
        if handle:
            self._api.stop_redirect(handle)
