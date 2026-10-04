"""Enumerate and open Windows physical disks (HDD, SSD, USB, SD/MMC)."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import threading
import time
from ctypes import wintypes

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows import safety
    winreg = None
from dataclasses import dataclass

from ext4lib.io.backend import IO_CHUNK, BlockDevice, IoError

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
FILE_BEGIN = 0
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_NO_BUFFERING = 0x20000000
FILE_FLAG_WRITE_THROUGH = 0x80000000

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_RELEASE = 0x00008000
PAGE_READWRITE = 0x04
STORAGE_ACCESS_ALIGNMENT_PROPERTY = 6

# Native NT file I/O flags. Rufus' Windows extfs backend uses NtOpenFile /
# NtWriteFile on raw devices, which avoids extra Win32 file-api translation.
FILE_READ_DATA = 0x00000001
FILE_WRITE_DATA = 0x00000002
SYNCHRONIZE = 0x00100000
OBJ_CASE_INSENSITIVE = 0x00000040
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
FSCTL_LOCK_VOLUME = 0x00090018
FSCTL_DISMOUNT_VOLUME = 0x00090020
FSCTL_ALLOW_EXTENDED_DASD_IO = 0x00090083
IOCTL_VOLUME_ONLINE = 0x0056C008
IOCTL_VOLUME_OFFLINE = 0x0056C00C
IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x002D1080
IOCTL_STORAGE_CHECK_VERIFY2 = 0x002D0800
STALE_HANDLE_ERRORS = {6, 31, 995, 1167}  # invalid handle / gen fail / aborted / unplugged

IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x000700A0
IOCTL_DISK_GET_PARTITION_INFO_EX = 0x00070048
IOCTL_DISK_GET_DISK_ATTRIBUTES = 0x000700F0
IOCTL_DISK_SET_DISK_ATTRIBUTES = 0x0007C0F4
IOCTL_DISK_UPDATE_PROPERTIES = 0x00070140
IOCTL_DISK_IS_WRITABLE = 0x00070024
IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
IOCTL_SCSI_PASS_THROUGH = 0x0004D004
IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x0004D014

SCSI_IOCTL_DATA_OUT = 0
SCSI_IOCTL_DATA_UNSPECIFIED = 2
SCSI_STATUS_GOOD = 0x00
SCSI_WRITE10 = 0x2A
SCSI_SYNCHRONIZE_CACHE10 = 0x35
SCSI_WRITE_FUA = 0x08

TOKEN_QUERY = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
SE_PRIVILEGE_ENABLED = 0x00000002
ERROR_NOT_ALL_ASSIGNED = 1300
SE_MANAGE_VOLUME_NAME = "SeManageVolumePrivilege"

DISK_ATTRIBUTE_OFFLINE = 0x0000000000000001
DISK_ATTRIBUTE_READ_ONLY = 0x0000000000000002
PARTITION_STYLE_GPT = 1
GPT_ATTRIBUTE_READ_ONLY = 0x1000000000000000
GPT_ATTRIBUTE_HIDDEN = 0x4000000000000000
GPT_ATTRIBUTE_NO_DRIVE_LETTER = 0x8000000000000000

BUS_NAMES = {
    0: "알 수 없음",
    1: "SCSI",
    2: "ATAPI",
    3: "ATA",
    4: "IEEE1394",
    6: "Fibre",
    7: "USB",
    8: "RAID",
    9: "iSCSI",
    10: "SAS",
    11: "SATA",
    12: "SD",
    13: "MMC",
    14: "Virtual",
    15: "VHD",
    17: "NVMe",
    19: "UFS",
}

BUS_KIND = {
    3: "HDD/SSD",
    7: "USB",
    11: "HDD/SSD",
    12: "SD 카드",
    13: "SD 카드",
    17: "SSD",
    19: "SD 카드",
}


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
try:
    fveapi = ctypes.WinDLL("fveapi", use_last_error=True)
    _FveEnableRawAccessW = fveapi.FveEnableRawAccessW
    _FveEnableRawAccessW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL]
    _FveEnableRawAccessW.restype = ctypes.c_long
except (OSError, AttributeError):
    fveapi = None
    _FveEnableRawAccessW = None


kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
kernel32.CreateFileW.restype = ctypes.c_void_p
kernel32.ReadFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
kernel32.ReadFile.restype = wintypes.BOOL
kernel32.WriteFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
kernel32.WriteFile.restype = wintypes.BOOL
kernel32.SetFilePointerEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_longlong,
    ctypes.POINTER(ctypes.c_longlong),
    wintypes.DWORD,
]
kernel32.SetFilePointerEx.restype = wintypes.BOOL
kernel32.DeviceIoControl.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
kernel32.DeviceIoControl.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
kernel32.FlushFileBuffers.restype = wintypes.BOOL
kernel32.GetOverlappedResult.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.BOOL,
]
kernel32.GetOverlappedResult.restype = wintypes.BOOL
kernel32.VirtualAlloc.argtypes = [
    wintypes.LPVOID,
    ctypes.c_size_t,
    wintypes.DWORD,
    wintypes.DWORD,
]
kernel32.VirtualAlloc.restype = ctypes.c_void_p
kernel32.VirtualFree.argtypes = [
    wintypes.LPVOID,
    ctypes.c_size_t,
    wintypes.DWORD,
]
kernel32.VirtualFree.restype = wintypes.BOOL

# Synchronous handle + OVERLAPPED offset: one call, file pointer stays put.
class _OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_void_p),
        ("InternalHigh", ctypes.c_void_p),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


ERROR_IO_PENDING = 997
ERROR_INVALID_PARAMETER = 87
kernel32.SetLastError.argtypes = [wintypes.DWORD]
kernel32.SetLastError.restype = None
kernel32.FindFirstVolumeW.argtypes = [wintypes.LPWSTR, wintypes.DWORD]
kernel32.FindFirstVolumeW.restype = wintypes.HANDLE
kernel32.FindNextVolumeW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD]
kernel32.FindNextVolumeW.restype = wintypes.BOOL
kernel32.FindVolumeClose.argtypes = [wintypes.HANDLE]
kernel32.FindVolumeClose.restype = wintypes.BOOL
kernel32.QueryDosDeviceW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
kernel32.QueryDosDeviceW.restype = wintypes.DWORD

class _LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", ctypes.c_long),
    ]


class _LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", _LUID),
        ("Attributes", wintypes.DWORD),
    ]


class _TOKEN_PRIVILEGES_ONE(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", _LUID_AND_ATTRIBUTES * 1),
    ]


kernel32.GetCurrentProcess.argtypes = []
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.HANDLE),
]
advapi32.OpenProcessToken.restype = wintypes.BOOL
advapi32.LookupPrivilegeValueW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    ctypes.POINTER(_LUID),
]
advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
advapi32.AdjustTokenPrivileges.argtypes = [
    wintypes.HANDLE,
    wintypes.BOOL,
    ctypes.POINTER(_TOKEN_PRIVILEGES_ONE),
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.LPVOID,
]
advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL



class _UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
    ]


class _OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", wintypes.HANDLE),
        ("ObjectName", ctypes.POINTER(_UNICODE_STRING)),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", wintypes.LPVOID),
        ("SecurityQualityOfService", wintypes.LPVOID),
    ]


class _IO_STATUS_BLOCK_U(ctypes.Union):
    _fields_ = [
        ("Status", ctypes.c_long),
        ("Pointer", ctypes.c_void_p),
    ]


class _IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [
        ("u", _IO_STATUS_BLOCK_U),
        ("Information", ctypes.c_size_t),
    ]


ntdll = ctypes.WinDLL("ntdll")
ntdll.NtOpenFile.argtypes = [
    ctypes.POINTER(wintypes.HANDLE),
    wintypes.DWORD,
    ctypes.POINTER(_OBJECT_ATTRIBUTES),
    ctypes.POINTER(_IO_STATUS_BLOCK),
    wintypes.ULONG,
    wintypes.ULONG,
]
ntdll.NtOpenFile.restype = ctypes.c_long
ntdll.NtWriteFile.argtypes = [
    wintypes.HANDLE,
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.LPVOID,
    ctypes.POINTER(_IO_STATUS_BLOCK),
    wintypes.LPVOID,
    wintypes.ULONG,
    ctypes.POINTER(ctypes.c_longlong),
    wintypes.LPVOID,
]
ntdll.NtWriteFile.restype = ctypes.c_long
ntdll.NtFlushBuffersFile.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(_IO_STATUS_BLOCK),
]
ntdll.NtFlushBuffersFile.restype = ctypes.c_long
ntdll.NtClose.argtypes = [wintypes.HANDLE]
ntdll.NtClose.restype = ctypes.c_long
ntdll.RtlNtStatusToDosError.argtypes = [ctypes.c_long]
ntdll.RtlNtStatusToDosError.restype = wintypes.ULONG


def _nt_success(status: int) -> bool:
    return int(status) >= 0


def _nt_status_hex(status: int) -> str:
    return f"0x{(int(status) & 0xFFFFFFFF):08X}"


def _nt_native_path(path: str) -> str:
    """Convert a Win32 raw-device path into an NT object-manager path."""
    if path.startswith("\\\\.\\"):
        return "\\??\\" + path[4:]
    globalroot = "\\\\?\\GLOBALROOT"
    if path.startswith(globalroot):
        return path[len(globalroot):]
    if path.startswith("\\\\?\\"):
        return "\\??\\" + path[4:]
    return path


def _nt_open_raw_handle(path: str):
    """Open an existing raw device with NtOpenFile, mirroring Rufus extfs I/O."""
    native = _nt_native_path(path)
    name_buf = ctypes.create_unicode_buffer(native)
    name = _UNICODE_STRING()
    name.Length = len(native.encode("utf-16-le"))
    name.MaximumLength = name.Length + 2
    name.Buffer = ctypes.cast(name_buf, wintypes.LPWSTR)

    attrs = _OBJECT_ATTRIBUTES()
    attrs.Length = ctypes.sizeof(_OBJECT_ATTRIBUTES)
    attrs.RootDirectory = None
    attrs.ObjectName = ctypes.pointer(name)
    attrs.Attributes = OBJ_CASE_INSENSITIVE
    attrs.SecurityDescriptor = None
    attrs.SecurityQualityOfService = None

    iosb = _IO_STATUS_BLOCK()
    handle = wintypes.HANDLE()
    desired = SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA
    status = ntdll.NtOpenFile(
        ctypes.byref(handle),
        desired,
        ctypes.byref(attrs),
        ctypes.byref(iosb),
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_SYNCHRONOUS_IO_NONALERT,
    )
    if not _nt_success(status):
        dos = int(ntdll.RtlNtStatusToDosError(status))
        raise IoError(
            f"NtOpenFile {native} 실패 NTSTATUS={_nt_status_hex(status)} (Win32 {dos})",
            winerr=dos,
        )
    return handle


class STORAGE_DEVICE_NUMBER(ctypes.Structure):
    _fields_ = [
        ("DeviceType", wintypes.DWORD),
        ("DeviceNumber", wintypes.DWORD),
        ("PartitionNumber", wintypes.DWORD),
    ]


class SCSI_PASS_THROUGH(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("ScsiStatus", ctypes.c_ubyte),
        ("PathId", ctypes.c_ubyte),
        ("TargetId", ctypes.c_ubyte),
        ("Lun", ctypes.c_ubyte),
        ("CdbLength", ctypes.c_ubyte),
        ("SenseInfoLength", ctypes.c_ubyte),
        ("DataIn", ctypes.c_ubyte),
        ("DataTransferLength", wintypes.DWORD),
        ("TimeOutValue", wintypes.DWORD),
        ("DataBufferOffset", ctypes.c_size_t),
        ("SenseInfoOffset", wintypes.DWORD),
        ("Cdb", ctypes.c_ubyte * 16),
    ]


class SCSI_PASS_THROUGH_DIRECT(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("ScsiStatus", ctypes.c_ubyte),
        ("PathId", ctypes.c_ubyte),
        ("TargetId", ctypes.c_ubyte),
        ("Lun", ctypes.c_ubyte),
        ("CdbLength", ctypes.c_ubyte),
        ("SenseInfoLength", ctypes.c_ubyte),
        ("DataIn", ctypes.c_ubyte),
        ("DataTransferLength", wintypes.DWORD),
        ("TimeOutValue", wintypes.DWORD),
        ("DataBuffer", ctypes.c_void_p),
        ("SenseInfoOffset", wintypes.DWORD),
        ("Cdb", ctypes.c_ubyte * 16),
    ]


class _SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIcon", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


SEE_MASK_NOCLOSEPROCESS = 0x00000040
SEE_MASK_NOASYNC = 0x00000100
SW_SHOWNORMAL = 1
ERROR_CANCELLED = 1223

_shell32 = ctypes.WinDLL("shell32", use_last_error=True)
_shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(_SHELLEXECUTEINFOW)]
_shell32.ShellExecuteExW.restype = wintypes.BOOL


def is_admin() -> bool:
    if sys.platform != "win32":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _shell_runas(file: str, params: str, directory: str, hwnd=None) -> tuple[bool, str]:
    info = _SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(_SHELLEXECUTEINFOW)
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
    info.hwnd = hwnd if hwnd else None
    info.lpVerb = "runas"
    info.lpFile = file
    info.lpParameters = params or None
    info.lpDirectory = directory or None
    info.nShow = SW_SHOWNORMAL
    if not _shell32.ShellExecuteExW(ctypes.byref(info)):
        err = ctypes.get_last_error()
        if err in (ERROR_CANCELLED, 5):
            return False, "관리자 권한이 거부되었습니다. 확인 창에서 예를 눌러 주세요."
        return False, f"관리자 권한으로 시작하지 못했습니다. (Win32 {err})"
    if info.hProcess:
        kernel32.CloseHandle(info.hProcess)
    return True, ""


def restart_as_admin(hwnd=None) -> tuple[bool, str]:
    """Relaunch this app elevated. Returns (ok, error_message)."""
    if sys.platform != "win32":
        return False, "이 프로그램은 Windows용입니다."
    if is_admin():
        return True, ""
    from ext4lib.host import app_exe, is_frozen, project_root

    try:
        exe = app_exe()
    except RuntimeError as exc:
        return False, str(exc)
    root = project_root()
    extra = subprocess.list2cmdline(sys.argv[1:]) if len(sys.argv) > 1 else ""
    if is_frozen():
        ok, err = _shell_runas(exe, extra, root, hwnd)
        return (True, "") if ok else (False, err)
    # Elevated processes often start in C:\Windows\System32 and ignore lpDirectory,
    # so the child must put the project on sys.path itself.
    code = (
        "import os,sys,runpy;"
        f"p={root!r};"
        "os.chdir(p);"
        "sys.path.insert(0,p);"
        "os.environ['PYTHONPATH']=p;"
        "os.environ['EXT4READER_HOST']='1';"
        "runpy.run_path(os.path.join(p,'main.py'), run_name='__main__')"
    )
    params = "-c " + subprocess.list2cmdline([code])
    ok, err = _shell_runas(exe, params, root, hwnd)
    if ok:
        return True, ""
    bat = os.path.join(root, "run_as_admin.bat")
    if os.path.isfile(bat):
        ok2, err2 = _shell_runas(bat, "", root, hwnd)
        if ok2:
            return True, ""
        return False, err2 or err
    return False, err


@dataclass
class _LockedVolume:
    handle: int
    name: str
    partition_number: int
    locked: bool
    partition_offset: int = 0
    partition_size: int = 0
    offline: bool = False
    volume_guid: str | None = None
    fve_name: str | None = None
    fve_raw: bool = False


@dataclass
class DiskInfo:
    index: int
    path: str
    model: str
    vendor: str
    bus_type: int
    removable: bool
    size: int
    sector_size: int
    serial: str = ""
    error: str = ""

    @property
    def bus_name(self) -> str:
        return BUS_NAMES.get(self.bus_type, f"Bus {self.bus_type}")

    @property
    def kind(self) -> str:
        if self.bus_type in BUS_KIND:
            return BUS_KIND[self.bus_type]
        if self.removable:
            return "이동식"
        return "디스크"

    @property
    def title(self) -> str:
        name = (self.vendor + " " + self.model).strip() or f"PhysicalDrive{self.index}"
        return f"{self.kind} · {name}"


def _decode_c_string(buf: bytes, offset: int) -> str:
    if offset <= 0 or offset >= len(buf):
        return ""
    raw = buf[offset:]
    end = raw.find(b"\x00")
    if end >= 0:
        raw = raw[:end]
    return raw.decode("ascii", errors="ignore").strip()


def _query_geometry(handle) -> tuple[int, int]:
    out = ctypes.create_string_buffer(256)
    returned = wintypes.DWORD(0)
    ok = kernel32.DeviceIoControl(
        handle,
        IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
        None,
        0,
        out,
        256,
        ctypes.byref(returned),
        None,
    )
    if not ok:
        return 0, 512
    data = out.raw
    sector = int.from_bytes(data[20:24], "little") or 512
    size = int.from_bytes(data[24:32], "little")
    return size, sector


def _query_storage(handle) -> tuple[str, str, int, bool]:
    query = ctypes.create_string_buffer(12)
    # PropertyId = StorageDeviceProperty (0), QueryType = PropertyStandardQuery (0)
    out = ctypes.create_string_buffer(1024)
    returned = wintypes.DWORD(0)
    ok = kernel32.DeviceIoControl(
        handle,
        IOCTL_STORAGE_QUERY_PROPERTY,
        query,
        12,
        out,
        1024,
        ctypes.byref(returned),
        None,
    )
    if not ok:
        return "", "", 0, False
    data = out.raw
    removable = bool(data[10])
    vendor_off = int.from_bytes(data[12:16], "little")
    product_off = int.from_bytes(data[16:20], "little")
    bus = data[28]
    vendor = _decode_c_string(data, vendor_off)
    product = _decode_c_string(data, product_off)
    return vendor, product, bus, removable


def _query_storage_serial(handle) -> str:
    """Return the STORAGE_DEVICE_DESCRIPTOR serial number when available."""
    query = ctypes.create_string_buffer(12)
    out = ctypes.create_string_buffer(1024)
    returned = wintypes.DWORD(0)
    ok = kernel32.DeviceIoControl(
        handle,
        IOCTL_STORAGE_QUERY_PROPERTY,
        query,
        12,
        out,
        1024,
        ctypes.byref(returned),
        None,
    )
    if not ok or returned.value < 32:
        return ""
    data = out.raw[: returned.value]
    serial_off = int.from_bytes(data[24:28], "little")
    return _decode_c_string(data, serial_off)



def _query_access_alignment(handle, fallback_sector: int = 512) -> tuple[int, int]:
    """Return logical and physical sector sizes for unbuffered I/O."""
    query = bytearray(12)
    query[0:4] = int(STORAGE_ACCESS_ALIGNMENT_PROPERTY).to_bytes(4, "little")
    try:
        raw = _ioctl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            bytes(query),
            out_cb=64,
        )
    except OSError:
        sector = int(fallback_sector or 512)
        return sector, sector

    if len(raw) < 28:
        sector = int(fallback_sector or 512)
        return sector, sector

    logical = int.from_bytes(raw[16:20], "little") or int(fallback_sector or 512)
    physical = int.from_bytes(raw[20:24], "little") or logical
    return max(1, logical), max(1, physical)


def _write_unbuffered_raw_path(
    path: str,
    offset: int,
    data: bytes,
    fallback_sector: int = 512,
    expected_device_number: int | None = None,
    expected_device_type: int | None = None,
) -> tuple[int, int]:
    """Perform aligned raw I/O with FILE_FLAG_NO_BUFFERING.

    Some SD/card-reader stacks reject cached raw writes while accepting direct
    unbuffered sector I/O. Use VirtualAlloc-backed aligned memory and verify
    through an unbuffered read on the same fresh device handle.
    """
    if not data:
        return int(fallback_sector or 512), int(fallback_sector or 512)

    handle = kernel32.CreateFileW(
        path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
        None,
    )
    if handle == INVALID_HANDLE_VALUE or handle is None:
        err = ctypes.get_last_error()
        raise IoError(
            f"NO_BUFFERING CreateFile 실패 path={path} Win32={err}",
            winerr=err,
        )

    base = None
    try:
        _allow_extended_io(handle)
        if expected_device_number is not None or expected_device_type is not None:
            try:
                raw_num = _ioctl(
                    handle,
                    IOCTL_STORAGE_GET_DEVICE_NUMBER,
                    out_cb=ctypes.sizeof(STORAGE_DEVICE_NUMBER),
                )
                dev_num = STORAGE_DEVICE_NUMBER.from_buffer_copy(raw_num)
            except OSError as exc:
                raise IoError(
                    f"NO_BUFFERING 장치 번호 확인 실패: {exc}",
                    winerr=int(exc.args[0]) if exc.args else 31,
                )
            if (
                expected_device_number is not None
                and int(dev_num.DeviceNumber) != int(expected_device_number)
            ):
                raise IoError(
                    "NO_BUFFERING PhysicalDrive 장치 번호 불일치",
                    winerr=1167,
                )
            if (
                expected_device_type is not None
                and int(dev_num.DeviceType) != int(expected_device_type)
            ):
                raise IoError(
                    "NO_BUFFERING PhysicalDrive 장치 유형 불일치",
                    winerr=1167,
                )

        logical, physical = _query_access_alignment(handle, fallback_sector)
        if offset < 0 or offset % logical or len(data) % logical:
            raise IoError(
                f"NO_BUFFERING 정렬 오류 offset={offset} len={len(data)} "
                f"logical={logical} physical={physical}",
                winerr=87,
            )

        alignment = max(int(physical), int(logical), 512)
        reserve = len(data) + alignment
        base = kernel32.VirtualAlloc(
            None,
            reserve,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
        if not base:
            err = ctypes.get_last_error()
            raise IoError(f"NO_BUFFERING VirtualAlloc 실패 Win32={err}", winerr=err)

        base_addr = int(base)
        aligned_addr = ((base_addr + alignment - 1) // alignment) * alignment
        if aligned_addr + len(data) > base_addr + reserve:
            raise IoError("NO_BUFFERING 정렬 버퍼 범위 오류", winerr=87)

        ctypes.memmove(aligned_addr, data, len(data))
        new_pos = ctypes.c_longlong()
        if not kernel32.SetFilePointerEx(
            handle,
            int(offset),
            ctypes.byref(new_pos),
            FILE_BEGIN,
        ):
            err = ctypes.get_last_error()
            raise IoError(f"NO_BUFFERING seek 실패 offset={offset} Win32={err}", winerr=err)

        done = wintypes.DWORD()
        ctypes.set_last_error(0)
        ok = kernel32.WriteFile(
            handle,
            ctypes.c_void_p(aligned_addr),
            len(data),
            ctypes.byref(done),
            None,
        )
        err = ctypes.get_last_error()
        if not ok or done.value != len(data):
            raise IoError(
                f"NO_BUFFERING WriteFile 실패 offset={offset} "
                f"{done.value}/{len(data)} Win32={err}",
                winerr=err,
            )
        kernel32.FlushFileBuffers(handle)

        ctypes.memset(aligned_addr, 0, len(data))
        if not kernel32.SetFilePointerEx(
            handle,
            int(offset),
            ctypes.byref(new_pos),
            FILE_BEGIN,
        ):
            err = ctypes.get_last_error()
            raise IoError(
                f"NO_BUFFERING read-back seek 실패 offset={offset} Win32={err}",
                winerr=err,
            )

        read_done = wintypes.DWORD()
        ctypes.set_last_error(0)
        ok = kernel32.ReadFile(
            handle,
            ctypes.c_void_p(aligned_addr),
            len(data),
            ctypes.byref(read_done),
            None,
        )
        err = ctypes.get_last_error()
        if not ok or read_done.value != len(data):
            raise IoError(
                f"NO_BUFFERING read-back 실패 offset={offset} "
                f"{read_done.value}/{len(data)} Win32={err}",
                winerr=err,
            )
        verify = ctypes.string_at(aligned_addr, len(data))
        if verify != data:
            raise IoError(
                f"NO_BUFFERING read-back 불일치 offset={offset} len={len(data)}",
                winerr=23,
            )
        return logical, physical
    finally:
        if base:
            kernel32.VirtualFree(base, 0, MEM_RELEASE)
        kernel32.CloseHandle(handle)

def _physical_index(path: str) -> int | None:
    tag = "PHYSICALDRIVE"
    up = path.upper().replace("/", "\\")
    if tag not in up:
        return None
    tail = up.split(tag, 1)[1]
    digits = "".join(ch for ch in tail if ch.isdigit())
    if not digits:
        return None
    return int(digits)


def _ioctl(handle, code: int, inbuf=None, out_cb: int = 0) -> bytes:
    out = ctypes.create_string_buffer(out_cb) if out_cb else None
    returned = wintypes.DWORD(0)
    ok = kernel32.DeviceIoControl(
        handle,
        code,
        inbuf,
        len(inbuf) if inbuf else 0,
        out,
        out_cb,
        ctypes.byref(returned),
        None,
    )
    if not ok:
        raise OSError(ctypes.get_last_error())
    return out.raw[: returned.value] if out else b""


def _allow_extended_io(handle) -> None:
    try:
        _ioctl(handle, FSCTL_ALLOW_EXTENDED_DASD_IO)
    except OSError:
        pass

def _enable_privilege(name: str) -> tuple[bool, int]:
    """Enable one privilege already assigned to the current process token."""
    token = wintypes.HANDLE()
    ctypes.set_last_error(0)
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
        ctypes.byref(token),
    ):
        return False, ctypes.get_last_error()

    try:
        luid = _LUID()
        ctypes.set_last_error(0)
        if not advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            return False, ctypes.get_last_error()

        tp = _TOKEN_PRIVILEGES_ONE()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        ctypes.set_last_error(0)
        if not advapi32.AdjustTokenPrivileges(
            token,
            False,
            ctypes.byref(tp),
            0,
            None,
            None,
        ):
            return False, ctypes.get_last_error()

        err = ctypes.get_last_error()
        if err == ERROR_NOT_ALL_ASSIGNED:
            return False, err
        return True, 0
    finally:
        kernel32.CloseHandle(token)


def _enable_storage_privileges() -> bool:
    """Enable privileges required by Windows volume/disk maintenance paths."""
    from ext4lib.debuglog import LOG

    ok, err = _enable_privilege(SE_MANAGE_VOLUME_NAME)
    if ok:
        LOG.info("%s 활성화 성공", SE_MANAGE_VOLUME_NAME)
        return True
    LOG.warning("%s 활성화 실패 (Win32 %s)", SE_MANAGE_VOLUME_NAME, err)
    return False


def _read_reg_dword(root, path: str, name: str) -> int | None:
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return int(value)
    except (FileNotFoundError, OSError, ValueError, TypeError):
        return None


def _windows_write_policy_blockers() -> list[str]:
    """Return Windows policies/settings that explicitly deny removable writes."""
    if winreg is None:
        return []

    disk_class = r"{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"
    checks = [
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices",
            "Deny_All",
            "컴퓨터 정책: 모든 이동식 저장장치 액세스 거부",
        ),
        (
            winreg.HKEY_CURRENT_USER,
            r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices",
            "Deny_All",
            "사용자 정책: 모든 이동식 저장장치 액세스 거부",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            rf"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{disk_class}",
            "Deny_Write",
            "컴퓨터 정책: 이동식 디스크 쓰기 액세스 거부",
        ),
        (
            winreg.HKEY_CURRENT_USER,
            rf"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{disk_class}",
            "Deny_Write",
            "사용자 정책: 이동식 디스크 쓰기 액세스 거부",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Policies\Microsoft\FVE",
            "RDVDenyWriteAccess",
            "BitLocker 정책: 보호되지 않은 이동식 드라이브 쓰기 거부",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\FVE",
            "RDVDenyWriteAccess",
            "BitLocker 정책(호환 경로): 이동식 드라이브 쓰기 거부",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies",
            "WriteProtect",
            "시스템 설정: 이동식 저장장치 쓰기 보호",
        ),
    ]
    blockers: list[str] = []
    for root, path, name, label in checks:
        value = _read_reg_dword(root, path, name)
        if value == 1:
            blockers.append(f"{label} [{name}=1]")
    return blockers


def _query_disk_attributes(handle) -> tuple[int | None, int]:
    try:
        raw = _ioctl(handle, IOCTL_DISK_GET_DISK_ATTRIBUTES, out_cb=16)
    except OSError as exc:
        return None, int(exc.args[0]) if exc.args else 0
    if len(raw) < 16:
        return None, 13
    return int.from_bytes(raw[8:16], "little"), 0


def _set_disk_offline_state(handle, offline: bool) -> tuple[bool, int]:
    """Set DISK_ATTRIBUTE_OFFLINE non-persistently and verify the result.

    SET_DISK_ATTRIBUTES.Version is documented as sizeof(GET_DISK_ATTRIBUTES),
    which is 16 bytes. The input structure itself is 40 bytes.
    """
    raw = bytearray(40)
    raw[0:4] = (16).to_bytes(4, "little")
    raw[4] = 0  # Persist = FALSE
    raw[8:16] = (
        DISK_ATTRIBUTE_OFFLINE if offline else 0
    ).to_bytes(8, "little")
    raw[16:24] = DISK_ATTRIBUTE_OFFLINE.to_bytes(8, "little")
    try:
        _ioctl(handle, IOCTL_DISK_SET_DISK_ATTRIBUTES, bytes(raw))
    except OSError as exc:
        return False, int(exc.args[0]) if exc.args else 0

    attrs, err = _query_disk_attributes(handle)
    if attrs is None:
        return False, err or 13
    expected = bool(offline)
    actual = bool(attrs & DISK_ATTRIBUTE_OFFLINE)
    if actual != expected:
        return False, 31
    return True, 0


def _close_locked_volume_without_online(item: _LockedVolume) -> None:
    """Drop a volume handle after the whole disk is offline.

    Do not send IOCTL_VOLUME_ONLINE while the containing disk is intentionally
    offline. FVE raw mode is released separately after the handle is closed.
    """
    from ext4lib.debuglog import LOG

    try:
        kernel32.CloseHandle(item.handle)
    except Exception:
        pass
    fve_name = item.fve_name or item.volume_guid
    if item.fve_raw and fve_name:
        ok, hr = _fve_raw_access(fve_name, False)
        if ok:
            LOG.info("FVE raw-access 해제 성공 %s", fve_name)
            item.fve_raw = False
        else:
            LOG.warning(
                "FVE raw-access 해제 실패 %s HRESULT=0x%08X",
                fve_name,
                hr,
            )


def _query_partition_gpt_attributes(handle) -> tuple[int | None, int]:
    """Return GPT partition attributes, or None for non-GPT/unavailable."""
    try:
        raw = _ioctl(handle, IOCTL_DISK_GET_PARTITION_INFO_EX, out_cb=160)
    except OSError as exc:
        return None, int(exc.args[0]) if exc.args else 0
    if len(raw) < 72:
        return None, 13
    style = int.from_bytes(raw[0:4], "little")
    if style != PARTITION_STYLE_GPT:
        return None, 0
    # PARTITION_INFORMATION_EX union starts at offset 32; GPT Attributes is
    # after PartitionType GUID (16) + PartitionId GUID (16).
    return int.from_bytes(raw[64:72], "little"), 0


def _query_partition_extent(handle) -> tuple[int, int, int] | None:
    """Return (starting_offset, partition_length, partition_number)."""
    try:
        raw = _ioctl(handle, IOCTL_DISK_GET_PARTITION_INFO_EX, out_cb=160)
    except OSError:
        return None
    if len(raw) < 32:
        return None
    start = int.from_bytes(raw[8:16], "little", signed=False)
    length = int.from_bytes(raw[16:24], "little", signed=False)
    number = int.from_bytes(raw[24:28], "little", signed=False)
    return start, length, number


def _partition_extent_matches(
    item: _LockedVolume,
    partition_number: int,
    partition_offset: int,
    partition_size: int,
) -> bool:
    if int(item.partition_number) != int(partition_number):
        return False
    if partition_offset and int(item.partition_offset) != int(partition_offset):
        return False
    if partition_size and int(item.partition_size) != int(partition_size):
        return False
    return True


def _log_write_environment(disk_handle=None, partition_handle=None) -> list[str]:
    from ext4lib.debuglog import LOG

    blockers = _windows_write_policy_blockers()
    if blockers:
        for blocker in blockers:
            LOG.warning("Windows 쓰기 차단 정책 감지: %s", blocker)
    else:
        LOG.info("Windows 이동식 저장장치 쓰기 차단 정책: 감지되지 않음")

    if disk_handle is not None:
        attrs, err = _query_disk_attributes(disk_handle)
        if attrs is None:
            LOG.info("디스크 속성 조회 불가 Win32=%s", err)
        else:
            LOG.info(
                "디스크 속성 attrs=0x%016X offline=%s readonly=%s",
                attrs,
                bool(attrs & DISK_ATTRIBUTE_OFFLINE),
                bool(attrs & DISK_ATTRIBUTE_READ_ONLY),
            )
            if attrs & DISK_ATTRIBUTE_READ_ONLY:
                blockers.append("디스크 자체가 READ_ONLY 속성입니다.")

    if partition_handle is not None:
        attrs, err = _query_partition_gpt_attributes(partition_handle)
        if attrs is None:
            if err:
                LOG.info("GPT 파티션 속성 조회 불가 Win32=%s", err)
        else:
            LOG.info(
                "GPT 파티션 속성 attrs=0x%016X readonly=%s hidden=%s no_drive_letter=%s",
                attrs,
                bool(attrs & GPT_ATTRIBUTE_READ_ONLY),
                bool(attrs & GPT_ATTRIBUTE_HIDDEN),
                bool(attrs & GPT_ATTRIBUTE_NO_DRIVE_LETTER),
            )
            if attrs & GPT_ATTRIBUTE_READ_ONLY:
                blockers.append("GPT 파티션에 READ_ONLY 속성이 설정되어 있습니다.")

    return blockers



def _volume_guid_for_fve(name: str) -> str | None:
    """Normalize Volume{GUID} aliases for FveEnableRawAccessW."""
    raw = name.rstrip("\\")
    if raw.startswith("\\\\?\\Volume{"):
        return raw + "\\"
    if raw.startswith("\\\\.\\Volume{"):
        return "\\\\?\\" + raw[4:] + "\\"
    if raw.startswith("Volume{"):
        return "\\\\?\\" + raw + "\\"
    return None


def _dos_device_target(name: str) -> str | None:
    buf = ctypes.create_unicode_buffer(4096)
    ctypes.set_last_error(0)
    n = kernel32.QueryDosDeviceW(name, buf, len(buf))
    if not n:
        return None
    return buf.value


def _volume_alias_candidates() -> list[tuple[str, str | None, str | None]]:
    """Enumerate both Volume{GUID} and HarddiskVolumeN DOS aliases.

    Returns (open_path, fve_volume_guid, NT target). Volume GUID aliases are
    preferred because they work with FveEnableRawAccessW.
    """
    buf = ctypes.create_unicode_buffer(65536)
    n = kernel32.QueryDosDeviceW(None, buf, len(buf))
    if not n:
        return []

    names = [x for x in buf[:n].split("\x00") if x]
    guids = sorted(x for x in names if x.startswith("Volume{"))
    hard = sorted(x for x in names if x.startswith("HarddiskVolume"))

    guid_by_target: dict[str, str] = {}
    for name in guids:
        target = _dos_device_target(name)
        if target:
            guid_by_target[target] = _volume_guid_for_fve(name) or ""

    out: list[tuple[str, str | None, str | None]] = []
    for name in guids:
        target = _dos_device_target(name)
        out.append(("\\\\?\\" + name, _volume_guid_for_fve(name), target))
    for name in hard:
        target = _dos_device_target(name)
        out.append(("\\\\.\\" + name, guid_by_target.get(target) or None, target))
    return out


def _fve_raw_access(volume_name: str | None, enabled: bool) -> tuple[bool, int]:
    """Ask Windows' FVE layer to permit raw sector access for a volume."""
    if not volume_name or _FveEnableRawAccessW is None:
        return False, -1
    hr = int(_FveEnableRawAccessW(volume_name, bool(enabled)))
    ok = hr >= 0
    return ok, hr & 0xFFFFFFFF


def _fve_raw_candidates(
    open_path: str,
    volume_guid: str | None,
    target: str | None,
) -> list[str]:
    """Return reader-independent volume identifiers for FVE raw mode.

    Microsoft documents the first FveEnableRawAccessW argument as a unique
    volume identifier, not specifically as a drive letter.  Some SD/MMC
    readers expose only HarddiskVolumeN and never publish a Volume{GUID}
    alias, so try the stable NT/GLOBALROOT forms as well.
    """
    values: list[str] = []
    if volume_guid:
        values.append(volume_guid)
    if target and target.startswith("\\Device\\"):
        values.append("\\\\?\\GLOBALROOT" + target)
        values.append(target)
    if open_path:
        values.append(open_path)

    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        key = value.rstrip("\\").lower()
        if key and key not in seen:
            seen.add(key)
            out.append(value)
    return out


def _try_enable_fve_raw_access(
    open_path: str,
    volume_guid: str | None,
    target: str | None,
) -> str | None:
    """Enable FVE raw mode using the first volume identifier Windows accepts."""
    from ext4lib.debuglog import LOG

    if _FveEnableRawAccessW is None:
        LOG.info("FVE raw-access API를 사용할 수 없습니다.")
        return None

    last_hr = -1
    for candidate in _fve_raw_candidates(open_path, volume_guid, target):
        ok, hr = _fve_raw_access(candidate, True)
        last_hr = hr
        if ok:
            LOG.info("FVE raw-access 활성화 성공 %s", candidate)
            return candidate
        LOG.info(
            "FVE raw-access 후보 실패 %s HRESULT=0x%08X",
            candidate,
            hr,
        )

    if last_hr != -1:
        LOG.info("FVE raw-access 가능한 볼륨 식별자를 찾지 못했습니다.")
    return None


def _release_locked_volume(item: _LockedVolume) -> None:
    try:
        _bring_volume_online(item)
    except Exception:
        pass
    try:
        kernel32.CloseHandle(item.handle)
    except Exception:
        pass
    fve_name = item.fve_name or item.volume_guid
    if item.fve_raw and fve_name:
        from ext4lib.debuglog import LOG
        ok, hr = _fve_raw_access(fve_name, False)
        if ok:
            LOG.info("FVE raw-access 해제 성공 %s", fve_name)
            item.fve_raw = False
        else:
            LOG.warning("FVE raw-access 해제 실패 %s HRESULT=0x%08X", fve_name, hr)


def _take_volume_offline(handle, name: str) -> bool:
    """Keep a dismounted volume from being automatically remounted.

    Microsoft documents that IOCTL_VOLUME_OFFLINE must follow a successful
    dismount and that taking a volume offline does not block I/O sent to the
    underlying physical disk.
    """
    from ext4lib.debuglog import LOG

    try:
        _ioctl(handle, IOCTL_VOLUME_OFFLINE)
        LOG.info("볼륨 오프라인 성공 %s", name)
        return True
    except OSError as exc:
        LOG.warning("볼륨 오프라인 실패 %s: %s", name, exc)
        return False


def _bring_volume_online(item: _LockedVolume) -> None:
    if not item.offline:
        return
    from ext4lib.debuglog import LOG

    try:
        _ioctl(item.handle, IOCTL_VOLUME_ONLINE)
        item.offline = False
        LOG.info("볼륨 온라인 복원 %s", item.name)
    except OSError as exc:
        LOG.warning("볼륨 온라인 복원 실패 %s: %s", item.name, exc)


def _is_writable_ioctl(handle) -> tuple[bool, int]:
    """Ask the storage stack whether writes are allowed on this device."""
    returned = wintypes.DWORD(0)
    kernel32.SetLastError(0)
    ok = kernel32.DeviceIoControl(
        handle,
        IOCTL_DISK_IS_WRITABLE,
        None,
        0,
        None,
        0,
        ctypes.byref(returned),
        None,
    )
    if ok:
        return True, 0
    return False, ctypes.get_last_error()


def _lock_volumes_for_disk(disk_index: int) -> list[_LockedVolume]:
    """Lock/dismount Windows volumes on this disk and keep their handles open.

    Windows Vista+ blocks raw PhysicalDrive writes that overlap a mounted
    volume unless that volume is explicitly locked/dismounted.  We also keep
    the matching RAW volume handle so writes inside the selected partition can
    be issued through the volume handle itself, which Windows permits for RAW
    filesystems.
    """
    from ext4lib.debuglog import LOG

    locked: list[_LockedVolume] = []
    name = ctypes.create_unicode_buffer(260)
    find = kernel32.FindFirstVolumeW(name, 260)
    if find == INVALID_HANDLE_VALUE or find is None:
        return locked
    try:
        while True:
            vol = name.value.rstrip("\\")
            handle = kernel32.CreateFileW(
                vol,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
            if handle != INVALID_HANDLE_VALUE and handle is not None:
                try:
                    raw = _ioctl(handle, IOCTL_STORAGE_GET_DEVICE_NUMBER, out_cb=ctypes.sizeof(STORAGE_DEVICE_NUMBER))
                    num = STORAGE_DEVICE_NUMBER.from_buffer_copy(raw)
                    if num.DeviceNumber == disk_index:
                        lock_ok = False
                        try:
                            _ioctl(handle, FSCTL_LOCK_VOLUME)
                            lock_ok = True
                            LOG.info(
                                "Windows 볼륨 잠금 성공 %s (PhysicalDrive%s part=%s)",
                                vol,
                                disk_index,
                                num.PartitionNumber,
                            )
                        except OSError as exc:
                            LOG.warning("볼륨 잠금 실패 %s: %s", vol, exc)
                        dismount_ok = False
                        try:
                            _ioctl(handle, FSCTL_DISMOUNT_VOLUME)
                            dismount_ok = True
                            LOG.info(
                                "Windows 볼륨 분리 %s (PhysicalDrive%s part=%s)",
                                vol,
                                disk_index,
                                num.PartitionNumber,
                            )
                        except OSError as exc:
                            LOG.warning("볼륨 분리 실패 %s: %s", vol, exc)
                        offline_ok = _take_volume_offline(handle, vol) if dismount_ok else False
                        _allow_extended_io(handle)
                        extent = _query_partition_extent(handle)
                        part_offset = int(extent[0]) if extent is not None else 0
                        part_size = int(extent[1]) if extent is not None else 0
                        part_number = (
                            int(extent[2]) if extent is not None else int(num.PartitionNumber)
                        )
                        locked.append(
                            _LockedVolume(
                                handle=int(handle),
                                name=vol,
                                partition_number=part_number,
                                locked=lock_ok,
                                partition_offset=part_offset,
                                partition_size=part_size,
                                offline=offline_ok,
                                volume_guid=_volume_guid_for_fve(name.value),
                            )
                        )
                        handle = None
                except OSError:
                    pass
                finally:
                    if handle:
                        kernel32.CloseHandle(handle)
            if not kernel32.FindNextVolumeW(find, name, 260):
                break
    finally:
        kernel32.FindVolumeClose(find)
    return locked


def _open_handle(path: str, writable: bool):
    """Open a raw disk handle with storage-tool style flags.

    For write access, prefer FILE_SHARE_READ only and FILE_ATTRIBUTE_NORMAL,
    matching established raw-disk utilities. If Windows refuses the stricter
    share mode, fall back to FILE_SHARE_READ|FILE_SHARE_WRITE.
    """
    from ext4lib.debuglog import LOG

    access = GENERIC_READ | (GENERIC_WRITE if writable else 0)
    shares = (
        [FILE_SHARE_READ, FILE_SHARE_READ | FILE_SHARE_WRITE]
        if writable
        else [FILE_SHARE_READ | FILE_SHARE_WRITE]
    )
    last_err = 0
    for share in shares:
        handle = kernel32.CreateFileW(
            path,
            access,
            share,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if handle != INVALID_HANDLE_VALUE and handle is not None:
            if writable:
                LOG.info("RAW 디스크 핸들 열기 성공 share=0x%X flags=FILE_ATTRIBUTE_NORMAL", share)
            _allow_extended_io(handle)
            return handle
        last_err = ctypes.get_last_error()
        if writable:
            LOG.warning("RAW 디스크 핸들 열기 재시도 share=0x%X Win32=%s", share, last_err)

    raise IoError(f"{path} 를 열 수 없습니다. (Win32 {last_err})", winerr=last_err)


def _open_hidden_volume_alias(
    disk_index: int,
    partition_number: int,
    partition_offset: int = 0,
    partition_size: int = 0,
) -> _LockedVolume | None:
    """Find a matching volume through every DOS alias exposed by Windows.

    Some built-in SD/MMC readers expose an EXT4 partition only as
    HarddiskVolumeN, while others also expose a Volume{GUID} alias.  We try
    both and enable Windows FVE raw-access mode when a GUID is available.
    """
    from ext4lib.debuglog import LOG

    candidates = _volume_alias_candidates()
    if not candidates:
        LOG.warning("QueryDosDeviceW 볼륨 별칭 열거 실패 (Win32 %s)", ctypes.get_last_error())
        return None

    for path, volume_guid, target in candidates:
        handle = kernel32.CreateFileW(
            path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if handle == INVALID_HANDLE_VALUE or handle is None:
            continue

        matched = False
        try:
            raw = _ioctl(
                handle,
                IOCTL_STORAGE_GET_DEVICE_NUMBER,
                out_cb=ctypes.sizeof(STORAGE_DEVICE_NUMBER),
            )
            num = STORAGE_DEVICE_NUMBER.from_buffer_copy(raw)
            extent = _query_partition_extent(handle)
            extent_ok = (
                extent is not None
                and (not partition_offset or int(extent[0]) == int(partition_offset))
                and (not partition_size or int(extent[1]) == int(partition_size))
            )
            matched = (
                int(num.DeviceNumber) == int(disk_index)
                and int(num.PartitionNumber) == int(partition_number)
                and extent_ok
            )
        except OSError:
            matched = False

        if not matched:
            kernel32.CloseHandle(handle)
            continue

        # FveEnableRawAccessW may need to acquire its own volume lock. Close our
        # discovery handle first, request raw access, then reopen the volume.
        kernel32.CloseHandle(handle)
        fve_name = _try_enable_fve_raw_access(path, volume_guid, target)
        fve_ok = fve_name is not None

        handle = kernel32.CreateFileW(
            path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if handle == INVALID_HANDLE_VALUE or handle is None:
            if fve_ok:
                _fve_raw_access(fve_name, False)
            continue

        keep = False
        try:
            extent = _query_partition_extent(handle)
            if (
                extent is None
                or (partition_offset and int(extent[0]) != int(partition_offset))
                or (partition_size and int(extent[1]) != int(partition_size))
            ):
                LOG.warning(
                    "볼륨 별칭 범위 불일치 %s expected_offset=%s expected_size=%s actual=%s",
                    path,
                    partition_offset,
                    partition_size,
                    extent,
                )
                continue
            writable_ok, writable_err = _is_writable_ioctl(handle)
            LOG.info(
                "볼륨 별칭 발견 %s target=%s -> PhysicalDrive%s part=%s "
                "writable=%s err=%s fve_raw=%s",
                path,
                target or "?",
                disk_index,
                partition_number,
                writable_ok,
                writable_err,
                fve_ok,
            )
            lock_ok = False
            try:
                _ioctl(handle, FSCTL_LOCK_VOLUME)
                lock_ok = True
                LOG.info("볼륨 잠금 성공 %s", path)
            except OSError as exc:
                LOG.info("볼륨 잠금 생략/실패 %s: %s", path, exc)

            dismount_ok = False
            try:
                _ioctl(handle, FSCTL_DISMOUNT_VOLUME)
                dismount_ok = True
                LOG.info("볼륨 분리 성공 %s", path)
            except OSError as exc:
                LOG.info("볼륨 분리 생략/실패 %s: %s", path, exc)

            offline_ok = _take_volume_offline(handle, path) if dismount_ok else False
            _allow_extended_io(handle)
            keep = True
            extent = _query_partition_extent(handle)
            return _LockedVolume(
                handle=int(handle),
                name=path,
                partition_number=int(partition_number),
                locked=lock_ok,
                partition_offset=int(extent[0]) if extent is not None else 0,
                partition_size=int(extent[1]) if extent is not None else 0,
                offline=offline_ok,
                volume_guid=volume_guid,
                fve_name=fve_name,
                fve_raw=fve_ok,
            )
        except OSError:
            pass
        finally:
            if not keep:
                kernel32.CloseHandle(handle)
                if fve_ok:
                    _fve_raw_access(fve_name, False)
    return None

def _open_partition_device(
    disk_index: int,
    partition_number: int,
    partition_offset: int = 0,
    partition_size: int = 0,
) -> _LockedVolume | None:
    """Open a partition DASD handle when Mount Manager exposes no Volume GUID."""
    from ext4lib.debuglog import LOG

    # The Win32 DASD alias is preferable. GLOBALROOT is retained as a fallback
    # because device naming differs across Windows/storage drivers.
    candidates = [
        rf"\\.\Harddisk{disk_index}Partition{partition_number}",
        rf"\\?\GLOBALROOT\Device\Harddisk{disk_index}\Partition{partition_number}",
    ]
    last_err = 0

    for path in candidates:
        handle = kernel32.CreateFileW(
            path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if handle == INVALID_HANDLE_VALUE or handle is None:
            last_err = ctypes.get_last_error()
            LOG.warning("파티션 DASD 열기 실패 %s (Win32 %s)", path, last_err)
            continue

        try:
            extent = _query_partition_extent(handle)
            if (
                extent is None
                or (partition_offset and int(extent[0]) != int(partition_offset))
                or (partition_size and int(extent[1]) != int(partition_size))
            ):
                LOG.warning(
                    "파티션 DASD 범위 불일치 %s expected_offset=%s expected_size=%s actual=%s",
                    path,
                    partition_offset,
                    partition_size,
                    extent,
                )
                kernel32.CloseHandle(handle)
                continue

            writable_ok, writable_err = _is_writable_ioctl(handle)
            if writable_ok:
                LOG.info("파티션 DASD 쓰기 가능 확인 %s", path)
            else:
                LOG.warning(
                    "파티션 DASD IOCTL_DISK_IS_WRITABLE 실패 %s (Win32 %s)",
                    path,
                    writable_err,
                )

            lock_ok = False
            try:
                _ioctl(handle, FSCTL_LOCK_VOLUME)
                lock_ok = True
                LOG.info("파티션 장치 잠금 성공 %s", path)
            except OSError as exc:
                LOG.info("파티션 장치 잠금 생략/실패 %s: %s", path, exc)
            try:
                _ioctl(handle, FSCTL_DISMOUNT_VOLUME)
                LOG.info("파티션 장치 분리 성공 %s", path)
            except OSError as exc:
                LOG.info("파티션 장치 분리 생략/실패 %s: %s", path, exc)
            _allow_extended_io(handle)

            # ERROR_WRITE_PROTECT (19) is decisive: retrying another alias will
            # not bypass a hardware/media or partition read-only condition.
            if not writable_ok and writable_err == 19:
                kernel32.CloseHandle(handle)
                raise IoError(
                    f"{path} 는 Windows에서 쓰기 금지 상태입니다. "
                    "SD 어댑터 LOCK 스위치 또는 디스크/파티션 읽기 전용 속성을 확인하세요. (Win32 19)",
                    winerr=19,
                )

            return _LockedVolume(
                handle=int(handle),
                name=path,
                partition_number=int(partition_number),
                locked=lock_ok,
                partition_offset=int(extent[0]),
                partition_size=int(extent[1]),
                offline=False,
                volume_guid=None,
                fve_raw=False,
            )
        except IoError:
            raise
        except Exception:
            kernel32.CloseHandle(handle)
            raise

    LOG.warning(
        "파티션 DASD를 열 수 없습니다 PhysicalDrive%s part=%s (마지막 Win32 %s)",
        disk_index,
        partition_number,
        last_err,
    )
    return None

def _verify_expected_medium(
    path: str,
    partition_offset: int,
    expected_size: int = 0,
    expected_serial: str = "",
    expected_ext_uuid: bytes | None = None,
) -> None:
    """Verify a PhysicalDrive before any writable volume lock/dismount."""
    handle = _open_handle(path, False)
    try:
        size, sector = _query_geometry(handle)
        if expected_size and size and int(expected_size) != int(size):
            raise IoError(
                f"검색 후 디스크 크기가 변경되었습니다: {expected_size} -> {size}",
                winerr=1167,
            )
        current_serial = _query_storage_serial(handle).strip().lower()
        scanned_serial = (expected_serial or "").strip().lower()
        if scanned_serial and current_serial and scanned_serial != current_serial:
            raise IoError("검색 후 저장장치 serial이 변경되었습니다.", winerr=1167)

        if expected_ext_uuid is not None:
            target = int(partition_offset) + 1024
            ss = int(sector or 512)
            start = (target // ss) * ss
            end = ((target + 1024 + ss - 1) // ss) * ss
            new_pos = ctypes.c_longlong(0)
            if not kernel32.SetFilePointerEx(
                handle, start, ctypes.byref(new_pos), FILE_BEGIN
            ):
                err = ctypes.get_last_error()
                raise IoError(
                    f"EXT4 대상 검증 seek 실패 (Win32 {err})",
                    winerr=err,
                )
            length = end - start
            buf = bytearray(length)
            done = wintypes.DWORD(0)
            ok = kernel32.ReadFile(
                handle,
                (ctypes.c_char * length).from_buffer(buf),
                length,
                ctypes.byref(done),
                None,
            )
            if not ok or int(done.value) != length:
                err = ctypes.get_last_error()
                raise IoError(
                    f"EXT4 대상 검증 read 실패 (Win32 {err})",
                    winerr=err or 23,
                )
            rel = target - start
            from ext4lib.fs.superblock import parse_superblock

            try:
                sb = parse_superblock(bytes(buf[rel : rel + 1024]))
            except Exception as exc:
                raise IoError(
                    "선택했던 위치에서 EXT4 슈퍼블록을 다시 찾지 못했습니다.",
                    winerr=1167,
                ) from exc
            if bytes(sb.uuid) != bytes(expected_ext_uuid):
                raise IoError(
                    "검색 후 선택한 EXT4 UUID가 변경되었습니다. 다른 디스크 보호를 위해 중단합니다.",
                    winerr=1167,
                )
    finally:
        kernel32.CloseHandle(handle)


def list_physical_disks() -> list[DiskInfo]:
    disks: list[DiskInfo] = []
    for idx in range(32):
        path = rf"\\.\PhysicalDrive{idx}"
        handle = kernel32.CreateFileW(
            path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if handle == INVALID_HANDLE_VALUE or handle is None:
            continue
        try:
            size, sector = _query_geometry(handle)
            vendor, product, bus, removable = _query_storage(handle)
            disks.append(
                DiskInfo(
                    index=idx,
                    path=path,
                    model=product or f"PhysicalDrive{idx}",
                    vendor=vendor,
                    bus_type=bus,
                    removable=removable,
                    size=size,
                    sector_size=sector or 512,
                    serial=_query_storage_serial(handle),
                )
            )
        except Exception as exc:
            disks.append(
                DiskInfo(
                    index=idx,
                    path=path,
                    model=f"PhysicalDrive{idx}",
                    vendor="",
                    bus_type=0,
                    removable=False,
                    size=0,
                    sector_size=512,
                    serial="",
                    error=str(exc),
                )
            )
        finally:
            kernel32.CloseHandle(handle)
    return disks


class WindowsPhysicalDevice(BlockDevice):
    def __init__(
        self,
        path: str,
        sector_size: int = 512,
        writable: bool = False,
        partition_number: int | None = None,
        partition_offset: int = 0,
        partition_size: int = 0,
        expected_size: int = 0,
        expected_serial: str = "",
        expected_ext_uuid: bytes | None = None,
    ):
        from ext4lib.debuglog import LOG

        self.path = path
        self.sector_size = sector_size or 512
        self._writable = writable
        self._io_lock = threading.RLock()
        self._closed = False
        self._stop_ka = threading.Event()
        self._volume_locks: list[_LockedVolume] = []
        self._partition_number = partition_number
        self._partition_offset = int(partition_offset or 0)
        self._partition_size = int(partition_size or 0)
        self._partition_volume: _LockedVolume | None = None
        self._nt_handle = None
        self._write_blockers: list[str] = []
        self._disk_offline = False
        self._usbdk = None
        # USB/SD bridges differ widely in SCSI cache semantics. Learn the
        # working durability method once per device instead of retrying a chain
        # of known-failing commands for every filesystem write.
        self._scsi_dirty = False
        self._scsi_fua_supported: bool | None = None
        self._scsi_sync_cache_supported: bool | None = None
        self._fallback_write_route: str | None = None
        LOG.info(
            "디스크 열기 %s writable=%s sector=%s part=%s part_offset=%s part_size=%s",
            path,
            writable,
            self.sector_size,
            partition_number,
            self._partition_offset,
            self._partition_size,
        )
        if expected_size or expected_serial or expected_ext_uuid is not None:
            _verify_expected_medium(
                path,
                self._partition_offset,
                expected_size=int(expected_size or 0),
                expected_serial=expected_serial,
                expected_ext_uuid=expected_ext_uuid,
            )
            LOG.info(
                "PhysicalDrive 대상 고정 검증 성공 path=%s size=%s serial=%s uuid=%s",
                path,
                expected_size or "-",
                expected_serial or "-",
                expected_ext_uuid.hex() if expected_ext_uuid is not None else "-",
            )
        if writable:
            _enable_storage_privileges()
            idx = _physical_index(path)
            if idx is not None:
                self._volume_locks = _lock_volumes_for_disk(idx)
                if partition_number is not None:
                    self._partition_volume = next(
                        (
                            item
                            for item in self._volume_locks
                            if _partition_extent_matches(
                                item,
                                int(partition_number),
                                self._partition_offset,
                                self._partition_size,
                            )
                        ),
                        None,
                    )
                    if self._partition_volume is not None:
                        LOG.info(
                            "파티션 직접 쓰기용 Windows 볼륨 핸들 선택 %s part=%s locked=%s",
                            self._partition_volume.name,
                            self._partition_volume.partition_number,
                            self._partition_volume.locked,
                        )
                    else:
                        LOG.warning(
                            "PhysicalDrive%s part=%s 에 해당하는 Volume{GUID} 핸들을 찾지 못했습니다. "
                            "숨은 Volume{GUID}/HarddiskVolume 별칭을 찾습니다.",
                            idx,
                            partition_number,
                        )
                        hidden = _open_hidden_volume_alias(
                            idx,
                            int(partition_number),
                            self._partition_offset,
                            self._partition_size,
                        )
                        if hidden is not None:
                            self._volume_locks.append(hidden)
                            self._partition_volume = hidden
                            LOG.info(
                                "파티션 직접 쓰기용 호환 볼륨 핸들 선택 %s part=%s locked=%s fve_raw=%s",
                                hidden.name,
                                hidden.partition_number,
                                hidden.locked,
                                hidden.fve_raw,
                            )
                        else:
                            LOG.warning(
                                "Volume GUID/HarddiskVolume 별칭도 없어 파티션 DASD를 직접 엽니다."
                            )
                            direct = _open_partition_device(
                                idx,
                                int(partition_number),
                                self._partition_offset,
                                self._partition_size,
                            )
                            if direct is not None:
                                self._volume_locks.append(direct)
                                self._partition_volume = direct
                                LOG.info(
                                    "파티션 직접 쓰기용 장치 핸들 선택 %s part=%s locked=%s",
                                    direct.name,
                                    direct.partition_number,
                                    direct.locked,
                                )
        self._handle = _open_handle(path, writable)
        try:
            _vendor, _product, self._bus_type, self._removable = _query_storage(self._handle)
            self._serial = _query_storage_serial(self._handle)
        except Exception:
            _vendor, _product, self._bus_type, self._removable = "", "", 0, False
            self._serial = ""
        LOG.info(
            "저장장치 경로 bus=%s(%s) removable=%s model=%s %s",
            self._bus_type,
            BUS_NAMES.get(self._bus_type, "알 수 없음"),
            self._removable,
            _vendor,
            _product,
        )
        if writable:
            self._write_blockers = _log_write_environment(
                self._handle,
                self._partition_volume.handle if self._partition_volume is not None else None,
            )
            writable_ok, writable_err = _is_writable_ioctl(self._handle)
            if writable_ok:
                LOG.info("물리 디스크 IOCTL_DISK_IS_WRITABLE: 쓰기 가능")
            else:
                LOG.warning(
                    "물리 디스크 IOCTL_DISK_IS_WRITABLE 실패 (Win32 %s)",
                    writable_err,
                )
                if writable_err == 19:
                    raise IoError(
                        "저장장치가 Windows에서 쓰기 금지 상태입니다. "
                        "SD 어댑터 LOCK 스위치 또는 디스크 읽기 전용 속성을 확인하세요. (Win32 19)",
                        winerr=19,
                    )
        # Use synchronous seek+WriteFile for writable raw disks. Some USB/card
        # reader drivers are more reliable with the classic DASD write pattern.
        self._use_overlapped = not writable
        self._size, geo_ss = _query_geometry(self._handle)
        if geo_ss:
            self.sector_size = geo_ss
        LOG.info("디스크 열림 size=%s sector=%s", self._size, self.sector_size)
        self._ka = None
        if self._size:
            self._ka = threading.Thread(target=self._keepalive, daemon=True, name=f"disk-ka-{path}")
            self._ka.start()

    @property
    def writable(self) -> bool:
        return self._writable

    @property
    def display_path(self) -> str:
        return self.path

    @property
    def serial(self) -> str:
        return self._serial

    def size(self) -> int:
        return self._size

    def _keepalive(self) -> None:
        from ext4lib.debuglog import LOG

        while not self._stop_ka.wait(15):
            try:
                with self._io_lock:
                    if self._closed:
                        return
                    try:
                        _ioctl(self._handle, IOCTL_STORAGE_CHECK_VERIFY2)
                    except OSError:
                        self._raw_read_once(0, self.sector_size)
            except Exception as exc:
                LOG.warning("디스크 연결 유지 실패 %s: %s", self.path, exc)
                try:
                    with self._io_lock:
                        if not self._closed:
                            self._reopen_locked()
                except Exception:
                    pass

    def _reopen_locked(self) -> None:
        from ext4lib.debuglog import LOG

        old = self._handle
        try:
            kernel32.CloseHandle(old)
        except Exception:
            pass
        if self._nt_handle is not None:
            try:
                ntdll.NtClose(self._nt_handle)
            except Exception:
                pass
            self._nt_handle = None
        if self._writable:
            _enable_storage_privileges()
            idx = _physical_index(self.path)
            if idx is not None and not self._disk_offline:
                for item in self._volume_locks:
                    _release_locked_volume(item)
                self._volume_locks = _lock_volumes_for_disk(idx)
                self._partition_volume = None
                if self._partition_number is not None:
                    self._partition_volume = next(
                        (
                            item
                            for item in self._volume_locks
                            if _partition_extent_matches(
                                item,
                                int(self._partition_number),
                                self._partition_offset,
                                self._partition_size,
                            )
                        ),
                        None,
                    )
                    if self._partition_volume is None:
                        hidden = _open_hidden_volume_alias(
                            idx,
                            int(self._partition_number),
                            self._partition_offset,
                            self._partition_size,
                        )
                        if hidden is not None:
                            self._volume_locks.append(hidden)
                            self._partition_volume = hidden
                    if self._partition_volume is None:
                        direct = _open_partition_device(
                            idx,
                            int(self._partition_number),
                            self._partition_offset,
                            self._partition_size,
                        )
                        if direct is not None:
                            self._volume_locks.append(direct)
                            self._partition_volume = direct
        self._handle = _open_handle(self.path, self._writable)
        self._use_overlapped = not self._writable
        self._size, geo_ss = _query_geometry(self._handle)
        if geo_ss:
            self.sector_size = geo_ss
        LOG.warning("디스크 핸들을 다시 열었습니다 %s", self.path)

    def _retry(self, fn):
        last: BaseException | None = None
        with self._io_lock:
            for attempt in range(3):
                try:
                    return fn()
                except IoError as exc:
                    last = exc
                    if exc.winerr not in STALE_HANDLE_ERRORS or attempt == 2 or self._closed:
                        raise
                    from ext4lib.debuglog import LOG

                    LOG.warning("디스크 I/O 재시도 Win32 %s (%s/%s)", exc.winerr, attempt + 1, 3)
                    self._reopen_locked()
        if last:
            raise last
        raise IoError("디스크 I/O 실패")

    def _seek(self, offset: int) -> None:
        kernel32.SetLastError(0)
        new_pos = ctypes.c_longlong(0)
        ok = kernel32.SetFilePointerEx(self._handle, offset, ctypes.byref(new_pos), FILE_BEGIN)
        if not ok:
            err = ctypes.get_last_error()
            raise IoError(f"오프셋 {offset} 이동 실패 (Win32 {err})", winerr=err)

    def _overlapped(self, offset: int) -> _OVERLAPPED:
        ov = _OVERLAPPED()
        ov.Offset = offset & 0xFFFFFFFF
        ov.OffsetHigh = (offset >> 32) & 0xFFFFFFFF
        return ov

    def _finish_overlapped(self, ok: bool, ov: _OVERLAPPED, done: wintypes.DWORD, what: str) -> None:
        if ok:
            return
        err = ctypes.get_last_error()
        if err == ERROR_IO_PENDING:
            ok = kernel32.GetOverlappedResult(self._handle, ctypes.byref(ov), ctypes.byref(done), True)
            if ok:
                return
            err = ctypes.get_last_error()
        if err == ERROR_INVALID_PARAMETER:
            self._use_overlapped = False
        raise IoError(f"{self.path} {what} 실패 (Win32 {err})", winerr=err)

    def _read_seek(self, offset: int, length: int) -> bytes:
        self._seek(offset)
        buf = bytearray(length)
        done = wintypes.DWORD(0)
        kernel32.SetLastError(0)
        ok = kernel32.ReadFile(
            self._handle,
            (ctypes.c_char * length).from_buffer(buf),
            length,
            ctypes.byref(done),
            None,
        )
        if not ok:
            err = ctypes.get_last_error()
            raise IoError(
                f"{self.path} 오프셋 {offset}에서 {length}바이트 읽기 실패 (Win32 {err})",
                winerr=err,
            )
        got = int(done.value)
        if got < length:
            buf[got:] = b"\x00" * (length - got)
        return bytes(buf)

    def _read_at(self, offset: int, length: int) -> bytes:
        if length <= 0:
            return b""
        if not self._use_overlapped:
            return self._read_seek(offset, length)
        buf = bytearray(length)
        ov = self._overlapped(offset)
        done = wintypes.DWORD(0)
        kernel32.SetLastError(0)
        ok = kernel32.ReadFile(
            self._handle,
            (ctypes.c_char * length).from_buffer(buf),
            length,
            ctypes.byref(done),
            ctypes.byref(ov),
        )
        try:
            self._finish_overlapped(bool(ok), ov, done, f"오프셋 {offset} 읽기")
        except IoError:
            if not self._use_overlapped:
                return self._read_seek(offset, length)
            raise
        got = int(done.value)
        if got < length:
            buf[got:] = b"\x00" * (length - got)
        return bytes(buf)

    def _write_seek(self, offset: int, data: bytes) -> None:
        self._seek(offset)
        done = wintypes.DWORD(0)
        buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
        kernel32.SetLastError(0)
        ok = kernel32.WriteFile(self._handle, buf, len(data), ctypes.byref(done), None)
        err = ctypes.get_last_error()
        if not ok or done.value != len(data):
            raise IoError(f"{offset}에서 쓰기 실패 (Win32 {err})", winerr=err)


    def _nt_write_at(self, absolute_offset: int, data: bytes) -> None:
        """Raw write through NtOpenFile/NtWriteFile and verify by read-back."""
        from ext4lib.debuglog import LOG

        if self._nt_handle is None:
            self._nt_handle = _nt_open_raw_handle(self.path)
            LOG.info("Native NT RAW 핸들 열기 성공 path=%s", _nt_native_path(self.path))

        iosb = _IO_STATUS_BLOCK()
        offset = ctypes.c_longlong(int(absolute_offset))
        buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
        status = ntdll.NtWriteFile(
            self._nt_handle,
            None,
            None,
            None,
            ctypes.byref(iosb),
            buf,
            len(data),
            ctypes.byref(offset),
            None,
        )
        if not _nt_success(status):
            dos = int(ntdll.RtlNtStatusToDosError(status))
            raise IoError(
                "NtWriteFile 실패 "
                f"offset={absolute_offset} len={len(data)} "
                f"NTSTATUS={_nt_status_hex(status)} (Win32 {dos})",
                winerr=dos,
            )
        if int(iosb.Information) != len(data):
            raise IoError(
                f"NtWriteFile 짧은 쓰기 offset={absolute_offset} "
                f"{int(iosb.Information)}/{len(data)}",
                winerr=23,
            )

        verify = self._read_at(absolute_offset, len(data))
        if verify != data:
            raise IoError(
                f"NtWriteFile read-back 검증 실패 offset={absolute_offset} len={len(data)}",
                winerr=23,
            )
        LOG.warning(
            "Win32 raw write 우회: NtWriteFile 성공 offset=%s len=%s",
            absolute_offset,
            len(data),
        )

    @staticmethod
    def _scsi_sense_from_error(exc: BaseException) -> tuple[int, int, int] | None:
        sense = getattr(exc, "scsi_sense", None)
        if (
            isinstance(sense, tuple)
            and len(sense) == 3
            and all(isinstance(v, int) for v in sense)
        ):
            return sense
        return None

    @staticmethod
    def _scsi_field_unsupported(exc: BaseException) -> bool:
        """Return True for ILLEGAL REQUEST / unsupported CDB field/opcode."""
        sense = WindowsPhysicalDevice._scsi_sense_from_error(exc)
        return bool(sense and sense[0] == 0x05 and sense[1] in (0x20, 0x24))

    def _scsi_sync_cache_once(
        self, direct: bool
    ) -> tuple[bool, tuple[int, int, int] | None, str]:
        """Issue one SYNCHRONIZE CACHE(10) command and return its status."""
        sense_len = 32
        returned = wintypes.DWORD(0)

        if direct:
            hdr_len = ctypes.sizeof(SCSI_PASS_THROUGH_DIRECT)
            sense_off = (hdr_len + 3) & ~3
            packet = ctypes.create_string_buffer(sense_off + sense_len)
            req = SCSI_PASS_THROUGH_DIRECT.from_buffer(packet)
            req.Length = hdr_len
            req.CdbLength = 10
            req.SenseInfoLength = sense_len
            req.DataIn = SCSI_IOCTL_DATA_UNSPECIFIED
            req.DataTransferLength = 0
            req.TimeOutValue = 60
            req.DataBuffer = None
            req.SenseInfoOffset = sense_off
            req.Cdb[0] = SCSI_SYNCHRONIZE_CACHE10
            ioctl = IOCTL_SCSI_PASS_THROUGH_DIRECT
            label = "DIRECT"
        else:
            hdr_len = ctypes.sizeof(SCSI_PASS_THROUGH)
            sense_off = (hdr_len + 3) & ~3
            packet = ctypes.create_string_buffer(sense_off + sense_len)
            req = SCSI_PASS_THROUGH.from_buffer(packet)
            req.Length = hdr_len
            req.CdbLength = 10
            req.SenseInfoLength = sense_len
            req.DataIn = SCSI_IOCTL_DATA_UNSPECIFIED
            req.DataTransferLength = 0
            req.TimeOutValue = 60
            req.DataBufferOffset = 0
            req.SenseInfoOffset = sense_off
            req.Cdb[0] = SCSI_SYNCHRONIZE_CACHE10
            ioctl = IOCTL_SCSI_PASS_THROUGH
            label = "BUFFERED"

        kernel32.SetLastError(0)
        ok = kernel32.DeviceIoControl(
            self._handle,
            ioctl,
            packet,
            len(packet),
            packet,
            len(packet),
            ctypes.byref(returned),
            None,
        )
        err = ctypes.get_last_error()
        result = (
            SCSI_PASS_THROUGH_DIRECT.from_buffer(packet)
            if direct
            else SCSI_PASS_THROUGH.from_buffer(packet)
        )
        status = int(result.ScsiStatus)
        if ok and status == SCSI_STATUS_GOOD:
            return True, None, label

        if ok:
            sense = bytes(packet.raw[sense_off : sense_off + sense_len])
            parsed = (
                sense[2] & 0x0F if len(sense) > 2 else 0,
                sense[12] if len(sense) > 12 else 0,
                sense[13] if len(sense) > 13 else 0,
            )
            detail = (
                f"{label} status=0x{status:02X} "
                f"sense=0x{parsed[0]:X}/0x{parsed[1]:02X}/0x{parsed[2]:02X}"
            )
            return False, parsed, detail

        return False, None, f"{label} Win32={err}"

    def _scsi_synchronize_cache(self) -> None:
        """Flush plain WRITE(10) cache when the bridge supports that command.

        Some SD/MMC USB readers legitimately expose WRITE(10) but not
        SYNCHRONIZE CACHE(10). That capability mismatch must not turn every file
        operation into EIO. Prefer FUA writes; if both FUA and cache-sync are not
        implemented by the bridge, use serialized command-completion mode and
        report the compatibility choice once.
        """
        from ext4lib.debuglog import LOG

        if not self._scsi_dirty:
            return
        if self._scsi_sync_cache_supported is False:
            # Capability was already learned. Plain WRITE(10) on these simple
            # removable bridges is serialized by BOT; avoid repeating a command
            # the device has explicitly rejected as unsupported.
            self._scsi_dirty = False
            return

        results = [
            self._scsi_sync_cache_once(True),
            self._scsi_sync_cache_once(False),
        ]
        for ok, _sense, label in results:
            if ok:
                self._scsi_sync_cache_supported = True
                self._scsi_dirty = False
                LOG.debug("SCSI SYNCHRONIZE CACHE(10) %s 성공", label)
                return

        unsupported = any(
            sense is not None
            and sense[0] == 0x05
            and sense[1] in (0x20, 0x24)
            for _ok, sense, _detail in results
        )
        if unsupported:
            self._scsi_sync_cache_supported = False
            self._scsi_dirty = False
            LOG.info(
                "SCSI cache-sync 명령 미지원 장치 — 반복 오류 없이 "
                "WRITE(10) 호환 모드로 계속합니다."
            )
            return

        details = " | ".join(detail for _ok, _sense, detail in results)
        raise IoError("SCSI SYNCHRONIZE CACHE(10) 실패: " + details, winerr=31)

    def _scsi_write10_direct(
        self, absolute_offset: int, data: bytes, *, fua: bool = True
    ) -> None:
        """Send SCSI WRITE(10) with IOCTL_SCSI_PASS_THROUGH_DIRECT."""
        from ext4lib.debuglog import LOG

        ss = int(self.sector_size or 512)
        if absolute_offset < 0 or absolute_offset % ss or len(data) % ss:
            raise IoError(
                f"SCSI direct 정렬 오류 offset={absolute_offset} len={len(data)} sector={ss}",
                winerr=87,
            )
        lba = absolute_offset // ss
        blocks = len(data) // ss
        if lba > 0xFFFFFFFF or blocks <= 0 or blocks > 0xFFFF:
            raise IoError(
                f"SCSI WRITE(10) 범위 초과 lba={lba} blocks={blocks}",
                winerr=87,
            )

        sense_len = 32
        hdr_len = ctypes.sizeof(SCSI_PASS_THROUGH_DIRECT)
        sense_off = (hdr_len + 3) & ~3
        packet = ctypes.create_string_buffer(sense_off + sense_len)
        payload = ctypes.create_string_buffer(data, len(data))
        sptd = SCSI_PASS_THROUGH_DIRECT.from_buffer(packet)
        sptd.Length = hdr_len
        sptd.CdbLength = 10
        sptd.SenseInfoLength = sense_len
        sptd.DataIn = SCSI_IOCTL_DATA_OUT
        sptd.DataTransferLength = len(data)
        sptd.TimeOutValue = 30
        sptd.DataBuffer = ctypes.addressof(payload)
        sptd.SenseInfoOffset = sense_off
        sptd.Cdb[0] = SCSI_WRITE10
        sptd.Cdb[1] = SCSI_WRITE_FUA if fua else 0
        sptd.Cdb[2] = (lba >> 24) & 0xFF
        sptd.Cdb[3] = (lba >> 16) & 0xFF
        sptd.Cdb[4] = (lba >> 8) & 0xFF
        sptd.Cdb[5] = lba & 0xFF
        sptd.Cdb[7] = (blocks >> 8) & 0xFF
        sptd.Cdb[8] = blocks & 0xFF

        returned = wintypes.DWORD(0)
        kernel32.SetLastError(0)
        ok = kernel32.DeviceIoControl(
            self._handle,
            IOCTL_SCSI_PASS_THROUGH_DIRECT,
            packet,
            len(packet),
            packet,
            len(packet),
            ctypes.byref(returned),
            None,
        )
        err = ctypes.get_last_error()
        if not ok:
            raise IoError(
                f"SCSI WRITE(10) DIRECT 실패 lba={lba} blocks={blocks} (Win32 {err})",
                winerr=err,
            )

        result = SCSI_PASS_THROUGH_DIRECT.from_buffer(packet)
        if int(result.ScsiStatus) != SCSI_STATUS_GOOD:
            sense = bytes(packet.raw[sense_off : sense_off + sense_len])
            parsed = (
                sense[2] & 0x0F if len(sense) > 2 else 0,
                sense[12] if len(sense) > 12 else 0,
                sense[13] if len(sense) > 13 else 0,
            )
            exc = IoError(
                "SCSI WRITE(10) DIRECT 장치 오류 "
                f"status=0x{int(result.ScsiStatus):02X} "
                f"sense=0x{parsed[0]:X}/0x{parsed[1]:02X}/0x{parsed[2]:02X}",
                winerr=5,
            )
            exc.scsi_sense = parsed
            raise exc

        verify = self._read_at(absolute_offset, len(data))
        if verify != data:
            raise IoError(
                f"SCSI WRITE(10) DIRECT 검증 실패 offset={absolute_offset} len={len(data)}",
                winerr=23,
            )
        if fua:
            self._scsi_fua_supported = True
        else:
            self._scsi_dirty = True
        LOG.debug(
            "SCSI WRITE(10) DIRECT%s 성공 offset=%s lba=%s blocks=%s",
            "+FUA" if fua else "",
            absolute_offset,
            lba,
            blocks,
        )

    def _scsi_write10_buffered(
        self, absolute_offset: int, data: bytes, *, fua: bool = True
    ) -> None:
        """Send SCSI WRITE(10) with buffered IOCTL_SCSI_PASS_THROUGH."""
        from ext4lib.debuglog import LOG

        ss = int(self.sector_size or 512)
        if absolute_offset < 0 or absolute_offset % ss or len(data) % ss:
            raise IoError(
                f"SCSI fallback 정렬 오류 offset={absolute_offset} len={len(data)} sector={ss}",
                winerr=87,
            )
        lba = absolute_offset // ss
        blocks = len(data) // ss
        if lba > 0xFFFFFFFF or blocks <= 0 or blocks > 0xFFFF:
            raise IoError(
                f"SCSI WRITE(10) 범위 초과 lba={lba} blocks={blocks}",
                winerr=87,
            )

        sense_len = 32
        hdr_len = ctypes.sizeof(SCSI_PASS_THROUGH)
        sense_off = hdr_len
        data_off = (sense_off + sense_len + 15) & ~15
        total = data_off + len(data)
        packet = ctypes.create_string_buffer(total)
        spt = SCSI_PASS_THROUGH.from_buffer(packet)
        spt.Length = hdr_len
        spt.CdbLength = 10
        spt.SenseInfoLength = sense_len
        spt.DataIn = SCSI_IOCTL_DATA_OUT
        spt.DataTransferLength = len(data)
        spt.TimeOutValue = 30
        spt.DataBufferOffset = data_off
        spt.SenseInfoOffset = sense_off
        spt.Cdb[0] = SCSI_WRITE10
        spt.Cdb[1] = SCSI_WRITE_FUA if fua else 0
        spt.Cdb[2] = (lba >> 24) & 0xFF
        spt.Cdb[3] = (lba >> 16) & 0xFF
        spt.Cdb[4] = (lba >> 8) & 0xFF
        spt.Cdb[5] = lba & 0xFF
        spt.Cdb[7] = (blocks >> 8) & 0xFF
        spt.Cdb[8] = blocks & 0xFF
        ctypes.memmove(ctypes.addressof(packet) + data_off, data, len(data))

        returned = wintypes.DWORD(0)
        kernel32.SetLastError(0)
        ok = kernel32.DeviceIoControl(
            self._handle,
            IOCTL_SCSI_PASS_THROUGH,
            packet,
            total,
            packet,
            total,
            ctypes.byref(returned),
            None,
        )
        err = ctypes.get_last_error()
        if not ok:
            raise IoError(
                f"SCSI WRITE(10) DeviceIoControl 실패 lba={lba} blocks={blocks} (Win32 {err})",
                winerr=err,
            )

        result = SCSI_PASS_THROUGH.from_buffer(packet)
        if int(result.ScsiStatus) != SCSI_STATUS_GOOD:
            sense = bytes(packet.raw[sense_off : sense_off + sense_len])
            parsed = (
                sense[2] & 0x0F if len(sense) > 2 else 0,
                sense[12] if len(sense) > 12 else 0,
                sense[13] if len(sense) > 13 else 0,
            )
            exc = IoError(
                "SCSI WRITE(10) 장치 오류 "
                f"status=0x{int(result.ScsiStatus):02X} "
                f"sense=0x{parsed[0]:X}/0x{parsed[1]:02X}/0x{parsed[2]:02X}",
                winerr=5,
            )
            exc.scsi_sense = parsed
            raise exc

        verify = self._read_at(absolute_offset, len(data))
        if verify != data:
            raise IoError(
                f"SCSI WRITE(10) 검증 실패 offset={absolute_offset} len={len(data)}",
                winerr=23,
            )
        if fua:
            self._scsi_fua_supported = True
        else:
            self._scsi_dirty = True
        LOG.debug(
            "SCSI WRITE(10)%s 성공 offset=%s lba=%s blocks=%s",
            "+FUA" if fua else "",
            absolute_offset,
            lba,
            blocks,
        )

    def _scsi_write10(self, absolute_offset: int, data: bytes) -> None:
        """Adaptive SCSI write for USB/SD bridges.

        Prefer FUA so successful command completion is itself the durability
        barrier. If the bridge rejects only the FUA field, remember that once
        and retry plain WRITE(10), using SYNCHRONIZE CACHE when available.
        """
        from ext4lib.debuglog import LOG

        use_fua = self._scsi_fua_supported is not False
        direct_error: IoError | None = None

        try:
            self._scsi_write10_direct(absolute_offset, data, fua=use_fua)
            return
        except IoError as exc:
            if use_fua and self._scsi_field_unsupported(exc):
                self._scsi_fua_supported = False
                LOG.info(
                    "이 카드리더는 WRITE(10) FUA를 지원하지 않습니다. "
                    "일반 WRITE(10) 호환 모드로 자동 전환합니다."
                )
                try:
                    self._scsi_write10_direct(absolute_offset, data, fua=False)
                    return
                except IoError as plain_exc:
                    direct_error = plain_exc
            else:
                direct_error = exc

        LOG.debug("SCSI WRITE(10) DIRECT 경로 실패: %s", direct_error)

        use_fua = self._scsi_fua_supported is not False
        try:
            self._scsi_write10_buffered(absolute_offset, data, fua=use_fua)
            return
        except IoError as exc:
            if use_fua and self._scsi_field_unsupported(exc):
                self._scsi_fua_supported = False
                LOG.info(
                    "버퍼드 SCSI에서도 FUA 미지원 확인 — 일반 WRITE(10)으로 전환합니다."
                )
                self._scsi_write10_buffered(absolute_offset, data, fua=False)
                return
            raise IoError(
                "SCSI WRITE(10) 경로 실패: "
                f"DIRECT={direct_error} | BUFFERED={exc}",
                winerr=getattr(exc, "winerr", 5) or 5,
            ) from exc

    def _write_locked_partition_device(self, offset: int, data: bytes) -> None:
        """Write via the partition device after the real matching volume is locked.

        Earlier versions tried HarddiskNPartitionM before we could positively
        lock the corresponding hidden HarddiskVolume.  On Windows these are
        different device objects.  Retry the partition PDO only after the
        matching volume lock/dismount has succeeded.
        """
        from ext4lib.debuglog import LOG

        disk_index = _physical_index(self.path)
        part = self._partition_number
        if disk_index is None or part is None:
            raise IoError("파티션 장치 경로를 계산할 수 없습니다.", winerr=87)
        if offset < 0 or (self._partition_size and offset + len(data) > self._partition_size):
            raise IoError(
                f"파티션 범위 밖 쓰기 offset={offset} len={len(data)}",
                winerr=87,
            )

        candidates = [
            rf"\\.\Harddisk{disk_index}Partition{int(part)}",
            rf"\\?\GLOBALROOT\Device\Harddisk{disk_index}\Partition{int(part)}",
        ]
        failures: list[str] = []

        for path in candidates:
            handle = kernel32.CreateFileW(
                path,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            if handle == INVALID_HANDLE_VALUE or handle is None:
                failures.append(f"{path} open Win32={ctypes.get_last_error()}")
                continue
            try:
                _allow_extended_io(handle)
                new_pos = ctypes.c_longlong(0)
                kernel32.SetLastError(0)
                if not kernel32.SetFilePointerEx(
                    handle,
                    int(offset),
                    ctypes.byref(new_pos),
                    FILE_BEGIN,
                ):
                    failures.append(f"{path} seek Win32={ctypes.get_last_error()}")
                    continue

                done = wintypes.DWORD(0)
                buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
                kernel32.SetLastError(0)
                ok = kernel32.WriteFile(handle, buf, len(data), ctypes.byref(done), None)
                err = ctypes.get_last_error()
                if ok and done.value == len(data):
                    kernel32.FlushFileBuffers(handle)
                    absolute = self._partition_offset + offset
                    if self._read_at(absolute, len(data)) != data:
                        raise IoError(
                            f"{path} 파티션 쓰기 read-back 검증 실패 offset={offset}",
                            winerr=23,
                        )
                    LOG.warning(
                        "잠금된 hidden volume 우회: 파티션 장치 WriteFile 성공 "
                        "path=%s offset=%s len=%s",
                        path,
                        offset,
                        len(data),
                    )
                    return
                failures.append(
                    f"{path} WriteFile Win32={err} {done.value}/{len(data)}"
                )
            finally:
                kernel32.CloseHandle(handle)

        # Win32 partition-device WriteFile may itself be filtered. Try the same
        # partition device through Native NT I/O before falling back to the
        # whole PhysicalDrive object.
        for path in candidates:
            nt_handle = None
            try:
                nt_handle = _nt_open_raw_handle(path)
                iosb = _IO_STATUS_BLOCK()
                nt_offset = ctypes.c_longlong(int(offset))
                buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
                status = ntdll.NtWriteFile(
                    nt_handle,
                    None,
                    None,
                    None,
                    ctypes.byref(iosb),
                    buf,
                    len(data),
                    ctypes.byref(nt_offset),
                    None,
                )
                if not _nt_success(status):
                    failures.append(
                        f"{_nt_native_path(path)} NtWriteFile "
                        f"NTSTATUS={_nt_status_hex(status)}"
                    )
                    continue
                if int(iosb.Information) != len(data):
                    failures.append(
                        f"{_nt_native_path(path)} NtWriteFile short "
                        f"{int(iosb.Information)}/{len(data)}"
                    )
                    continue

                flush_iosb = _IO_STATUS_BLOCK()
                ntdll.NtFlushBuffersFile(nt_handle, ctypes.byref(flush_iosb))
                absolute = self._partition_offset + offset
                if self._read_at(absolute, len(data)) != data:
                    raise IoError(
                        f"{path} Native NT 파티션 쓰기 read-back 검증 실패 offset={offset}",
                        winerr=23,
                    )
                LOG.warning(
                    "잠금된 hidden volume 우회: 파티션 장치 NtWriteFile 성공 "
                    "path=%s offset=%s len=%s",
                    _nt_native_path(path),
                    offset,
                    len(data),
                )
                return
            except IoError as exc:
                failures.append(str(exc))
            finally:
                if nt_handle is not None:
                    ntdll.NtClose(nt_handle)

        raise IoError(
            "잠금된 파티션 장치 쓰기 실패: " + " | ".join(failures[-6:]),
            winerr=5,
        )

    def _adopt_whole_disk_offline(self) -> None:
        """Switch the instance to PhysicalDrive-only I/O while disk is offline."""
        from ext4lib.debuglog import LOG

        self._disk_offline = True
        self._partition_volume = None
        for item in self._volume_locks:
            _close_locked_volume_without_online(item)
        self._volume_locks = []

        if self._nt_handle is not None:
            try:
                ntdll.NtClose(self._nt_handle)
            except Exception:
                pass
            self._nt_handle = None

        # Keep the current PhysicalDrive file object alive. If it is still
        # denied after the global disk state changes, the LocalSystem stage
        # below will create a genuinely fresh file object.
        self._use_overlapped = False
        LOG.warning(
            "전체 디스크 OFFLINE 모드 채택: PhysicalDrive-only I/O size=%s sector=%s",
            self._size,
            self.sector_size,
        )

    def _activate_whole_disk_offline(self) -> tuple[bool, int]:
        """Take only a removable data disk offline, non-persistently."""
        from ext4lib.debuglog import LOG

        if self._disk_offline:
            return True, 0
        if not self._removable:
            return False, 5

        ok, err = _set_disk_offline_state(self._handle, True)
        if not ok:
            LOG.warning("전체 디스크 OFFLINE 전환 실패 Win32=%s", err)
            return False, err

        LOG.warning(
            "전체 디스크 OFFLINE 전환 성공 path=%s (비영구 설정)",
            self.path,
        )
        self._adopt_whole_disk_offline()
        return True, 0

    def _restore_whole_disk_online(self) -> tuple[bool, int]:
        """Clear the temporary whole-disk OFFLINE state before closing."""
        from ext4lib.debuglog import LOG

        if not self._disk_offline:
            return True, 0

        ok, err = _set_disk_offline_state(self._handle, False)
        if not ok:
            LOG.error(
                "전체 디스크 ONLINE 복구 실패 path=%s Win32=%s. "
                "카드 재삽입 또는 재부팅 시 비영구 OFFLINE 상태가 해제됩니다.",
                self.path,
                err,
            )
            return False, err

        try:
            _ioctl(self._handle, IOCTL_DISK_UPDATE_PROPERTIES)
        except OSError as exc:
            LOG.info("디스크 속성 재검색 생략/실패: %s", exc)

        self._disk_offline = False
        LOG.info("전체 디스크 ONLINE 복구 성공 path=%s", self.path)
        return True, 0

    def _prepare_system_helper_handle(self) -> None:
        """Reopen PhysicalDrive with write sharing for a fresh SYSTEM open.

        The normal raw handle intentionally prefers FILE_SHARE_READ only. That
        prevents a second writer from opening the same PhysicalDrive, including
        a LocalSystem helper. Once every administrator write path has failed,
        keep the matching volume lock but reopen only the PhysicalDrive with
        FILE_SHARE_READ|FILE_SHARE_WRITE so SYSTEM can create a fresh file
        object under its own security context.
        """
        from ext4lib.debuglog import LOG

        old = self._handle
        old_size = int(self._size or 0)
        old_sector = int(self.sector_size or 512)

        if self._nt_handle is not None:
            try:
                ntdll.NtClose(self._nt_handle)
            except Exception:
                pass
            self._nt_handle = None

        try:
            kernel32.CloseHandle(old)
        except Exception:
            pass

        handle = kernel32.CreateFileW(
            self.path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if handle == INVALID_HANDLE_VALUE or handle is None:
            err = ctypes.get_last_error()
            self._handle = _open_handle(self.path, True)
            raise IoError(
                f"LocalSystem 준비용 PhysicalDrive 재오픈 실패 (Win32 {err})",
                winerr=err,
            )

        self._handle = handle
        _allow_extended_io(handle)
        size, sector = _query_geometry(handle)
        _vendor, _product, _bus, removable = _query_storage(handle)
        if not removable:
            kernel32.CloseHandle(handle)
            self._handle = _open_handle(self.path, True)
            raise IoError(
                "LocalSystem helper는 removable 저장장치에만 허용됩니다.",
                winerr=5,
            )
        if old_size and size and int(size) != old_size:
            kernel32.CloseHandle(handle)
            self._handle = _open_handle(self.path, True)
            raise IoError("LocalSystem 준비 중 디스크 크기가 변경되었습니다.", winerr=1167)

        self._size = int(size or old_size)
        self.sector_size = int(sector or old_sector)
        self._use_overlapped = False
        LOG.warning(
            "추가 raw handle 준비: PhysicalDrive share=READ|WRITE size=%s sector=%s",
            self._size,
            self.sector_size,
        )

    def _restore_windows_after_usbdk_failure(self) -> None:
        """Reopen the Windows storage path after a failed UsbDk redirect attempt."""
        from ext4lib.debuglog import LOG

        self._usbdk = None
        self._stop_ka = threading.Event()
        last = None
        for attempt in range(12):
            try:
                self._reopen_locked()
                last = None
                break
            except Exception as exc:
                last = exc
                # StopRedirect causes USB PnP re-enumeration; PhysicalDrive may
                # need a short moment before it exists again.
                time.sleep(0.25)
        if last is not None:
            raise IoError(
                f"UsbDk 실패 후 Windows storage 경로 복구 실패: {last}",
                winerr=getattr(last, "winerr", 1167) or 1167,
            ) from last
        if self._size:
            self._ka = threading.Thread(
                target=self._keepalive,
                daemon=True,
                name=f"disk-ka-{self.path}",
            )
            self._ka.start()
        LOG.warning("UsbDk 실패 후 Windows storage 경로 복구 완료 %s", self.path)

    def _activate_usbdk_backend(self) -> None:
        """Switch only this USB removable reader to direct UsbDk BOT I/O.

        Normal readers never enter this path. It is reached only after all
        native/admin/LocalSystem write routes have failed.
        """
        from ext4lib.debuglog import LOG
        from ext4lib.windows.usbdk_setup import UsbDkRequiredError, usbdk_ready

        if self._usbdk is not None:
            return
        if not self._writable or not self._removable or int(self._bus_type) != 7:
            raise IoError(
                "UsbDk fallback은 쓰기 가능한 USB removable 장치에만 사용합니다.",
                winerr=50,
            )
        if self._partition_size <= 0:
            raise IoError("UsbDk fallback에 유효한 파티션 범위가 없습니다.", winerr=87)
        if not usbdk_ready():
            raise UsbDkRequiredError(
                "이 USB 카드리더는 Windows raw-write를 모두 거부했습니다. "
                "선택적 UsbDk direct-USB 백엔드가 필요합니다.",
                manual_install=True,
            )

        # Identify the exact medium before PnP redirection removes PhysicalDrive.
        prefix_len = min(int(self._size or 0), max(4096, int(self.sector_size or 512)))
        if prefix_len <= 0:
            raise IoError("UsbDk 전환 전에 장치 크기를 확인할 수 없습니다.", winerr=1167)
        prefix_len = (prefix_len // int(self.sector_size or 512)) * int(self.sector_size or 512)
        expected_prefix = self._raw_read_once(0, prefix_len)

        if self._disk_offline:
            self._restore_whole_disk_online()

        # Stop the keepalive and release all Windows handles so PnP can detach
        # exactly this reader cleanly.
        self._stop_ka.set()
        if self._nt_handle is not None:
            try:
                ntdll.NtClose(self._nt_handle)
            except Exception:
                pass
            self._nt_handle = None
        for item in self._volume_locks:
            _release_locked_volume(item)
        self._volume_locks = []
        self._partition_volume = None
        old_handle = self._handle
        try:
            kernel32.CloseHandle(old_handle)
        except Exception:
            pass
        self._handle = None

        backend = None
        try:
            from ext4lib.windows.usbdk import UsbDkBotBackend

            backend = UsbDkBotBackend(
                self.path,
                expected_size=int(self._size),
                expected_sector_size=int(self.sector_size or 512),
                partition_offset=int(self._partition_offset),
                partition_size=int(self._partition_size),
                expected_prefix=expected_prefix,
            )
            self._usbdk = backend
            self.sector_size = int(backend.sector_size)
            LOG.warning(
                "Windows storage stack 우회: UsbDk direct-USB BOT 백엔드로 전환 %s",
                self.path,
            )
        except Exception as usb_exc:
            if backend is not None:
                try:
                    backend.close()
                except Exception:
                    pass
            LOG.warning("UsbDk direct-USB backend 활성화 실패: %s", usb_exc)
            try:
                self._restore_windows_after_usbdk_failure()
            except Exception as restore_exc:
                raise IoError(
                    "UsbDk direct-USB 활성화 실패: "
                    + str(usb_exc)
                    + " | Windows storage 복구 실패: "
                    + str(restore_exc),
                    winerr=getattr(usb_exc, "winerr", 5) or 5,
                ) from usb_exc
            raise

    def _write_unbuffered_physical(self, offset: int, data: bytes) -> None:
        from ext4lib.debuglog import LOG

        logical, physical = _write_unbuffered_raw_path(
            self.path,
            int(offset),
            bytes(data),
            int(self.sector_size or 512),
        )
        LOG.warning(
            "NO_BUFFERING PhysicalDrive 쓰기 성공 absolute=%s len=%s logical=%s physical=%s",
            offset,
            len(data),
            logical,
            physical,
        )

    def _fallback_after_volume_access_denied(self, offset: int, data: bytes) -> None:
        """Retry through PhysicalDrive after the matching volume is locked.

        SCSI passthrough is used only if the PhysicalDrive write is still denied.
        Kept separate so the routing can be unit-tested without real hardware.
        """
        from ext4lib.debuglog import LOG

        absolute = self._partition_offset + offset

        # Do not rediscover the same failing Windows routes on every 512-byte
        # metadata write. Once this bridge has proven that SCSI passthrough is
        # the working route, keep using it for the lifetime of this device.
        if self._fallback_write_route == "scsi":
            self._scsi_write10(absolute, data)
            return

        try:
            self._write_locked_partition_device(offset, data)
            return
        except IoError as part_exc:
            LOG.info(
                "잠금된 파티션 장치 쓰기도 실패: %s; PhysicalDrive write 시도",
                part_exc,
            )

        try:
            self._write_at(absolute, data)
            LOG.warning(
                "볼륨 WriteFile Win32 5 우회: 잠금된 볼륨 상태에서 PhysicalDrive 쓰기 성공 "
                "absolute=%s len=%s",
                absolute,
                len(data),
            )
            return
        except IoError as phys_exc:
            LOG.info(
                "잠금 후 PhysicalDrive Win32 쓰기 실패: %s; Native NT write 시도",
                phys_exc,
            )

        try:
            self._nt_write_at(absolute, data)
            return
        except IoError as nt_exc:
            LOG.info(
                "Native NT write도 실패: %s; NO_BUFFERING raw write 시도",
                nt_exc,
            )

        try:
            # The fresh unbuffered handle needs existing PhysicalDrive handles
            # to share write access.
            self._prepare_system_helper_handle()
            self._write_unbuffered_physical(absolute, data)
            return
        except IoError as direct_exc:
            LOG.info(
                "NO_BUFFERING raw write도 실패: %s; SCSI fallback 시도",
                direct_exc,
            )

        try:
            self._scsi_write10(absolute, data)
            self._fallback_write_route = "scsi"
            LOG.info(
                "USB/SD 쓰기 경로 고정: SCSI WRITE(10)%s",
                "+FUA" if self._scsi_fua_supported else " compatibility",
            )
            return
        except IoError as scsi_exc:
            blockers = list(self._write_blockers)
            if blockers:
                detail = " / ".join(blockers)
                raise IoError(
                    "Windows가 저장장치 쓰기를 정책/속성으로 차단하고 있습니다: "
                    f"{detail}",
                    winerr=5,
                ) from scsi_exc

            LOG.warning(
                "관리자 raw-write 경로가 모두 거부됨: %s; 전체 디스크 OFFLINE 모드 시도",
                scsi_exc,
            )

            offline_ok, offline_err = self._activate_whole_disk_offline()
            if offline_ok:
                for label, writer in (
                    ("OFFLINE PhysicalDrive WriteFile", self._write_at),
                    ("OFFLINE PhysicalDrive NtWriteFile", self._nt_write_at),
                    ("OFFLINE SCSI WRITE(10)", self._scsi_write10),
                ):
                    try:
                        writer(absolute, data)
                        LOG.warning(
                            "%s 성공 absolute=%s len=%s",
                            label,
                            absolute,
                            len(data),
                        )
                        return
                    except IoError as offline_exc:
                        LOG.warning("%s 실패: %s", label, offline_exc)
            else:
                LOG.warning(
                    "전체 디스크 OFFLINE 모드를 사용할 수 없음 Win32=%s",
                    offline_err,
                )

            LOG.warning("LocalSystem helper 시도")
            from ext4lib.windows.system_raw import run_system_raw_write

            self._prepare_system_helper_handle()
            item = self._partition_volume
            result = run_system_raw_write(
                physical_path=self.path,
                parent_pid=os.getpid(),
                physical_handle=int(self._handle),
                volume_handle=int(item.handle) if item is not None else None,
                relative_offset=int(offset),
                absolute_offset=int(absolute),
                partition_offset=int(self._partition_offset),
                partition_size=int(self._partition_size),
                data=bytes(data),
                sector_size=int(self.sector_size or 512),
                try_disk_offline=not self._disk_offline,
            )
            if not result.get("ok"):
                system_detail = str(result.get("error") or result)
                if self._removable and int(self._bus_type) == 7:
                    LOG.warning(
                        "LocalSystem도 raw-write 거부: %s; UsbDk direct-USB BOT fallback 시도",
                        system_detail,
                    )
                    try:
                        self._activate_usbdk_backend()
                        self._usbdk.write(absolute, bytes(data))
                        LOG.warning(
                            "UsbDk direct-USB BOT write 성공 absolute=%s len=%s",
                            absolute,
                            len(data),
                        )
                        return
                    except Exception as usb_exc:
                        from ext4lib.windows.usbdk_setup import UsbDkRequiredError

                        if isinstance(usb_exc, UsbDkRequiredError):
                            raise
                        raise IoError(
                            "LocalSystem raw helper 실패: "
                            + system_detail
                            + " | UsbDk direct-USB 실패: "
                            + str(usb_exc),
                            winerr=getattr(usb_exc, "winerr", 5) or 5,
                        ) from scsi_exc
                raise IoError(
                    "LocalSystem raw helper 실패: " + system_detail,
                    winerr=5,
                ) from scsi_exc

            if result.get("disk_offline") and not self._disk_offline:
                self._adopt_whole_disk_offline()

            LOG.warning(
                "LocalSystem raw helper 성공 method=%s absolute=%s len=%s disk_offline=%s",
                result.get("method"),
                absolute,
                len(data),
                bool(result.get("disk_offline")),
            )
            verify = self._read_at(absolute, len(data))
            if verify != data:
                raise IoError(
                    f"LocalSystem raw helper read-back 불일치 offset={absolute}",
                    winerr=23,
                )
            return

    def _nt_write_volume_handle(
        self,
        item: _LockedVolume,
        offset: int,
        data: bytes,
    ) -> None:
        """Issue NtWriteFile on the already locked hidden-volume handle.

        This preserves the exact volume object that Windows allowed us to open
        and lock.  It is useful on card-reader stacks where the partition PDO
        cannot be opened directly even though HarddiskVolumeN is writable.
        """
        from ext4lib.debuglog import LOG

        iosb = _IO_STATUS_BLOCK()
        nt_offset = ctypes.c_longlong(int(offset))
        buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
        status = ntdll.NtWriteFile(
            wintypes.HANDLE(item.handle),
            None,
            None,
            None,
            ctypes.byref(iosb),
            buf,
            len(data),
            ctypes.byref(nt_offset),
            None,
        )
        if not _nt_success(status):
            dos = int(ntdll.RtlNtStatusToDosError(status))
            raise IoError(
                f"{item.name} NtWriteFile 실패 offset={offset} len={len(data)} "
                f"NTSTATUS={_nt_status_hex(status)} (Win32 {dos})",
                winerr=dos,
            )
        if int(iosb.Information) != len(data):
            raise IoError(
                f"{item.name} NtWriteFile 짧은 쓰기 offset={offset} "
                f"{int(iosb.Information)}/{len(data)}",
                winerr=23,
            )

        flush_iosb = _IO_STATUS_BLOCK()
        ntdll.NtFlushBuffersFile(
            wintypes.HANDLE(item.handle),
            ctypes.byref(flush_iosb),
        )

        absolute = self._partition_offset + int(offset)
        verify = self._read_at(absolute, len(data))
        if verify != data:
            raise IoError(
                f"{item.name} NtWriteFile read-back 검증 실패 offset={offset} len={len(data)}",
                winerr=23,
            )
        LOG.warning(
            "숨은 볼륨 Native NT write 성공 path=%s offset=%s len=%s",
            item.name,
            offset,
            len(data),
        )

    def _write_volume_seek(self, item: _LockedVolume, offset: int, data: bytes) -> None:
        """Write relative to a locked/dismounted volume handle."""
        if item.offline:
            from ext4lib.debuglog import LOG
            LOG.info(
                "오프라인 볼륨은 직접 쓰지 않고 PhysicalDrive 경로 사용 %s offset=%s",
                item.name,
                offset,
            )
            self._fallback_after_volume_access_denied(offset, data)
            return
        kernel32.SetLastError(0)
        new_pos = ctypes.c_longlong(0)
        ok = kernel32.SetFilePointerEx(
            item.handle,
            offset,
            ctypes.byref(new_pos),
            FILE_BEGIN,
        )
        if not ok:
            err = ctypes.get_last_error()
            raise IoError(
                f"{item.name} 볼륨 오프셋 {offset} 이동 실패 (Win32 {err})",
                winerr=err,
            )
        done = wintypes.DWORD(0)
        buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
        kernel32.SetLastError(0)
        ok = kernel32.WriteFile(item.handle, buf, len(data), ctypes.byref(done), None)
        err = ctypes.get_last_error()
        if not ok or done.value != len(data):
            if err == 5:
                from ext4lib.debuglog import LOG
                try:
                    self._nt_write_volume_handle(item, offset, data)
                    return
                except IoError as nt_exc:
                    LOG.warning(
                        "숨은 볼륨 Native NT write도 실패: %s; 다른 raw 경로 시도",
                        nt_exc,
                    )
                self._fallback_after_volume_access_denied(offset, data)
                return
            raise IoError(
                f"{item.name} 볼륨 오프셋 {offset} 쓰기 실패 (Win32 {err})",
                winerr=err,
            )

    def _partition_write_target(self, offset: int, length: int) -> tuple[_LockedVolume, int] | None:
        item = self._partition_volume
        if item is None or length <= 0:
            return None
        start = self._partition_offset
        end = start + self._partition_size if self._partition_size else self._size
        if offset < start or offset + length > end:
            return None
        return item, offset - start

    def _write_at(self, offset: int, data: bytes) -> None:
        if not data:
            return
        if not self._use_overlapped:
            self._write_seek(offset, data)
            return
        ov = self._overlapped(offset)
        done = wintypes.DWORD(0)
        buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
        kernel32.SetLastError(0)
        ok = kernel32.WriteFile(self._handle, buf, len(data), ctypes.byref(done), ctypes.byref(ov))
        try:
            self._finish_overlapped(bool(ok), ov, done, f"오프셋 {offset} 쓰기")
        except IoError:
            if not self._use_overlapped:
                self._write_seek(offset, data)
                return
            raise
        if done.value != len(data):
            err = ctypes.get_last_error()
            raise IoError(f"{offset}에서 쓰기 실패 (Win32 {err}, {done.value}/{len(data)})", winerr=err)

    def _raw_read_once(self, offset: int, length: int) -> bytes:
        if length <= IO_CHUNK:
            return self._read_at(offset, length)
        parts: list[bytes] = []
        pos = 0
        while pos < length:
            n = min(IO_CHUNK, length - pos)
            parts.append(self._read_at(offset + pos, n))
            pos += n
        return b"".join(parts)

    def _raw_write_once(self, offset: int, data: bytes) -> None:
        # When this device was opened for one selected partition, no write is
        # allowed to escape that partition. Falling back to whole-PhysicalDrive
        # I/O outside the selected range could corrupt another partition.
        if self._partition_size > 0:
            start = self._partition_offset
            end = start + self._partition_size
            if offset < start or offset + len(data) > end:
                raise IoError(
                    "선택한 EXT4 파티션 범위를 벗어난 raw write를 차단했습니다. "
                    f"offset={offset} len={len(data)} allowed=[{start},{end})",
                    winerr=87,
                )
        pos = 0
        while pos < len(data):
            n = min(IO_CHUNK, len(data) - pos)
            absolute = offset + pos
            chunk = data[pos : pos + n]
            target = self._partition_write_target(absolute, len(chunk))
            if target is not None:
                item, relative = target
                self._write_volume_seek(item, relative, chunk)
            else:
                self._write_at(absolute, chunk)
            pos += n

    def _raw_read(self, offset: int, length: int) -> bytes:
        with self._io_lock:
            if self._usbdk is not None:
                return self._usbdk.read(offset, length)
        return self._retry(lambda: self._raw_read_once(offset, length))

    def _raw_write(self, offset: int, data: bytes) -> None:
        with self._io_lock:
            if self._usbdk is not None:
                self._usbdk.write(offset, bytes(data))
                return
        self._retry(lambda: self._raw_write_once(offset, data))

    def flush(self) -> None:
        with self._io_lock:
            if self._closed:
                return
            if self._usbdk is not None:
                self._usbdk.flush()
                return

            # First drain normal Windows/native file-object buffers.
            kernel32.FlushFileBuffers(self._handle)
            if self._partition_volume is not None:
                kernel32.FlushFileBuffers(self._partition_volume.handle)
            if self._nt_handle is not None:
                iosb = _IO_STATUS_BLOCK()
                status = ntdll.NtFlushBuffersFile(self._nt_handle, ctypes.byref(iosb))
                if not _nt_success(status):
                    from ext4lib.debuglog import LOG
                    LOG.warning(
                        "Native NT flush 실패 NTSTATUS=%s",
                        _nt_status_hex(status),
                    )

            # WRITE(10) bypasses those file-object caches. Do not claim an
            # EXT4/JBD2 commit is durable until the bridge confirms its own
            # volatile write cache has been synchronized to the card.
            self._scsi_synchronize_cache()

    def close(self) -> None:
        self._stop_ka.set()
        with self._io_lock:
            if self._closed:
                return
            self._closed = True
            if self._usbdk is not None:
                backend = self._usbdk
                self._usbdk = None
                try:
                    backend.close()
                finally:
                    self._volume_locks = []
                    self._partition_volume = None
                    self._nt_handle = None
                    self._handle = None
                return
            if self._disk_offline:
                self._restore_whole_disk_online()
            try:
                kernel32.CloseHandle(self._handle)
            except Exception:
                pass
            if self._nt_handle is not None:
                try:
                    ntdll.NtClose(self._nt_handle)
                except Exception:
                    pass
                self._nt_handle = None
            for item in self._volume_locks:
                _release_locked_volume(item)
            self._volume_locks = []

    def __enter__(self) -> "WindowsPhysicalDevice":
        return self

    def __exit__(self, *args) -> None:
        self.close()
