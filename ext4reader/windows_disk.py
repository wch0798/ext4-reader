"""Enumerate and open Windows physical disks (HDD, SSD, USB, SD/MMC)."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import threading
from ctypes import wintypes

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows import safety
    winreg = None
from dataclasses import dataclass

from ext4reader.io_backend import IO_CHUNK, BlockDevice, IoError

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
IOCTL_DISK_IS_WRITABLE = 0x00070024
IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
IOCTL_SCSI_PASS_THROUGH = 0x0004D004
IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x0004D014

SCSI_IOCTL_DATA_OUT = 0
SCSI_STATUS_GOOD = 0x00
SCSI_WRITE10 = 0x2A

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
    from ext4reader.host import app_exe, is_frozen, project_root

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
        "runpy.run_module('ext4reader', run_name='__main__')"
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
    offline: bool = False
    volume_guid: str | None = None
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
    from ext4reader.debuglog import LOG

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


def _log_write_environment(disk_handle=None, partition_handle=None) -> list[str]:
    from ext4reader.debuglog import LOG

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


def _fve_raw_access(volume_guid: str | None, enabled: bool) -> tuple[bool, int]:
    """Ask Windows' FVE layer to permit raw sector access for a volume."""
    if not volume_guid or _FveEnableRawAccessW is None:
        return False, -1
    hr = int(_FveEnableRawAccessW(volume_guid, bool(enabled)))
    ok = hr >= 0
    return ok, hr & 0xFFFFFFFF


def _release_locked_volume(item: _LockedVolume) -> None:
    try:
        _bring_volume_online(item)
    except Exception:
        pass
    try:
        kernel32.CloseHandle(item.handle)
    except Exception:
        pass
    if item.fve_raw and item.volume_guid:
        from ext4reader.debuglog import LOG
        ok, hr = _fve_raw_access(item.volume_guid, False)
        if ok:
            LOG.info("FVE raw-access 해제 성공 %s", item.volume_guid)
            item.fve_raw = False
        else:
            LOG.warning("FVE raw-access 해제 실패 %s HRESULT=0x%08X", item.volume_guid, hr)


def _take_volume_offline(handle, name: str) -> bool:
    """Keep a dismounted volume from being automatically remounted.

    Microsoft documents that IOCTL_VOLUME_OFFLINE must follow a successful
    dismount and that taking a volume offline does not block I/O sent to the
    underlying physical disk.
    """
    from ext4reader.debuglog import LOG

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
    from ext4reader.debuglog import LOG

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
    from ext4reader.debuglog import LOG

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
                        locked.append(
                            _LockedVolume(
                                handle=int(handle),
                                name=vol,
                                partition_number=int(num.PartitionNumber),
                                locked=lock_ok,
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
    from ext4reader.debuglog import LOG

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


def _open_hidden_volume_alias(disk_index: int, partition_number: int) -> _LockedVolume | None:
    """Find a matching volume through every DOS alias exposed by Windows.

    Some built-in SD/MMC readers expose an EXT4 partition only as
    HarddiskVolumeN, while others also expose a Volume{GUID} alias.  We try
    both and enable Windows FVE raw-access mode when a GUID is available.
    """
    from ext4reader.debuglog import LOG

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
            matched = (
                int(num.DeviceNumber) == int(disk_index)
                and int(num.PartitionNumber) == int(partition_number)
            )
        except OSError:
            matched = False

        if not matched:
            kernel32.CloseHandle(handle)
            continue

        # FveEnableRawAccessW may need to acquire its own volume lock. Close our
        # discovery handle first, request raw access, then reopen the volume.
        kernel32.CloseHandle(handle)
        fve_ok = False
        if volume_guid:
            fve_ok, hr = _fve_raw_access(volume_guid, True)
            if fve_ok:
                LOG.info("FVE raw-access 활성화 성공 %s", volume_guid)
            else:
                LOG.info(
                    "FVE raw-access 활성화 생략/실패 %s HRESULT=0x%08X",
                    volume_guid,
                    hr,
                )

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
                _fve_raw_access(volume_guid, False)
            continue

        keep = False
        try:
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
            return _LockedVolume(
                handle=int(handle),
                name=path,
                partition_number=int(partition_number),
                locked=lock_ok,
                offline=offline_ok,
                volume_guid=volume_guid,
                fve_raw=fve_ok,
            )
        except OSError:
            pass
        finally:
            if not keep:
                kernel32.CloseHandle(handle)
                if fve_ok:
                    _fve_raw_access(volume_guid, False)
    return None

def _open_partition_device(disk_index: int, partition_number: int) -> _LockedVolume | None:
    """Open a partition DASD handle when Mount Manager exposes no Volume GUID."""
    from ext4reader.debuglog import LOG

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
    ):
        from ext4reader.debuglog import LOG

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
        LOG.info(
            "디스크 열기 %s writable=%s sector=%s part=%s part_offset=%s part_size=%s",
            path,
            writable,
            self.sector_size,
            partition_number,
            self._partition_offset,
            self._partition_size,
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
                            if item.partition_number == int(partition_number)
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
                        hidden = _open_hidden_volume_alias(idx, int(partition_number))
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
                            direct = _open_partition_device(idx, int(partition_number))
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
        except Exception:
            _vendor, _product, self._bus_type, self._removable = "", "", 0, False
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

    def size(self) -> int:
        return self._size

    def _keepalive(self) -> None:
        from ext4reader.debuglog import LOG

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
        from ext4reader.debuglog import LOG

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
            if idx is not None:
                for item in self._volume_locks:
                    _release_locked_volume(item)
                self._volume_locks = _lock_volumes_for_disk(idx)
                self._partition_volume = None
                if self._partition_number is not None:
                    self._partition_volume = next(
                        (
                            item
                            for item in self._volume_locks
                            if item.partition_number == int(self._partition_number)
                        ),
                        None,
                    )
                    if self._partition_volume is None:
                        hidden = _open_hidden_volume_alias(idx, int(self._partition_number))
                        if hidden is not None:
                            self._volume_locks.append(hidden)
                            self._partition_volume = hidden
                    if self._partition_volume is None:
                        direct = _open_partition_device(idx, int(self._partition_number))
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
                    from ext4reader.debuglog import LOG

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
        from ext4reader.debuglog import LOG

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

    def _scsi_write10_direct(self, absolute_offset: int, data: bytes) -> None:
        """Send SCSI WRITE(10) with IOCTL_SCSI_PASS_THROUGH_DIRECT."""
        from ext4reader.debuglog import LOG

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
        # Keep request+sense in one stable buffer and payload in a separate
        # aligned Python-owned buffer, as required by *_DIRECT.
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

        sptd2 = SCSI_PASS_THROUGH_DIRECT.from_buffer(packet)
        if int(sptd2.ScsiStatus) != SCSI_STATUS_GOOD:
            sense = bytes(packet.raw[sense_off : sense_off + sense_len])
            sense_key = sense[2] & 0x0F if len(sense) > 2 else 0
            asc = sense[12] if len(sense) > 12 else 0
            ascq = sense[13] if len(sense) > 13 else 0
            raise IoError(
                "SCSI WRITE(10) DIRECT 장치 오류 "
                f"status=0x{int(sptd2.ScsiStatus):02X} sense=0x{sense_key:X}/0x{asc:02X}/0x{ascq:02X}",
                winerr=5,
            )

        verify = self._read_at(absolute_offset, len(data))
        if verify != data:
            raise IoError(
                f"SCSI WRITE(10) DIRECT 검증 실패 offset={absolute_offset} len={len(data)}",
                winerr=23,
            )
        LOG.warning(
            "WriteFile Win32 5 우회: SCSI WRITE(10) DIRECT 성공 offset=%s lba=%s blocks=%s",
            absolute_offset,
            lba,
            blocks,
        )

    def _scsi_write10(self, absolute_offset: int, data: bytes) -> None:
        """Fallback raw write through the disk class driver.

        Try DIRECT first because USB/card-reader class drivers commonly reject
        buffered pass-through data-out while accepting the direct form.
        """
        from ext4reader.debuglog import LOG

        try:
            self._scsi_write10_direct(absolute_offset, data)
            return
        except IoError as direct_exc:
            LOG.warning("SCSI WRITE(10) DIRECT 경로 실패: %s", direct_exc)

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

        spt2 = SCSI_PASS_THROUGH.from_buffer(packet)
        if int(spt2.ScsiStatus) != SCSI_STATUS_GOOD:
            sense = bytes(packet.raw[sense_off : sense_off + sense_len])
            sense_key = sense[2] & 0x0F if len(sense) > 2 else 0
            asc = sense[12] if len(sense) > 12 else 0
            ascq = sense[13] if len(sense) > 13 else 0
            raise IoError(
                "SCSI WRITE(10) 장치 오류 "
                f"status=0x{int(spt2.ScsiStatus):02X} sense=0x{sense_key:X}/0x{asc:02X}/0x{ascq:02X}",
                winerr=5,
            )

        verify = self._read_at(absolute_offset, len(data))
        if verify != data:
            raise IoError(
                f"SCSI WRITE(10) 검증 실패 offset={absolute_offset} len={len(data)}",
                winerr=23,
            )
        LOG.warning(
            "WriteFile Win32 5 우회: SCSI WRITE(10) 성공 offset=%s lba=%s blocks=%s",
            absolute_offset,
            lba,
            blocks,
        )

    def _write_locked_partition_device(self, offset: int, data: bytes) -> None:
        """Write via the partition device after the real matching volume is locked.

        Earlier versions tried HarddiskNPartitionM before we could positively
        lock the corresponding hidden HarddiskVolume.  On Windows these are
        different device objects.  Retry the partition PDO only after the
        matching volume lock/dismount has succeeded.
        """
        from ext4reader.debuglog import LOG

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

    def _fallback_after_volume_access_denied(self, offset: int, data: bytes) -> None:
        """Retry through PhysicalDrive after the matching volume is locked.

        SCSI passthrough is used only if the PhysicalDrive write is still denied.
        Kept separate so the routing can be unit-tested without real hardware.
        """
        from ext4reader.debuglog import LOG

        absolute = self._partition_offset + offset

        try:
            self._write_locked_partition_device(offset, data)
            return
        except IoError as part_exc:
            LOG.warning(
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
            LOG.warning(
                "잠금 후 PhysicalDrive Win32 쓰기 실패: %s; Native NT write 시도",
                phys_exc,
            )

        try:
            self._nt_write_at(absolute, data)
            return
        except IoError as nt_exc:
            LOG.warning(
                "Native NT write도 실패: %s; SCSI fallback 시도",
                nt_exc,
            )

        try:
            self._scsi_write10(absolute, data)
        except IoError as scsi_exc:
            blockers = list(self._write_blockers)
            if blockers:
                detail = " / ".join(blockers)
                raise IoError(
                    "Windows가 저장장치 쓰기를 정책/속성으로 차단하고 있습니다: "
                    f"{detail}",
                    winerr=5,
                ) from scsi_exc
            raise

    def _write_volume_seek(self, item: _LockedVolume, offset: int, data: bytes) -> None:
        """Write relative to a locked/dismounted volume handle."""
        if item.offline:
            from ext4reader.debuglog import LOG
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
        return self._retry(lambda: self._raw_read_once(offset, length))

    def _raw_write(self, offset: int, data: bytes) -> None:
        self._retry(lambda: self._raw_write_once(offset, data))

    def flush(self) -> None:
        with self._io_lock:
            if self._closed:
                return
            kernel32.FlushFileBuffers(self._handle)
            if self._partition_volume is not None:
                kernel32.FlushFileBuffers(self._partition_volume.handle)
            if self._nt_handle is not None:
                iosb = _IO_STATUS_BLOCK()
                status = ntdll.NtFlushBuffersFile(self._nt_handle, ctypes.byref(iosb))
                if not _nt_success(status):
                    from ext4reader.debuglog import LOG
                    LOG.warning(
                        "Native NT flush 실패 NTSTATUS=%s",
                        _nt_status_hex(status),
                    )

    def close(self) -> None:
        self._stop_ka.set()
        with self._io_lock:
            if self._closed:
                return
            self._closed = True
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
