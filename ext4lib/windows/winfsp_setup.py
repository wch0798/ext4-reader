"""Download and silently install WinFsp when it is missing."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from ctypes import wintypes
from glob import glob
from typing import Callable

GITHUB_API = "https://api.github.com/repos/winfsp/winfsp/releases/latest"
FALLBACK_MSI_URL = "https://github.com/winfsp/winfsp/releases/download/v2.1/winfsp-2.1.25156.msi"
FALLBACK_SHA256 = "073a70e00f77423e34bed98b86e600def93393ba5822204fac57a29324db9f7a"
USER_AGENT = "Ext4Reader-WinFspSetup"
Progress = Callable[[str], None]

SEE_MASK_NOCLOSEPROCESS = 0x00000040
SW_HIDE = 0
INFINITE = 0xFFFFFFFF
ERROR_CANCELLED = 1223
WAIT_OBJECT_0 = 0
REBOOT_EXIT_CODES = {3010, 1641}


class SHELLEXECUTEINFOW(ctypes.Structure):
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


class WinFspSetupError(RuntimeError):
    def __init__(self, message: str, reboot_required: bool = False):
        super().__init__(message)
        self.reboot_required = reboot_required


def find_winfsp_dll() -> str | None:
    env = os.environ.get("FUSE_LIBRARY_PATH")
    if env and os.path.isfile(env):
        return env
    arch = "x64"
    pa = os.environ.get("PROCESSOR_ARCHITECTURE", "")
    if pa.lower() in ("x86", "wow64"):
        arch = "x86"
    if os.environ.get("PROCESSOR_ARCHITEW6432") or pa.lower() in ("amd64", "x64"):
        arch = "x64"
    names = [f"winfsp-{arch}.dll", "winfsp-x64.dll", "winfsp-x86.dll"]
    roots = [
        r"C:\Program Files (x86)\WinFsp",
        r"C:\Program Files\WinFsp",
    ]
    try:
        import winreg

        for hive, flag in (
            (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_READ | winreg.KEY_WOW64_32KEY),
            (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_READ),
        ):
            try:
                key = winreg.OpenKey(hive, r"SOFTWARE\WinFsp", 0, flag)
                try:
                    install, _ = winreg.QueryValueEx(key, "InstallDir")
                finally:
                    winreg.CloseKey(key)
                if install:
                    roots.insert(0, install)
            except OSError:
                continue
    except Exception:
        pass
    seen: set[str] = set()
    for root in roots:
        norm = os.path.normcase(os.path.abspath(root))
        if norm in seen:
            continue
        seen.add(norm)
        for name in names:
            p = os.path.join(root, "bin", name)
            if os.path.isfile(p):
                return p
        matches = []
        for name in names:
            matches.extend(glob(os.path.join(root, "SxS", "*", "bin", name)))
        if matches:
            matches.sort(key=os.path.getmtime, reverse=True)
            return matches[0]
    return None


def winfsp_ready() -> bool:
    return find_winfsp_dll() is not None


def _progress(cb: Progress | None, text: str) -> None:
    if cb:
        cb(text)


def _http_open(url: str, timeout: int = 60):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    return urllib.request.urlopen(req, timeout=timeout)


def resolve_msi_url() -> tuple[str, str | None]:
    try:
        with _http_open(GITHUB_API, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        for asset in data.get("assets") or []:
            name = str(asset.get("name") or "")
            url = asset.get("browser_download_url")
            if name.lower().endswith(".msi") and "test" not in name.lower() and url:
                digest = str(asset.get("digest") or "")
                sha = digest.split(":", 1)[1].lower() if digest.startswith("sha256:") else None
                return str(url), sha
    except Exception:
        pass
    return FALLBACK_MSI_URL, FALLBACK_SHA256


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download_winfsp_msi(dest: str, progress: Progress | None = None) -> str:
    url, expect_sha = resolve_msi_url()
    _progress(progress, "WinFsp 설치 파일을 받는 중…")
    try:
        with _http_open(url, timeout=60) as resp, open(dest, "wb") as fp:
            total = int(resp.headers.get("Content-Length") or 0)
            got = 0
            while True:
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                fp.write(chunk)
                got += len(chunk)
                if total:
                    _progress(progress, f"WinFsp 다운로드 중… {got * 100 // total}%")
    except urllib.error.URLError as exc:
        raise WinFspSetupError(
            "WinFsp 설치 파일을 받지 못했습니다.\n"
            "인터넷 연결을 확인한 뒤 다시 시도하세요.\n"
            f"주소: {url}\n({exc})"
        ) from exc
    if os.path.getsize(dest) < 200_000:
        raise WinFspSetupError("받은 WinFsp 설치 파일이 손상되었습니다. 다시 시도하세요.")
    with open(dest, "rb") as fp:
        magic = fp.read(8)
    if magic[:2] != b"MZ" and magic != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        raise WinFspSetupError("받은 파일이 WinFsp 설치 프로그램이 아닙니다.")
    if expect_sha:
        actual = _sha256_file(dest)
        if actual != expect_sha.lower():
            raise WinFspSetupError("WinFsp 설치 파일 무결성 검사가 실패했습니다. 다시 시도하세요.")
    return dest


def _msiexec_path() -> str:
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    return os.path.join(root, "System32", "msiexec.exe")


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


_shell32 = ctypes.WinDLL("shell32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
_shell32.ShellExecuteExW.restype = wintypes.BOOL
_kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
_kernel32.WaitForSingleObject.restype = wintypes.DWORD
_kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
_kernel32.GetExitCodeProcess.restype = wintypes.BOOL
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32.CloseHandle.restype = wintypes.BOOL


def _run_process(exe: str, args: list[str], progress: Progress | None = None) -> int:
    if _is_admin():
        completed = subprocess.run(
            [exe, *args],
            capture_output=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return int(completed.returncode)

    _progress(progress, "관리자 권한으로 WinFsp를 설치합니다. 확인 창이 뜨면 허용하세요.")
    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
    info.fMask = SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = exe
    info.lpParameters = subprocess.list2cmdline(args)
    info.nShow = SW_HIDE
    if not _shell32.ShellExecuteExW(ctypes.byref(info)):
        err = ctypes.get_last_error()
        if err == ERROR_CANCELLED:
            raise WinFspSetupError("WinFsp 설치가 취소되었습니다. 관리자 권한을 허용해야 합니다.")
        raise WinFspSetupError(f"WinFsp 설치를 시작하지 못했습니다. (Win32 {err})")
    handle = info.hProcess
    try:
        waited = _kernel32.WaitForSingleObject(handle, INFINITE)
        if waited != WAIT_OBJECT_0:
            raise WinFspSetupError("WinFsp 설치 프로세스를 기다리지 못했습니다.")
        code = wintypes.DWORD(0)
        if not _kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            raise WinFspSetupError("WinFsp 설치 결과를 확인하지 못했습니다.")
        return int(code.value)
    finally:
        _kernel32.CloseHandle(handle)


def _install_msi(msi_path: str, progress: Progress | None = None) -> int:
    _progress(progress, "WinFsp를 설치하는 중…")
    return _run_process(
        _msiexec_path(),
        ["/i", msi_path, "/qn", "/norestart", "INSTALLLEVEL=1000"],
        progress,
    )


def _install_with_winget(progress: Progress | None = None) -> bool:
    winget = shutil.which("winget")
    if not winget:
        candidate = os.path.expandvars(r"%LocalAppData%\Microsoft\WindowsApps\winget.exe")
        if os.path.isfile(candidate):
            winget = candidate
    if not winget:
        return False
    _progress(progress, "winget으로 WinFsp를 설치하는 중…")
    args = [
        "install",
        "--id",
        "WinFsp.WinFsp",
        "-e",
        "--accept-package-agreements",
        "--accept-source-agreements",
        "--disable-interactivity",
    ]
    code = _run_process(winget, args, progress)
    return code in (0, 3010, -1978335189)


def start_winfsp_services() -> None:
    creation = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    for name in ("WinFsp", "WinFsp.Launcher"):
        subprocess.run(["sc", "start", name], capture_output=True, creationflags=creation)


def ensure_winfsp_installed(progress: Progress | None = None, force: bool = False) -> str:
    """Return the WinFsp DLL path, installing if needed."""
    if not force:
        dll = find_winfsp_dll()
        if dll:
            start_winfsp_services()
            return dll

    if sys.platform != "win32":
        raise WinFspSetupError("WinFsp는 Windows에서만 설치됩니다.")

    cache_dir = os.path.join(tempfile.gettempdir(), "Ext4Reader")
    os.makedirs(cache_dir, exist_ok=True)
    msi_path = os.path.join(cache_dir, "winfsp-setup.msi")
    download_error: Exception | None = None
    try:
        download_winfsp_msi(msi_path, progress)
        code = _install_msi(msi_path, progress)
        if code not in (0, *REBOOT_EXIT_CODES):
            download_error = WinFspSetupError(f"WinFsp MSI 설치가 실패했습니다. (코드 {code})")
        else:
            download_error = None
            if code in REBOOT_EXIT_CODES:
                start_winfsp_services()
                dll = find_winfsp_dll()
                if dll:
                    return dll
                raise WinFspSetupError(
                    "WinFsp 설치는 끝났습니다. 드라이버를 켜려면 PC를 재시작한 뒤 다시 실행하세요.",
                    reboot_required=True,
                )
    except WinFspSetupError as exc:
        download_error = exc

    if not find_winfsp_dll():
        try:
            if _install_with_winget(progress) and find_winfsp_dll():
                download_error = None
        except WinFspSetupError:
            pass

    start_winfsp_services()
    for _ in range(20):
        dll = find_winfsp_dll()
        if dll:
            os.environ["FUSE_LIBRARY_PATH"] = dll
            os.environ["PATH"] = os.path.dirname(dll) + os.pathsep + os.environ.get("PATH", "")
            _progress(progress, "WinFsp 설치가 완료되었습니다.")
            return dll
        import time

        time.sleep(0.25)

    if isinstance(download_error, WinFspSetupError) and download_error.reboot_required:
        raise download_error
    extra = f"\n\n{download_error}" if download_error else ""
    raise WinFspSetupError(
        "WinFsp를 자동 설치하지 못했습니다. 인터넷과 관리자 권한을 확인하세요." + extra
    )
