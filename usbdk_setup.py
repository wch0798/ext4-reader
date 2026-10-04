"""Optional UsbDk runtime download/install support.

UsbDk is not required for normal readers. EXT4 Reader only offers it after
all native Windows raw-write paths have failed on a USB removable device.
The installer is downloaded from the official daynix/UsbDk GitHub release
and pinned to a known SHA-256.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import platform
import shutil
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

USBDK_VERSION = "1.0.22"
USBDK_RELEASE_TAG = "v1.00-22"
USBDK_X64_URL = (
    "https://github.com/daynix/UsbDk/releases/download/"
    "v1.00-22/UsbDk_1.0.22_x64.msi"
)
USBDK_X64_SHA256 = "91f6f695e1e13c656024e6d3b55620bf08d8835ef05ee0496935ba6bb62466a5"
USBDK_RELEASE_URL = "https://github.com/daynix/UsbDk/releases/tag/v1.00-22"
USBDK_INSTALL_DIR = r"C:\Program Files\UsbDk Runtime Library"


class UsbDkSetupError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        reboot_required: bool = False,
        manual_install: bool = False,
    ):
        super().__init__(message)
        self.reboot_required = reboot_required
        self.manual_install = manual_install


class UsbDkRequiredError(UsbDkSetupError):
    """Raised only after normal Windows write paths failed and UsbDk is absent."""


@dataclass(frozen=True)
class UsbDkInstallResult:
    ready: bool
    reboot_required: bool
    helper_path: str | None
    installer_path: str
    log_path: str


def _is_64bit_windows() -> bool:
    machine = (platform.machine() or "").lower()
    return "64" in machine or bool(os.environ.get("PROGRAMFILES(X86)"))


def _candidate_helper_paths() -> list[str]:
    out = [
        os.path.join(USBDK_INSTALL_DIR, "UsbDkHelper.dll"),
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "UsbDkHelper.dll"),
    ]
    program_files = os.environ.get("ProgramFiles")
    if program_files:
        out.insert(0, os.path.join(program_files, "UsbDk Runtime Library", "UsbDkHelper.dll"))
    return list(dict.fromkeys(os.path.abspath(x) for x in out))


def find_usbdk_helper() -> str | None:
    for path in _candidate_helper_paths():
        if os.path.isfile(path):
            return path
    return None


def _service_running() -> bool:
    if os.name != "nt":
        return False
    try:
        proc = subprocess.run(
            ["sc.exe", "query", "UsbDk"],
            capture_output=True,
            text=True,
            timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        return False
    blob = (proc.stdout or "") + "\n" + (proc.stderr or "")
    return proc.returncode == 0 and "RUNNING" in blob.upper()


def usbdk_ready() -> bool:
    return bool(find_usbdk_helper()) and _service_running()


def _download_dir() -> str:
    root = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
    path = os.path.join(root, "Ext4Reader", "downloads")
    os.makedirs(path, exist_ok=True)
    return path


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download_usbdk(
    progress=None,
    *,
    force: bool = False,
) -> str:
    """Download the official x64 UsbDk MSI and verify its pinned SHA-256."""
    if os.name != "nt":
        raise UsbDkSetupError("UsbDk는 Windows에서만 설치할 수 있습니다.")
    if not _is_64bit_windows():
        raise UsbDkSetupError(
            "현재 자동 설치 기능은 64비트 Windows용 UsbDk만 지원합니다. "
            f"수동 설치: {USBDK_RELEASE_URL}",
            manual_install=True,
        )

    dest = os.path.join(_download_dir(), "UsbDk_1.0.22_x64.msi")
    if not force and os.path.isfile(dest):
        if _sha256_file(dest).lower() == USBDK_X64_SHA256:
            if progress:
                progress("기존 UsbDk 설치 파일의 SHA-256을 확인했습니다.")
            return dest
        try:
            os.remove(dest)
        except OSError:
            pass

    if progress:
        progress("공식 UsbDk 1.0.22 x64 설치 파일을 다운로드하는 중…")

    tmp = dest + ".part"
    try:
        req = urllib.request.Request(
            USBDK_X64_URL,
            headers={"User-Agent": "Ext4Reader-UsbDk-Setup/1.0"},
        )
        with urllib.request.urlopen(req, timeout=45) as response, open(tmp, "wb") as fp:
            total = int(response.headers.get("Content-Length") or 0)
            received = 0
            while True:
                chunk = response.read(256 * 1024)
                if not chunk:
                    break
                received += len(chunk)
                if received > 16 * 1024 * 1024:
                    raise UsbDkSetupError("UsbDk 설치 파일 크기가 예상 범위를 벗어났습니다.")
                fp.write(chunk)
                if progress and total:
                    progress(f"UsbDk 다운로드 중… {received * 100 // total}%")
    except UsbDkSetupError:
        raise
    except Exception as exc:
        raise UsbDkSetupError(
            "UsbDk 자동 다운로드에 실패했습니다. "
            f"공식 릴리스에서 수동 설치할 수 있습니다: {USBDK_RELEASE_URL}\n\n{exc}",
            manual_install=True,
        ) from exc

    digest = _sha256_file(tmp).lower()
    if digest != USBDK_X64_SHA256:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise UsbDkSetupError(
            "다운로드한 UsbDk MSI의 SHA-256이 공식 고정값과 다릅니다. "
            "안전을 위해 설치하지 않았습니다.",
            manual_install=True,
        )

    os.replace(tmp, dest)
    if progress:
        progress("UsbDk 설치 파일 무결성 확인 완료.")
    return dest


def _is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def install_usbdk(
    progress=None,
    *,
    force_download: bool = False,
) -> UsbDkInstallResult:
    """Download and install the official signed UsbDk runtime.

    This function never runs silently from startup. The GUI calls it only
    after explicit user approval because UsbDk installs a system USB filter.
    """
    if usbdk_ready():
        helper = find_usbdk_helper()
        return UsbDkInstallResult(True, False, helper, "", "")

    if not _is_admin():
        raise UsbDkSetupError("UsbDk 설치에는 관리자 권한이 필요합니다.")

    installer = download_usbdk(progress, force=force_download)
    log_dir = os.path.join(_download_dir(), "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "usbdk-install.log")

    if progress:
        progress("UsbDk 시스템 드라이버를 설치하는 중…")

    cmd = [
        "msiexec.exe",
        "/i",
        installer,
        "/qn",
        "/norestart",
        "/L*v",
        log_path,
    ]
    try:
        proc = subprocess.run(
            cmd,
            timeout=120,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as exc:
        raise UsbDkSetupError(
            f"UsbDk 설치 실행에 실패했습니다: {exc}\n설치 로그: {log_path}",
            manual_install=True,
        ) from exc

    # 0: success, 3010: success/reboot required, 1641: success/reboot initiated.
    if proc.returncode not in (0, 3010, 1641):
        raise UsbDkSetupError(
            f"UsbDk 설치가 실패했습니다 (MSI {proc.returncode}).\n"
            f"설치 로그: {log_path}\n"
            f"수동 설치: {USBDK_RELEASE_URL}",
            manual_install=True,
        )

    helper = find_usbdk_helper()
    ready = usbdk_ready()
    reboot_required = proc.returncode in (3010, 1641) or not ready

    if progress:
        if ready:
            progress("UsbDk 설치 및 서비스 확인 완료.")
        else:
            progress("UsbDk 설치 완료. 적용을 위해 재부팅이 필요합니다.")

    return UsbDkInstallResult(
        ready=ready,
        reboot_required=reboot_required,
        helper_path=helper,
        installer_path=installer,
        log_path=log_path,
    )


def manual_install_message() -> str:
    return (
        "UsbDk 자동 설치를 사용할 수 없습니다. 공식 UsbDk 1.0.22 x64 MSI를 "
        f"직접 설치한 뒤 재부팅하세요.\n\n{USBDK_RELEASE_URL}"
    )
