"""Mount an EXT4 volume as a Windows drive letter using WinFsp + fusepy."""

from __future__ import annotations

import atexit
import ctypes
import errno
import json
import os
import stat
import subprocess
import threading
import time
from ctypes import wintypes

from ext4reader.debuglog import LOG, exception_chain
from ext4reader.directory import DirError, list_dir
from ext4reader.io_backend import IoError
from ext4reader.volume import Ext4Error, Ext4Volume
from ext4reader.winfsp_setup import find_winfsp_dll, start_winfsp_services, winfsp_ready
from ext4reader.writer import (
    create_empty_file,
    lookup_parent,
    lookup_path,
    mkdir,
    move_entry,
    read_range,
    set_file_size,
    unlink_checked,
    write_range,
)


def find_fsptool() -> str | None:
    dll = find_winfsp_dll()
    if not dll:
        return None
    folder = os.path.dirname(dll)
    for name in ("fsptool-x64.exe", "fsptool-x86.exe", "fsptool-a64.exe"):
        p = os.path.join(folder, name)
        if os.path.isfile(p):
            return p
    return None


def winfsp_available() -> bool:
    return winfsp_ready()


def ensure_winfsp_services() -> None:
    start_winfsp_services()


def explain_fuse_error(exc: BaseException) -> str:
    text = str(exc).strip()
    blob = (text + "\n" + exception_chain(exc)).lower()
    extra = exception_chain(exc)
    if text in {"1", "RuntimeError(1)", "마운트 실패: 1"} or blob.strip("runtimeerror() ") == "1":
        msg = (
            "탐색기 드라이브 연결이 실패했습니다 (WinFsp 코드 1).\n\n"
            "보통 아래 중 하나입니다.\n"
            "1. run_as_admin.bat 으로 실행하지 않음\n"
            "2. WinFsp 설치 직후 PC를 아직 재시작하지 않음\n"
            "3. 같은 드라이브 문자가 이미 사용 중 (이전 Ext4Reader/python 창을 모두 종료)\n\n"
            "모든 Ext4Reader 창을 닫고 run_as_admin.bat 을 다시 실행해 보세요."
        )
    elif "c0000185" in blob or "service python" in blob or "failed to start" in blob:
        msg = (
            "WinFsp 드라이버가 파일시스템을 시작하지 못했습니다 (c0000185).\n\n"
            "WinFsp를 방금 설치했다면 PC를 재시작한 뒤 run_as_admin.bat 으로 실행하세요.\n"
            "이미 설치되어 있다면 다른 Ext4Reader/python 창을 모두 닫고 다시 시도하세요."
        )
    else:
        msg = text or "알 수 없는 마운트 오류"
    return msg + "\n\n--- 상세 ---\n" + extra


def normalize_drive_letter(letter: str) -> str:
    letter = (letter or "").strip().upper().rstrip("\\")
    if len(letter) == 1:
        letter += ":"
    if len(letter) != 2 or not letter[0].isalpha() or letter[1] != ":":
        raise RuntimeError(f"잘못된 드라이브 문자입니다: {letter}")
    return letter


def used_drive_letters() -> dict[str, str]:
    """Map 'Z' -> reason. Includes disconnected network mappings (the usual Z: case)."""
    import ctypes
    from ctypes import wintypes

    used: dict[str, str] = {}
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if mask & (1 << i):
            used[chr(ord("A") + i)] = "이미 사용 중"

    buf = ctypes.create_unicode_buffer(1024)
    kernel32 = ctypes.windll.kernel32
    kernel32.QueryDosDeviceW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    kernel32.QueryDosDeviceW.restype = wintypes.DWORD
    for i in range(26):
        letter = chr(ord("A") + i)
        if kernel32.QueryDosDeviceW(letter + ":", buf, 1024):
            used.setdefault(letter, buf.value)

    wnet = ctypes.windll.mpr.WNetGetConnectionW
    wnet.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    wnet.restype = wintypes.DWORD
    ERROR_CONNECTION_UNAVAIL = 1201
    ERROR_SESSION_CREDENTIAL_CONFLICT = 1219
    remote = ctypes.create_unicode_buffer(512)
    for i in range(26):
        letter = chr(ord("A") + i)
        n = wintypes.DWORD(512)
        wr = wnet(letter + ":", remote, ctypes.byref(n))
        if wr == 0 and remote.value:
            used[letter] = f"네트워크 {remote.value}"
        elif wr == ERROR_CONNECTION_UNAVAIL:
            used[letter] = "연결이 끊긴 네트워크 드라이브"
        elif wr == ERROR_SESSION_CREDENTIAL_CONFLICT:
            used[letter] = "네트워크 자격 증명이 필요한 드라이브"

    try:
        import winreg

        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Network")
        try:
            idx = 0
            while True:
                try:
                    name = winreg.EnumKey(key, idx)
                except OSError:
                    break
                idx += 1
                if len(name) != 1 or not name.isalpha():
                    continue
                letter = name.upper()
                remote = ""
                try:
                    sub = winreg.OpenKey(key, name)
                    try:
                        remote, _ = winreg.QueryValueEx(sub, "RemotePath")
                    finally:
                        winreg.CloseKey(sub)
                except OSError:
                    pass
                used.setdefault(
                    letter,
                    f"저장된 네트워크 드라이브 {remote}".strip()
                    if remote
                    else "저장된 네트워크 드라이브",
                )
        finally:
            winreg.CloseKey(key)
    except OSError:
        pass

    try:
        r = subprocess.run(
            ["net", "use"],
            capture_output=True,
            text=True,
            encoding="oem",
            errors="replace",
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        import re

        blob = (r.stdout or "") + "\n" + (r.stderr or "")
        for m in re.finditer(r"\b([A-Za-z]):\s+", blob):
            used.setdefault(m.group(1).upper(), "네트워크 드라이브")
    except Exception:
        pass
    LOG.info("사용 중인 드라이브: %s", ", ".join(f"{k}: ({v})" for k, v in sorted(used.items())) or "(없음)")
    return used


def free_drive_letters() -> list[str]:
    used = used_drive_letters()
    out = [f"{chr(ord('A') + i)}:" for i in range(3, 26) if chr(ord("A") + i) not in used]
    if not out:
        raise RuntimeError("남는 드라이브 문자가 없습니다.")
    return out


def next_drive_letter() -> str:
    return free_drive_letters()[0]


def next_drive_letters(count: int = 5) -> list[str]:
    return free_drive_letters()[:count]


def _safe_volname(label: str) -> str:
    raw = (label or "EXT4").strip()[:31]
    cleaned = "".join(ch if ch.isalnum() or ch in "-_" else "" for ch in raw)
    return cleaned or "EXT4"


def _ensure_fuse():
    dll = find_winfsp_dll()
    if not dll:
        from ext4reader.winfsp_setup import ensure_winfsp_installed

        dll = ensure_winfsp_installed()
    ensure_winfsp_services()
    os.environ["FUSE_LIBRARY_PATH"] = dll
    os.environ["PATH"] = os.path.dirname(dll) + os.pathsep + os.environ.get("PATH", "")
    from fuse import FUSE, FuseOSError, Operations  # noqa: WPS433

    return FUSE, FuseOSError, Operations


class Ext4FuseOps:
    """FUSE operations bound to an Ext4Volume. Mixed in after fuse.Operations is loaded."""

    use_ns = False

    def __init__(self, vol: Ext4Volume, read_only: bool):
        self.vol = vol
        self.read_only = read_only
        self._lock = threading.RLock()
        self._logged: set[tuple] = set()
        self._stop = threading.Event()

    def _ro(self) -> None:
        if self.read_only:
            raise self._err(errno.EROFS)

    def _err(self, code: int):
        from fuse import FuseOSError

        return FuseOSError(code)

    def _check_stop(self) -> None:
        if not self._stop.is_set():
            return
        try:
            from fuse import fuse_exit

            fuse_exit()
        except Exception:
            pass
        raise self._err(errno.ENODEV)

    def _fuse_path(self, path) -> str:
        if isinstance(path, bytes):
            path = path.decode("utf-8", "surrogateescape")
        path = (path or "/").replace("\\", "/")
        if not path.startswith("/"):
            path = "/" + path
        if path != "/":
            path = path.rstrip("/")
        return path or "/"

    def _wrap(self, fn, *args):
        try:
            with self._lock:
                self._check_stop()
                return fn(*args)
        except FileNotFoundError as exc:
            LOG.debug("ENOENT %s %s", getattr(fn, "__name__", fn), args)
            raise self._err(errno.ENOENT) from exc
        except PermissionError as exc:
            LOG.warning("EACCES %s %s: %s", getattr(fn, "__name__", fn), args, exc)
            raise self._err(errno.EACCES) from exc
        except DirError as exc:
            msg = str(exc)
            LOG.warning("DirError %s %s: %s", getattr(fn, "__name__", fn), args, exc)
            if "이미" in msg:
                raise self._err(errno.EEXIST) from exc
            if "비어" in msg:
                raise self._err(errno.ENOTEMPTY) from exc
            if "찾을 수 없" in msg or "찾지" in msg:
                raise self._err(errno.ENOENT) from exc
            raise self._err(errno.EIO) from exc
        except Ext4Error as exc:
            LOG.warning("Ext4Error %s %s: %s", getattr(fn, "__name__", fn), args, exc)
            raise self._err(errno.EROFS if "쓸 수 없" in str(exc) else errno.EIO) from exc
        except IoError as exc:
            key = (getattr(fn, "__name__", str(fn)), type(exc).__name__, str(exc)[:200])
            if key not in self._logged:
                self._logged.add(key)
                LOG.exception("디스크 I/O 실패 %s %s", getattr(fn, "__name__", fn), args)
            raise self._err(errno.EIO) from exc
        except OSError as exc:
            from fuse import FuseOSError

            if isinstance(exc, FuseOSError):
                raise
            LOG.exception("OSError %s %s", getattr(fn, "__name__", fn), args)
            raise self._err(getattr(exc, "errno", errno.EIO) or errno.EIO) from exc
        except Exception as exc:
            key = (getattr(fn, "__name__", str(fn)), type(exc).__name__, str(exc)[:200])
            if key not in self._logged:
                self._logged.add(key)
                LOG.exception("FUSE 처리 실패 %s %s", getattr(fn, "__name__", fn), args)
            raise self._err(errno.EIO) from exc

    def init(self, path):
        return None

    def destroy(self, path):
        return None

    def getattr(self, path, fh=None):
        return self._wrap(self._getattr, self._fuse_path(path))

    def _getattr(self, path):
        node = lookup_path(self.vol, path)
        mode = int(node.mode)
        if not stat.S_IFMT(mode):
            mode |= stat.S_IFDIR if node.is_dir else stat.S_IFREG
        if self.read_only:
            mode &= ~0o222
        nlink = max(2 if node.is_dir else 1, node.links)
        return {
            "st_mode": mode,
            "st_ino": node.ino,
            "st_dev": 0,
            "st_nlink": min(nlink, 65535),
            "st_uid": node.uid,
            "st_gid": node.gid,
            "st_size": node.size,
            "st_atime": node.atime or 0,
            "st_mtime": node.mtime or 0,
            "st_ctime": node.ctime or 0,
            "st_blocks": node.blocks,
            "st_blksize": self.vol.sb.block_size,
        }

    def readdir(self, path, fh):
        return self._wrap(self._readdir, self._fuse_path(path))

    def _readdir(self, path):
        node = lookup_path(self.vol, path)
        if not node.is_dir:
            raise self._err(errno.ENOTDIR)
        names = [".", ".."]
        for e in list_dir(self.vol, node):
            if e.name not in (".", ".."):
                names.append(e.name)
        return names

    def open(self, path, flags):
        return self._wrap(self._open, self._fuse_path(path), flags)

    def _open(self, path, flags):
        creat = bool(flags & os.O_CREAT)
        trunc = bool(flags & os.O_TRUNC)
        excl = bool(flags & os.O_EXCL)
        writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_TRUNC | os.O_CREAT))
        if self.read_only and writing:
            raise self._err(errno.EROFS)
        try:
            node = lookup_path(self.vol, path)
        except FileNotFoundError:
            if not creat:
                raise
            self._create(path, 0o644)
            return 0
        if excl and creat:
            raise self._err(errno.EEXIST)
        if trunc:
            if node.is_dir:
                raise self._err(errno.EISDIR)
            set_file_size(self.vol, node, 0)
        return 0

    def mknod(self, path, mode, dev):
        self._ro()
        if stat.S_ISDIR(mode):
            return self.mkdir(path, mode)
        return self.create(path, mode)

    def _lookup(self, path):
        return lookup_path(self.vol, path)

    def opendir(self, path):
        self._wrap(self._lookup, self._fuse_path(path))
        return 0

    def create(self, path, mode, fi=None):
        self._ro()
        return self._wrap(self._create, self._fuse_path(path), mode)

    def _create(self, path, mode):
        try:
            node = lookup_path(self.vol, path)
        except FileNotFoundError:
            parent, name = lookup_parent(self.vol, path)
            create_empty_file(self.vol, parent, name, mode & 0o777)
            return 0
        if node.is_dir:
            raise self._err(errno.EISDIR)
        set_file_size(self.vol, node, 0)
        return 0

    def mkdir(self, path, mode):
        self._ro()
        return self._wrap(self._mkdir, self._fuse_path(path))

    def _mkdir(self, path):
        try:
            node = lookup_path(self.vol, path)
            if node.is_dir:
                return 0
            raise self._err(errno.EEXIST)
        except FileNotFoundError:
            parent, name = lookup_parent(self.vol, path)
            mkdir(self.vol, parent, name)

    def unlink(self, path):
        self._ro()
        return self._wrap(self._unlink, self._fuse_path(path))

    def rmdir(self, path):
        self._ro()
        return self._wrap(self._unlink, self._fuse_path(path))

    def _unlink(self, path):
        parent, name = lookup_parent(self.vol, path)
        unlink_checked(self.vol, parent, name)

    def rename(self, old, new):
        self._ro()
        return self._wrap(move_entry, self.vol, self._fuse_path(old), self._fuse_path(new), True)

    def read(self, path, size, offset, fh):
        return self._wrap(self._read, self._fuse_path(path), size, offset)

    def _read(self, path, size, offset):
        node = lookup_path(self.vol, path)
        return read_range(self.vol, node, offset, size)

    def write(self, path, data, offset, fh):
        self._ro()
        return self._wrap(self._write, self._fuse_path(path), data, offset)

    def _write(self, path, data, offset):
        node = lookup_path(self.vol, path)
        return write_range(self.vol, node, offset, data, flush=False)

    def truncate(self, path, length, fh=None):
        self._ro()
        return self._wrap(self._truncate, self._fuse_path(path), length)

    def _truncate(self, path, length):
        node = lookup_path(self.vol, path)
        set_file_size(self.vol, node, length)

    def flush(self, path, fh):
        with self._lock:
            self.vol.flush_metadata()
        return 0

    def fsync(self, path, datasync, fh):
        with self._lock:
            self.vol.flush_metadata()
        return 0

    def release(self, path, fh):
        with self._lock:
            try:
                self.vol.flush_metadata()
            except Exception:
                pass
        return 0

    def chmod(self, path, mode):
        return 0

    def chown(self, path, uid, gid):
        return 0

    def utimens(self, path, times=None):
        return self._wrap(self._utimens, self._fuse_path(path), times)

    def _utimens(self, path, times):
        node = lookup_path(self.vol, path)
        if times:
            node.set_atime_mtime(int(times[0]), int(times[1]))
        else:
            node.set_times()
        self.vol.write_inode(node)
        return 0

    def lock(self, path, fh, cmd, lock):
        return 0

    def releasedir(self, path, fh):
        return 0

    def fsyncdir(self, path, datasync, fh):
        with self._lock:
            self.vol.flush_metadata()
        return 0

    def statfs(self, path):
        sb = self.vol.sb
        return {
            "f_bsize": sb.block_size,
            "f_frsize": sb.block_size,
            "f_blocks": sb.blocks_count,
            "f_bfree": sb.free_blocks_count,
            "f_bavail": sb.free_blocks_count,
            "f_files": sb.inodes_count,
            "f_ffree": sb.free_inodes_count,
            "f_favail": sb.free_inodes_count,
            "f_namemax": 255,
        }

    def access(self, path, amode):
        # Always allow. Rejecting W_OK here makes Explorer show a login/permission dialog.
        return 0


class MountSession:
    def __init__(self, letter: str, volume: Ext4Volume, thread: threading.Thread, read_only: bool = True):
        self.letter = letter
        self.volume = volume
        self.thread = thread
        self.read_only = read_only
        self.error: BaseException | None = None
        self.stop = threading.Event()
        self.ops: Ext4FuseOps | None = None


_SESSIONS: dict[str, MountSession] = {}
_STATE_LOCK = threading.Lock()
_ATEXIT_DONE = False


def _state_path() -> str:
    base = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "Ext4Reader")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, "mounted.json")


def _read_state() -> list[str]:
    try:
        with open(_state_path(), encoding="utf-8") as fp:
            data = json.load(fp)
        if isinstance(data, list):
            return [str(x) for x in data]
    except Exception:
        pass
    return []


def _write_state(letters: list[str]) -> None:
    try:
        with open(_state_path(), "w", encoding="utf-8") as fp:
            json.dump(letters, fp)
    except OSError:
        pass


def _remember(letter: str) -> None:
    with _STATE_LOCK:
        letters = _read_state()
        if letter not in letters:
            letters.append(letter)
        _write_state(letters)


def _forget(letter: str) -> None:
    with _STATE_LOCK:
        letters = [x for x in _read_state() if x != letter]
        _write_state(letters)


def _ctl_code(device: int, function: int, method: int, access: int) -> int:
    return (device << 16) | (access << 14) | (function << 2) | method


FSP_FSCTL_STOP = _ctl_code(9, 0x800 + ord("S"), 0, 0)
FSP_FSCTL_STOP0 = _ctl_code(9, 0x800 + ord("s"), 0, 0)
DDD_REMOVE_DEFINITION = 0x00000002
DDD_EXACT_MATCH_ON_REMOVE = 0x00000004
SHCNE_DRIVEREMOVED = 0x00000080
SHCNE_MEDIAREMOVED = 0x00000040
SHCNF_PATHW = 0x0005


def _open_volume(path: str):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = ctypes.c_void_p
    handle = kernel32.CreateFileW(
        path,
        0xC0000000,
        0x00000003,
        None,
        3,
        0x02000000,
        None,
    )
    if handle in (None, 0, ctypes.c_void_p(-1).value):
        return None
    return handle


def _ioctl_stop(handle, code: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    returned = wintypes.DWORD(0)
    kernel32.DeviceIoControl(handle, code, None, 0, None, 0, ctypes.byref(returned), None)


def _stop_winfsp_volume(letter: str) -> None:
    dll = find_winfsp_dll()
    lib = None
    if dll:
        try:
            lib = ctypes.CDLL(dll)
        except OSError:
            lib = None
    targets = [rf"\\.\{letter}", letter + "\\", letter]
    buf = ctypes.create_unicode_buffer(512)
    try:
        ctypes.windll.kernel32.QueryDosDeviceW(letter, buf, 512)
        if buf.value:
            targets.append(r"\\?\GLOBALROOT" + buf.value)
            targets.append(buf.value)
    except Exception:
        pass
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    for path in targets:
        handle = _open_volume(path)
        if not handle:
            continue
        try:
            LOG.info("WinFsp STOP %s", path)
            _ioctl_stop(handle, FSP_FSCTL_STOP0)
            _ioctl_stop(handle, FSP_FSCTL_STOP)
            if lib is not None:
                try:
                    lib.FspFsctlStop.argtypes = [ctypes.c_void_p]
                    lib.FspFsctlStop.restype = ctypes.c_long
                    lib.FspFsctlStop(handle)
                except Exception:
                    pass
        finally:
            kernel32.CloseHandle(handle)
    if lib is not None:
        try:
            lib.fuse_unmount.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
            lib.fuse_unmount.restype = None
            for mp in (letter, rf"\\.\{letter}", letter + "\\"):
                lib.fuse_unmount(mp.encode("utf-8"), None)
        except Exception:
            pass


def _remove_drive_letter(letter: str) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    root = letter + "\\"
    try:
        kernel32.DeleteVolumeMountPointW(root)
    except Exception:
        pass
    try:
        kernel32.DefineDosDeviceW(DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE, letter, None)
    except Exception:
        pass
    try:
        kernel32.DefineDosDeviceW(DDD_REMOVE_DEFINITION, letter, None)
    except Exception:
        pass
    try:
        ctypes.windll.shell32.SHChangeNotify(SHCNE_DRIVEREMOVED, SHCNF_PATHW, root, None)
        ctypes.windll.shell32.SHChangeNotify(SHCNE_MEDIAREMOVED, SHCNF_PATHW, root, None)
    except Exception:
        pass


def _close_explorer_views(letter: str) -> None:
    root = letter + "\\"
    script = (
        "$l = [regex]::Escape('" + root.replace("'", "''") + "'); "
        "$s = New-Object -ComObject Shell.Application; "
        "foreach ($w in @($s.Windows())) { "
        "try { $p = [string]$w.Document.Folder.Self.Path; "
        "if ($p -match ('^' + $l)) { $w.Quit() } } catch {} }"
    )
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", script],
            check=False,
            timeout=4,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        pass


def _letter_present(letter: str) -> bool:
    try:
        if os.path.exists(letter + "\\"):
            return True
    except OSError:
        return True
    buf = ctypes.create_unicode_buffer(512)
    try:
        n = ctypes.windll.kernel32.QueryDosDeviceW(letter, buf, 512)
        return bool(n)
    except Exception:
        return False


def unmount(letter: str) -> None:
    letter = normalize_drive_letter(letter)
    LOG.info("언마운트 시작 %s", letter)
    session = _SESSIONS.pop(letter, None)
    if session:
        session.stop.set()
        if session.ops is not None:
            session.ops._stop.set()
    _stop_winfsp_volume(letter)
    _remove_drive_letter(letter)
    if _letter_present(letter):
        _close_explorer_views(letter)
        _stop_winfsp_volume(letter)
        _remove_drive_letter(letter)
    if session and session.thread.is_alive():
        session.thread.join(timeout=6)
    deadline = time.time() + 5
    while time.time() < deadline:
        if not _letter_present(letter):
            break
        time.sleep(0.1)
        _remove_drive_letter(letter)
    gone = not _letter_present(letter)
    LOG.info("언마운트 %s %s", letter, "완료" if gone else "드라이브가 아직 남아 있음")
    _forget(letter)
    if session:
        try:
            session.volume.close()
        except Exception:
            pass


def unmount_all() -> None:
    letters = list(_SESSIONS.keys()) + _read_state()
    seen: set[str] = set()
    for letter in letters:
        try:
            letter = normalize_drive_letter(letter)
        except Exception:
            continue
        if letter in seen:
            continue
        seen.add(letter)
        try:
            unmount(letter)
        except Exception:
            LOG.exception("언마운트 실패 %s", letter)


def cleanup_stale_mounts() -> None:
    leftover = list(_read_state())
    for i in range(3, 26):
        letter = f"{chr(ord('A') + i)}:"
        if _looks_like_orphan_winfsp(letter) and letter not in leftover:
            leftover.append(letter)
    if not leftover:
        return
    LOG.warning("이전에 남은 드라이브 해제: %s", ", ".join(leftover))
    for letter in leftover:
        try:
            unmount(normalize_drive_letter(letter))
        except Exception:
            LOG.exception("남은 드라이브 해제 실패 %s", letter)


def _looks_like_orphan_winfsp(letter: str) -> bool:
    """Dead WinFsp volume letter. Never touch unused letters or network maps."""
    buf = ctypes.create_unicode_buffer(512)
    try:
        n = ctypes.windll.kernel32.QueryDosDeviceW(letter, buf, 512)
    except Exception:
        return False
    if not n:
        return False
    target = buf.value or ""
    if "Volume{" not in target:
        return False
    if "HarddiskVolume" in target or "Lanman" in target:
        return False
    try:
        os.listdir(letter + "\\")
        return False
    except OSError:
        return True


def _atexit_unmount() -> None:
    global _ATEXIT_DONE
    if _ATEXIT_DONE:
        return
    _ATEXIT_DONE = True
    try:
        unmount_all()
    except Exception:
        pass


atexit.register(_atexit_unmount)


def _fuse_mountpoint(letter: str) -> str:
    """Mount as \\\\.\\X: so Windows treats it as a local volume, not a network share."""
    letter = letter.rstrip("\\")
    if not letter.endswith(":"):
        letter += ":"
    return "\\\\.\\" + letter


def _log_drive(letter: str) -> None:
    import ctypes
    from ctypes import wintypes

    root = letter.rstrip("\\")
    if not root.endswith(":"):
        root += ":"
    path = root + "\\"
    GetDriveTypeW = ctypes.windll.kernel32.GetDriveTypeW
    GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    GetDriveTypeW.restype = wintypes.UINT
    kind = GetDriveTypeW(path)
    names = {
        0: "UNKNOWN",
        1: "NO_ROOT",
        2: "REMOVABLE",
        3: "FIXED",
        4: "REMOTE",
        5: "CDROM",
        6: "RAMDISK",
    }
    buf = ctypes.create_unicode_buffer(512)
    ctypes.windll.kernel32.QueryDosDeviceW(root, buf, 512)
    wnet = ctypes.windll.mpr.WNetGetConnectionW
    wnet.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    wnet.restype = wintypes.DWORD
    remote = ctypes.create_unicode_buffer(512)
    n = wintypes.DWORD(512)
    wr = wnet(root, remote, ctypes.byref(n))
    LOG.info(
        "드라이브 %s type=%s(%s) dosdevice=%s wnet=%s remote=%s",
        root,
        kind,
        names.get(kind, "?"),
        buf.value,
        wr,
        remote.value if wr == 0 else "",
    )


def _run_fuse(ops, letter: str, label: str, read_only: bool, session: MountSession) -> None:
    FUSE, _FuseOSError, Operations = _ensure_fuse()

    class EXT4FS(Ext4FuseOps, Operations):
        pass

    bound = EXT4FS(ops.vol, read_only)
    bound._stop = session.stop
    session.ops = bound
    mountpoint = _fuse_mountpoint(letter)
    kwargs = {
        "foreground": True,
        "nothreads": True,
        "uid": -1,
        "gid": -1,
        "umask": 0,
        "volname": _safe_volname(label),
        "fsname": "fuse",
        "FileSecurity": "D:P(A;;FA;;;WD)",
    }
    LOG.info(
        "FUSE 시작 mount=%s fuse_mp=%s volname=%s ro=%s kwargs=%s",
        letter,
        mountpoint,
        kwargs["volname"],
        read_only,
        kwargs,
    )
    try:
        FUSE(bound, mountpoint, **kwargs)
        if session.error is None and not os.path.exists(letter + "\\"):
            session.error = RuntimeError("1")
            LOG.error("FUSE가 반환했지만 드라이브 %s 가 없습니다", letter)
    except Exception as exc:
        LOG.exception("FUSE 실패 mount=%s", letter)
        session.error = RuntimeError(explain_fuse_error(exc))


def mount_volume(vol: Ext4Volume, read_only: bool, letter: str | None = None, label: str = "EXT4") -> MountSession:
    _ensure_fuse()
    try:
        g, off = vol._inode_loc(2)
        LOG.info(
            "루트 inode 위치 group=%s fs_off=%s part_off=%s abs=%s inode_size=%s block=%s",
            g,
            off,
            vol.part_offset,
            vol.part_offset + off,
            vol.sb.inode_size,
            vol.sb.block_size,
        )
        node = lookup_path(vol, "/")
        LOG.info(
            "루트 inode ino=%s mode=%s size=%s links=%s flags=0x%X dir=%s",
            node.ino,
            oct(node.mode),
            node.size,
            node.links,
            node.flags,
            node.is_dir,
        )
    except Exception as exc:
        LOG.exception("EXT4 루트 읽기 실패")
        raise RuntimeError(
            "EXT4 루트를 읽지 못해 탐색기에 연결할 수 없습니다.\n"
            f"{type(exc).__name__}: {exc}\n\n"
            "콘솔 로그를 복사해 주세요."
        ) from exc
    if letter:
        letter = normalize_drive_letter(letter)
        why = used_drive_letters().get(letter[0])
        if why:
            raise RuntimeError(f"{letter} 는 이미 사용 중입니다 ({why}).\n다른 드라이브 문자를 선택하세요.")
        letters = [letter]
        LOG.info("사용할 드라이브 문자 %s", letter)
    else:
        letters = [next_drive_letter()]
    last_error: BaseException | None = None
    for cand in letters:
        if not cand.endswith(":"):
            cand = cand + ":"
        ops = Ext4FuseOps(vol, read_only)
        session = MountSession(cand, vol, threading.Thread(daemon=True), read_only=read_only)
        ops._stop = session.stop
        session.ops = ops
        session.thread = threading.Thread(
            target=_run_fuse,
            args=(ops, cand, label, read_only, session),
            daemon=True,
            name=f"ext4-fuse-{cand}",
        )
        _SESSIONS[cand] = session
        _remember(cand)
        session.thread.start()
        deadline = time.time() + 8
        root = cand + "\\"
        while time.time() < deadline:
            if session.error:
                break
            if os.path.exists(root):
                LOG.info("마운트 성공 %s", cand)
                _log_drive(cand)
                return session
            time.sleep(0.12)
        if os.path.exists(root):
            LOG.info("마운트 성공 %s", cand)
            _log_drive(cand)
            return session
        last_error = session.error
        LOG.error("마운트 실패 %s error=%s", cand, last_error)
        try:
            unmount(cand)
        except Exception:
            pass
    if last_error:
        raise RuntimeError(explain_fuse_error(last_error))
    raise RuntimeError(
        "탐색기에 드라이브가 나타나지 않았습니다.\n"
        "모든 Ext4Reader/python 창을 닫고, PC를 재시작한 다음 run_as_admin.bat 으로 다시 실행하세요."
    )


def open_explorer(letter: str) -> None:
    root = letter.rstrip("\\")
    if not root.endswith(":"):
        root += ":"
    # ShellExecute/startfile goes through the network provider and can show
    # "Enter network credentials". explorer.exe on the drive path does not.
    try:
        subprocess.Popen(
            [os.path.expandvars(r"%SystemRoot%\explorer.exe"), root + "\\"],
            close_fds=True,
        )
    except OSError:
        os.startfile(root + "\\")  # noqa: S606
