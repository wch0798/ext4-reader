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

from ext4lib.debuglog import LOG, exception_chain
from ext4lib.fs.directory import DirError, list_dir
from ext4lib.io.backend import IoError
from ext4lib.fs.volume import Ext4Error, Ext4Volume
from ext4lib.windows.winfsp_setup import find_winfsp_dll, start_winfsp_services, winfsp_ready
from ext4lib.fs.writer import (
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


_RECYCLE_INI = (
    b"[.ShellClassInfo]\r\n"
    b"CLSID={645FF040-5081-101B-9F08-00AA002F954E}\r\n"
    b"LocalizedResourceName=@%SystemRoot%\\system32\\shell32.dll,-8964\r\n"
)


# WinFsp fuse_common.h. Reported through fuse_stat_ex.st_flags.
_UF_HIDDEN = 0x00008000
_UF_SYSTEM = 0x00000080
_FSP_CAP_STAT_EX = 1 << 23


def recycle_attr_path(path: str) -> bool:
    """``$RECYCLE.BIN``, its SID folder, and their desktop.ini need hidden+system."""
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    if not parts or parts[0].upper() != "$RECYCLE.BIN":
        return False
    if len(parts) == 1:
        return True
    if len(parts) == 2 and parts[1].lower() == "desktop.ini":
        return True
    if len(parts) == 2 and parts[1].upper().startswith("S-1-"):
        return True
    if len(parts) == 3 and parts[1].upper().startswith("S-1-") and parts[2].lower() == "desktop.ini":
        return True
    return False


def recycle_repair_targets(path: str) -> tuple[str, str] | None:
    """Paths under an existing ``$RECYCLE.BIN`` that Explorer expects to exist."""
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    if not parts or parts[0].upper() != "$RECYCLE.BIN":
        return None
    bin_dir = "/" + parts[0]
    sid_dir = ""
    if len(parts) >= 2 and parts[1].upper().startswith("S-1-"):
        sid_dir = bin_dir + "/" + parts[1]
    return bin_dir, sid_dir


def _brief_args(args: tuple) -> str:
    parts: list[str] = []
    for arg in args:
        if isinstance(arg, memoryview):
            parts.append(f"<memoryview {len(arg)}>")
        elif isinstance(arg, (bytes, bytearray)):
            parts.append(f"<{type(arg).__name__} {len(arg)}>")
        else:
            text = repr(arg)
            if len(text) > 160:
                text = text[:160] + "…"
            parts.append(text)
    return "(" + ", ".join(parts) + ")"


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
        from ext4lib.windows.winfsp_setup import ensure_winfsp_installed

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
        self._path_ino: dict[str, int] = {}
        self._ra: tuple | None = None
        self._wb: list | None = None
        self._win_flags: dict[str, int] = {}
        self._st_flags = 0
        self._write_failure: BaseException | None = None
        self._write_failure_repeat_count = 0

    def _node(self, path: str):
        ino = self._path_ino.get(path)
        if ino:
            try:
                return self.vol.read_inode(ino)
            except Exception:
                self._path_ino.pop(path, None)
        node = lookup_path(self.vol, path)
        self._path_ino[path] = node.ino
        if len(self._path_ino) > 8192:
            self._path_ino.clear()
            self._path_ino[path] = node.ino
        return node

    def _apply_linux_defaults(self, node, *, directory: bool) -> None:
        """Normalize an existing Windows-touched inode for Steam Deck use."""
        uid = int(getattr(self.vol, "default_uid", 1000))
        gid = int(getattr(self.vol, "default_gid", 1000))
        perm = int(
            getattr(
                self.vol,
                "default_dir_mode" if directory else "default_file_mode",
                0o755,
            )
        ) & 0o777
        changed = False
        if node.uid != uid or node.gid != gid:
            node.set_owner(uid, gid)
            changed = True
        desired_mode = stat.S_IFMT(node.mode) | perm
        if node.mode != desired_mode:
            node.set_mode(desired_mode)
            changed = True
        if changed:
            node.set_times()
            self.vol.write_inode(node)
            LOG.info(
                "Linux 권한 정상화 path inode=%s uid=%s gid=%s mode=%04o",
                node.ino,
                uid,
                gid,
                perm,
            )

    def _visible_size(self, node) -> int:
        size = node.size
        wb = self._wb
        if wb and wb[0] == node.ino:
            end = wb[1] + len(wb[2])
            if end > size:
                size = end
        return size

    def _latch_write_failure(self, exc: BaseException, operation: str) -> None:
        if self._write_failure is None:
            self._write_failure = exc
            self.read_only = True
            LOG.error(
                "쓰기 경로 중단 operation=%s error=%s; 이후 쓰기를 EIO로 거부합니다",
                operation,
                exc,
            )

    def _ensure_write_healthy(self) -> None:
        if self._write_failure is not None:
            raise IoError(
                "이전 디스크 쓰기/flush 오류로 안전을 위해 쓰기를 중단했습니다: "
                + str(self._write_failure),
                winerr=getattr(self._write_failure, "winerr", 0) or 0,
            )

    def _wb_flush(self) -> None:
        wb = self._wb
        if not wb:
            return
        ino, off, buf = wb
        if not buf:
            self._wb = None
            return
        self._ensure_write_healthy()
        try:
            node = self.vol.read_inode(ino)
            write_range(self.vol, node, off, bytes(buf), flush=False)
        except Exception as exc:
            self._latch_write_failure(exc, "buffered-write")
            raise
        self._wb = None

    def sync_pending(self) -> None:
        """Durably flush pending writes and leave the on-disk EXT4 clean."""
        with self._lock:
            self._ensure_write_healthy()
            try:
                self._wb_flush()
                # Windows policy: Linux freedesktop trash is not retained on an
                # Ext4Reader writable mount. Recovery, when desired, is a Linux
                # concern; Windows should reclaim the blocks automatically.
                # Purge every root .Trash-<uid> tree at the durability boundary
                # so stale trash cannot silently consume tens of GiB.
                try:
                    root = lookup_path(self.vol, "/")
                    trash_names = [
                        ent.name for ent in list(list_dir(self.vol, root))
                        if ent.name.startswith(".Trash-") and ent.name[7:].isdigit()
                    ]
                    for name in trash_names:
                        LOG.warning("Linux 휴지통 자동 삭제: /%s", name)
                        self._purge_trash_tree("/" + name)
                except FileNotFoundError:
                    pass
                if getattr(self.vol, "_write_session_active", False):
                    self.vol.finish_write_session()
                else:
                    self.vol.commit_metadata(sync=True)
            except Exception as exc:
                self._latch_write_failure(exc, "sync")
                raise
            LOG.info("최종 디스크 flush/EXT4 clean 성공")

    def _drop_paths(self) -> None:
        self._wb_flush()
        self._path_ino.clear()
        self._ra = None

    def _ro(self) -> None:
        try:
            self._ensure_write_healthy()
        except IoError as exc:
            raise self._err(errno.EIO) from exc
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
            LOG.debug("ENOENT %s %s", getattr(fn, "__name__", fn), _brief_args(args))
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
            was_failed = self._write_failure is not None
            self._latch_write_failure(exc, getattr(fn, "__name__", str(fn)))
            if was_failed:
                self._write_failure_repeat_count += 1
                if (
                    self._write_failure_repeat_count == 1
                    or self._write_failure_repeat_count % 128 == 0
                ):
                    LOG.debug(
                        "이전 쓰기 오류로 EIO 반환 %s %s (반복=%s)",
                        getattr(fn, "__name__", fn),
                        _brief_args(args),
                        self._write_failure_repeat_count,
                    )
            else:
                key = (getattr(fn, "__name__", str(fn)), type(exc).__name__, str(exc)[:200])
                if key not in self._logged:
                    self._logged.add(key)
                    LOG.exception(
                        "디스크 I/O 실패 %s %s",
                        getattr(fn, "__name__", fn),
                        _brief_args(args),
                    )
            raise self._err(errno.EIO) from exc
        except OSError as exc:
            from fuse import FuseOSError

            if isinstance(exc, FuseOSError):
                raise
            self._latch_write_failure(exc, getattr(fn, "__name__", str(fn)))
            LOG.exception("OSError %s %s", getattr(fn, "__name__", fn), _brief_args(args))
            raise self._err(getattr(exc, "errno", errno.EIO) or errno.EIO) from exc
        except Exception as exc:
            key = (getattr(fn, "__name__", str(fn)), type(exc).__name__, str(exc)[:200])
            if key not in self._logged:
                self._logged.add(key)
                LOG.exception("FUSE 처리 실패 %s %s", getattr(fn, "__name__", fn), _brief_args(args))
            raise self._err(errno.EIO) from exc

    def init(self, path):
        return None

    def destroy(self, path):
        return None

    def getattr(self, path, fh=None):
        return self._wrap(self._getattr, self._fuse_path(path))

    def _ensure_recycle_ini(self, dir_path: str) -> None:
        ini_path = dir_path.rstrip("/") + "/desktop.ini"
        try:
            node = lookup_path(self.vol, ini_path)
        except FileNotFoundError:
            parent, name = lookup_parent(self.vol, ini_path)
            node = create_empty_file(self.vol, parent, name, 0o644)
            self._drop_paths()
            write_range(self.vol, node, 0, _RECYCLE_INI, flush=True)
            return
        if node.is_dir or node.size > 4096:
            return
        data = read_range(self.vol, node, 0, node.size) if node.size else b""
        folded = data.upper().replace(b"\x00", b"")
        if b"645FF040-5081-101B-9F08-00AA002F954E" in folded:
            return
        node = self.vol.read_inode(node.ino)
        write_range(self.vol, node, 0, _RECYCLE_INI, flush=True)
        if node.size != len(_RECYCLE_INI):
            set_file_size(self.vol, self.vol.read_inode(node.ino), len(_RECYCLE_INI))

    def _materialize_recycle(self, path: str) -> None:
        if self.read_only:
            return
        targets = recycle_repair_targets(path)
        if targets is None:
            return
        bin_dir, sid_dir = targets
        try:
            bin_node = lookup_path(self.vol, bin_dir)
        except FileNotFoundError:
            return
        if not bin_node.is_dir:
            return
        self._ensure_recycle_ini(bin_dir)
        if not sid_dir:
            return
        try:
            sid_node = lookup_path(self.vol, sid_dir)
        except FileNotFoundError:
            parent, name = lookup_parent(self.vol, sid_dir)
            mkdir(self.vol, parent, name)
            self._drop_paths()
            sid_node = lookup_path(self.vol, sid_dir)
        if sid_node.is_dir:
            self._ensure_recycle_ini(sid_dir)

    def _getattr(self, path):
        try:
            self._materialize_recycle(path)
        except Exception:
            LOG.exception("휴지통 항목 준비 실패 %s", path)
        self._st_flags = 0
        node = self._node(path)
        mode = int(node.mode)
        if not stat.S_IFMT(mode):
            mode |= stat.S_IFDIR if node.is_dir else stat.S_IFREG
        if self.read_only:
            mode &= ~0o222
        nlink = max(2 if node.is_dir else 1, node.links)
        flags = int(self._win_flags.get(path, 0))
        if recycle_attr_path(path):
            flags |= _UF_HIDDEN | _UF_SYSTEM
        self._st_flags = flags
        return {
            "st_mode": mode,
            "st_flags": flags,
            "st_ino": node.ino,
            "st_dev": 0,
            "st_nlink": min(nlink, 65535),
            "st_uid": node.uid,
            "st_gid": node.gid,
            "st_size": self._visible_size(node),
            "st_atime": node.atime or 0,
            "st_mtime": node.mtime or 0,
            "st_ctime": node.ctime or 0,
            "st_blocks": node.blocks,
            "st_blksize": max(self.vol.sb.block_size, 65536),
        }

    def chflags(self, path, flags):
        return self._wrap(self._chflags, self._fuse_path(path), flags)

    def _chflags(self, path, flags):
        if self.read_only:
            raise self._err(errno.EROFS)
        self._win_flags[path] = int(flags) & 0xFFFFFFFF
        return 0

    def readdir(self, path, fh):
        return self._wrap(self._readdir, self._fuse_path(path))

    def _readdir(self, path):
        node = self._node(path)
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
        if writing:
            self._ro()
        try:
            node = self._node(path)
        except FileNotFoundError:
            if not creat:
                raise
            self._create(path, None)
            return 0
        if excl and creat:
            raise self._err(errno.EEXIST)
        if trunc:
            if node.is_dir:
                raise self._err(errno.EISDIR)
            self._discard_wb(node.ino)
            set_file_size(self.vol, node, 0)
        return 0

    def mknod(self, path, mode, dev):
        self._ro()
        if stat.S_ISDIR(mode):
            return self.mkdir(path, mode)
        return self.create(path, mode)

    def _discard_wb(self, ino: int) -> None:
        if self._wb and self._wb[0] == ino:
            self._wb = None
            self._ra = None
        elif self._wb:
            self._wb_flush()
            self._ra = None
        else:
            self._ra = None

    def _lookup(self, path):
        return self._node(path)

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
            self._drop_paths()
            parent, name = lookup_parent(self.vol, path)
            # Windows has no POSIX execute-bit semantics. Use the volume's
            # Linux/Steam Deck default mode rather than letting WinFsp's
            # synthetic 0644/0666 mode make native binaries non-executable.
            create_empty_file(self.vol, parent, name, None)
            return 0
        if node.is_dir:
            raise self._err(errno.EISDIR)
        self._discard_wb(node.ino)
        self._apply_linux_defaults(node, directory=False)
        self._drop_paths()
        set_file_size(self.vol, self.vol.read_inode(node.ino), 0)
        return 0

    def mkdir(self, path, mode):
        self._ro()
        return self._wrap(self._mkdir, self._fuse_path(path))

    def _mkdir(self, path):
        try:
            node = lookup_path(self.vol, path)
            if node.is_dir:
                self._apply_linux_defaults(node, directory=True)
                return 0
            raise self._err(errno.EEXIST)
        except FileNotFoundError:
            self._drop_paths()
            parent, name = lookup_parent(self.vol, path)
            mkdir(self.vol, parent, name)

    def unlink(self, path):
        self._ro()
        return self._wrap(self._unlink, self._fuse_path(path))

    def rmdir(self, path):
        self._ro()
        return self._wrap(self._unlink, self._fuse_path(path))

    def _unlink(self, path):
        self._drop_paths()
        parent, name = lookup_parent(self.vol, path)
        unlink_checked(self.vol, parent, name)

    def _purge_trash_tree(self, path: str) -> None:
        """Permanently remove a freedesktop trash tree when Windows deletes it."""
        try:
            node = lookup_path(self.vol, path)
        except FileNotFoundError:
            return
        if not node.is_dir:
            parent, name = lookup_parent(self.vol, path)
            unlink_checked(self.vol, parent, name)
            return
        for ent in list(list_dir(self.vol, node)):
            if ent.name in (".", ".."):
                continue
            child = path.rstrip("/") + "/" + ent.name
            self._purge_trash_tree(child)
            node = self.vol.read_inode(node.ino)
        if path != "/":
            parent, name = lookup_parent(self.vol, path)
            unlink_checked(self.vol, parent, name)

    def _maybe_empty_linux_trash(self, path: str) -> None:
        # Linux/Steam Deck freedesktop trash lives at .Trash-<uid>. When
        # Explorer deletes that trash directory, do not translate the request
        # into another recycle/rename cycle: permanently unlink its files and
        # matching .trashinfo metadata so space is actually returned.
        norm = path.rstrip("/")
        leaf = norm.rsplit("/", 1)[-1]
        if not (leaf.startswith(".Trash-") and leaf[7:].isdigit()):
            return
        self._purge_trash_tree(norm)
        self.vol.commit_metadata(sync=True)

    def rename(self, old, new):
        self._ro()
        return self._wrap(self._rename, self._fuse_path(old), self._fuse_path(new))

    def _rename(self, old, new):
        self._drop_paths()
        # A Windows shell delete may arrive as a rename into $RECYCLE.BIN.
        # Preserve normal Windows semantics, but if the source itself is a
        # Linux freedesktop trash directory, empty it instead of nesting one
        # trash system inside the other.
        leaf = old.rstrip("/").rsplit("/", 1)[-1]
        if leaf.startswith(".Trash-") and leaf[7:].isdigit() and "$RECYCLE.BIN" in new.upper():
            self._maybe_empty_linux_trash(old)
            return
        move_entry(self.vol, old, new, True)

    def read(self, path, size, offset, fh):
        return self._wrap(self._read, self._fuse_path(path), size, offset)

    def _read(self, path, size, offset):
        node = self._node(path)
        if self._wb and self._wb[0] == node.ino:
            self._wb_flush()
            node = self.vol.read_inode(node.ino)
        if size <= 0 or offset >= node.size:
            return b""
        ra = self._ra
        if ra and ra[0] == node.ino and ra[1] <= offset and offset + size <= ra[1] + len(ra[2]):
            rel = offset - ra[1]
            return ra[2][rel : rel + size]
        need = min(size, node.size - offset)
        fetch = need
        if need < 1024 * 1024:
            fetch = min(1024 * 1024, node.size - offset)
        data = read_range(self.vol, node, offset, fetch)
        if fetch > need and len(data) > need:
            self._ra = (node.ino, offset, data)
            return data[:need]
        self._ra = None
        return data

    def write(self, path, data, offset, fh):
        self._ro()
        return self._wrap(self._write, self._fuse_path(path), data, offset)

    def _write(self, path, data, offset):
        self._ra = None
        node = self._node(path)
        if isinstance(data, memoryview):
            data = data.tobytes()
        elif not isinstance(data, bytes):
            data = bytes(data)
        wb = self._wb
        if (
            wb
            and wb[0] == node.ino
            and wb[1] + len(wb[2]) == offset
            and len(wb[2]) + len(data) <= 1024 * 1024
        ):
            wb[2].extend(data)
            return len(data)
        self._wb_flush()
        if len(data) >= 1024 * 1024:
            node = self.vol.read_inode(node.ino)
            return write_range(self.vol, node, offset, data, flush=False)
        self._wb = [node.ino, offset, bytearray(data)]
        return len(data)

    def truncate(self, path, length, fh=None):
        self._ro()
        return self._wrap(self._truncate, self._fuse_path(path), length)

    def _truncate(self, path, length):
        node = self._node(path)
        self._discard_wb(node.ino)
        set_file_size(self.vol, self.vol.read_inode(node.ino), length)

    def _flush_file(self, sync: bool) -> int:
        self._ensure_write_healthy()
        try:
            self._wb_flush()
            # fsync/release is a durability boundary for this file, not a whole
            # filesystem unmount boundary. Commit the current JBD2 transaction
            # but keep the write session alive. sync_pending()/close() performs
            # the final journal-empty + EXT4_VALID_FS transition once.
            self.vol.commit_metadata(sync=sync)
        except Exception as exc:
            self._latch_write_failure(exc, "fsync" if sync else "flush")
            raise
        if sync:
            LOG.debug("파일 데이터/메타데이터 durable commit 성공")
        return 0

    def flush(self, path, fh):
        return self._wrap(self._flush_file, False)

    def fsync(self, path, datasync, fh):
        return self._wrap(self._flush_file, True)

    def release(self, path, fh):
        # Never swallow the final write/flush error. Explorer must receive EIO
        # instead of reporting a successful copy when the device did not commit.
        return self._wrap(self._flush_file, True)

    def chmod(self, path, mode):
        return 0

    def chown(self, path, uid, gid):
        return 0

    def utimens(self, path, times=None):
        self._ro()
        return self._wrap(self._utimens, self._fuse_path(path), times)

    def _utimens(self, path, times):
        node = self._node(path)
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
        return self._wrap(self._flush_file, True)

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
    sync_error: BaseException | None = None
    close_error: BaseException | None = None

    # Flush before asking WinFsp to stop. If a write error is already latched,
    # do not execute the same known-failing barrier again just to print another
    # traceback; preserve the original failure and tear the mount down safely.
    if session and session.ops is not None:
        latched = session.ops._write_failure
        if latched is not None:
            sync_error = latched
            LOG.error(
                "이전 쓰기 오류가 남아 있어 최종 flush 재시도를 생략합니다 %s: %s",
                letter,
                latched,
            )
        elif not session.read_only:
            try:
                session.ops.sync_pending()
                session.volume.finish_write_session()
            except Exception as exc:
                sync_error = exc
                LOG.error(
                    "언마운트 전 최종 디스크 flush/clean 처리 실패 %s: %s",
                    letter,
                    exc,
                )

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
            session.volume.close(abort=sync_error is not None)
        except Exception as exc:
            close_error = exc
            LOG.error("언마운트 중 볼륨 close 실패 %s: %s", letter, exc)

    failure = sync_error or close_error
    if failure is not None:
        raise IoError(
            f"{letter} 연결 해제 중 마지막 디스크 반영이 실패했습니다: {failure}",
            winerr=getattr(failure, "winerr", 0) or 0,
        ) from failure
    if not gone:
        raise RuntimeError(f"{letter} 드라이브 연결을 완전히 해제하지 못했습니다.")


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


def _drive_letter_registered(letter: str) -> tuple[bool, str]:
    """Return whether Windows has registered the WinFsp drive letter.

    os.path.exists('X:\\') can lag behind mount-manager registration while
    WinFsp is still finishing startup. QueryDosDevice is the authoritative
    signal that the drive letter exists and avoids tearing down a healthy mount
    merely because Explorer/root probing took longer than eight seconds.
    """
    import ctypes
    from ctypes import wintypes

    root = normalize_drive_letter(letter)
    buf = ctypes.create_unicode_buffer(512)
    kernel32 = ctypes.windll.kernel32
    kernel32.QueryDosDeviceW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    kernel32.QueryDosDeviceW.restype = wintypes.DWORD
    n = kernel32.QueryDosDeviceW(root, buf, 512)
    if not n:
        return False, ""
    target = buf.value or ""
    return True, target


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


_WINFSP_STAT_EX = False


def _conn_addr(conn) -> int:
    if conn is None:
        return 0
    if isinstance(conn, int):
        return conn
    value = getattr(conn, "value", None)
    if isinstance(value, int):
        return value
    try:
        return int(ctypes.cast(conn, ctypes.c_void_p).value or 0)
    except (TypeError, ValueError):
        return 0


def _install_winfsp_stat_ex(FUSE) -> None:
    """Teach fusepy the WinFsp chflags slot and fuse_stat_ex.st_flags."""
    global _WINFSP_STAT_EX
    if _WINFSP_STAT_EX:
        return
    import fuse as fuse_mod

    fields = list(fuse_mod.fuse_operations._fields_)
    if not any(name == "chflags" for name, *_rest in fields):
        gaps = (
            "poll",
            "write_buf",
            "read_buf",
            "flock",
            "fallocate",
            "getpath",
            "reserved01",
            "reserved02",
            "statfs_x",
            "setvolname",
            "exchange",
            "getxtimes",
            "setbkuptime",
            "setchgtime",
            "setcrtime",
        )
        fields.extend((name, ctypes.c_void_p) for name in gaps)
        fields.append(
            ("chflags", ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32))
        )

        class fuse_operations_ex(ctypes.Structure):
            _fields_ = fields

        # fusepy looks this name up when the mount starts. The stock struct
        # stops before WinFsp's chflags slot, so attributes never persist.
        fuse_mod.fuse_operations = fuse_operations_ex

    orig_init = FUSE.init

    def init(self, conn):
        self._stat_ex = False
        addr = _conn_addr(conn)
        try:
            if addr:
                capable = ctypes.c_uint.from_address(addr + 20).value
                if capable & _FSP_CAP_STAT_EX:
                    want = ctypes.c_uint.from_address(addr + 24)
                    want.value |= _FSP_CAP_STAT_EX
                    self._stat_ex = True
        except Exception:
            LOG.exception("파일 속성 확장(STAT_EX)을 켜지 못했습니다")
        if not self._stat_ex:
            LOG.warning("WinFsp가 확장 속성을 받지 않습니다. 숨김/시스템 속성이 빠질 수 있습니다.")
        return orig_init(self, conn)

    FUSE.init = init

    orig_fgetattr = FUSE.fgetattr

    def fgetattr(self, path, buf, fip):
        rc = orig_fgetattr(self, path, buf, fip)
        if rc == 0 and getattr(self, "_stat_ex", False):
            flags = int(getattr(self.operations, "_st_flags", 0) or 0) & 0xFFFFFFFF
            extra = ctypes.addressof(buf.contents) + ctypes.sizeof(fuse_mod.c_stat)
            ctypes.memset(extra, 0, 32)
            ctypes.c_uint32.from_address(extra).value = flags
        return rc

    FUSE.fgetattr = fgetattr

    def chflags(self, path, flags):
        decoded = path.decode(self.encoding) if isinstance(path, bytes) else path
        return self.operations("chflags", decoded, flags)

    FUSE.chflags = chflags
    _WINFSP_STAT_EX = True


def _run_fuse(ops, letter: str, label: str, read_only: bool, session: MountSession) -> None:
    FUSE, _FuseOSError, Operations = _ensure_fuse()
    _install_winfsp_stat_ex(FUSE)

    class EXT4FS(Ext4FuseOps, Operations):
        pass

    bound = EXT4FS(ops.vol, read_only)
    bound._stop = session.stop
    session.ops = bound
    mountpoint = _fuse_mountpoint(letter)
    bs = bound.vol.sb.block_size
    sector = 4096 if bs >= 4096 else 512
    kwargs = {
        "foreground": True,
        "nothreads": True,
        "uid": -1,
        "gid": -1,
        "umask": 0,
        "volname": _safe_volname(label),
        "fsname": "fuse",
        "FileSecurity": "D:P(A;;FA;;;WD)",
        # 64KB clusters let Windows ask for larger reads and writes.
        "SectorSize": sector,
        "SectorsPerAllocationUnit": 65536 // sector,
        "FileInfoTimeout": 2000,
        "DirInfoTimeout": 2000,
        "VolumeInfoTimeout": 2000,
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
        if session.stop.is_set():
            LOG.info("FUSE 정상 종료 mount=%s", letter)
            return
        registered, target = _drive_letter_registered(letter)
        if session.error is None and not registered:
            session.error = RuntimeError(
                f"WinFsp가 종료되었고 {letter} 드라이브 등록도 없습니다."
            )
            LOG.error(
                "FUSE가 예기치 않게 반환됨 mount=%s registered=%s target=%s",
                letter,
                registered,
                target,
            )
    except Exception as exc:
        if session.stop.is_set():
            # WinFsp/fusepy commonly reports RuntimeError(1) when the host is
            # deliberately stopped. This is an expected teardown result, not a
            # filesystem failure and should not flood the user log.
            LOG.info("FUSE 종료 확인 mount=%s (%s)", letter, exc)
            return
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
        if not read_only:
            # Keep the medium clean until the first real mutation. require_write()
            # lazily opens a dirty/JBD2 session, and fsync/release closes it again.
            LOG.info("쓰기 마운트 준비: 첫 실제 쓰기 전까지 EXT4 clean 상태 유지")
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
        deadline = time.time() + 20
        root = cand + "\\"
        registered_at: float | None = None
        registered_target = ""
        while time.time() < deadline:
            if session.error:
                break
            registered, target = _drive_letter_registered(cand)
            if registered:
                registered_target = target
                if registered_at is None:
                    registered_at = time.time()
                    LOG.info(
                        "WinFsp 드라이브 문자 등록 확인 %s target=%s",
                        cand,
                        target,
                    )
                # Prefer a fully probeable root, but do not tear down a valid
                # WinFsp registration just because shell/path visibility lags.
                if os.path.exists(root) or time.time() - registered_at >= 1.5:
                    LOG.info(
                        "마운트 성공 %s root_visible=%s target=%s",
                        cand,
                        os.path.exists(root),
                        registered_target,
                    )
                    _log_drive(cand)
                    return session
            elif not session.thread.is_alive() and session.error is None:
                last_error = RuntimeError("WinFsp mount thread가 드라이브 등록 전에 종료되었습니다.")
                break
            time.sleep(0.12)

        registered, target = _drive_letter_registered(cand)
        if registered and session.error is None:
            LOG.info(
                "마운트 성공 %s (지연 등록) root_visible=%s target=%s",
                cand,
                os.path.exists(root),
                target,
            )
            _log_drive(cand)
            return session
        last_error = session.error or locals().get("last_error")
        LOG.error(
            "마운트 실패 %s error=%s registered=%s target=%s",
            cand,
            last_error,
            registered,
            target,
        )
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
