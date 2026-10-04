"""LocalSystem raw-write helper for reader drivers that reject administrator I/O.

The GUI process keeps the matching EXT4 volume locked. When every normal
user-mode raw-write path returns ACCESS_DENIED, it schedules this same EXE as
NT AUTHORITY\\SYSTEM and asks the helper process to duplicate the already-open
volume/PhysicalDrive handles. This preserves the parent's volume lock while
raising only the security context used for the actual I/O request.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from ctypes import wintypes

from ext4lib.io.backend import IoError

PROCESS_DUP_HANDLE = 0x0040
DUPLICATE_SAME_ACCESS = 0x00000002
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
MAX_WRITE = 1024 * 1024
_PHYSICAL_RE = re.compile(r"^\\\\\.\\PhysicalDrive(\d+)$", re.IGNORECASE)


def _program_data_dir() -> str:
    root = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
    path = os.path.join(root, "Ext4Reader", "RawHelper")
    os.makedirs(path, exist_ok=True)
    return path


def _task_run_command(exe: str, request_path: str) -> str:
    return f'"{exe}" --raw-helper-request "{request_path}"'


def _system_helper_exe(source_exe: str) -> str:
    """Run SYSTEM work from a verified copy, not the live PyInstaller image.

    This avoids a second one-file PyInstaller process reopening the exact EXE
    that the GUI may still lazily import modules from.
    """
    source = os.path.abspath(source_exe)
    with open(source, "rb") as fp:
        digest = hashlib.sha256(fp.read()).hexdigest()[:16]
    target = os.path.join(_program_data_dir(), f"Ext4Reader-System-{digest}.exe")
    if not os.path.isfile(target) or os.path.getsize(target) != os.path.getsize(source):
        tmp = target + ".tmp"
        shutil.copy2(source, tmp)
        os.replace(tmp, target)
    return target


def _run_hidden(args: list[str], timeout: float = 15.0) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=CREATE_NO_WINDOW,
    )


def _safe_unlink(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def run_system_raw_write(
    *,
    physical_path: str,
    parent_pid: int,
    physical_handle: int,
    volume_handle: int | None,
    relative_offset: int,
    absolute_offset: int,
    partition_offset: int,
    partition_size: int,
    data: bytes,
    sector_size: int,
    try_disk_offline: bool = False,
    timeout: float = 25.0,
) -> dict:
    """Run one raw-write attempt in a LocalSystem scheduled task."""
    from ext4lib.debuglog import LOG
    from ext4lib.host import app_exe

    if not _PHYSICAL_RE.match(physical_path):
        raise IoError(f"지원하지 않는 raw 장치 경로: {physical_path}", winerr=87)
    if not data or len(data) > MAX_WRITE:
        raise IoError(f"SYSTEM helper 쓰기 크기 오류: {len(data)}", winerr=87)
    if sector_size <= 0 or absolute_offset % sector_size or len(data) % sector_size:
        raise IoError(
            f"SYSTEM helper 정렬 오류 offset={absolute_offset} len={len(data)} sector={sector_size}",
            winerr=87,
        )

    token = uuid.uuid4().hex
    base = os.path.join(_program_data_dir(), f"raw-{token}")
    request_path = base + ".json"
    result_path = base + ".result.json"
    task_name = rf"\Ext4Reader\RawWrite_{token[:16]}"

    request = {
        "version": 1,
        "physical_path": physical_path,
        "parent_pid": int(parent_pid),
        "physical_handle": int(physical_handle),
        "volume_handle": int(volume_handle) if volume_handle is not None else None,
        "relative_offset": int(relative_offset),
        "absolute_offset": int(absolute_offset),
        "partition_offset": int(partition_offset),
        "partition_size": int(partition_size),
        "sector_size": int(sector_size),
        "try_disk_offline": bool(try_disk_offline),
        "data_b64": base64.b64encode(data).decode("ascii"),
        "sha256": hashlib.sha256(data).hexdigest(),
        "result_path": result_path,
        "token": token,
    }

    with open(request_path, "w", encoding="utf-8") as fp:
        json.dump(request, fp, ensure_ascii=False)

    exe = _system_helper_exe(os.path.abspath(app_exe()))
    task_run = _task_run_command(exe, request_path)
    LOG.warning(
        "SYSTEM raw helper 시작 path=%s offset=%s len=%s volume_handle=%s",
        physical_path,
        absolute_offset,
        len(data),
        volume_handle,
    )

    create_cmd = [
        "schtasks.exe",
        "/Create",
        "/TN",
        task_name,
        "/TR",
        task_run,
        "/SC",
        "DAILY",
        "/ST",
        "00:00",
        "/RU",
        "SYSTEM",
        "/RL",
        "HIGHEST",
        "/F",
    ]

    try:
        created = _run_hidden(create_cmd)
        if created.returncode != 0:
            msg = (created.stderr or created.stdout or "").strip()
            raise IoError(f"SYSTEM helper 작업 생성 실패: {msg}", winerr=5)

        started = _run_hidden(["schtasks.exe", "/Run", "/TN", task_name])
        if started.returncode != 0:
            msg = (started.stderr or started.stdout or "").strip()
            raise IoError(f"SYSTEM helper 작업 시작 실패: {msg}", winerr=5)

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if os.path.isfile(result_path):
                try:
                    with open(result_path, "r", encoding="utf-8") as fp:
                        result = json.load(fp)
                except (OSError, ValueError) as exc:
                    raise IoError(f"SYSTEM helper 결과 읽기 실패: {exc}", winerr=13)
                if result.get("token") != token:
                    raise IoError("SYSTEM helper 결과 토큰 불일치", winerr=5)
                return result
            time.sleep(0.1)

        query = _run_hidden(
            ["schtasks.exe", "/Query", "/TN", task_name, "/V", "/FO", "LIST"],
            timeout=5.0,
        )
        detail = (query.stdout or query.stderr or "").strip()
        raise IoError(
            "SYSTEM helper 시간 초과" + (f": {detail[-800:]}" if detail else ""),
            winerr=1460,
        )
    finally:
        try:
            _run_hidden(["schtasks.exe", "/Delete", "/TN", task_name, "/F"], timeout=5.0)
        except Exception:
            pass
        _safe_unlink(request_path)
        _safe_unlink(result_path)


def _duplicate_handle(parent_pid: int, source_value: int) -> int:
    from ext4lib.windows.disk import kernel32

    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.DuplicateHandle.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    kernel32.DuplicateHandle.restype = wintypes.BOOL

    process = kernel32.OpenProcess(PROCESS_DUP_HANDLE, False, int(parent_pid))
    if not process:
        raise IoError(
            f"SYSTEM helper parent process 열기 실패 pid={parent_pid} Win32={ctypes.get_last_error()}",
            winerr=ctypes.get_last_error(),
        )
    try:
        target = wintypes.HANDLE()
        ctypes.set_last_error(0)
        ok = kernel32.DuplicateHandle(
            process,
            wintypes.HANDLE(int(source_value)),
            kernel32.GetCurrentProcess(),
            ctypes.byref(target),
            0,
            False,
            DUPLICATE_SAME_ACCESS,
        )
        if not ok:
            err = ctypes.get_last_error()
            raise IoError(
                f"SYSTEM helper handle 복제 실패 handle={source_value} Win32={err}",
                winerr=err,
            )
        return int(target.value)
    finally:
        kernel32.CloseHandle(process)


def _write_win32(handle: int, offset: int, data: bytes) -> None:
    from ext4lib.windows.disk import FILE_BEGIN, kernel32

    pos = ctypes.c_longlong()
    ctypes.set_last_error(0)
    if not kernel32.SetFilePointerEx(
        wintypes.HANDLE(handle),
        int(offset),
        ctypes.byref(pos),
        FILE_BEGIN,
    ):
        err = ctypes.get_last_error()
        raise IoError(f"SYSTEM Win32 seek 실패 offset={offset} Win32={err}", winerr=err)

    done = wintypes.DWORD()
    buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
    ctypes.set_last_error(0)
    ok = kernel32.WriteFile(
        wintypes.HANDLE(handle),
        buf,
        len(data),
        ctypes.byref(done),
        None,
    )
    err = ctypes.get_last_error()
    if not ok or done.value != len(data):
        raise IoError(
            f"SYSTEM Win32 WriteFile 실패 offset={offset} "
            f"{done.value}/{len(data)} Win32={err}",
            winerr=err,
        )
    kernel32.FlushFileBuffers(wintypes.HANDLE(handle))


def _write_nt(handle: int, offset: int, data: bytes) -> None:
    from ext4lib.windows.disk import (
        _IO_STATUS_BLOCK,
        _nt_status_hex,
        _nt_success,
        ntdll,
    )

    iosb = _IO_STATUS_BLOCK()
    nt_offset = ctypes.c_longlong(int(offset))
    buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
    status = ntdll.NtWriteFile(
        wintypes.HANDLE(handle),
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
            f"SYSTEM NtWriteFile 실패 offset={offset} len={len(data)} "
            f"NTSTATUS={_nt_status_hex(status)} Win32={dos}",
            winerr=dos,
        )
    if int(iosb.Information) != len(data):
        raise IoError(
            f"SYSTEM NtWriteFile 짧은 쓰기 offset={offset} "
            f"{int(iosb.Information)}/{len(data)}",
            winerr=23,
        )
    flush_iosb = _IO_STATUS_BLOCK()
    ntdll.NtFlushBuffersFile(wintypes.HANDLE(handle), ctypes.byref(flush_iosb))


def _read_win32(handle: int, offset: int, length: int) -> bytes:
    from ext4lib.windows.disk import FILE_BEGIN, kernel32

    pos = ctypes.c_longlong()
    if not kernel32.SetFilePointerEx(
        wintypes.HANDLE(handle),
        int(offset),
        ctypes.byref(pos),
        FILE_BEGIN,
    ):
        err = ctypes.get_last_error()
        raise IoError(f"SYSTEM read seek 실패 offset={offset} Win32={err}", winerr=err)

    done = wintypes.DWORD()
    buf = ctypes.create_string_buffer(length)
    ctypes.set_last_error(0)
    ok = kernel32.ReadFile(
        wintypes.HANDLE(handle),
        buf,
        length,
        ctypes.byref(done),
        None,
    )
    err = ctypes.get_last_error()
    if not ok or done.value != length:
        raise IoError(
            f"SYSTEM read-back 실패 offset={offset} {done.value}/{length} Win32={err}",
            winerr=err,
        )
    return bytes(buf.raw[:length])


def _execute_request(req: dict) -> dict:
    from ext4lib.windows.disk import (
        IOCTL_DISK_UPDATE_PROPERTIES,
        IOCTL_STORAGE_GET_DEVICE_NUMBER,
        STORAGE_DEVICE_NUMBER,
        WindowsPhysicalDevice,
        _enable_storage_privileges,
        _ioctl,
        _nt_open_raw_handle,
        _open_handle,
        _query_storage,
        _set_disk_offline_state,
        _write_unbuffered_raw_path,
        kernel32,
        ntdll,
    )

    path = str(req.get("physical_path") or "")
    if not _PHYSICAL_RE.match(path):
        raise IoError(f"잘못된 PhysicalDrive 경로: {path}", winerr=87)

    parent_pid = int(req["parent_pid"])
    physical_source = int(req["physical_handle"])
    volume_source = req.get("volume_handle")
    relative_offset = int(req["relative_offset"])
    absolute_offset = int(req["absolute_offset"])
    partition_offset = int(req["partition_offset"])
    partition_size = int(req["partition_size"])
    sector_size = int(req["sector_size"])
    try_disk_offline = bool(req.get("try_disk_offline", False))
    data = base64.b64decode(req["data_b64"], validate=True)

    if not data or len(data) > MAX_WRITE:
        raise IoError("SYSTEM helper 데이터 크기 오류", winerr=87)
    if hashlib.sha256(data).hexdigest() != req.get("sha256"):
        raise IoError("SYSTEM helper 데이터 SHA-256 불일치", winerr=13)
    if sector_size <= 0 or absolute_offset % sector_size or len(data) % sector_size:
        raise IoError("SYSTEM helper 쓰기 정렬 오류", winerr=87)
    if partition_offset < 0 or partition_size <= 0:
        raise IoError("SYSTEM helper 파티션 범위 오류", winerr=87)
    if relative_offset < 0 or relative_offset + len(data) > partition_size:
        raise IoError("SYSTEM helper 파티션 밖 쓰기 거부", winerr=87)
    if absolute_offset != partition_offset + relative_offset:
        raise IoError("SYSTEM helper 물리/파티션 오프셋 불일치", winerr=87)

    _enable_storage_privileges()

    handles: list[int] = []
    failures: list[str] = []
    physical_dup = _duplicate_handle(parent_pid, physical_source)
    handles.append(physical_dup)

    _vendor, _product, _bus, removable = _query_storage(wintypes.HANDLE(physical_dup))
    if not removable:
        raise IoError(
            "SYSTEM helper는 removable 저장장치에만 raw write를 허용합니다.",
            winerr=5,
        )

    volume_dup = None
    if volume_source is not None:
        try:
            volume_dup = _duplicate_handle(parent_pid, int(volume_source))
            handles.append(volume_dup)
        except IoError as exc:
            failures.append(str(exc))

    parent_dev_raw = _ioctl(
        wintypes.HANDLE(physical_dup),
        IOCTL_STORAGE_GET_DEVICE_NUMBER,
        out_cb=ctypes.sizeof(STORAGE_DEVICE_NUMBER),
    )
    parent_dev = STORAGE_DEVICE_NUMBER.from_buffer_copy(parent_dev_raw)

    try:
        methods: list[tuple[str, int, int, callable]] = []
        if volume_dup is not None:
            methods.extend(
                [
                    ("SYSTEM duplicated-volume WriteFile", volume_dup, relative_offset, _write_win32),
                    ("SYSTEM duplicated-volume NtWriteFile", volume_dup, relative_offset, _write_nt),
                ]
            )
        methods.extend(
            [
                ("SYSTEM duplicated-PhysicalDrive WriteFile", physical_dup, absolute_offset, _write_win32),
                ("SYSTEM duplicated-PhysicalDrive NtWriteFile", physical_dup, absolute_offset, _write_nt),
            ]
        )

        for name, handle, offset, writer in methods:
            try:
                writer(handle, offset, data)
                if _read_win32(physical_dup, absolute_offset, len(data)) != data:
                    raise IoError(f"{name} read-back 불일치", winerr=23)
                return {"ok": True, "method": name, "disk_offline": False}
            except IoError as exc:
                failures.append(f"{name}: {exc}")

        try:
            logical, physical = _write_unbuffered_raw_path(
                path,
                absolute_offset,
                data,
                sector_size,
                expected_device_number=int(parent_dev.DeviceNumber),
                expected_device_type=int(parent_dev.DeviceType),
            )
            return {
                "ok": True,
                "method": "SYSTEM fresh-PhysicalDrive NO_BUFFERING",
                "disk_offline": False,
                "logical_sector": logical,
                "physical_sector": physical,
            }
        except IoError as exc:
            failures.append(f"SYSTEM fresh NO_BUFFERING: {exc}")

        helper_set_offline = False
        if try_disk_offline:
            ok_offline, err_offline = _set_disk_offline_state(
                wintypes.HANDLE(physical_dup),
                True,
            )
            if ok_offline:
                helper_set_offline = True
                failures.append("SYSTEM whole-disk OFFLINE: success")
            else:
                failures.append(
                    f"SYSTEM whole-disk OFFLINE: Win32={err_offline}"
                )

        if helper_set_offline:
            try:
                logical, physical = _write_unbuffered_raw_path(
                    path,
                    absolute_offset,
                    data,
                    sector_size,
                    expected_device_number=int(parent_dev.DeviceNumber),
                    expected_device_type=int(parent_dev.DeviceType),
                )
                return {
                    "ok": True,
                    "method": "SYSTEM OFFLINE fresh-PhysicalDrive NO_BUFFERING",
                    "disk_offline": True,
                    "logical_sector": logical,
                    "physical_sector": physical,
                }
            except IoError as exc:
                failures.append(f"SYSTEM OFFLINE NO_BUFFERING: {exc}")

        # A duplicated handle preserves the parent's original file object.
        # Create a fresh PhysicalDrive file object as LocalSystem so drivers
        # that make their access decision at IRP_MJ_CREATE see SYSTEM itself.
        fresh = None
        try:
            fresh = _open_handle(path, True)
            fresh_raw = _ioctl(
                fresh,
                IOCTL_STORAGE_GET_DEVICE_NUMBER,
                out_cb=ctypes.sizeof(STORAGE_DEVICE_NUMBER),
            )
            fresh_dev = STORAGE_DEVICE_NUMBER.from_buffer_copy(fresh_raw)
            if (
                int(fresh_dev.DeviceType) != int(parent_dev.DeviceType)
                or int(fresh_dev.DeviceNumber) != int(parent_dev.DeviceNumber)
            ):
                raise IoError("SYSTEM fresh PhysicalDrive 장치 번호 불일치", winerr=5)

            _vendor2, _product2, _bus2, removable2 = _query_storage(fresh)
            if not removable2:
                raise IoError(
                    "SYSTEM fresh PhysicalDrive가 removable 장치가 아닙니다.",
                    winerr=5,
                )

            for name, writer in [
                ("SYSTEM fresh-PhysicalDrive WriteFile", _write_win32),
                ("SYSTEM fresh-PhysicalDrive NtWriteFile(on Win32 handle)", _write_nt),
            ]:
                try:
                    writer(int(fresh), absolute_offset, data)
                    if _read_win32(int(fresh), absolute_offset, len(data)) != data:
                        raise IoError(f"{name} read-back 불일치", winerr=23)
                    return {
                        "ok": True,
                        "method": name,
                        "disk_offline": helper_set_offline,
                    }
                except IoError as exc:
                    failures.append(f"{name}: {exc}")

            nt_handle = None
            try:
                nt_handle = _nt_open_raw_handle(path)
                _write_nt(int(nt_handle.value), absolute_offset, data)
                if _read_win32(int(fresh), absolute_offset, len(data)) != data:
                    raise IoError("SYSTEM fresh NT read-back 불일치", winerr=23)
                return {
                    "ok": True,
                    "method": "SYSTEM fresh-PhysicalDrive NtOpenFile/NtWriteFile",
                    "disk_offline": helper_set_offline,
                }
            except IoError as exc:
                failures.append(f"SYSTEM fresh NtOpenFile/NtWriteFile: {exc}")
            finally:
                if nt_handle is not None:
                    ntdll.NtClose(nt_handle)

            try:
                dev = WindowsPhysicalDevice.__new__(WindowsPhysicalDevice)
                dev._handle = fresh
                dev.sector_size = sector_size
                dev._read_at = lambda off, length: _read_win32(int(fresh), off, length)
                dev._scsi_write10(absolute_offset, data)
                return {
                    "ok": True,
                    "method": "SYSTEM fresh SCSI WRITE(10)",
                    "disk_offline": helper_set_offline,
                }
            except IoError as exc:
                failures.append(f"SYSTEM fresh SCSI WRITE(10): {exc}")
        except IoError as exc:
            failures.append(f"SYSTEM fresh PhysicalDrive open/verify: {exc}")
        finally:
            if fresh is not None:
                kernel32.CloseHandle(fresh)

        if helper_set_offline:
            ok_online, err_online = _set_disk_offline_state(
                wintypes.HANDLE(physical_dup),
                False,
            )
            if ok_online:
                try:
                    _ioctl(
                        wintypes.HANDLE(physical_dup),
                        IOCTL_DISK_UPDATE_PROPERTIES,
                    )
                except OSError:
                    pass
                failures.append("SYSTEM whole-disk ONLINE restore: success")
            else:
                failures.append(
                    f"SYSTEM whole-disk ONLINE restore failed Win32={err_online}"
                )

        return {
            "ok": False,
            "error": " | ".join(failures[-14:]),
            "failures": failures,
            "disk_offline": False,
        }
    finally:
        for handle in handles:
            try:
                kernel32.CloseHandle(wintypes.HANDLE(handle))
            except Exception:
                pass


def run_helper_request(request_path: str) -> int:
    result_path = request_path + ".result.json"
    token = None
    result: dict
    try:
        with open(request_path, "r", encoding="utf-8") as fp:
            req = json.load(fp)
        result_path = str(req.get("result_path") or result_path)
        token = req.get("token")
        result = _execute_request(req)
    except Exception as exc:
        result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    result["token"] = token
    tmp = result_path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fp:
            json.dump(result, fp, ensure_ascii=False)
        os.replace(tmp, result_path)
        return 0 if result.get("ok") else 2
    except OSError:
        return 3
