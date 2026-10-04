"""Locate the app, and when running from source copy Ext4Reader.exe for WinFsp."""

from __future__ import annotations

import os
import shutil
import sys


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def project_root() -> str:
    if is_frozen():
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def is_store_python(path: str) -> bool:
    p = os.path.normcase(path)
    return "windowsapps" in p or "\\microsoft\\windowsapps\\" in p


def host_exe_path() -> str:
    exe = sys.executable
    folder = os.path.dirname(os.path.abspath(exe))
    return os.path.join(folder, "Ext4Reader.exe")


def app_exe() -> str:
    if is_frozen():
        return os.path.abspath(sys.executable)
    return ensure_host_exe()


def ensure_host_exe() -> str:
    if is_frozen():
        return os.path.abspath(sys.executable)
    src = os.path.abspath(sys.executable)
    dst = host_exe_path()
    if is_store_python(src):
        raise RuntimeError(
            "Microsoft Store용 Python이 실행되었습니다.\n"
            "run_as_admin.bat 으로 다시 시작해 주세요."
        )
    if os.path.normcase(os.path.basename(src)) == "ext4reader.exe":
        return src
    try:
        if (not os.path.isfile(dst)) or (os.path.getmtime(src) > os.path.getmtime(dst)):
            shutil.copy2(src, dst)
    except OSError:
        return src
    return dst


def relaunch_as_host() -> None:
    if is_frozen():
        os.environ["EXT4READER_HOST"] = "1"
        return
    if os.environ.get("EXT4READER_HOST") == "1":
        return
    if os.path.normcase(os.path.basename(sys.executable)) == "ext4reader.exe":
        os.environ["EXT4READER_HOST"] = "1"
        return
    host = ensure_host_exe()
    if os.path.normcase(host) == os.path.normcase(sys.executable):
        return
    root = project_root()
    os.chdir(root)
    env = os.environ.copy()
    env["EXT4READER_HOST"] = "1"
    env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
    os.execve(host, [host, os.path.join(root, "main.py"), *sys.argv[1:]], env)
