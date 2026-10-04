"""Windows Explorer drag-and-drop onto a Tk window (WM_DROPFILES)."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from collections.abc import Callable

WM_DROPFILES = 0x0233
GWL_WNDPROC = -4

user32 = ctypes.windll.user32
shell32 = ctypes.windll.shell32

LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

user32.GetParent.argtypes = [wintypes.HWND]
user32.GetParent.restype = wintypes.HWND
user32.DragAcceptFiles = shell32.DragAcceptFiles
shell32.DragAcceptFiles.argtypes = [wintypes.HWND, wintypes.BOOL]
shell32.DragQueryFileW.argtypes = [wintypes.HANDLE, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT]
shell32.DragQueryFileW.restype = wintypes.UINT
shell32.DragFinish.argtypes = [wintypes.HANDLE]

user32.GetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int]
user32.GetWindowLongPtrW.restype = ctypes.c_void_p
user32.SetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
user32.SetWindowLongPtrW.restype = ctypes.c_void_p
user32.CallWindowProcW.argtypes = [ctypes.c_void_p, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.CallWindowProcW.restype = LRESULT


def _hwnd_of(widget) -> int:
    hwnd = widget.winfo_id()
    parent = user32.GetParent(hwnd)
    return parent or hwnd


def _parse_drop(hdrop) -> list[str]:
    count = shell32.DragQueryFileW(hdrop, 0xFFFFFFFF, None, 0)
    files: list[str] = []
    buf = ctypes.create_unicode_buffer(32768)
    for i in range(count):
        n = shell32.DragQueryFileW(hdrop, i, buf, 32768)
        if n:
            files.append(buf.value)
    return files


class DropTarget:
    def __init__(self, widget, callback: Callable[[list[str]], None]):
        self.widget = widget
        self.callback = callback
        self.hwnd = _hwnd_of(widget)
        self._old = user32.GetWindowLongPtrW(self.hwnd, GWL_WNDPROC)

        def _proc(hwnd, msg, wparam, lparam):
            if msg == WM_DROPFILES:
                try:
                    files = _parse_drop(wparam)
                finally:
                    shell32.DragFinish(wparam)
                if files:
                    widget.after(0, lambda f=files: callback(f))
                return 0
            return user32.CallWindowProcW(self._old, hwnd, msg, wparam, lparam)

        self._wndproc = WNDPROC(_proc)
        user32.SetWindowLongPtrW(self.hwnd, GWL_WNDPROC, ctypes.cast(self._wndproc, ctypes.c_void_p).value)
        shell32.DragAcceptFiles(self.hwnd, True)

    def close(self) -> None:
        try:
            shell32.DragAcceptFiles(self.hwnd, False)
            if self._old:
                user32.SetWindowLongPtrW(self.hwnd, GWL_WNDPROC, self._old)
        except Exception:
            pass
