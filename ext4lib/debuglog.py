"""Console + in-app logging so errors can be copied."""

from __future__ import annotations

import logging
import os
import sys
import traceback

LOG = logging.getLogger("ext4reader")
_configured = False


def exception_chain(exc: BaseException) -> str:
    lines: list[str] = []
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        lines.append(f"{type(cur).__name__}: {cur}")
        cur = cur.__cause__ if cur.__cause__ is not None else cur.__context__
    return "\n".join(lines)


def format_traceback(exc: BaseException | None = None) -> str:
    if exc is None:
        return traceback.format_exc()
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


def want_console() -> bool:
    if os.environ.get("EXT4READER_CONSOLE") == "1":
        return True
    if getattr(sys, "frozen", False):
        return False
    return True


def log_file_path() -> str | None:
    if not getattr(sys, "frozen", False):
        return None
    base = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "Ext4Reader")
    try:
        os.makedirs(base, exist_ok=True)
        return os.path.join(base, "Ext4Reader.log")
    except OSError:
        return None


def ensure_console() -> None:
    if sys.platform != "win32":
        return
    if not want_console():
        return
    import ctypes

    kernel32 = ctypes.windll.kernel32
    kernel32.SetConsoleOutputCP(65001)
    try:
        kernel32.SetConsoleTitleW("EXT4 Reader 로그")
    except Exception:
        pass
    if kernel32.GetConsoleWindow():
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
        return
    if not kernel32.AllocConsole():
        return
    kernel32.SetConsoleOutputCP(65001)
    try:
        kernel32.SetConsoleTitleW("EXT4 Reader 로그")
    except Exception:
        pass
    sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="replace", buffering=1)
    sys.stderr = open("CONOUT$", "w", encoding="utf-8", errors="replace", buffering=1)
    try:
        sys.stdin = open("CONIN$", "r", encoding="utf-8", errors="replace")
    except OSError:
        pass


class QueueHandler(logging.Handler):
    def __init__(self, queue):
        super().__init__()
        self.queue = queue

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.queue.put(self.format(record))
        except Exception:
            pass


def setup_logging(queue=None) -> logging.Logger:
    global _configured
    if want_console():
        ensure_console()
    LOG.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
    if sys.stderr is not None and not any(
        isinstance(h, logging.StreamHandler) and not isinstance(h, QueueHandler) for h in LOG.handlers
    ):
        stream = logging.StreamHandler(sys.stderr)
        stream.setFormatter(fmt)

        def _emit(record, handler=stream):
            logging.StreamHandler.emit(handler, record)
            handler.flush()

        stream.emit = _emit  # type: ignore[method-assign]
        LOG.addHandler(stream)
    log_path = log_file_path()
    if log_path and not any(isinstance(h, logging.FileHandler) for h in LOG.handlers):
        try:
            fh = logging.FileHandler(log_path, encoding="utf-8")
            fh.setFormatter(fmt)
            LOG.addHandler(fh)
        except OSError:
            pass
    if queue is not None and not any(isinstance(h, QueueHandler) for h in LOG.handlers):
        qh = QueueHandler(queue)
        qh.setFormatter(fmt)
        LOG.addHandler(qh)
    LOG.propagate = False
    if not _configured:
        _configured = True
        from ext4lib import __version__
        from ext4lib.windows.disk import is_admin

        LOG.info("==== EXT4 Reader %s ====", __version__)
        LOG.info("pid=%s admin=%s frozen=%s", os.getpid(), "yes" if is_admin() else "no", getattr(sys, "frozen", False))
        LOG.info("exe=%s", sys.executable)
        LOG.info("cwd=%s", os.getcwd())
        LOG.info("argv=%s", sys.argv)
        if log_path:
            LOG.info("logfile=%s", log_path)
    return LOG
