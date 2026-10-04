"""Sector-aligned read/write for disk images and Windows physical drives."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod

# One device transfer. Large enough to hide syscall latency, small enough for USB bridges.
IO_CHUNK = 1024 * 1024


class IoError(OSError):
    def __init__(self, message: str, winerr: int = 0):
        super().__init__(message)
        self.winerr = winerr


class BlockDevice(ABC):
    sector_size: int = 512

    @abstractmethod
    def size(self) -> int:
        ...

    @abstractmethod
    def _raw_read(self, offset: int, length: int) -> bytes:
        ...

    @abstractmethod
    def _raw_write(self, offset: int, data: bytes) -> None:
        ...

    @abstractmethod
    def flush(self) -> None:
        ...

    @abstractmethod
    def close(self) -> None:
        ...

    @property
    def writable(self) -> bool:
        return False

    @property
    def display_path(self) -> str:
        return ""

    def read(self, offset: int, length: int) -> bytes:
        if length <= 0:
            return b""
        ss = self.sector_size
        start = (offset // ss) * ss
        end = ((offset + length + ss - 1) // ss) * ss
        buf = self._raw_read(start, end - start)
        rel = offset - start
        return buf[rel : rel + length]

    def write(self, offset: int, data: bytes | bytearray) -> None:
        if not data:
            return
        if not self.writable:
            raise IoError("읽기 전용으로 열려 있습니다.")
        ss = self.sector_size
        data = bytes(data)
        start = (offset // ss) * ss
        end = ((offset + len(data) + ss - 1) // ss) * ss
        span = end - start
        if start == offset and span == len(data):
            cached = getattr(self, "_sec_key", None)
            if cached is not None:
                c0, clen = cached
                if start < c0 + clen and c0 < start + span:
                    self._sec_key = None
            self._raw_write(start, data)
            return
        key = (start, span)
        cached = getattr(self, "_sec_key", None)
        if cached == key:
            buf = bytearray(self._sec_buf)
        else:
            buf = bytearray(self._raw_read(start, span))
        rel = offset - start
        buf[rel : rel + len(data)] = data
        out = bytes(buf)
        self._raw_write(start, out)
        # Same inode sector is rewritten on every file growth. Keep it so the next
        # read-modify-write does not go back to the device.
        self._sec_key = key
        self._sec_buf = out


class ImageDevice(BlockDevice):
    def __init__(self, path: str, writable: bool = False):
        self.path = path
        self._writable = writable
        mode = "r+b" if writable else "rb"
        self._fp = open(path, mode, buffering=IO_CHUNK)
        self._fp.seek(0, os.SEEK_END)
        self._size = self._fp.tell()
        self.sector_size = 512
        self._closed = False

    @property
    def writable(self) -> bool:
        return self._writable

    @property
    def display_path(self) -> str:
        return self.path

    def size(self) -> int:
        return self._size

    def _raw_read(self, offset: int, length: int) -> bytes:
        if offset + length > self._size:
            length = max(0, self._size - offset)
        self._fp.seek(offset)
        data = self._fp.read(length)
        if len(data) < length:
            data += b"\x00" * (length - len(data))
        return data

    def _raw_write(self, offset: int, data: bytes) -> None:
        self._fp.seek(offset)
        self._fp.write(data)

    def flush(self) -> None:
        self._fp.flush()
        os.fsync(self._fp.fileno())

    def close(self) -> None:
        if not self._closed:
            try:
                self._fp.close()
            finally:
                self._closed = True

    def __enter__(self) -> "ImageDevice":
        return self

    def __exit__(self, *args) -> None:
        self.close()
