"""CRC32C (Castagnoli) matching the Linux kernel / e2fsprogs incremental API."""

from __future__ import annotations

_POLY = 0x82F63B78


def _build_table() -> tuple[int, ...]:
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ _POLY
            else:
                crc >>= 1
        table.append(crc & 0xFFFFFFFF)
    return tuple(table)


_TABLE = _build_table()


def crc32c(crc: int, data: bytes | bytearray | memoryview) -> int:
    """Linux-style crc32c(crc, buf, len): no final XOR."""
    crc &= 0xFFFFFFFF
    table = _TABLE
    for byte in data:
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc & 0xFFFFFFFF


def crc32c_seed(uuid16: bytes) -> int:
    return crc32c(0xFFFFFFFF, uuid16)
