"""MBR and GPT partition table parsing."""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass

from ext4lib.fs.constants import LINUX_GPT_GUIDS, MBR_LINUX
from ext4lib.io.backend import BlockDevice


@dataclass
class Partition:
    index: int
    start: int
    size: int
    ptype: str
    name: str
    is_linux: bool
    scheme: str


def _guid_from_le(raw: bytes) -> str:
    return str(uuid.UUID(bytes_le=raw)).upper()


def _parse_mbr(dev: BlockDevice, sector: int) -> list[Partition]:
    data = dev.read(0, min(sector, 512) if sector >= 512 else 512)
    if len(data) < 512 or data[510:512] != b"\x55\xaa":
        return []
    parts: list[Partition] = []
    # Protective GPT?
    t0 = data[450]
    if t0 == 0xEE:
        return []

    def add_entry(entry: bytes, idx: int, ebr_base: int, ebr_this: int) -> int | None:
        status, ptype = entry[0], entry[4]
        lba = struct.unpack_from("<I", entry, 8)[0]
        count = struct.unpack_from("<I", entry, 12)[0]
        if ptype == 0 or count == 0:
            return None
        if ptype in (0x05, 0x0F, 0x85):
            next_lba = lba + (ebr_base if ebr_base else 0)
            if ebr_this:
                next_lba = ebr_base + lba
            return next_lba
        start = (ebr_this if ebr_this else 0) + lba * sector
        # For primary, ebr_this is 0; lba is absolute
        if ebr_this == 0:
            start = lba * sector
        else:
            start = ebr_this + lba * sector
        size = count * sector
        parts.append(
            Partition(
                index=idx,
                start=start,
                size=size,
                ptype=f"MBR 0x{ptype:02X}",
                name="",
                is_linux=ptype in MBR_LINUX,
                scheme="MBR",
            )
        )
        return None

    next_ebr = None
    for i in range(4):
        entry = data[446 + i * 16 : 462 + i * 16]
        nxt = add_entry(entry, i + 1, 0, 0)
        if nxt:
            next_ebr = nxt

    # Extended chain
    ebr_base = next_ebr
    guard = 0
    logical_idx = 5
    while next_ebr and guard < 128:
        guard += 1
        ebr = dev.read(next_ebr, 512)
        if ebr[510:512] != b"\x55\xaa":
            break
        entry = ebr[446:462]
        add_entry(entry, logical_idx, ebr_base, next_ebr)
        logical_idx += 1
        link = ebr[462:478]
        ptype = link[4]
        lba = struct.unpack_from("<I", link, 8)[0]
        if ptype in (0x05, 0x0F, 0x85) and lba:
            next_ebr = ebr_base + lba * sector
        else:
            break
    return parts


def _parse_gpt(dev: BlockDevice, sector: int) -> list[Partition]:
    header = dev.read(sector, sector)
    if header[0:8] != b"EFI PART":
        return []
    part_lba = struct.unpack_from("<Q", header, 72)[0]
    part_count = struct.unpack_from("<I", header, 80)[0]
    part_size = struct.unpack_from("<I", header, 84)[0]
    if part_size < 128 or part_count == 0 or part_count > 4096:
        return []
    table = dev.read(part_lba * sector, part_count * part_size)
    parts: list[Partition] = []
    for i in range(part_count):
        rec = table[i * part_size : (i + 1) * part_size]
        type_guid = rec[0:16]
        if type_guid == b"\x00" * 16:
            continue
        first = struct.unpack_from("<Q", rec, 32)[0]
        last = struct.unpack_from("<Q", rec, 40)[0]
        name = rec[56:128].decode("utf-16le", errors="ignore").rstrip("\x00")
        guid_s = _guid_from_le(type_guid)
        linux = guid_s in LINUX_GPT_GUIDS
        ptype = LINUX_GPT_GUIDS.get(guid_s, guid_s)
        parts.append(
            Partition(
                index=i + 1,
                start=first * sector,
                size=(last - first + 1) * sector,
                ptype=ptype,
                name=name,
                is_linux=linux,
                scheme="GPT",
            )
        )
    return parts


def list_partitions(dev: BlockDevice) -> list[Partition]:
    reported = getattr(dev, "sector_size", 512) or 512
    tried: set[int] = set()
    for sector in (reported, 512, 4096):
        if sector in tried:
            continue
        tried.add(sector)
        gpt = _parse_gpt(dev, sector)
        if gpt:
            return gpt
        mbr = _parse_mbr(dev, sector)
        if mbr:
            return mbr
    return []
