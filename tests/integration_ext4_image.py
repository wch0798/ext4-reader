"""Linux integration test against a real mkfs.ext4 image.

The workflow creates the image with e2fsprogs. This script then exercises the
same library code used by Windows image mounts and leaves e2fsck to validate
the resulting on-disk metadata.
"""

from __future__ import annotations

import argparse
import os
import struct

from ext4lib.fs import constants as C
from ext4lib.fs.journal import _JournalLog
from ext4lib.fs.extents import extent_at, file_extents
from ext4lib.fs.orphan import _orphan_block_checksum
from ext4lib.fs.bitmap import bitmap_checksum_valid, bitmap_free_count
from ext4lib.fs.crc32c import crc32c
from ext4lib.fs.superblock import parse_superblock, update_group_desc_fields
from ext4lib.fs.volume import Ext4Volume, discover_volumes
from ext4lib.fs.writer import (
    create_empty_file,
    lookup_path,
    mkdir,
    move_entry,
    read_range,
    set_file_size,
    unlink_checked,
    write_range,
)
from ext4lib.io.backend import ImageDevice


def open_volume(path: str, writable: bool) -> Ext4Volume:
    dev = ImageDevice(path, writable=writable)
    return Ext4Volume(dev, 0, os.path.getsize(path), owns_device=True)


def clean_roundtrip(path: str) -> None:
    vol = open_volume(path, True)
    blockers = vol.hard_write_blockers()
    if blockers:
        raise AssertionError("mkfs image is not writable by ext4-reader: " + " | ".join(blockers))

    vol.begin_write_session()
    root = lookup_path(vol, "/")

    node = create_empty_file(vol, root, "alpha.bin")
    assert node.uid == C.DEFAULT_LINUX_UID == 1000
    assert node.gid == C.DEFAULT_LINUX_GID == 1000
    assert (node.mode & 0o777) == C.DEFAULT_LINUX_FILE_MODE == 0o755
    payload = (bytes(range(256)) * 8193) + b"EXT4-READER-END"
    written = write_range(vol, node, 0, payload, flush=True)
    assert written == len(payload)

    node = lookup_path(vol, "/alpha.bin")
    assert read_range(vol, node, 0, len(payload)) == payload

    move_entry(vol, "/alpha.bin", "/renamed.bin")
    node = lookup_path(vol, "/renamed.bin")
    assert read_range(vol, node, 0, len(payload)) == payload

    shrink = 1024 * 1024 + 17
    set_file_size(vol, node, shrink)
    node = lookup_path(vol, "/renamed.bin")
    assert node.size == shrink
    assert read_range(vol, node, 0, shrink) == payload[:shrink]

    root = lookup_path(vol, "/")
    sub = mkdir(vol, root, "subdir")
    assert sub.uid == C.DEFAULT_LINUX_UID == 1000
    assert sub.gid == C.DEFAULT_LINUX_GID == 1000
    assert (sub.mode & 0o777) == C.DEFAULT_LINUX_DIR_MODE == 0o755
    temp = create_empty_file(vol, sub, "temp.txt")
    assert temp.uid == 1000 and temp.gid == 1000
    assert (temp.mode & 0o777) == 0o755
    write_range(vol, temp, 0, b"temporary-data" * 4096, flush=True)
    sub = lookup_path(vol, "/subdir")
    unlink_checked(vol, sub, "temp.txt")
    root = lookup_path(vol, "/")
    unlink_checked(vol, root, "subdir")

    vol.finish_write_session()
    assert vol.sb.state & C.EXT4_VALID_FS
    vol.close()

    check = open_volume(path, False)
    try:
        node = lookup_path(check, "/renamed.bin")
        assert node.uid == 1000 and node.gid == 1000
        assert (node.mode & 0o777) == 0o755
        assert node.size == shrink
        assert read_range(check, node, 0, shrink) == payload[:shrink]
        assert check.sb.state & C.EXT4_VALID_FS
    finally:
        check.close()


def journal_replay_roundtrip(path: str) -> None:
    """Crash after a durable JBD2 commit and verify recovery replays metadata."""
    vol = open_volume(path, True)
    blockers = vol.hard_write_blockers()
    if blockers:
        raise AssertionError("journal image is not writable by ext4-reader: " + " | ".join(blockers))

    initial_sequence = _JournalLog(vol).info.sequence
    vol.begin_write_session()
    assert vol._journal_writer is not None

    root = lookup_path(vol, "/")
    node = create_empty_file(vol, root, "replay.bin")
    # Operation boundaries are durable, but the mount-wide JBD2 write session
    # intentionally stays active until clean close/unmount.
    assert vol._write_session_active
    assert vol.journal_start() != 0
    assert not (vol.sb.state & C.EXT4_VALID_FS)
    before_crash = _JournalLog(vol).info.sequence
    payload = (b"jbd2-ordered-data-" * 4096) + b"END"

    original_checkpoint = vol._checkpoint_metadata_blocks

    def crash_after_commit(_metadata):
        raise RuntimeError("simulated power loss after JBD2 commit")

    vol._checkpoint_metadata_blocks = crash_after_commit
    try:
        try:
            write_range(vol, node, 0, payload, flush=True)
        except RuntimeError as exc:
            assert "simulated power loss" in str(exc)
        else:
            raise AssertionError("crash injection did not fire")
    finally:
        vol._checkpoint_metadata_blocks = original_checkpoint

    # An interrupted/crashed path must explicitly abort. A normal close is a
    # clean boundary and would correctly finish the healthy session.
    vol.close(abort=True)

    recovery = open_volume(path, True)
    try:
        assert recovery.journal_needs_recovery()
        stats = recovery.recover_pending_journal()
        assert stats.transactions >= 1
        assert stats.replayed_blocks >= 1

        # The crash transaction starts one ID after the clean journal sequence.
        # Recovery advances once past end_transaction before resetting.
        expected_recovery_sequence = (before_crash + 3) & 0xFFFFFFFF
        clean_log = _JournalLog(recovery)
        assert clean_log.info.start == 0
        assert clean_log.info.sequence == expected_recovery_sequence
        assert stats.next_sequence == expected_recovery_sequence
    finally:
        recovery.close()

    check = open_volume(path, False)
    try:
        node = lookup_path(check, "/replay.bin")
        assert node.size == len(payload)
        assert read_range(check, node, 0, len(payload)) == payload
        assert check.sb.state & C.EXT4_VALID_FS
        assert not check.sb.needs_recovery
        assert not check.journal_needs_recovery()
    finally:
        check.close()

    # Exercise a normal clean session after recovery too. This catches an
    # off-by-one in JournalWriter.mark_clean() that a one-shot crash replay
    # alone cannot detect.
    again = open_volume(path, True)
    try:
        before = _JournalLog(again).info.sequence
        assert before == expected_recovery_sequence
        again.begin_write_session()
        root = lookup_path(again, "/")
        create_empty_file(again, root, "after-replay.bin")
        again.finish_write_session()

        clean_log = _JournalLog(again)
        assert clean_log.info.start == 0
        assert clean_log.info.sequence == ((before + 2) & 0xFFFFFFFF)
        assert again.sb.state & C.EXT4_VALID_FS
        assert not again.sb.needs_recovery
    finally:
        again.close()



def raw_scan_roundtrip(path: str) -> None:
    """Discover and write an EXT4 filesystem at 1 MiB with no partition table."""
    dev = ImageDevice(path, writable=True)
    vols = discover_volumes(dev)
    if len(vols) != 1:
        dev.close()
        raise AssertionError(
            f"expected one raw-scanned EXT volume, found {len(vols)}"
        )
    info = vols[0]
    assert info.scheme == "RAW-SCAN"
    assert info.partition_index == 0
    assert info.offset == 1024 * 1024
    assert info.size == info.sb.blocks_count * info.sb.block_size

    vol = Ext4Volume(dev, info.offset, info.size, owns_device=True)
    blockers = vol.hard_write_blockers()
    if blockers:
        vol.close()
        raise AssertionError(
            "raw-scanned EXT4 is not writable: " + " | ".join(blockers)
        )
    root = lookup_path(vol, "/")
    node = create_empty_file(vol, root, "raw-discovered.bin")
    payload = b"raw-ext4-discovery" * 4096
    write_range(vol, node, 0, payload, flush=True)
    vol.close()

    check_dev = ImageDevice(path, writable=False)
    try:
        current = discover_volumes(check_dev)
        assert len(current) == 1
        assert current[0].scheme == "RAW-SCAN"
        assert current[0].offset == 1024 * 1024
        check = Ext4Volume(
            check_dev,
            current[0].offset,
            current[0].size,
            owns_device=False,
        )
        node = lookup_path(check, "/raw-discovered.bin")
        assert read_range(check, node, 0, len(payload)) == payload
    finally:
        check_dev.close()


def backup_gpt_discovery_roundtrip(path: str) -> None:
    """Use the backup GPT when the primary GPT header is unreadable."""
    dev = ImageDevice(path, writable=False)
    try:
        vols = discover_volumes(dev)
        if len(vols) != 1:
            raise AssertionError(
                f"expected one EXT volume via backup GPT, found {len(vols)}"
            )
        info = vols[0]
        assert info.scheme == "GPT"
        assert info.partition_index == 1
        assert info.offset == 1024 * 1024
        assert info.sb.fs_type == "EXT4"
    finally:
        dev.close()


def gpt_portable_roundtrip(path: str) -> None:
    """Write inside a GPT partition and prove both GPT copies stay untouched."""
    size = os.path.getsize(path)
    guard = 1024 * 1024
    with open(path, "rb") as fp:
        prefix_before = fp.read(guard)
        fp.seek(max(0, size - guard))
        suffix_before = fp.read(guard)

    dev = ImageDevice(path, writable=True)
    vols = discover_volumes(dev)
    if len(vols) != 1:
        dev.close()
        raise AssertionError(f"expected one EXT volume in GPT image, found {len(vols)}")
    info = vols[0]
    assert info.scheme == "GPT"
    assert info.offset >= guard
    vol = Ext4Volume(dev, info.offset, info.size, owns_device=True)
    blockers = vol.hard_write_blockers()
    if blockers:
        vol.close()
        raise AssertionError("GPT EXT4 image is not writable: " + " | ".join(blockers))

    root = lookup_path(vol, "/")
    node = create_empty_file(vol, root, "portable.bin")
    assert vol._write_session_active
    assert vol.journal_start() != 0
    assert vol.sb.needs_recovery
    assert not (vol.sb.state & C.EXT4_VALID_FS)

    payload = (b"portable-ext4-" * 8192) + b"END"
    write_range(vol, node, 0, payload, flush=True)
    assert vol._write_session_active
    assert vol.journal_start() != 0
    assert vol.sb.needs_recovery
    assert not (vol.sb.state & C.EXT4_VALID_FS)

    # A normal close is the single clean handoff point for the mount.
    vol.close()

    with open(path, "rb") as fp:
        prefix_after = fp.read(guard)
        fp.seek(max(0, size - guard))
        suffix_after = fp.read(guard)
    assert prefix_after == prefix_before, "primary GPT / pre-partition area changed"
    assert suffix_after == suffix_before, "backup GPT / end-of-disk area changed"

    check_dev = ImageDevice(path, writable=False)
    try:
        current = discover_volumes(check_dev)
        assert len(current) == 1
        assert current[0].scheme == "GPT"
        assert current[0].offset == info.offset
        assert current[0].size == info.size
        assert current[0].sb.uuid == info.sb.uuid
        check = Ext4Volume(check_dev, current[0].offset, current[0].size, owns_device=False)
        node = lookup_path(check, "/portable.bin")
        assert read_range(check, node, 0, len(payload)) == payload
        assert check.sb.state & C.EXT4_VALID_FS
        assert not check.sb.needs_recovery
        assert not check.journal_needs_recovery()
    finally:
        check_dev.close()



def error_repair_roundtrip(path: str) -> None:
    """Inject a stale ERROR_FS bit and repair it entirely in Windows-side code."""
    dev = ImageDevice(path, writable=True)
    vol = Ext4Volume(dev, 0, os.path.getsize(path), owns_device=True)
    try:
        raw = bytearray(dev.read(1024, 1024))
        sb = parse_superblock(raw)
        sb.state |= C.EXT4_ERROR_FS | C.EXT4_VALID_FS
        struct.pack_into("<H", sb.raw, 0x3A, sb.state & 0xFFFF)
        # Preserve realistic historical diagnostics; the repair clears only the
        # active ERROR_FS state after structural validation.
        struct.pack_into("<I", sb.raw, 0x194, 2)
        struct.pack_into("<I", sb.raw, 0x19C, C.EXT4_ROOT_INO)
        struct.pack_into("<Q", sb.raw, 0x1A0, 1)
        sb.write_checksum()
        dev.write(1024, bytes(sb.raw[:1024]))
        dev.flush()
    finally:
        vol.close(abort=True)

    check = open_volume(path, True)
    try:
        assert check.sb.state & C.EXT4_ERROR_FS
        assert not check.journal_needs_recovery()
        stats = check.repair_error_state_if_safe()
        assert stats.repaired
        assert stats.groups_checked == check.sb.groups_count
        assert stats.bitmaps_checked > 0
        assert not (check.sb.state & C.EXT4_ERROR_FS)
        assert check.sb.state & C.EXT4_VALID_FS

        root = lookup_path(check, "/")
        node = create_empty_file(check, root, "windows-repaired.bin")
        payload = b"windows-ext4-error-repair" * 128
        write_range(check, node, 0, payload, flush=True)
        check.close()
    except Exception:
        check.close(abort=True)
        raise

    final = open_volume(path, False)
    try:
        assert not (final.sb.state & C.EXT4_ERROR_FS)
        assert not final.sb.needs_recovery
        assert final.sb.state & C.EXT4_VALID_FS
        node = lookup_path(final, "/windows-repaired.bin")
        assert read_range(final, node, 0, len(payload)) == payload
    finally:
        final.close()


def full_block_bitmap_rebuild_roundtrip(path: str) -> None:
    """Replace group-0 block bitmap with 0xFF and rebuild it from metadata."""
    inject = open_volume(path, True)
    try:
        gd = inject.groups[0]
        if gd.flags & C.BG_BLOCK_UNINIT:
            raise AssertionError("group 0 block bitmap must be initialized")
        original = inject.read_block(gd.block_bitmap)
        original_free = gd.free_blocks
        assert bitmap_checksum_valid(inject, gd, "block", original)

        # Simulate the real device log: descriptor/free-count/checksum fields
        # still describe the original bitmap, while the bitmap block itself has
        # become all-used (free count = 0).
        inject.dev.write(
            gd.block_bitmap * inject.sb.block_size,
            b"\xFF" * inject.sb.block_size,
        )

        raw = bytearray(inject.dev.read(1024, 1024))
        sb = parse_superblock(raw)
        sb.state |= C.EXT4_ERROR_FS | C.EXT4_VALID_FS
        struct.pack_into("<H", sb.raw, 0x3A, sb.state & 0xFFFF)
        struct.pack_into("<I", sb.raw, 0x194, 1)
        func = b"ext4_validate_block_bitmap"
        sb.raw[0x1A8:0x1C8] = b"\x00" * 32
        sb.raw[0x1A8:0x1A8 + len(func)] = func
        struct.pack_into("<I", sb.raw, 0x1C8, 423)
        sb.write_checksum()
        inject.dev.write(1024, bytes(sb.raw[:1024]))
        inject.dev.flush()
        inject.close(abort=True)
    except Exception:
        inject.close(abort=True)
        raise

    repair = open_volume(path, True)
    try:
        gd = repair.groups[0]
        broken = repair.read_block(gd.block_bitmap)
        assert bitmap_free_count(broken, repair.sb.blocks_per_group) == 0
        stats = repair.repair_error_state_if_safe()
        assert stats.repaired
        assert stats.bitmap_checksums_repaired >= 1
        assert not (repair.sb.state & C.EXT4_ERROR_FS)
        gd = repair.groups[0]
        rebuilt = repair.read_block(gd.block_bitmap)
        assert gd.free_blocks == original_free
        assert rebuilt == original
        assert bitmap_checksum_valid(repair, gd, "block", rebuilt)
        repair.close()
    except Exception:
        repair.close(abort=True)
        raise


def bitmap_high_half_repair_roundtrip(path: str) -> None:
    """Repair a Linux-style block bitmap checksum with only stale high bits."""
    inject = open_volume(path, True)
    try:
        gd = inject.groups[0]
        if inject.sb.desc_size < 64 or not inject.sb.has_metadata_csum:
            raise AssertionError("fixture must use 64-byte metadata_csum descriptors")
        if gd.flags & C.BG_BLOCK_UNINIT:
            raise AssertionError("group 0 block bitmap must be initialized")

        block_raw = inject.read_block(gd.block_bitmap)
        block_crc = crc32c(
            inject.sb.csum_seed(),
            block_raw[: inject.sb.blocks_per_group // 8],
        )
        # Keep the low half correct and corrupt only the high half. This
        # reproduces the class of media in which Linux reported
        # ext4_validate_block_bitmap but all local bitmap invariants remain
        # consistent.
        gd.raw[0x18:0x1A] = (block_crc & 0xFFFF).to_bytes(2, "little")
        gd.raw[0x38:0x3A] = (((block_crc >> 16) ^ 1) & 0xFFFF).to_bytes(2, "little")
        update_group_desc_fields(inject.sb, gd)
        gdt_block = inject.sb.first_data_block + 1
        inject.dev.write(
            gdt_block * inject.sb.block_size,
            bytes(gd.raw[: inject.sb.desc_size]),
        )

        raw = bytearray(inject.dev.read(1024, 1024))
        sb = parse_superblock(raw)
        sb.state |= C.EXT4_ERROR_FS | C.EXT4_VALID_FS
        struct.pack_into("<H", sb.raw, 0x3A, sb.state & 0xFFFF)
        struct.pack_into("<I", sb.raw, 0x194, 1)
        func = b"ext4_validate_block_bitmap"
        sb.raw[0x1A8:0x1C8] = b"\x00" * 32
        sb.raw[0x1A8:0x1A8 + len(func)] = func
        struct.pack_into("<I", sb.raw, 0x1C8, 423)
        sb.write_checksum()
        inject.dev.write(1024, bytes(sb.raw[:1024]))
        inject.dev.flush()
        inject.close(abort=True)
    except Exception:
        inject.close(abort=True)
        raise

    repair = open_volume(path, True)
    try:
        gd = repair.groups[0]
        assert not bitmap_checksum_valid(
            repair, gd, "block", repair.read_block(gd.block_bitmap)
        )
        stats = repair.repair_error_state_if_safe()
        assert stats.repaired
        assert stats.bitmap_checksums_repaired == 1
        assert not (repair.sb.state & C.EXT4_ERROR_FS)
        gd = repair.groups[0]
        assert bitmap_checksum_valid(
            repair, gd, "block", repair.read_block(gd.block_bitmap)
        )
        repair.close()
    except Exception:
        repair.close(abort=True)
        raise


def legacy_bitmap_checksum_repair_roundtrip(path: str) -> None:
    """Reproduce the old Ext4Reader 64-byte bitmap checksum layout bug."""
    inject = open_volume(path, True)
    try:
        gd = inject.groups[0]
        if inject.sb.desc_size < 64 or not inject.sb.has_metadata_csum:
            raise AssertionError("fixture must use 64-byte metadata_csum descriptors")
        if gd.flags & (C.BG_BLOCK_UNINIT | C.BG_INODE_UNINIT):
            raise AssertionError("group 0 bitmaps must be initialized")

        block_raw = inject.read_block(gd.block_bitmap)
        inode_raw = inject.read_block(gd.inode_bitmap)
        block_crc = crc32c(
            inject.sb.csum_seed(),
            block_raw[: inject.sb.blocks_per_group // 8],
        )
        inode_crc = crc32c(
            inject.sb.csum_seed(),
            inode_raw[: inject.sb.inodes_per_group // 8],
        )
        legacy_block_crc = crc32c(inject.sb.csum_seed(), block_raw[: inject.sb.block_size])
        legacy_inode_crc = crc32c(inject.sb.csum_seed(), inode_raw[: inject.sb.block_size])

        # Exact pre-fix Ext4Reader layout: low halves in the right fields,
        # high halves incorrectly overwrite bg_exclude_bitmap_hi.
        gd.raw[0x18:0x1A] = (legacy_block_crc & 0xFFFF).to_bytes(2, "little")
        gd.raw[0x1A:0x1C] = (legacy_inode_crc & 0xFFFF).to_bytes(2, "little")
        gd.raw[0x34:0x36] = ((legacy_block_crc >> 16) & 0xFFFF).to_bytes(2, "little")
        gd.raw[0x36:0x38] = ((legacy_inode_crc >> 16) & 0xFFFF).to_bytes(2, "little")

        # The old writer left the real high-half fields stale. Force them stale
        # while keeping the descriptor checksum internally valid.
        gd.raw[0x38:0x3A] = (((block_crc >> 16) ^ 1) & 0xFFFF).to_bytes(2, "little")
        gd.raw[0x3A:0x3C] = (((inode_crc >> 16) ^ 1) & 0xFFFF).to_bytes(2, "little")
        update_group_desc_fields(inject.sb, gd)
        gdt_block = inject.sb.first_data_block + 1
        off = gdt_block * inject.sb.block_size
        inject.dev.write(off, bytes(gd.raw[: inject.sb.desc_size]))

        raw = bytearray(inject.dev.read(1024, 1024))
        sb = parse_superblock(raw)
        sb.state |= C.EXT4_ERROR_FS | C.EXT4_VALID_FS
        struct.pack_into("<H", sb.raw, 0x3A, sb.state & 0xFFFF)
        struct.pack_into("<I", sb.raw, 0x194, 1)
        func = b"ext4_validate_block_bitmap"
        sb.raw[0x1A8:0x1C8] = b"\x00" * 32
        sb.raw[0x1A8:0x1A8 + len(func)] = func
        struct.pack_into("<I", sb.raw, 0x1C8, 423)
        sb.write_checksum()
        inject.dev.write(1024, bytes(sb.raw[:1024]))
        inject.dev.flush()
        inject.close(abort=True)
    except Exception:
        inject.close(abort=True)
        raise

    repair = open_volume(path, True)
    try:
        gd = repair.groups[0]
        assert not bitmap_checksum_valid(
            repair, gd, "block", repair.read_block(gd.block_bitmap)
        )
        assert not bitmap_checksum_valid(
            repair, gd, "inode", repair.read_block(gd.inode_bitmap)
        )
        stats = repair.repair_error_state_if_safe()
        assert stats.repaired
        assert stats.bitmap_checksums_repaired == 2
        assert not (repair.sb.state & C.EXT4_ERROR_FS)
        gd = repair.groups[0]
        assert bitmap_checksum_valid(
            repair, gd, "block", repair.read_block(gd.block_bitmap)
        )
        assert bitmap_checksum_valid(
            repair, gd, "inode", repair.read_block(gd.inode_bitmap)
        )
        assert repair.groups[0].raw[0x34:0x38] == b"\x00\x00\x00\x00"
        repair.close()
    except Exception:
        repair.close(abort=True)
        raise


def orphan_repair_roundtrip(path: str) -> None:
    """Inject a real orphan-file entry + ERROR_FS and recover it on Windows."""
    seed = open_volume(path, True)
    try:
        if not (seed.sb.feature_compat & C.EXT4_FEATURE_COMPAT_ORPHAN_FILE):
            raise AssertionError("test image has no orphan_file feature")
        if not seed.sb.orphan_file_inum:
            raise AssertionError("test image has no orphan file inode")

        root = lookup_path(seed, "/")
        node = create_empty_file(seed, root, "orphan-keep.bin")
        payload = b"orphan-recovery-data" * 512
        write_range(seed, node, 0, payload, flush=True)
        seed.close()
    except Exception:
        seed.close(abort=True)
        raise

    inject = open_volume(path, True)
    try:
        node = lookup_path(inject, "/orphan-keep.bin")
        orphan_inode = inject.read_inode(inject.sb.orphan_file_inum)
        ex = extent_at(file_extents(inject, orphan_inode), 0)
        if ex is None or ex.uninitialized:
            raise AssertionError("orphan file block 0 is not mapped")
        phys = ex.physical
        raw = bytearray(inject.read_block(phys))
        bs = inject.sb.block_size
        struct.pack_into("<I", raw, 0, node.ino)
        struct.pack_into("<I", raw, bs - 8, C.EXT4_ORPHAN_BLOCK_MAGIC)
        if inject.sb.has_metadata_csum:
            struct.pack_into("<I", raw, bs - 4, 0)
            struct.pack_into(
                "<I",
                raw,
                bs - 4,
                _orphan_block_checksum(inject, orphan_inode, phys, raw),
            )
        inject.write_block(phys, bytes(raw))

        inject.sb.feature_ro_compat |= C.EXT4_FEATURE_RO_COMPAT_ORPHAN_PRESENT
        inject.sb.state |= C.EXT4_ERROR_FS | C.EXT4_VALID_FS
        struct.pack_into("<I", inject.sb.raw, 0x64, inject.sb.feature_ro_compat)
        struct.pack_into("<H", inject.sb.raw, 0x3A, inject.sb.state & 0xFFFF)
        inject.sb.write_checksum()
        inject.dev.write(1024, bytes(inject.sb.raw[:1024]))
        inject.dev.flush()
        inject.close(abort=True)
    except Exception:
        inject.close(abort=True)
        raise

    repair = open_volume(path, True)
    try:
        assert repair.sb.feature_ro_compat & C.EXT4_FEATURE_RO_COMPAT_ORPHAN_PRESENT
        assert repair.sb.state & C.EXT4_ERROR_FS
        assert not repair.journal_needs_recovery()

        ostats = repair.recover_pending_orphans()
        assert ostats.entries_found == 1
        assert ostats.truncated == 1
        assert ostats.deleted == 0
        assert not (
            repair.sb.feature_ro_compat
            & C.EXT4_FEATURE_RO_COMPAT_ORPHAN_PRESENT
        )

        estats = repair.repair_error_state_if_safe()
        assert estats.repaired
        assert not (repair.sb.state & C.EXT4_ERROR_FS)
        repair.close()
    except Exception:
        repair.close(abort=True)
        raise

    final = open_volume(path, False)
    try:
        assert not (
            final.sb.feature_ro_compat & C.EXT4_FEATURE_RO_COMPAT_ORPHAN_PRESENT
        )
        assert not (final.sb.state & C.EXT4_ERROR_FS)
        assert final.sb.state & C.EXT4_VALID_FS
        node = lookup_path(final, "/orphan-keep.bin")
        assert read_range(final, node, 0, len(payload)) == payload
    finally:
        final.close()


def htree_roundtrip(path: str) -> None:
    """Insert into a Linux-built indexed directory and verify the same path."""
    vol = open_volume(path, True)
    try:
        indexed = lookup_path(vol, "/indexed")
        assert indexed.is_dir
        assert indexed.is_indexed, "fixture directory was not indexed by e2fsck -D"

        node = create_empty_file(vol, indexed, "from-windows.bin")
        payload = b"steam-deck-visible" * 1024
        write_range(vol, node, 0, payload, flush=True)
        vol.close()
    except Exception:
        vol.close(abort=True)
        raise

    check = open_volume(path, False)
    try:
        indexed = lookup_path(check, "/indexed")
        assert indexed.is_indexed
        node = lookup_path(check, "/indexed/from-windows.bin")
        assert read_range(check, node, 0, len(payload)) == payload
    finally:
        check.close()

def dirty_marker_roundtrip(path: str) -> None:
    vol = open_volume(path, True)
    blockers = vol.hard_write_blockers()
    if blockers:
        raise AssertionError("mkfs image is not writable by ext4-reader: " + " | ".join(blockers))

    vol.begin_write_session()
    assert not (vol.sb.state & C.EXT4_VALID_FS)
    # Simulate application/device loss explicitly. A normal close is a clean
    # boundary; abort=True preserves the dirty marker and must never fabricate
    # EXT4_VALID_FS after an interrupted write session.
    vol.close(abort=True)

    check = open_volume(path, False)
    try:
        assert not (check.sb.state & C.EXT4_VALID_FS), (
            "unclean write session incorrectly restored EXT4_VALID_FS"
        )
    finally:
        check.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    parser.add_argument(
        "--mode",
        choices=(
            "clean",
            "dirty-marker",
            "journal-replay",
            "gpt-portable",
            "raw-scan",
            "backup-gpt",
            "error-repair",
            "orphan-repair",
            "legacy-bitmap-repair",
            "bitmap-high-repair",
            "bitmap-rebuild",
            "htree",
        ),
        default="clean",
    )
    args = parser.parse_args()

    if args.mode == "clean":
        clean_roundtrip(args.image)
    elif args.mode == "dirty-marker":
        dirty_marker_roundtrip(args.image)
    elif args.mode == "journal-replay":
        journal_replay_roundtrip(args.image)
    elif args.mode == "gpt-portable":
        gpt_portable_roundtrip(args.image)
    elif args.mode == "raw-scan":
        raw_scan_roundtrip(args.image)
    elif args.mode == "backup-gpt":
        backup_gpt_discovery_roundtrip(args.image)
    elif args.mode == "error-repair":
        error_repair_roundtrip(args.image)
    elif args.mode == "orphan-repair":
        orphan_repair_roundtrip(args.image)
    elif args.mode == "legacy-bitmap-repair":
        legacy_bitmap_checksum_repair_roundtrip(args.image)
    elif args.mode == "bitmap-high-repair":
        bitmap_high_half_repair_roundtrip(args.image)
    elif args.mode == "bitmap-rebuild":
        full_block_bitmap_rebuild_roundtrip(args.image)
    else:
        htree_roundtrip(args.image)


if __name__ == "__main__":
    main()
