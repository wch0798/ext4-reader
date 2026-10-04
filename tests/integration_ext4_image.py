"""Linux integration test against a real mkfs.ext4 image.

The workflow creates the image with e2fsprogs. This script then exercises the
same library code used by Windows image mounts and leaves e2fsck to validate
the resulting on-disk metadata.
"""

from __future__ import annotations

import argparse
import os

from ext4lib.fs import constants as C
from ext4lib.fs.journal import _JournalLog
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
    temp = create_empty_file(vol, sub, "temp.txt")
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
    # create_empty_file is a completed namespace operation and now leaves the
    # medium clean/portable before the next write begins.
    assert not vol._write_session_active
    assert vol.journal_start() == 0
    assert vol.sb.state & C.EXT4_VALID_FS
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

    # close() must not manufacture another transaction on an unclean path.
    vol.close()

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
    assert not vol._write_session_active
    assert vol.journal_start() == 0
    assert not vol.sb.needs_recovery
    assert vol.sb.state & C.EXT4_VALID_FS

    payload = (b"portable-ext4-" * 8192) + b"END"
    write_range(vol, node, 0, payload, flush=True)
    assert not vol._write_session_active
    assert vol.journal_start() == 0
    assert not vol.sb.needs_recovery
    assert vol.sb.state & C.EXT4_VALID_FS
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
        choices=("clean", "dirty-marker", "journal-replay", "gpt-portable"),
        default="clean",
    )
    args = parser.parse_args()

    if args.mode == "clean":
        clean_roundtrip(args.image)
    elif args.mode == "dirty-marker":
        dirty_marker_roundtrip(args.image)
    elif args.mode == "journal-replay":
        journal_replay_roundtrip(args.image)
    else:
        gpt_portable_roundtrip(args.image)


if __name__ == "__main__":
    main()
