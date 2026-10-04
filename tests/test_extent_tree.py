"""Round-trip a fragmented extent tree and keep metadata off the append cursor."""

import struct
from types import SimpleNamespace

from bitmap import Bitmap, alloc_blocks
from extents import Extent, build_extent_tree, walk_extents
from superblock import GroupDesc
from writer import _add_runs, _initialize_range


class MemInode:
    def __init__(self):
        self.ino = 12
        self.generation = 7
        self.blocks = 0
        self.i_block = b"\x00" * 60

    def set_blocks(self, fs_blocks, block_size):
        self.blocks = fs_blocks * (block_size // 512)

    def set_i_block(self, data):
        self.i_block = data


def make_vol(nbits=4096, checksum=True):
    sb = SimpleNamespace(
        groups_count=1,
        first_data_block=0,
        blocks_per_group=nbits,
        blocks_count=nbits,
        free_blocks_count=nbits,
        block_size=4096,
        has_metadata_csum=checksum,
        has_gdt_csum=False,
        has_64bit=False,
        desc_size=32,
    )
    sb.csum_seed = lambda: 0x12345678
    gd = GroupDesc(
        group=0,
        block_bitmap=1,
        inode_bitmap=2,
        inode_table=3,
        free_blocks=nbits,
        free_inodes=0,
        used_dirs=0,
        flags=0,
        itable_unused=0,
        raw=bytearray(32),
    )
    vol = SimpleNamespace(
        sb=sb,
        groups=[gd],
        dirty_groups=set(),
        dirty_super=False,
        _alloc_hint={},
        _block_bm_cache={0: Bitmap(bytearray(4096), nbits)},
        _dirty_block_bm=set(),
        blocks={},
    )

    def read_block(phys):
        return vol.blocks[phys]

    def write_block(phys, data):
        vol.blocks[phys] = bytes(data)

    vol.read_block = read_block
    vol.write_block = write_block
    return vol


def test_deep_tree():
    vol = make_vol()
    inode = MemInode()
    extents = [Extent(i, 1, 50_000 + i, False) for i in range(1361)]
    extents[-1] = Extent(1360, 3, (1 << 32) + 9, True)
    inode.blocks = sum(e.length for e in extents) * (4096 // 512)
    body = build_extent_tree(vol, inode, extents)
    magic, entries, _mx, depth = struct.unpack_from("<HHHH", body, 0)
    assert magic == 0xF30A
    assert depth == 2, depth
    assert entries == 1, entries
    inode.set_i_block(body)
    got = walk_extents(vol, inode)
    assert len(got) == 1361
    assert [(e.logical, e.length, e.physical, e.uninitialized) for e in got] == [
        (e.logical, e.length, e.physical, e.uninitialized) for e in extents
    ]
    stale = list(inode._extent_index_old)
    assert stale == []
    small = [Extent(0, 1, 10, False), Extent(1, 2, 20, False), Extent(3, 1, 30, True)]
    inode.blocks = 4 * (4096 // 512)
    body2 = build_extent_tree(vol, inode, small)
    _m, ent2, _x, depth2 = struct.unpack_from("<HHHH", body2, 0)
    assert depth2 == 0 and ent2 == 3
    assert len(inode._extent_index_old) == 6  # 5 leaves + 1 index
    print("deep tree ok", len(vol.blocks))


def test_metadata_spares_append_cursor():
    vol = make_vol(nbits=128, checksum=False)
    first = alloc_blocks(vol, 10)
    assert first == list(range(10))
    assert vol._alloc_hint[0] == 10
    meta = alloc_blocks(vol, 1, metadata=True)
    assert meta == [127], meta
    assert vol._alloc_hint[0] == 10
    second = alloc_blocks(vol, 5)
    assert second == list(range(10, 15)), second
    print("metadata cursor ok")


def test_block_count_is_not_capped_at_2tb():
    import struct

    from inode import Inode

    raw = bytearray(256)
    inode = Inode(
        ino=12,
        raw=raw,
        mode=0,
        uid=0,
        gid=0,
        size=0,
        atime=0,
        ctime=0,
        mtime=0,
        dtime=0,
        links=1,
        blocks=0,
        flags=0,
        generation=1,
        extra_isize=32,
        crtime=0,
        file_acl=0,
    )
    inode.set_blocks(1 << 30, 4096)
    lo = struct.unpack_from("<I", inode.raw, 0x1C)[0]
    hi = struct.unpack_from("<H", inode.raw, 0x74)[0]
    assert inode.blocks == (1 << 33)
    assert lo == inode.blocks & 0xFFFFFFFF
    assert hi == 2
    print("block count ok", inode.blocks)


def test_prealloc_tail_initializes():
    extents = _add_runs([], 0, list(range(10)))
    extents = _add_runs(extents, 10, list(range(10, 30)), uninit=True)
    assert len(extents) == 2
    assert extents[1].uninitialized
    extents = _initialize_range(extents, 10, 4)
    assert [(e.logical, e.length, e.uninitialized) for e in extents] == [
        (0, 14, False),
        (14, 16, True),
    ]
    print("prealloc tail ok")


def test_recycle_targets():
    from fuse_mount import recycle_attr_path, recycle_repair_targets

    assert recycle_repair_targets("/Game/desktop.ini") is None
    assert recycle_repair_targets("/$RECYCLE.BIN") == ("/$RECYCLE.BIN", "")
    sid = "/$RECYCLE.BIN/S-1-5-21-1-1001"
    assert recycle_repair_targets(sid + "/desktop.ini") == ("/$RECYCLE.BIN", sid)
    assert recycle_attr_path("/$RECYCLE.BIN")
    assert recycle_attr_path("/$RECYCLE.BIN/desktop.ini")
    assert recycle_attr_path(sid)
    assert recycle_attr_path(sid + "/desktop.ini")
    assert not recycle_attr_path(sid + "/$Iabc")
    assert not recycle_attr_path("/Game")
    print("recycle targets ok")


def test_htree_grows_levels():
    from directory import _dx_entries, _dx_insert_pointer, _dx_pick, _write_dx_entries

    bs = 64
    root = bytearray(bs)
    root[28] = 1
    root[29] = 8
    root[30] = 0
    _write_dx_entries(root, 32, 3, [(0, 1)])
    blocks = {0: root}
    nxt = 2
    placed = {0: 1}

    def alloc():
        nonlocal nxt
        logical = nxt
        nxt += 1
        return logical

    def probe(h):
        node = blocks[0]
        levels = node[30]
        _limit, _count, items = _dx_entries(node, 32)
        lblk = _dx_pick(items, h)
        for _ in range(levels):
            _limit, _count, items = _dx_entries(blocks[lblk], 8)
            lblk = _dx_pick(items, h)
        return lblk

    for i in range(80):
        h = (i + 1) * 10
        target = 100000 + i
        dirty = _dx_insert_pointer(lambda lb: blocks[lb], blocks[0], h, target, bs, 0, alloc)
        for logical, data in dirty.items():
            blocks[logical] = data
        placed[h] = target
        for eh, expect in placed.items():
            assert probe(eh) == expect, (eh, probe(eh), expect, blocks[0][30])
    assert blocks[0][30] >= 2
    print("htree levels ok", blocks[0][30], "index blocks", nxt - 2)


def test_unlink_frees_extent_indexes():
    from writer import release_inode_blocks

    vol = make_vol()
    inode = MemInode()
    inode.uses_extents = True
    start = vol.sb.free_blocks_count
    data = alloc_blocks(vol, 8)
    extents = [Extent(i, 1, data[i], False) for i in range(8)]
    inode.set_i_block(build_extent_tree(vol, inode, extents))
    assert vol.sb.free_blocks_count == start - 9
    release_inode_blocks(vol, inode)
    assert vol.sb.free_blocks_count == start
    print("unlink index free ok")


def test_journal_recovery_blocks_writes():
    import types

    from volume import Ext4Error, Ext4Volume

    sb = SimpleNamespace(feature_incompat=0, feature_ro_compat=0, has_extents=True, state=1, needs_recovery=True)
    vol = SimpleNamespace(
        sb=sb,
        dev=SimpleNamespace(writable=True),
        journal_start=lambda: 0,
    )
    vol.journal_needs_recovery = types.MethodType(Ext4Volume.journal_needs_recovery, vol)
    vol.hard_write_blockers = types.MethodType(Ext4Volume.hard_write_blockers, vol)
    assert Ext4Volume.journal_needs_recovery(vol) is True
    try:
        Ext4Volume.require_write(vol)
    except Ext4Error as exc:
        assert "저널" in str(exc)
    else:
        raise AssertionError("RECOVER 플래그가 남았는데 쓰기가 허용되었습니다.")
    vol.journal_start = lambda: 4
    assert Ext4Volume.journal_needs_recovery(vol) is True
    try:
        Ext4Volume.require_write(vol)
    except Ext4Error as exc:
        assert "저널" in str(exc)
    else:
        raise AssertionError("저널 재생이 필요한데도 쓰기가 허용되었습니다.")
    assert not any("저널" in item for item in Ext4Volume.soft_write_warnings(vol))
    print("journal block ok")


def test_stat_ex_slot():
    import ctypes

    import fuse

    from fuse_mount import _install_winfsp_stat_ex

    before = ctypes.sizeof(fuse.fuse_operations)
    _install_winfsp_stat_ex(fuse.FUSE)
    after = ctypes.sizeof(fuse.fuse_operations)
    assert after - before == 16 * 8
    assert fuse.fuse_operations.chflags.offset == before + 15 * 8
    assert callable(fuse.FUSE.chflags)
    print("stat ex slot ok", before, after)


if __name__ == "__main__":
    test_deep_tree()
    test_metadata_spares_append_cursor()
    test_block_count_is_not_capped_at_2tb()
    test_prealloc_tail_initializes()
    test_recycle_targets()
    test_htree_grows_levels()
    test_unlink_frees_extent_indexes()
    test_journal_recovery_blocks_writes()
    test_stat_ex_slot()
    print("all ok")
