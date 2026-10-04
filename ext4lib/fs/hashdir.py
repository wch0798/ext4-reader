"""ext4 htree directory hash — port of e2fsprogs lib/ext2fs/dirhash.c."""

from __future__ import annotations

import struct

from ext4lib.fs import constants as C

DELTA = 0x9E3779B9


def _str2hashbuf(msg: bytes, num: int, signed: bool) -> list[int]:
    pad = (len(msg) | (len(msg) << 8)) & 0xFFFF
    pad |= pad << 16
    pad &= 0xFFFFFFFF
    out = []
    length = min(len(msg), num * 4)
    val = pad
    for i in range(length):
        if i % 4 == 0:
            val = pad
        ch = msg[i]
        if signed and ch >= 128:
            add = ch - 256
        else:
            add = ch
        val = (add + ((val << 8) & 0xFFFFFFFF)) & 0xFFFFFFFF
        if i % 4 == 3:
            out.append(val)
            val = pad
            num -= 1
    num -= 1
    if num >= 0:
        out.append(val)
        num -= 1
    while num >= 0:
        out.append(pad)
        num -= 1
    while len(out) < 4:
        out.append(pad)
    return out[:4]


def _str2hashbuf_n(msg: bytes, nwords: int, signed: bool) -> list[int]:
    pad = (len(msg) | (len(msg) << 8)) & 0xFFFF
    pad |= pad << 16
    pad &= 0xFFFFFFFF
    out: list[int] = []
    length = min(len(msg), nwords * 4)
    val = pad
    remaining = nwords
    for i in range(length):
        if i % 4 == 0:
            val = pad
        ch = msg[i]
        add = (ch - 256) if (signed and ch >= 128) else ch
        val = (add + ((val << 8) & 0xFFFFFFFF)) & 0xFFFFFFFF
        if i % 4 == 3:
            out.append(val)
            val = pad
            remaining -= 1
    remaining -= 1
    if remaining >= 0:
        out.append(val)
        remaining -= 1
    while remaining >= 0:
        out.append(pad)
        remaining -= 1
    while len(out) < nwords:
        out.append(pad)
    return out[:nwords]


def _tea_transform(buf: list[int], inp: list[int]) -> None:
    total = 0
    b0, b1 = buf[0], buf[1]
    a, b, c, d = inp
    for _ in range(16):
        total = (total + DELTA) & 0xFFFFFFFF
        b0 = (b0 + (((b1 << 4) + a) ^ (b1 + total) ^ ((b1 >> 5) + b))) & 0xFFFFFFFF
        b1 = (b1 + (((b0 << 4) + c) ^ (b0 + total) ^ ((b0 >> 5) + d))) & 0xFFFFFFFF
    buf[0] = (buf[0] + b0) & 0xFFFFFFFF
    buf[1] = (buf[1] + b1) & 0xFFFFFFFF


def half_md4_transform(buf: list[int], inp: list[int]) -> None:
    a, b, c, d = buf

    def rol(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def f(x, y, z):
        return (z ^ (x & (y ^ z))) & 0xFFFFFFFF

    def g(x, y, z):
        return ((x & y) + ((x ^ y) & z)) & 0xFFFFFFFF

    def h(x, y, z):
        return (x ^ y ^ z) & 0xFFFFFFFF

    def r1(a, b, c, d, k, s):
        return rol((a + f(b, c, d) + inp[k]) & 0xFFFFFFFF, s)

    def r2(a, b, c, d, k, s):
        return rol((a + g(b, c, d) + inp[k] + 0x5A827999) & 0xFFFFFFFF, s)

    def r3(a, b, c, d, k, s):
        return rol((a + h(b, c, d) + inp[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)

    a = r1(a, b, c, d, 0, 3)
    d = r1(d, a, b, c, 1, 7)
    c = r1(c, d, a, b, 2, 11)
    b = r1(b, c, d, a, 3, 19)
    a = r1(a, b, c, d, 4, 3)
    d = r1(d, a, b, c, 5, 7)
    c = r1(c, d, a, b, 6, 11)
    b = r1(b, c, d, a, 7, 19)
    a = r2(a, b, c, d, 1, 3)
    d = r2(d, a, b, c, 6, 5)
    c = r2(c, d, a, b, 5, 9)
    b = r2(b, c, d, a, 2, 13)
    a = r2(a, b, c, d, 3, 3)
    d = r2(d, a, b, c, 0, 5)
    c = r2(c, d, a, b, 7, 9)
    b = r2(b, c, d, a, 4, 13)
    a = r3(a, b, c, d, 3, 3)
    d = r3(d, a, b, c, 4, 9)
    c = r3(c, d, a, b, 7, 11)
    b = r3(b, c, d, a, 1, 15)
    a = r3(a, b, c, d, 6, 3)
    d = r3(d, a, b, c, 2, 9)
    c = r3(c, d, a, b, 5, 11)
    b = r3(b, c, d, a, 0, 15)
    buf[0] = (buf[0] + a) & 0xFFFFFFFF
    buf[1] = (buf[1] + b) & 0xFFFFFFFF
    buf[2] = (buf[2] + c) & 0xFFFFFFFF
    buf[3] = (buf[3] + d) & 0xFFFFFFFF


def _legacy(name: bytes, signed: bool) -> int:
    hash0 = 0x12A3FE2D
    hash1 = 0x37ABE8F9
    for ch in name:
        cc = (ch - 256) if (signed and ch >= 128) else ch
        h = (hash1 + (hash0 ^ ((cc * 7152373) & 0xFFFFFFFF))) & 0xFFFFFFFF
        if h & 0x80000000:
            h = (h - 0x7FFFFFFF) & 0xFFFFFFFF
        hash1 = hash0
        hash0 = h
    return (hash0 << 1) & 0xFFFFFFFF


def dirhash(name: bytes, hash_version: int, seed: bytes) -> int:
    if hash_version == C.DX_HASH_SIPHASH:
        raise ValueError("SipHash 디렉터리는 지원하지 않습니다.")
    signed = hash_version in (C.DX_HASH_LEGACY, C.DX_HASH_HALF_MD4, C.DX_HASH_TEA)
    if hash_version in (C.DX_HASH_LEGACY, C.DX_HASH_LEGACY_UNSIGNED):
        return _legacy(name, signed) & 0xFFFFFFFE

    buf = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    if seed and any(seed):
        # e2fsprogs ext2fs_dirhash(): a non-zero s_hash_seed REPLACES the
        # default IV. It is not XORed with it.
        buf = list(struct.unpack("<4I", seed[:16].ljust(16, b"\x00")))

    if hash_version in (C.DX_HASH_TEA, C.DX_HASH_TEA_UNSIGNED):
        msg = name
        while True:
            inp = _str2hashbuf(msg[:16], 4, signed)
            _tea_transform(buf, inp)
            if len(msg) <= 16:
                break
            msg = msg[16:]
        return buf[0] & 0xFFFFFFFE

    msg = name
    while True:
        inp = _str2hashbuf_n(msg[:32], 8, signed)
        half_md4_transform(buf, inp)
        if len(msg) <= 32:
            break
        msg = msg[32:]
    return buf[1] & 0xFFFFFFFE
