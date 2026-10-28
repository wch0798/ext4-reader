"""Linux fs/unicode utf8_casefold() for ext4 casefold, Unicode 12.1.0.

ext4 always loads the 12.1.0 table (s_encoding = EXT4_ENC_UTF8_12_1), so this
does not use Python's unicodedata, whose Unicode version follows the
interpreter. Code points unassigned in 12.1 pass through unchanged with
combining class 0.
"""

from __future__ import annotations

from ext4lib.fs.ucd_12_1 import CCC, IGNORABLE, NFDICF

_MAP: dict[int, str] = dict(NFDICF)
for _a, _b in IGNORABLE:
    for _cp in range(_a, _b + 1):
        _MAP[_cp] = ""
del _a, _b, _cp

_SBASE, _LBASE, _VBASE, _TBASE = 0xAC00, 0x1100, 0x1161, 0x11A7
_VCOUNT, _TCOUNT, _SCOUNT = 21, 28, 11172
_PATH_MAX = 4096


def _nfdicf(cp: int) -> str | None:
    """Leaf decomposition of ``cp``; None if it maps to itself."""
    s = cp - _SBASE
    if 0 <= s < _SCOUNT:
        t = s % _TCOUNT
        return (
            chr(_LBASE + s // (_VCOUNT * _TCOUNT))
            + chr(_VBASE + (s % (_VCOUNT * _TCOUNT)) // _TCOUNT)
            + (chr(_TBASE + t) if t else "")
        )
    return _MAP.get(cp)


def _decode(name: bytes) -> str | None:
    # utf8ncursor() stops at NUL. The kernel trie has a leaf exactly for what
    # Python's strict decoder accepts: no overlongs, surrogates, > U+10FFFF
    # or truncated sequences.
    try:
        return name.split(b"\0", 1)[0].decode("utf-8")
    except UnicodeDecodeError:
        return None


def utf8_validate(name: bytes) -> bool:
    """utf8_validate() == 0: what strict mode (s_encoding_flags bit 0) accepts."""
    return _decode(name) is not None


def utf8_casefold(name: bytes) -> bytes | None:
    """NFD + full case folding + ignorable removal. None when Linux fails (-EINVAL)."""
    text = _decode(name)
    if text is None:
        return _utf8byte_casefold(name.split(b"\0", 1)[0])
    # -1 marks a removed ignorable: utf8byte() treats its empty decomposition
    # as a starter, so combining marks never reorder across it.
    cps: list[int] = []
    for ch in text:
        m = _nfdicf(ord(ch))
        if m is None:
            cps.append(ord(ch))
        elif m:
            cps.extend(map(ord, m))
        else:
            cps.append(-1)
    # Canonical ordering: stable sort each run of non-starters by class.
    i, n = 0, len(cps)
    while i < n:
        if not CCC.get(cps[i]):
            i += 1
            continue
        j = i
        while j < n and CCC.get(cps[j]):
            j += 1
        cps[i:j] = sorted(cps[i:j], key=CCC.__getitem__)
        i = j
    return "".join(chr(cp) for cp in cps if cp >= 0).encode("utf-8")


def _clen(b: int) -> int:
    return 1 + (b >= 0xC0) + (b >= 0xE0) + (b >= 0xF0)


def _leaf(buf: bytes, i: int, limit: int) -> tuple[int, bytes | None] | None:
    """utf8nlookup(): (ccc, decomposition) of the character at buf[i]."""
    n = _clen(buf[i])
    if n > limit:
        return None
    try:
        cp = ord(buf[i : i + n].decode("utf-8"))
    except UnicodeDecodeError:
        return None
    m = _nfdicf(cp)
    return CCC.get(cp, 0), (None if m is None else m.encode("utf-8"))


def _utf8byte_casefold(name: bytes) -> bytes | None:
    """Port of the utf8_casefold()/utf8byte() loop, used for malformed names.

    Linux only fails when a character has no trie leaf. Stray continuation
    bytes after a valid character are copied through, so e.g. b"A\\x80"
    folds to b"a\\x80" and is hashed in that form.
    """
    if name[:1] and name[0] & 0xC0 == 0x80:
        return None
    s, si = name + b"\0", 0
    length = len(name)
    p = sp = ss = None
    slen = 0
    cur = nxt = 0  # u8c->ccc, u8c->nccc
    out = bytearray()
    while len(out) < _PATH_MAX:
        while True:
            if p is not None and s[si] == 0:
                (s, si), p = p, None
            if p is None and (length == 0 or s[si] == 0):
                if cur == 0:
                    return bytes(out)
                ccc = 0
            elif s[si] & 0xC0 == 0x80:
                if p is None:
                    length -= 1
                out.append(s[si])
                si += 1
                break
            else:
                leaf = _leaf(s, si, length if p is None else 4)
                if leaf is None:
                    return None
                ccc, dec = leaf
                if dec is not None:
                    length -= _clen(s[si])
                    p = (s, si + _clen(s[si]))
                    s, si = dec + b"\0", 0
                    if not dec:
                        if cur == 0:
                            continue
                        ccc = 0
                    else:
                        ccc = _leaf(s, 0, 4)[0]
                if ccc and cur < ccc < nxt:
                    nxt = ccc
                if ccc == cur:
                    if p is None:
                        length -= 1
                    out.append(s[si])
                    si += 1
                    break
            # ccc_mismatch
            if nxt == 0:
                cur, nxt = -1, ccc
                sp, ss, slen = p, (s, si), length
                if p is None:
                    length -= _clen(s[si])
                si += _clen(s[si])
            elif ccc:
                if p is None:
                    length -= _clen(s[si])
                si += _clen(s[si])
            elif nxt != 255:
                cur, nxt = nxt, 255
                (s, si), p, length = ss, sp, slen
            else:
                cur = nxt = 0
                sp = ss = None
                slen = 0
    return None
