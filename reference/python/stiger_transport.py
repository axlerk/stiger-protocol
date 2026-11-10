# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Pavel Khudiakov
"""The LSB transport layer of the Stiger wire format (spec/lsb-layer.md).

Shared by the reference decoder (`stiger_decode.py`) and the reference encoder
(`stiger_encode.py`). Everything a decoder needs is plain Python on the
standard library: eligible pixels (§3), the stream size (§4), the permuted
walk (§5), the sub-matrix generator (§6.1) and the syndrome H*y (§6). The
encoder's Viterbi search over the trellis (§7) needs numpy and lives in
`stiger_encode.py`.

Written from the spec only; no Stiger code involved.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from functools import lru_cache

# ---------------------------------------------------------------------------
# Constants (spec/lsb-layer.md).
# ---------------------------------------------------------------------------

H_BITS = 10                                  # constraint height of the STC
MAX_STREAM_BYTES = 2100                      # §4: min(2100, floor(N / 8))
PERM_INFO = b"stiger-permutation-v4"         # §5
SUBMATRIX_LABEL = b"stiger-stc-v4"           # §6.1
COLUMN_MASK = (1 << H_BITS) - 1              # 0x3FF
COLUMN_REQUIRED = 1 | (1 << (H_BITS - 1))    # 0x201: bits 0 and 9 set


# ---------------------------------------------------------------------------
# §3 eligible pixels, §4 stream size.
# ---------------------------------------------------------------------------


@dataclass
class Cover:
    """Eligible (alpha == 255) pixels of an RGBA raster, row-major.

    `blue_offsets[i]` is the offset of cover element i's blue byte in `raw`.
    """

    blue_offsets: list[int]
    raw: bytearray

    @property
    def n(self) -> int:
        return len(self.blue_offsets)

    @property
    def stream_bytes(self) -> int:
        return stream_size(self.n)

    def lsb(self, i: int) -> int:
        return self.raw[self.blue_offsets[i]] & 1


def cover_from_rgba(raw: bytes | bytearray) -> Cover:
    """`raw` is straight-alpha RGBA, 4 bytes per pixel, row-major (§1)."""
    offsets = [i + 2 for i in range(0, len(raw), 4) if raw[i + 3] == 0xFF]
    return Cover(blue_offsets=offsets, raw=bytearray(raw))


def stream_size(n: int) -> int:
    """§4: bytes of stream a cover of n eligible pixels carries."""
    return min(MAX_STREAM_BYTES, n // 8)


# ---------------------------------------------------------------------------
# §5 the permuted walk.
# ---------------------------------------------------------------------------


def keystream_hmac_ctr(key: bytes, info: bytes, length: int) -> bytes:
    """HMAC-SHA256 in counter mode: HMAC(key, BE32(0) || info) || HMAC(key, BE32(1) || info) ..."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hmac.new(key, counter.to_bytes(4, "big") + info, hashlib.sha256).digest())
        counter += 1
    return bytes(out[:length])


def permutation(perm_key: bytes, n: int) -> list[int]:
    """§5: Fisher-Yates shuffle of [0, n) driven by keystream(n * 4). pi[t] = cover index of walk element t."""
    indices = list(range(n))
    if n < 2:
        return indices
    ks = keystream_hmac_ctr(perm_key, PERM_INFO, n * 4)
    for i in range(n - 1, 0, -1):
        off = i * 4
        j = int.from_bytes(ks[off:off + 4], "big") % (i + 1)
        indices[i], indices[j] = indices[j], indices[i]
    return indices


# ---------------------------------------------------------------------------
# §6 the syndrome-trellis code.
# ---------------------------------------------------------------------------


@lru_cache(maxsize=None)
def submatrix(width: int) -> tuple[int, ...]:
    """§6.1: `width` distinct 10-bit columns with bits 0 and 9 set, from HMAC-SHA256(label, BE16(w) || BE32(i))."""
    if not 1 <= width <= 256:
        raise ValueError("sub-matrix width out of range")
    cols: list[int] = []
    seen: set[int] = set()
    counter = 0
    while len(cols) < width:
        digest = hmac.new(SUBMATRIX_LABEL, width.to_bytes(2, "big") + counter.to_bytes(4, "big"),
                          hashlib.sha256).digest()
        v = int.from_bytes(digest[0:2], "big") & COLUMN_MASK
        counter += 1
        if v & COLUMN_REQUIRED != COLUMN_REQUIRED or v in seen:
            continue
        seen.add(v)
        cols.append(v)
    return tuple(cols)


def block_width(n: int, m: int) -> int:
    """§6: w = ceil(n / m), the widest block."""
    return -(-n // m)


def block_start(j: int, n: int, m: int) -> int:
    """§6: first walk element of block j, floor(j * n / m)."""
    return (j * n) // m


def syndrome(walk_bits, n: int, m: int) -> list[int]:
    """§6: s = H * y (mod 2). `walk_bits(t)` returns y[t], the LSB of walk element t."""
    if m <= 0 or m > n:
        raise ValueError("m must satisfy 0 < m <= n")
    cols = submatrix(block_width(n, m))
    s = [0] * m
    j, start, end = 0, 0, n // m                        # block 0 = [0, floor(n / m))
    for t in range(n):
        while t >= end:
            j += 1
            start, end = end, ((j + 1) * n) // m
        if walk_bits(t) == 0:
            continue
        col = cols[t - start]
        r = j
        while col and r < m:
            if col & 1:
                s[r] ^= 1
            col >>= 1
            r += 1
    return s


def pack_bits(bits: list[int]) -> bytes:
    """§6: MSB-first packing of a bit list whose length is a multiple of 8."""
    out = bytearray(len(bits) // 8)
    for i in range(0, len(bits), 8):
        b = 0
        for k in range(8):
            b = (b << 1) | (bits[i + k] & 1)
        out[i // 8] = b
    return bytes(out)


def unpack_bits(data: bytes) -> list[int]:
    return [(byte >> (7 - k)) & 1 for byte in data for k in range(8)]


def extract_stream(cover: Cover, perm_key: bytes) -> bytes:
    """§8 steps 2-3: the S-byte stream of `cover` under the walk keyed by `perm_key`."""
    n = cover.n
    m = 8 * stream_size(n)
    if m == 0:
        return b""
    pi = permutation(perm_key, n)
    bits = syndrome(lambda t: cover.lsb(pi[t]), n, m)
    return pack_bits(bits)
