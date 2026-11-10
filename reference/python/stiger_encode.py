# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Pavel Khudiakov
"""Reference encoder for the Stiger wire format (open-v2, stealth-v4, plain).

The decode path is what the spec makes normative; this encoder exists so that
the spec can be exercised end to end without the Swift engine, and to
produce carriers an independent decoder can be checked against. It follows
`spec/lsb-layer.md` §7: a Viterbi search over the syndrome-trellis code with
HILL costs on the blue channel, +-1 matching with a random sign, forced at
0 and 255. It is written for clarity, not speed: a 512x512 sticker takes a
few seconds.

Usage:

    python stiger_encode.py in.png out.png --message 'hello'                     # open-v2
    python stiger_encode.py in.png out.png --message 'hello' --password 'pw'     # stealth-v4
    python stiger_encode.py in.png out.png                                       # plain send

Deps: Pillow, cryptography, numpy, scipy (scipy only for the cost map's
nearest-eligible fill).
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import sys
from pathlib import Path
from typing import Optional

import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scipy import ndimage

import stiger_decode as D
from stiger_transport import (H_BITS, block_width, cover_from_rgba, permutation, stream_size,
                              submatrix, syndrome, unpack_bits)

STATES = 1 << H_BITS


# ---------------------------------------------------------------------------
# Stream construction (the mode documents).
# ---------------------------------------------------------------------------


def open_stream(payload: bytes, s_bytes: int) -> bytes:
    """open-v2 §2: STEG || 0x02 || length || payload || random fill."""
    if not 1 <= len(payload) <= D.MAX_PAYLOAD_BYTES:
        raise ValueError("payload must be 1..2048 bytes")
    if len(payload) > s_bytes - D.OPEN_HEADER_SIZE:
        raise ValueError("carrier too small for this payload")
    frame = D.OPEN_MAGIC + bytes([D.OPEN_VERSION]) + len(payload).to_bytes(4, "big") + payload
    return frame + os.urandom(s_bytes - len(frame))


def stealth_stream(payload: bytes, password: str, s_bytes: int) -> bytes:
    """stealth-v4 §2, §4, §5: header(22) || AES-GCM(nonce || ct || tag) over a padded block."""
    plaintext_size = s_bytes - D.STEALTH_HEADER_SIZE - D.GCM_OVERHEAD
    if not 1 <= len(payload) <= D.MAX_PAYLOAD_BYTES or len(payload) > plaintext_size - D.STEALTH_LEN_PREFIX:
        raise ValueError("carrier too small for this payload")
    salt = os.urandom(D.SALT_LEN)
    main_key = D.pbkdf2(password, salt, dklen=32)
    derived = D.hkdf_sha256(main_key, D.HEADER_INFO, 34)
    mac_key, mask = derived[0:32], derived[32:34]
    masked_version = D.STEALTH_VERSION ^ mask[0]
    masked_reserved = 0x00 ^ mask[1]
    marker = hmac.new(mac_key, salt + bytes([masked_version, masked_reserved]), hashlib.sha256).digest()[:4]
    header = salt + marker + bytes([masked_version, masked_reserved])

    block = len(payload).to_bytes(2, "big") + payload
    block += os.urandom(plaintext_size - len(block))
    nonce = os.urandom(D.GCM_NONCE_LEN)
    sealed = nonce + AESGCM(main_key).encrypt(nonce, block, None)     # ct || tag
    stream = header + sealed
    assert len(stream) == s_bytes
    return stream


# ---------------------------------------------------------------------------
# Cost map (lsb-layer.md §7, informative): HILL on the blue channel.
# ---------------------------------------------------------------------------

KB = np.array([[-1, 2, -1], [2, -4, 2], [-1, 2, -1]], float)


def hill_cost(blue: np.ndarray, eligible: np.ndarray) -> np.ndarray:
    """HILL (Li, Wang, Huang, Li 2014); non-eligible pixels filled from the nearest eligible one."""
    x = blue.astype(float)
    if not eligible.all():
        idx = ndimage.distance_transform_edt(~eligible, return_distances=False, return_indices=True)
        x = x[idx[0], idx[1]]
    residual = np.abs(ndimage.convolve(x, KB, mode="reflect"))
    rho = 1.0 / (ndimage.uniform_filter(residual, 3, mode="reflect") + 1e-10)
    rho = ndimage.uniform_filter(rho, 15, mode="reflect")
    return rho


# ---------------------------------------------------------------------------
# The Viterbi search over the trellis (lsb-layer.md §6-§7).
# ---------------------------------------------------------------------------


def stc_embed(x: np.ndarray, rho: np.ndarray, message_bits: np.ndarray) -> np.ndarray:
    """Minimum-cost y with H*y = message (mod 2). x, y: uint8 0/1 over the walk; rho: cost of y[t] != x[t]."""
    n, m = x.size, message_bits.size
    if not 0 < m <= n:
        raise ValueError("m must satisfy 0 < m <= n")
    cols = submatrix(block_width(n, m))
    states = np.arange(STATES)
    xor_index = {c: states ^ c for c in set(cols)}
    choices = np.zeros((n, STATES // 8), np.uint8)          # one bit per state and step
    pc = np.full(STATES, np.inf)
    pc[0] = 0.0
    j, start, end = 0, 0, n // m
    for t in range(n):
        while t >= end:
            j += 1
            start, end = end, ((j + 1) * n) // m
        col = cols[t - start]
        cost_keep, cost_flip = (rho[t], 0.0) if x[t] else (0.0, rho[t])
        a = pc + cost_keep                                  # y[t] = 0
        b = pc[xor_index[col]] + cost_flip                  # y[t] = 1
        take = b < a
        nc = np.where(take, b, a)
        choices[t] = np.packbits(take, bitorder="little")
        if t == end - 1:                                    # row j complete
            bit = int(message_bits[j])
            pc = np.full(STATES, np.inf)
            pc[:STATES // 2] = nc[bit::2]
        else:
            pc = nc
    state = int(np.argmin(pc))                              # truncated H: any final state
    y = np.zeros(n, np.uint8)
    j, end, start = m - 1, n, ((m - 1) * n) // m
    for t in range(n - 1, -1, -1):
        while t < start:
            j -= 1
            end, start = start, (j * n) // m
        if t == end - 1:
            state = ((state << 1) | int(message_bits[j])) & (STATES - 1)
        bit = (choices[t, state >> 3] >> (state & 7)) & 1
        y[t] = bit
        if bit:
            state ^= cols[t - start]
    if state != 0:
        raise RuntimeError("traceback did not return to state 0 (bug)")
    return y


# ---------------------------------------------------------------------------
# Putting it together.
# ---------------------------------------------------------------------------


def embed(rgba: bytes, width: int, height: int, stream: bytes, perm_key: bytes,
          rng: Optional[np.random.Generator] = None) -> bytes:
    """Returns new RGBA bytes carrying `stream` under the walk keyed by `perm_key`."""
    rng = rng or np.random.default_rng()
    cover = cover_from_rgba(rgba)
    n = cover.n
    m = 8 * len(stream)
    if m != 8 * stream_size(n):
        raise ValueError("stream is not the carrier's stream size")
    pi = np.asarray(permutation(perm_key, n))
    raw = np.frombuffer(bytes(rgba), np.uint8).reshape(height, width, 4).copy()
    blue = raw[..., 2]
    eligible = raw[..., 3] == 255
    offsets = np.asarray(cover.blue_offsets)
    blue_flat = raw.reshape(-1)[offsets]                     # blue of cover element i
    x_walk = (blue_flat[pi] & 1).astype(np.uint8)
    rho_walk = hill_cost(blue, eligible)[eligible][pi]
    y_walk = stc_embed(x_walk, rho_walk, np.asarray(unpack_bits(stream), np.uint8))
    flip = y_walk != x_walk
    # +-1 matching with a random sign, forced at 0 and 255 (lsb-layer.md §2).
    v = blue_flat[pi].astype(np.int16)
    sign = rng.choice(np.array([-1, 1], np.int16), n)
    nv = v + np.where(flip, sign, 0)
    nv = np.where(nv < 0, 1, np.where(nv > 255, 254, nv)).astype(np.uint8)
    new_blue = blue_flat.copy()
    new_blue[pi] = nv
    raw.reshape(-1)[offsets] = new_blue
    # Self-check: the decoder's syndrome of the result is the stream.
    out_cover = cover_from_rgba(raw.tobytes())
    got = syndrome(lambda t: out_cover.lsb(int(pi[t])), n, m)
    if bytes(np.packbits(np.asarray(got, np.uint8))) != stream:
        raise RuntimeError("syndrome of the embedded carrier does not match the stream (bug)")
    return raw.tobytes()


def encode_file(src: Path, dst: Path, message: Optional[bytes], password: Optional[str]) -> str:
    img = Image.open(src).convert("RGBA")
    rgba = img.tobytes()
    s_bytes = stream_size(cover_from_rgba(rgba).n)
    if message is None:
        stream, perm_key, mode = os.urandom(s_bytes), os.urandom(32), "plain"
    elif password:
        stream, perm_key, mode = stealth_stream(message, password, s_bytes), D.stealth_perm_key(password), "stealth"
    else:
        stream, perm_key, mode = open_stream(message, s_bytes), D.OPEN_PERM_KEY, "open"
    out = embed(rgba, img.width, img.height, stream, perm_key)
    Image.frombytes("RGBA", img.size, out).save(dst, "PNG")
    return mode


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Reference encoder for Stiger PNG stickers.")
    ap.add_argument("src", type=Path)
    ap.add_argument("dst", type=Path)
    ap.add_argument("--message", type=str, default=None, help="UTF-8 text; omit for a plain (no-secret) send")
    ap.add_argument("--password", type=str, default=None, help="non-empty selects stealth-v4")
    args = ap.parse_args(argv)
    try:
        mode = encode_file(args.src, args.dst, args.message.encode("utf-8") if args.message is not None else None,
                           args.password or None)
    except ValueError as e:
        print(f"encode failed: {e}", file=sys.stderr)
        return 1
    print(f"mode: {mode}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
