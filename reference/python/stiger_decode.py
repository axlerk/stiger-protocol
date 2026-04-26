"""Reference decoder for the Stiger wire format.

This file is the *canonical* example implementation of the spec in
`spec/open-v1.md` and `spec/stealth-v3.md`. It deliberately uses standard
library + widely-audited primitives (PyCA `cryptography`, Pillow), no Stiger
code, no clever tricks. If you can read this file you can read every Stiger
sticker you have the password for, and prove to yourself the binary on your
phone is not doing anything else.

Usage:

    python stiger_decode.py path/to/sticker.png
    python stiger_decode.py path/to/sticker.png --password 'hunter2'

Exit status:

    0  decoded successfully
    1  no payload / wrong password / corrupt
    2  bad arguments
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# Constants — must match spec/open-v1.md and spec/stealth-v3.md.
# ---------------------------------------------------------------------------

OPEN_MAGIC = b"STEG"
OPEN_VERSION = 0x01
OPEN_HEADER_SIZE = 9

STEALTH_VERSION = 0x03
STEALTH_HEADER_SIZE = 22
STEALTH_LEN_PREFIX = 2

GCM_NONCE_LEN = 12
GCM_TAG_LEN = 16
GCM_OVERHEAD = GCM_NONCE_LEN + GCM_TAG_LEN

MAX_PAYLOAD_BYTES = 2048

PBKDF2_ITER = 600_000
SALT_LEN = 16

PERM_KDF_SALT = b"stiger-perm-v3-salt"
PERM_INFO = b"stiger-permutation-v3"
HEADER_INFO = b"stiger-v3-header"


# ---------------------------------------------------------------------------
# LSB transport layer (spec/lsb-layer.md).
# ---------------------------------------------------------------------------


@dataclass
class Slots:
    """Eligible (alpha == 255) pixel byte-offsets, row-major."""

    blue_offsets: list[int]      # offset of the blue byte in raw RGBA buffer
    raw: bytes                   # full RGBA buffer

    @property
    def n(self) -> int:
        return len(self.blue_offsets)

    @property
    def available_bytes(self) -> int:
        return self.n // 8


def load_slots(png_path: Path) -> Slots:
    img = Image.open(png_path).convert("RGBA")
    raw = img.tobytes()
    blue_offsets: list[int] = []
    for i in range(0, len(raw), 4):
        if raw[i + 3] == 0xFF:
            blue_offsets.append(i + 2)
    return Slots(blue_offsets=blue_offsets, raw=raw)


def read_bytes(slots: Slots, count: int, order: Optional[list[int]] = None,
               start_slot: int = 0) -> bytes:
    """Read `count` bytes (MSB-first within each byte) from the LSB stream.

    `order[i]` is the eligible-pixel index that holds logical bit `i`.
    `order=None` means row-major (logical i -> eligible pixel i).
    """
    out = bytearray(count)
    for byte_index in range(count):
        b = 0
        for bit in range(8):
            slot = start_slot + byte_index * 8 + bit
            if slot >= slots.n:
                break
            logical = order[slot] if order is not None else slot
            blue = slots.raw[slots.blue_offsets[logical]]
            b = (b << 1) | (blue & 1)
        out[byte_index] = b
    return bytes(out)


# ---------------------------------------------------------------------------
# Open mode (spec/open-v1.md).
# ---------------------------------------------------------------------------


def decode_open(slots: Slots) -> bytes:
    if slots.available_bytes < OPEN_HEADER_SIZE:
        raise ValueError("no payload found")

    header = read_bytes(slots, OPEN_HEADER_SIZE)
    if header[0:4] != OPEN_MAGIC:
        raise ValueError("no payload found")

    length = int.from_bytes(header[5:9], "big")
    if length == 0 or length > MAX_PAYLOAD_BYTES:
        raise ValueError("no payload found")
    if OPEN_HEADER_SIZE + length > slots.available_bytes:
        raise ValueError("payload truncated")

    return read_bytes(slots, length, start_slot=OPEN_HEADER_SIZE * 8)


# ---------------------------------------------------------------------------
# Stealth mode (spec/stealth-v3.md).
# ---------------------------------------------------------------------------


def pbkdf2(password: str, salt: bytes, dklen: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITER,
        dklen=dklen,
    )


def hkdf_sha256(ikm: bytes, info: bytes, length: int,
                salt: bytes = b"") -> bytes:
    """RFC 5869 HKDF-SHA256, matching CryptoKit's empty-salt default."""
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def keystream_hmac_ctr(key: bytes, info: bytes, length: int) -> bytes:
    """HMAC-SHA256 in counter mode -> arbitrary-length pseudo-random stream."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(
            key,
            counter.to_bytes(4, "big") + info,
            hashlib.sha256,
        ).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def derive_permutation(password: str, n: int) -> list[int]:
    """Fisher-Yates shuffle of [0, n) driven by HMAC-SHA256 in counter mode."""
    if n < 2:
        return list(range(n))
    perm_key = pbkdf2(password, PERM_KDF_SALT, dklen=32)
    ks = keystream_hmac_ctr(perm_key, PERM_INFO, n * 4)
    indices = list(range(n))
    i = n - 1
    while i > 0:
        off = i * 4
        r = int.from_bytes(ks[off:off + 4], "big")
        j = r % (i + 1)
        indices[i], indices[j] = indices[j], indices[i]
        i -= 1
    return indices


def decode_stealth(slots: Slots, password: str) -> bytes:
    available = slots.available_bytes
    plaintext_size = available - STEALTH_HEADER_SIZE - GCM_OVERHEAD
    if plaintext_size < STEALTH_LEN_PREFIX:
        raise ValueError("no payload found")

    permutation = derive_permutation(password, slots.n)
    stream = read_bytes(slots, available, order=permutation)

    salt = stream[0:16]
    marker = stream[16:20]
    masked_version = stream[20]
    masked_reserved = stream[21]

    main_key = pbkdf2(password, salt, dklen=32)
    derived = hkdf_sha256(main_key, HEADER_INFO, 34)
    mac_key = derived[0:32]
    mask = derived[32:34]

    expected = hmac.new(
        mac_key,
        salt + bytes([masked_version, masked_reserved]),
        hashlib.sha256,
    ).digest()[:4]
    if not hmac.compare_digest(expected, marker):
        raise ValueError("no payload found")

    version = masked_version ^ mask[0]
    if version != STEALTH_VERSION:
        raise ValueError("no payload found")

    cipher_blob = stream[STEALTH_HEADER_SIZE:available]
    aesgcm = AESGCM(main_key)
    try:
        plaintext_block = aesgcm.decrypt(
            cipher_blob[:GCM_NONCE_LEN],
            cipher_blob[GCM_NONCE_LEN:],
            None,
        )
    except Exception:
        raise ValueError("no payload found") from None

    if len(plaintext_block) < STEALTH_LEN_PREFIX:
        raise ValueError("payload truncated")
    length = int.from_bytes(plaintext_block[0:2], "big")
    if length == 0:
        raise ValueError("no payload found")
    if length > MAX_PAYLOAD_BYTES or length > len(plaintext_block) - STEALTH_LEN_PREFIX:
        raise ValueError("payload truncated")
    return plaintext_block[STEALTH_LEN_PREFIX:STEALTH_LEN_PREFIX + length]


# ---------------------------------------------------------------------------
# Top-level decode.
# ---------------------------------------------------------------------------


@dataclass
class DecodeResult:
    data: bytes
    encrypted: bool


def decode(png_path: Path, password: Optional[str] = None) -> DecodeResult:
    slots = load_slots(png_path)
    if password:
        try:
            return DecodeResult(data=decode_stealth(slots, password),
                                encrypted=True)
        except ValueError:
            pass    # fall through to open mode (e.g. legacy public sticker)
    return DecodeResult(data=decode_open(slots), encrypted=False)


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Reference decoder for Stiger PNG stickers.",
    )
    parser.add_argument("path", type=Path, help="Path to the sticker PNG.")
    parser.add_argument(
        "--password",
        type=str,
        default=None,
        help="Stealth-mode password. Omit for open-mode stickers.",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Print payload as raw bytes to stdout instead of UTF-8 text.",
    )
    args = parser.parse_args(argv)

    try:
        result = decode(args.path, args.password)
    except ValueError as e:
        print(f"decode failed: {e}", file=sys.stderr)
        return 1

    mode = "stealth" if result.encrypted else "open"
    print(f"mode: {mode}", file=sys.stderr)
    if args.raw:
        sys.stdout.buffer.write(result.data)
    else:
        try:
            print(result.data.decode("utf-8"))
        except UnicodeDecodeError:
            sys.stdout.buffer.write(result.data)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
