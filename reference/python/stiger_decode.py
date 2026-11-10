# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Pavel Khudiakov
"""Reference decoder for the Stiger wire format.

This file is the *canonical* example implementation of the spec in
`spec/open-v2.md` and `spec/stealth-v4.md`, over the transport layer of
`spec/lsb-layer.md` (`stiger_transport.py`). It deliberately uses standard
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

from stiger_transport import Cover, cover_from_rgba, extract_stream


# ---------------------------------------------------------------------------
# Constants — must match spec/open-v2.md and spec/stealth-v4.md.
# ---------------------------------------------------------------------------

OPEN_MAGIC = b"STEG"
OPEN_VERSION = 0x02
OPEN_HEADER_SIZE = 9
OPEN_PERM_KEY = hashlib.sha256(b"stiger-open-v2-perm").digest()

STEALTH_VERSION = 0x04
STEALTH_HEADER_SIZE = 22
STEALTH_LEN_PREFIX = 2

GCM_NONCE_LEN = 12
GCM_TAG_LEN = 16
GCM_OVERHEAD = GCM_NONCE_LEN + GCM_TAG_LEN

MAX_PAYLOAD_BYTES = 2048

PBKDF2_ITER = 600_000
SALT_LEN = 16

PERM_KDF_SALT = b"stiger-perm-v4-salt"
HEADER_INFO = b"stiger-v4-header"


def load_cover(png_path: Path) -> Cover:
    img = Image.open(png_path).convert("RGBA")
    return cover_from_rgba(img.tobytes())


# ---------------------------------------------------------------------------
# Open mode (spec/open-v2.md).
# ---------------------------------------------------------------------------


def decode_open(cover: Cover) -> bytes:
    s_bytes = cover.stream_bytes
    if s_bytes < OPEN_HEADER_SIZE + 1:
        raise ValueError("no payload found")

    stream = extract_stream(cover, OPEN_PERM_KEY)
    header = stream[:OPEN_HEADER_SIZE]
    if header[0:4] != OPEN_MAGIC:
        raise ValueError("no payload found")
    # Reject versions we do not know, so a future incompatible format that
    # reuses the magic is not silently parsed as open-v2.
    if header[4] != OPEN_VERSION:
        raise ValueError("no payload found")

    length = int.from_bytes(header[5:9], "big")
    if length == 0 or length > MAX_PAYLOAD_BYTES:
        raise ValueError("no payload found")
    if length > s_bytes - OPEN_HEADER_SIZE:
        raise ValueError("payload truncated")

    return stream[OPEN_HEADER_SIZE:OPEN_HEADER_SIZE + length]


# ---------------------------------------------------------------------------
# Stealth mode (spec/stealth-v4.md).
# ---------------------------------------------------------------------------


def pbkdf2(password: str, salt: bytes, dklen: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITER, dklen=dklen)


def hkdf_sha256(ikm: bytes, info: bytes, length: int, salt: bytes = b"") -> bytes:
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


def stealth_perm_key(password: str) -> bytes:
    """stealth-v4 §3: the walk is keyed by the password alone."""
    return pbkdf2(password, PERM_KDF_SALT, dklen=32)


def decode_stealth(cover: Cover, password: str) -> bytes:
    s_bytes = cover.stream_bytes
    plaintext_size = s_bytes - STEALTH_HEADER_SIZE - GCM_OVERHEAD
    if plaintext_size < STEALTH_LEN_PREFIX:
        raise ValueError("no payload found")

    stream = extract_stream(cover, stealth_perm_key(password))

    salt = stream[0:16]
    marker = stream[16:20]
    masked_version = stream[20]
    masked_reserved = stream[21]

    main_key = pbkdf2(password, salt, dklen=32)
    derived = hkdf_sha256(main_key, HEADER_INFO, 34)
    mac_key = derived[0:32]
    mask = derived[32:34]

    expected = hmac.new(mac_key, salt + bytes([masked_version, masked_reserved]),
                        hashlib.sha256).digest()[:4]
    if not hmac.compare_digest(expected, marker):
        raise ValueError("no payload found")

    version = masked_version ^ mask[0]
    if version != STEALTH_VERSION:
        raise ValueError("no payload found")

    cipher_blob = stream[STEALTH_HEADER_SIZE:s_bytes]
    aesgcm = AESGCM(main_key)
    try:
        plaintext_block = aesgcm.decrypt(cipher_blob[:GCM_NONCE_LEN], cipher_blob[GCM_NONCE_LEN:], None)
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
    cover = load_cover(png_path)
    # Open mode first: it needs no key, and a stealth stream shows the open
    # header only by a 2^-40 accident (magic and version).
    try:
        return DecodeResult(data=decode_open(cover), encrypted=False)
    except ValueError as open_error:
        if not password:
            raise open_error
    return DecodeResult(data=decode_stealth(cover, password), encrypted=True)


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Reference decoder for Stiger PNG stickers.")
    parser.add_argument("path", type=Path, help="Path to the sticker PNG.")
    parser.add_argument("--password", type=str, default=None,
                        help="Stealth-mode password. Omit for open-mode stickers.")
    parser.add_argument("--raw", action="store_true",
                        help="Print payload as raw bytes to stdout instead of UTF-8 text.")
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
