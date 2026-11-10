# Open Mode (open-v2)

**Open mode is not a privacy feature.** Anyone who reads this document and
the transport layer can read every open-mode payload with a short script. It
exists so the app is useful before the user pays for stealth mode.

If you are evaluating Stiger's privacy guarantees, you want
[`stealth-v4.md`](stealth-v4.md). This document is here for completeness.

What changed from v1: the frame is recovered as a syndrome under a public
permutation ([`lsb-layer.md`](lsb-layer.md) §5–§6) instead of being read
from the first pixels in row-major order; the version byte is `0x02`; the
bytes after the frame are specified as random fill.

## 1. Permutation key

The walk over the cover is keyed by a fixed, public value:

```
permKey = SHA-256(b"stiger-open-v2-perm")      # ASCII, 19 bytes in; 32 bytes out
```

Everyone knows it; that is the point of open mode. It is there so that the
code's blocks are spread over the image rather than following its rows
(the reason is in [`lsb-layer.md`](lsb-layer.md) §5), and so that an open
carrier and a stealth carrier are built the same way.

## 2. Framing

The stream of `S = min(2100, floor(N / 8))` bytes (`N` eligible pixels,
[`lsb-layer.md`](lsb-layer.md) §4) starts with a 9-byte fixed header followed
by the payload:

```
offset  size  field
------  ----  -----------------------------------------------------------
  0      4    magic            = 0x53 0x54 0x45 0x47   ("STEG", ASCII)
  4      1    version          = 0x02
  5      4    payloadLength    = uint32, big-endian
  9      L    payload          = raw bytes, length = payloadLength
  9+L    S-9-L   fill          = unspecified (see §3)
```

`L` is the value read from `payloadLength`. The decoder MUST reject:
- a missing or mismatched magic,
- a `version` other than `0x02`, so that a future incompatible format reusing
  the same magic is not silently parsed as open-v2,
- a `payloadLength` of `0`,
- a `payloadLength` greater than `2048`,
- a `payloadLength` greater than `S - 9`.

A carrier is too small for open mode iff `S < 9 + 1`.

## 3. Bytes outside the frame

The frame is the 9-byte header plus `payloadLength` bytes. The remaining
`S − 9 − L` stream bytes are **unspecified**: a decoder MUST NOT read, check
or depend on them. The Swift engine fills them with random bytes, so that a
one-character open send and a 2 KB one are coded alike; an encoder MAY do
otherwise.

Which pixels of the carrier change is the encoder's choice
([`lsb-layer.md`](lsb-layer.md) §7) and is not visible in the stream.

## 4. Payload semantics

At the wire-format level the payload is opaque bytes. Stiger's app layer
uses UTF-8 text, but that interpretation is application-level and not part
of this spec.

## 5. What "open" means

Anyone who can copy the PNG can read the payload. There is no integrity
check, no encryption, no obfuscation. A passive observer who extracts the
stream of every image they intercept under the public key will see the
`STEG` magic and learn that Stiger was used.

Use open mode for messages you would also be willing to write on a postcard.
