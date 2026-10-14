# Open Mode (open-v1)

**Open mode is not a privacy feature.** Anyone who reads this document and
writes 30 lines of Python can read every open-mode payload. It exists so the
app is useful before the user pays for stealth mode.

If you are evaluating Stiger's privacy guarantees, you want
[`stealth-v3.md`](stealth-v3.md). This document is here for completeness.

## 1. Framing

The LSB byte stream (see [`lsb-layer.md`](lsb-layer.md), row-major order)
starts with a 9-byte fixed header followed by the payload:

```
offset  size  field
------  ----  -----------------------------------------------------------
  0      4    magic            = 0x53 0x54 0x45 0x47   ("STEG", ASCII)
  4      1    version          = 0x01
  5      4    payloadLength    = uint32, big-endian
  9      L    payload          = raw bytes, length = payloadLength
```

`L` is the value read from `payloadLength`. The decoder MUST reject:
- a missing or mismatched magic,
- a `version` other than `0x01`, so that a future incompatible format reusing
  the same magic is not silently parsed as open-v1,
- a `payloadLength` of `0`,
- a `payloadLength` greater than `2048`,
- a `payloadLength` greater than `floor(N / 8) - 9` where `N` is the eligible
  pixel count.

## 2. Payload semantics

At the wire-format level the payload is opaque bytes. Stiger's app layer
uses UTF-8 text, but that interpretation is application-level and not part
of this spec.

## 2a. Bits outside the frame

The frame is the 9-byte header plus `payloadLength` bytes. Every other LSB of
the carrier is **unspecified**: a decoder MUST NOT read, check or depend on it,
and an encoder MAY leave it as it was or fill it with random bits. The Swift
engine fills it with random bits (so that open, stealth and no-secret sends of
a sticker look alike to statistical tests); older releases left it untouched.
Both are valid open-v1 carriers.

## 3. What "open" means

Anyone who can copy the PNG can read the payload. There is no integrity
check, no encryption, no obfuscation. A passive observer who runs LSB
analysis on every image they intercept will see the `STEG` magic and learn
that Stiger was used.

Use open mode for messages you would also be willing to write on a postcard.
