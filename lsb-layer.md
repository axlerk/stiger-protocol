# LSB Transport Layer

Both modes (open-v1, stealth-v3) share the same way of mapping a flat byte
stream to PNG pixels. This document defines that mapping.

## 1. Pixel decode

The carrier is a PNG. The decoder MUST decode it into 8-bit-per-channel RGBA
with **straight (non-premultiplied)** RGB values, in row-major order
(top-left first, x increases fastest).

Implementations that go through a premultiplied pipeline (e.g. CoreGraphics
with `premultipliedLast`) MUST end up with the same straight-alpha RGB
values; semi-transparent pixels are excluded from the LSB stream precisely
because that round-trip is lossy on them (see §3).

## 2. Channel and bit position

Each LSB-bearing pixel contributes **one bit**: the least-significant bit of
the **blue** channel.

```
pixel byte layout in memory: [ R, G, B, A ]
                                       ^
                                  bit used = (B & 1)
```

## 3. Pixel selection

A pixel is **eligible** if and only if its alpha is `0xFF` (fully opaque).

Semi-transparent pixels (alpha 1–254) and fully transparent pixels
(alpha 0) are skipped. Rationale: most encoder pipelines premultiply RGB by
alpha at save time, so LSBs of non-opaque pixels are not preserved across a
PNG save/load round trip.

The eligible pixels, taken in row-major order, form the **slot array** of
length `N` where each slot is one bit of capacity. Capacity in bytes is
`floor(N / 8)`.

## 4. Bit-to-byte packing

Bytes are written **MSB-first** within each byte:

```
byte b at byte index i occupies slots [i*8 .. i*8+7]
slot i*8 + k holds bit  (b >> (7 - k)) & 1   for k in 0..7
```

That is: the most-significant bit of each byte goes into the lowest-numbered
slot, exactly as if you wrote the byte stream as a big-endian bit string.

## 5. Slot ordering

The byte stream is laid into slots in one of two orders:

- **Row-major** (used by open-v1): logical slot `i` → eligible-pixel slot `i`.
- **Permuted** (used by stealth-v3): logical slot `i` → eligible-pixel slot
  `π(i)`, where `π` is a deterministic permutation of `[0, N)` derived from
  the password. The permutation is defined in [`stealth-v3.md`](stealth-v3.md).

The permutation operates on the entire slot array, not just the message
bits. In stealth mode every eligible pixel is overwritten, so the LSB
stream of the carrier is statistically uniform from any observer who does
not know the password.

## 6. Reference

The Swift engine that defines this mapping lives in
`StigerCore/ImageStegoEngine.swift` (`opaqueIndices`, `writeBits`,
`readBytes`). The reference Python decoder in
[`reference/python/stiger_decode.py`](reference/python/stiger_decode.py)
re-implements the read path independently.
