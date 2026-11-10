# LSB Transport Layer

Both modes (open-v2, stealth-v4) share the same way of carrying a short byte
stream in the pixels of a PNG. This document defines that carrier: which
pixels take part (§3), how the stream is coded into their least-significant
bits (§5–§7), and how a decoder reads it back (§8).

Earlier versions (open-v1, stealth-v3) wrote the stream bit for bit into the
pixels and filled the whole carrier. That design is retired; its text is kept
in [`open-v1.md`](open-v1.md) and [`stealth-v3.md`](stealth-v3.md) as history.

> **Notation.** `floor(x)` and `ceil(x)` round down and up. `⊕` is XOR on
> bits, `||` is byte-string concatenation. Integers on the wire are big-endian.

## 1. Pixel decode

The carrier is a PNG. The decoder MUST decode it into 8-bit-per-channel RGBA
with **straight (non-premultiplied)** RGB values, in row-major order
(top-left first, x increases fastest).

Implementations that go through a premultiplied pipeline (e.g. CoreGraphics
with `premultipliedLast`) MUST end up with the same straight-alpha RGB
values; semi-transparent pixels are excluded from the carrier precisely
because that round-trip is lossy on them (see §3).

## 2. Channel and bit position

Each carrier pixel contributes **one bit**: the least-significant bit of
the **blue** channel.

```
pixel byte layout in memory: [ R, G, B, A ]
                                       ^
                                  bit used = (B & 1)
```

**Encoder note.** Decoders read only `B & 1`. The Swift engine changes a bit
by **±1 LSB matching**: `B` becomes `B + 1` or `B − 1`, chosen at random,
except that 0 can only become 1 and 255 only 254. Red, green and alpha are
not changed. Setting the bit by replacement (`B = (B & 0xFE) | bit`) gives a
valid carrier too; it is detectable by the pairs-of-values test, which is why
the engine does not do it.

## 3. Pixel selection

A pixel is **eligible** if and only if its alpha is `0xFF` (fully opaque).

Semi-transparent pixels (alpha 1–254) and fully transparent pixels
(alpha 0) are skipped. Rationale: most encoder pipelines premultiply RGB by
alpha at save time, so LSBs of non-opaque pixels are not preserved across a
PNG save/load round trip.

The eligible pixels, taken in row-major order, form the **cover** of length
`N`, indexed `0 .. N−1`. Each element is one bit, the blue LSB of that pixel.

## 4. Stream size

Every carrier holds a **stream** of exactly `S` bytes, `m = 8·S` bits:

```
S = min(2100, floor(N / 8))
```

The stream is the same size for every mode, and for every send of a given
image — a message of one character and a message of 2 048 bytes give the same
`S`. 2 100 is the largest stealth stream a 2 048-byte message needs
(`stealth-v4.md` §1). Carriers with `N < 16 800` hold a shorter stream, the
whole capacity; their modes' own minimum sizes still apply.

A carrier is too small for a mode when the mode's framing does not fit in `S`
(each mode document says what that means); decoders MUST report such carriers
as "no payload found".

## 5. Cover order: the permutation

The code of §6 is applied to the cover elements in a **permuted order**, not
row-major: the cover's blocks (§6) would otherwise be spatial runs, and runs
of flat colour would have to carry bits the encoder cannot place without
being noticed.

`π` is a deterministic permutation of `[0, N)` derived from a 32-byte key
`permKey`:

```
keystream(L) = HMAC-SHA256(permKey, BE32(0) || INFO)
            || HMAC-SHA256(permKey, BE32(1) || INFO)
            || ...
            truncated to L bytes

INFO    = b"stiger-permutation-v4"      # ASCII, 21 bytes
BE32(c) = c encoded as 4-byte big-endian
```

The permutation is a Fisher–Yates shuffle of `indices = [0, 1, ..., N−1]`
driven by `keystream(N · 4)`:

```
ks = keystream(N * 4)
for i = N-1 down to 1:
    r = uint32_be(ks[i*4 .. i*4+4])     # 4 bytes per swap
    j = r mod (i + 1)
    swap indices[i] and indices[j]

π = indices
```

Element `t` of the **walk** is cover element `π[t]`: the walk visits the
eligible pixels in the order `π[0], π[1], …, π[N−1]`.

Where `permKey` comes from is the mode's business:

- **open-v2**: a fixed public key, `permKey = SHA-256(b"stiger-open-v2-perm")`
  (32 bytes; [`open-v2.md`](open-v2.md) §1).
- **stealth-v4**: a key derived from the password by PBKDF2
  ([`stealth-v4.md`](stealth-v4.md) §3), so that a decoder can reconstruct
  the walk before it has read anything from the carrier.

> The 4-bytes-per-swap, modulo-`(i+1)` construction has a `2^32 / (i+1)`
> modulo bias. For sticker-sized images (`N` ≤ a few hundred thousand) the
> bias is below `2^-13` and not a meaningful distinguisher.

## 6. The code: a binary syndrome-trellis code

The `m` stream bits are not written into `m` of the `N` cover bits. They are
the **syndrome** of all `N` cover bits under a parity-check matrix `H` of
`m` rows and `N` columns:

```
stream bits  s = H · y   (mod 2)
```

where `y[t]` is the blue LSB of walk element `t` after embedding. The decoder
computes `H · y`; the encoder chooses which of the `N` bits to change so that
the equation holds, and it is free to pick the cheapest such set (§7). No bit
of the stream sits at any particular pixel, and nothing on the wire says which
pixels were changed.

`H` is a **syndrome-trellis code** (Filler, Judas, Fridrich 2011) of
constraint height `h = 10`, built from a sub-matrix `Ĥ` of `h` rows and `w`
columns (§6.1), laid along the diagonal in **blocks**: row `j` of `H`
(`0 ≤ j < m`) owns the block of walk elements

```
block(j) = [ floor(j · N / m),  floor((j + 1) · N / m) )
w        = ceil(N / m)             # the widest block; every block has w or w−1 elements
```

Walk element `t` in block `j`, at position `c = t − floor(j · N / m)` inside
it, contributes column `c` of `Ĥ` to `H`, placed with its bit 0 on row `j`
and its bit `k` on row `j + k`. Rows beyond `m − 1` are dropped (`H` is
truncated; equivalently, the trellis may end in any state).

In other words, `H · y` is computed like this:

```
s = [0] * m
for t in 0 .. N-1:
    if y[t] == 1:
        j = block index of t
        c = t - floor(j * N / m)
        col = Ĥcol(w, c)                  # a 10-bit integer, §6.1
        for k in 0 .. 9:
            if (col >> k) & 1 and j + k < m:
                s[j + k] ^= 1
```

The stream bytes are then packed MSB-first: stream byte `i` is
`s[8i] s[8i+1] … s[8i+7]` with `s[8i]` the most-significant bit.

When `m = N` (a carrier of fewer than 16 800 eligible pixels, §4) every block
is one element wide, `w = 1`, and `H` is lower-triangular; the same rule
covers it with no special case.

### 6.1 The sub-matrix generator

`Ĥ` has `w` columns, each a 10-bit integer with **bit 0 and bit 9 set** (the
form every published STC uses: the first and last row of every column are 1).
Rather than a table for every `w` from 1 to 63, the columns are generated:

```
Ĥcol(w, c) = the c-th distinct value (0-indexed) in the sequence
             v_0, v_1, v_2, ...  that satisfies  v & 0x201 == 0x201,
             where
             v_i = uint16_be(HMAC-SHA256(b"stiger-stc-v4", BE16(w) || BE32(i))[0..2]) & 0x3FF
```

That is: hash the width and a counter, take the low 10 bits of the first two
bytes, keep the values with bits 0 and 9 set, skip any value already used for
this `w`, and the `c`-th survivor is column `c`. There are 256 such values, so
every `w ≤ 63` finds its columns; an implementation MAY precompute the table
once and MUST get the same table.

The columns are random by construction, not searched for coding efficiency;
`../docs/experiment-steganalysis-v2.md` §7 measured them at 1.10–1.24 × the
rate–distortion bound. A searched table for the common widths may replace the
generator in a later version; the generator's output for a given `w` is fixed
by this document and the decoder depends on it.

## 7. The encoder (informative)

A decoder never needs this section. It is here so that an encoder written from
the spec reaches the same detectability the Swift engine does, and so that a
reviewer knows what the engine is doing.

- **Which bits change** is the encoder's choice, subject to `H · y = s`. The
  Swift engine runs the Viterbi algorithm over the trellis of `H` with a
  per-pixel **cost** of flipping, and takes the cheapest valid `y`.
- **The cost** SHOULD be content-adaptive: the engine uses HILL (Li, Wang,
  Huang, Li 2014) on the blue channel — the absolute 3×3 KB high-pass
  residual, smoothed by a 3×3 mean, inverted, smoothed by a 15×15 mean — with
  non-eligible pixels filled from their nearest eligible neighbour before
  filtering so the silhouette edge is not read as texture. A constant cost
  gives a valid carrier that is more detectable; §7 of the experiment doc has
  the numbers.
- **The flip** is ±1 matching (§2), sign at random, forced at 0 and 255.
- **Every send is coded the same way**: a send with no secret embeds `S`
  random bytes under a fresh random `permKey`; an open send embeds its frame
  under the public key; a stealth send embeds its stream under the password's
  key. Plain, open and stealth sends of one image are therefore alike in how
  many pixels change and in their statistics.

## 8. Decoder summary

1. Decode the PNG to straight-alpha RGBA (§1); collect the eligible pixels
   in row-major order (§3), `N` of them. Compute `S` and `m` (§4).
2. Build `π` from the mode's `permKey` (§5) and the walk `y[t] = B(π[t]) & 1`.
3. Compute `s = H · y` (§6) and pack it into `S` bytes.
4. Hand the bytes to the mode: [`open-v2.md`](open-v2.md) or
   [`stealth-v4.md`](stealth-v4.md).

## 9. Reference

The Swift engine that defines this layer lives in
`StigerCore/ImageStegoEngine.swift` (`opaqueIndices`, `applyByMatching`),
`StigerCore/STC.swift` (the code) and `StigerCore/HILLCost.swift` (the
encoder's cost). The reference Python decoder in
[`reference/python/stiger_decode.py`](reference/python/stiger_decode.py)
re-implements the read path independently; the TypeScript one in
[`reference/typescript/`](reference/typescript/) mirrors it.
