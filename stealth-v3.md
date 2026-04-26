# Stealth Mode v3 (stealth-v3)

The mode that protects messages. Without the password, every bit of the
LSB stream is computationally indistinguishable from uniform random noise:
no magic, no length, no fixed structure, no spatial pattern.

This document defines the wire format. For threat-model claims and the
adversaries this is designed to resist, see [`THREAT_MODEL.md`](THREAT_MODEL.md).

> **Notation.** All multi-byte integer fields are big-endian unless stated
> otherwise. `||` is byte-string concatenation. `[a..b]` denotes a half-open
> byte slice (b exclusive).

## 1. Inputs

- `password` — UTF-8 bytes of the user's passphrase. Non-empty.
- `image`    — eligible pixels as defined in [`lsb-layer.md`](lsb-layer.md).
  Let `N` = number of eligible pixels.

Define:

```
availableBytes = floor(N / 8)
headerSize     = 22
gcmOverhead    = 12 + 16        # nonce + tag
lenPrefix      = 2
plaintextSize  = availableBytes - headerSize - gcmOverhead
```

A carrier is too small for stealth mode iff
`plaintextSize < lenPrefix` (i.e. there is no room for even a zero-length
message). Decoders MUST reject such carriers as "no payload found".

## 2. LSB stream layout

The full LSB byte stream of length `availableBytes` is laid into eligible
pixels through a **password-derived permutation** `π` (see §3). The stream
itself is:

```
offset      size            field
------      --------------  ----------------------------------------------
  0          16             salt
 16           4             marker
 20           1             maskedVersion
 21           1             maskedReserved
 22         availableBytes  ciphertextBlob (AES-256-GCM, see §4)
              - 22
```

There is **no plaintext length field** anywhere in the wire format. The
ciphertext blob fills the entire remaining capacity, and the real message
length is stored *inside* the encrypted plaintext.

## 3. Permutation `π`

`π` is a deterministic permutation of `[0, N)`. It is keyed by the password
alone (not the per-message salt) so that a decoder can reconstruct the
permutation **before** reading the salt out of the first 16 stream bytes.

```
permKey = PBKDF2-HMAC-SHA256(
              password = password,
              salt     = b"stiger-perm-v3-salt",   # ASCII, 19 bytes
              iter     = 600000,
              dkLen    = 32)
```

A keystream is derived from `permKey` by HMAC-SHA256 in counter mode:

```
keystream(L) = HMAC-SHA256(permKey, BE32(0)  || INFO)
            || HMAC-SHA256(permKey, BE32(1)  || INFO)
            || ...
            truncated to L bytes

INFO = b"stiger-permutation-v3"      # ASCII, 21 bytes
BE32(c) = c encoded as 4-byte big-endian
```

The permutation is then a Fisher–Yates shuffle of `indices = [0, 1, ..., N-1]`
driven by `keystream(N * 4)`:

```
ks = keystream(N * 4)
for i = N-1 down to 1:
    r = uint32_be(ks[i*4 .. i*4+4])     # 4 bytes per swap
    j = r mod (i + 1)
    swap indices[i] and indices[j]

π = indices
```

Logical slot `s` (0-indexed bit in the byte stream) lives in eligible-pixel
slot `π[s]`.

> The 4-bytes-per-swap, modulo-`(i+1)` construction has a `2^32 / (i+1)`
> modulo bias. For sticker-sized images (`N` ≤ a few hundred thousand) the
> bias is below `2^-13` and not a meaningful distinguisher.

## 4. Header and key derivation

After reading the first 22 bytes through `π`:

```
salt           = stream[ 0 .. 16]     # 16 bytes
marker         = stream[16 .. 20]     #  4 bytes
maskedVersion  = stream[20]
maskedReserved = stream[21]
```

Derive per-message key material:

```
mainKey = PBKDF2-HMAC-SHA256(
              password = password,
              salt     = salt,                  # the 16 bytes from the header
              iter     = 600000,
              dkLen    = 32)

derived = HKDF-SHA256(
              ikm  = mainKey,
              salt = empty,                     # zero-length salt
              info = b"stiger-v3-header",       # ASCII, 16 bytes
              L    = 34)

macKey  = derived[0 .. 32]                      # 32 bytes
mask    = derived[32 .. 34]                     #  2 bytes
```

> "HKDF-SHA256 with empty salt" is HKDF as defined in RFC 5869 with a
> zero-length `salt` parameter, which makes the extract step
> `PRK = HMAC-SHA256(b"", ikm)`. This matches Apple CryptoKit's
> `HKDF<SHA256>.deriveKey(inputKeyMaterial:info:outputByteCount:)`
> behaviour when no salt is supplied.

Verify the marker (in **constant time** over the 4-byte comparison):

```
expected = HMAC-SHA256(macKey, salt || maskedVersion || maskedReserved)[0 .. 4]
require constant_time_equal(expected, marker)
```

If the comparison fails, the decoder MUST report "no payload found" and
MUST NOT proceed to the GCM step. The marker mismatch means one of:
the password is wrong; the image is not a Stiger stealth carrier; the
header has been tampered with; or the carrier was decoded with the wrong
pixel-eligibility rules.

Recover the version and require it to be exactly `0x03`:

```
version = maskedVersion XOR mask[0]
require version == 0x03
```

(The `maskedReserved` byte XORed against `mask[1]` is currently `0x00`. It
is reserved for future use; the HMAC marker authenticates it so any future
flag bits added there are tamper-evident from day one.)

## 5. Plaintext recovery

The ciphertext blob is `stream[22 .. availableBytes]`. Decrypt as a single
AES-256-GCM seal:

```
ciphertextBlob = nonce(12) || ciphertext || tag(16)

plaintextBlock = AES-GCM-Open(
                     key        = mainKey,
                     nonce      = ciphertextBlob[0 .. 12],
                     ciphertext = ciphertextBlob[12 .. -16],
                     tag        = ciphertextBlob[-16 ..],
                     aad        = empty)
```

If GCM authentication fails, the decoder MUST report "no payload found".
The associated data is empty — the stealth header is *not* fed to GCM as
AAD because it is already authenticated by the marker HMAC.

`plaintextBlock` has length `plaintextSize` (§1). It is structured as:

```
offset  size                       field
------  -------------------------  -----------------------------------------
  0      2                         length    = uint16, big-endian
  2      length                    message   = user payload
  2+L    plaintextSize - 2 - L     padding   = uniformly random bytes
```

The decoder MUST reject:
- `length == 0`,
- `length > plaintextSize - 2`,
- `length > 2048`.

The padding bytes carry no meaning. Their presence is what makes carriers
of the same image always have identical ciphertext length (= the carrier's
full LSB capacity), so an observer cannot infer the user-message length
from the carrier size.

## 6. Why each field is shaped this way

A short rationale, so reviewers do not have to reverse-engineer intent:

- **Salt at offset 0** — needed before any key material exists. A 16-byte
  uniformly random value adds zero structure to the LSB stream.
- **Marker at offset 16, 4 bytes** — proof-of-password. Truncated HMAC of a
  password-derived key is computationally indistinguishable from random
  without the password. 4 bytes balances false-positive rate (`2^-32` per
  guess) against header overhead.
- **Masked version + reserved** — earlier versions carried plaintext
  `version=2` and `flags=0`, giving an attacker ~15 bits of fixed structure
  to fingerprint. Masking with HKDF output removes that fingerprint.
  Authenticating the masked bytes via the marker HMAC makes them
  tamper-evident even though the values are encrypted.
- **No length field** — a length field has low-entropy upper bytes
  (`0x00 0x00 0x00 0x..`) for any realistic message size. Even masked, a
  constant-low-entropy field weakens the "indistinguishable from random"
  claim. Storing length inside the GCM-protected plaintext eliminates it.
- **Padding to full capacity** — equal-length carriers regardless of
  message length. An observer who has both the empty-message carrier and
  a 2 KB-message carrier cannot tell them apart by size.

## 7. Reference

Swift implementation: `StigerCore/StegoMarker.swift` and
`StigerCore/ImageStegoEngine.swift`.

Reference Python decoder, written from this document only:
[`reference/python/stiger_decode.py`](reference/python/stiger_decode.py).

Test vectors generated by the Swift engine and verified by the Python
decoder live in [`test-vectors/`](test-vectors/).
