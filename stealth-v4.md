# Stealth Mode v4 (stealth-v4)

The mode that protects messages. Without the password, every bit of the
stream a decoder can extract is computationally indistinguishable from
uniform random noise: no magic, no length, no fixed structure, no spatial
pattern. And unlike v3, the carrier no longer has every eligible pixel
written: the stream is a syndrome of the cover ([`lsb-layer.md`](lsb-layer.md)
§6), and only the pixels the encoder chose to change are changed.

This document defines the wire format. For threat-model claims and the
adversaries this is designed to resist, see [`THREAT_MODEL.md`](THREAT_MODEL.md).

What changed from v3: the stream is `S = min(2100, floor(N/8))` bytes
instead of the whole capacity; it is recovered as `H · y` instead of being
read bit for bit; the permutation and header labels carry `v4`; the version
byte is `0x04`. The cryptography (PBKDF2, HKDF, HMAC marker, AES-256-GCM,
the length-prefixed padded block) is unchanged.

> **Notation.** All multi-byte integer fields are big-endian unless stated
> otherwise. `||` is byte-string concatenation. `[a..b]` denotes a half-open
> byte slice (b exclusive).

## 1. Inputs

- `password` — UTF-8 bytes of the user's passphrase. Non-empty.
- `image`    — eligible pixels as defined in [`lsb-layer.md`](lsb-layer.md).
  Let `N` = number of eligible pixels.

Define:

```
S              = min(2100, floor(N / 8))        # lsb-layer.md §4
headerSize     = 22
gcmOverhead    = 12 + 16        # nonce + tag
lenPrefix      = 2
plaintextSize  = S - headerSize - gcmOverhead
```

A carrier is too small for stealth mode iff
`plaintextSize < lenPrefix` (i.e. there is no room for even a zero-length
message). Decoders MUST reject such carriers as "no payload found".

The largest message is 2 048 bytes (§5), which is why `S` tops out at
`22 + 28 + 2 + 2048 = 2100`: on any carrier with at least 16 800 eligible
pixels the stream is 2 100 bytes and the message capacity is 2 048 bytes.

## 2. Stream layout

The stream of `S` bytes is the syndrome of the cover under the walk of §3
(see [`lsb-layer.md`](lsb-layer.md) §5–§6 for how it is extracted). It is:

```
offset      size            field
------      --------------  ----------------------------------------------
  0          16             salt
 16           4             marker
 20           1             maskedVersion
 21           1             maskedReserved
 22         S - 22          ciphertextBlob (AES-256-GCM, see §5)
```

There is **no plaintext length field** anywhere in the wire format. The
ciphertext blob fills the stream, and the real message length is stored
*inside* the encrypted plaintext.

## 3. Permutation key

The walk over the cover ([`lsb-layer.md`](lsb-layer.md) §5) is keyed by the
password alone (not the per-message salt) so that a decoder can reconstruct
it **before** reading the salt out of the first 16 stream bytes:

```
permKey = PBKDF2-HMAC-SHA256(
              password = password,
              salt     = b"stiger-perm-v4-salt",   # ASCII, 19 bytes
              iter     = 600000,
              dkLen    = 32)
```

The permutation itself (HMAC-SHA256 keystream with `INFO =
b"stiger-permutation-v4"`, Fisher–Yates) is defined in the transport layer.

## 4. Header and key derivation

After extracting the stream:

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
              info = b"stiger-v4-header",       # ASCII, 16 bytes
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

Recover the version and require it to be exactly `0x04`:

```
version = maskedVersion XOR mask[0]
require version == 0x04
```

(The `maskedReserved` byte XORed against `mask[1]` is currently `0x00`. It
is reserved for future use; the HMAC marker authenticates it so any future
flag bits added there are tamper-evident from day one.)

## 5. Plaintext recovery

The ciphertext blob is `stream[22 .. S]`. Decrypt as a single AES-256-GCM
seal:

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

The padding bytes carry no meaning. Their presence is what makes every
stealth send of a given image carry a stream of the same `S` bytes, so an
observer cannot infer the user-message length from the carrier.

## 6. Why each field is shaped this way

A short rationale, so reviewers do not have to reverse-engineer intent:

- **Salt at offset 0** — needed before any key material exists. A 16-byte
  uniformly random value adds zero structure to the stream.
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
- **Padding to a fixed stream** — a one-character message and a 2 KB message
  give the same `S`, so the number of pixels the encoder changes does not
  depend on the message length. v3 padded to the carrier's whole capacity for
  the same reason; a fixed 2 100-byte stream hides the same range of lengths
  (the app allows at most 2 048 bytes) while changing a tenth as many pixels
  on a 512×512 sticker.
- **Syndrome, not bit placement** — with the stream as `H · y`, the encoder
  decides which pixels change and can keep them out of flat areas. The
  measurements behind that choice are in
  `../docs/experiment-steganalysis-v2.md`.

## 7. Reference

Swift implementation: `StigerCore/StegoMarker.swift`,
`StigerCore/ImageStegoEngine.swift` and `StigerCore/STC.swift`.

Reference Python decoder, written from this document and
[`lsb-layer.md`](lsb-layer.md) only:
[`reference/python/stiger_decode.py`](reference/python/stiger_decode.py).

Test vectors generated by the Swift engine and verified by the Python
decoder live in [`test-vectors/`](test-vectors/).
