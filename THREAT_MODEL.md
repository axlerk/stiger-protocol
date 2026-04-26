# Stiger — Threat Model

This document states what Stiger defends against, what it does **not**
defend against, and the assumptions behind those guarantees. Read it before
trusting the app with anything that matters.

If you find a gap between this document and the implementation, the
implementation is wrong — please open an issue.

For the byte-for-byte wire format and an independent reference decoder you
can run yourself, see [`spec/`](spec/README.md).

## 1. Scope

Stiger hides short messages (≤ 2 KB of user text) inside PNG sticker
images and ships them through Apple's iMessage as ordinary stickers. There
are two modes:

- **Open mode** — no password set. The carrier is a *public* sticker. The
  payload is framed by a fixed 9-byte header (`STEG` magic + version + length)
  and stored in row-major LSBs. Anyone with Stiger — or anyone with this
  spec and 30 lines of Python — can read it. **Open mode is not a privacy
  feature.** It exists so the app is useful before the user pays.

- **Stealth mode v3** — password set (Pro). The carrier is designed to be
  indistinguishable from an unmodified PNG to anyone who does not know the
  password. The whole LSB capacity is filled with AES-256-GCM ciphertext
  written through a password-derived pixel permutation, so there is no plaintext
  marker, no length field, and no spatial pattern.

The two modes share the same engine but have **fundamentally different
threat models**. The rest of this document covers stealth mode unless
otherwise stated.

## 2. Adversaries we defend against

### A. Passive LSB observer
Someone who intercepts the PNG (e.g. pulls it from an iMessage backup, a
forwarded screenshot, or a compromised relay) and runs standard LSB analysis.

**Defense:** the entire LSB stream of opaque pixels is one of:
- AES-GCM ciphertext, or
- header bytes that are HMAC-derived from the password.

Both are computationally indistinguishable from uniform random noise without
the password. PNG LSBs of natural images are already noisy, so the carrier
has no statistical fingerprint to grep for.

### B. Reverse engineer with a copy of the .ipa
Someone disassembles Stiger, reads the protocol, and tries every captured
sticker against the engine.

**Defense:** Kerckhoffs. We assume the protocol and the binary are public.
Security reduces to: *can you find the password?*

- Password-derived AES key: PBKDF2-SHA256, 600 000 iterations (OWASP 2024).
- Password-derived permutation key: same KDF, separate fixed salt.
- The 4-byte stealth marker is
  `HMAC-SHA256(K_mac, salt || maskedVersion || maskedReserved)[0..4]`, verified
  in constant time, so an attacker learns nothing from a marker mismatch other
  than "wrong password." The HMAC covers bytes 20–21 of the header, so the
  masked version byte and reserved-flags byte are tamper-evident — flipping
  any bit there makes `parseStealthHeader` return nil.
- There is no oracle. A wrong password produces a GCM authentication failure;
  the engine returns `noPayloadFound` either way.

The real defense here is **password entropy**. A 6-character password is
breakable. A 4-word diceware passphrase is not.

### C. Generic stego scanner
Tools that look for known magic bytes (`STEG`, `STG2`, `JPEG comment + base64`,
PNG `tEXt` chunks, etc).

**Defense:** stealth mode has no magic bytes. The first 16 bytes of the LSB
stream are a random salt; the next 4 bytes are an HMAC-derived marker that
varies per message; bytes 20–21 are XOR-masked version and reserved bytes
and are authenticated by the same HMAC. Two encodings of the same message
into the same image produce different LSB streams.

### D. Corpus stego analysis
An adversary collects many Stiger stickers and runs structural diffs
against the originals (which they may also have, since most stickers are
public emoji).

**Defense (partial):** length-hiding. Stealth mode pads the plaintext block
to fill the *entire* LSB capacity of the carrier, so every encoded carrier of
a given image has the same LSB modification rate (≈100% of opaque blue-channel
LSBs touched). The number of modified LSBs no longer leaks the message length.

**Limit:** the modification *rate* itself is still high (~50% of LSBs flipped
on average vs ~0% for an unmodified PNG of the same source). A corpus
adversary who has access to the *originals* can detect that *some* Stiger
sticker was sent, even if they cannot read it. We do not consider unmodified-
carrier indistinguishability a feature in v3 — see §4.

## 3. Adversaries we do NOT defend against

The following are out of scope. If your threat model includes any of these,
Stiger is the wrong tool.

### Compromised endpoint
- Malware on the sender's or recipient's iOS device. We have no defense
  against a keylogger, screen recorder, or anything reading the unlocked
  Keychain.
- iCloud Keychain sync of the password. The user controls this.
- Jailbroken devices.

### Coercion
- Rubber-hose cryptanalysis. The app has no plausible-deniability mode and
  no duress password.

### Side channels
- Shoulder surfing while typing the secret or the password.
- Anyone reading the system clipboard while a sticker is being copied (the
  "ghost mode" copies-instead-of-inserts feature trades metadata for clipboard
  exposure — that is the explicit tradeoff documented in `ParanoiaGuideView`).
- Keyboard caches, autocorrect dictionaries, predictive text.
- Screenshots of the compose UI sitting in the recents stack.

### Metadata about the conversation
- iMessage routing metadata (who sent what to whom, when).
- The fact that two people are exchanging Stiger stickers at all.
- Timing analysis on message exchange.

### iMessage transport
- iMessage may recompress or transcode images on some paths (group chats,
  cross-platform forwarding, "save to Photos" then re-share). LSB
  steganography does **not** survive lossy recompression. If the carrier is
  recompressed, the payload is gone — both modes fail closed (decoder returns
  `noPayloadFound`), so this is a reliability issue, not a confidentiality
  one.
- Screenshots of stickers do not preserve LSBs and are not valid carriers.

### Carrier indistinguishability vs the original PNG
v3 stealth hides *content* and *length*, not *the fact that LSB modification
happened*. An adversary who has the unmodified source PNG and the suspected
carrier can compute the diff and conclude "this PNG was processed by some
LSB tool." They cannot recover the message, identify it as Stiger
specifically (the LSB stream looks the same as any random data), or
distinguish it from any other LSB tool's output. Defending against this
class of adversary would require model-based or adaptive embedding (HUGO,
S-UNIWARD, etc.) and is not in scope.

### Cryptanalysis of AES-GCM, PBKDF2, HMAC-SHA256, HKDF-SHA256
We assume the underlying primitives are sound. If AES-256 is broken, this
app is the least of your problems.

## 4. Guarantees per mode

|                                          | Open mode | Stealth v3 |
|------------------------------------------|-----------|------------|
| Confidentiality of message content       | ❌ none   | ✅ AES-256-GCM |
| Authenticity of message content          | ❌ none   | ✅ GCM tag |
| Hides message length                     | ❌        | ✅ pads to capacity |
| Hides "is this a Stiger carrier?"     | ❌ `STEG` magic in cleartext | ✅ no magic, no fixed bytes |
| Hides "was this PNG LSB-modified?"       | ❌        | ❌ (out of scope) |
| Survives iMessage lossy recompression    | ❌        | ❌ |
| Survives screenshot                      | ❌        | ❌ |
| Survives device compromise               | ❌        | ❌ |

## 5. Trust assumptions

- The user's password is high entropy and not reused from a leaked corpus.
- The user shares the password through a channel Stiger does not see
  (in-person, Signal, paper).
- iOS Keychain on a non-jailbroken device is treated as confidential storage.
- Apple's CryptoKit and CommonCrypto implementations of AES-GCM, HMAC-SHA256,
  HKDF, and PBKDF2 are correct.
- `SecRandomCopyBytes` is a CSPRNG.

## 6. How to verify

The protocol is documented in `README.md` §Protocol. The implementation is
~700 lines of Swift split across:

- `StigerCore/StegoMarker.swift` — header framing and HKDF/HMAC derivations
- `StigerCore/ImageStegoEngine.swift` — LSB read/write, permutation, padding
- `StigerCore/AESHelper.swift` — AES-GCM and PBKDF2 wrappers

A reference decoder in any language can be written against §Protocol of the
README without reading the Swift source. If you write one and your decoder
disagrees with Stiger on a test vector, the spec is wrong — please report
it.

Tests in `StigerTests/` cover header roundtrips, wrong-password rejection,
length-hiding, the absence of plaintext fingerprints in stealth headers, and
end-to-end encode/decode through the LSB engine.

## 7. Known weaknesses (acknowledged, not fixed)

1. **Power-user fingerprint via LSB modification rate.** See §3, "carrier
   indistinguishability." Mitigation would require adaptive embedding.

2. **Password lives in iOS Keychain.** A device unlock + Keychain dump
   recovers it. Face ID/Touch ID gating reduces the window but does not
   close it.

3. **Open mode exists in the same UI as stealth mode.** A user who forgets
   to set a password sends a publicly readable message. Mitigated by explicit
   in-flow copy: the compose banner, the receive label, the intro flow, and
   the paranoia guide all state that public-mode messages are readable by
   anyone with Stiger. The risk is not zero — a user can still ignore the
   banner — but there is no UI surface left that misleadingly implies
   privacy.

4. **No forward secrecy.** A password leak retroactively decrypts every
   sticker ever sent under that password.

5. **No per-recipient keys.** Pro offers a separate contact's password slot, but
   password distribution is still manual.

6. **PBKDF2, not Argon2id.** PBKDF2-SHA256 at 600 000 iterations is OWASP-
   recommended and ships in CommonCrypto, so we avoid a third-party crypto
   dependency in the iMessage extension binary. Argon2id would be more
   memory-hard against GPU/ASIC attacks; the practical defense remains
   password entropy regardless.
