# Stiger — Threat Model

This document states what Stiger defends against, what it does **not**
defend against, and the assumptions behind those guarantees. Read it before
trusting the app with anything that matters.

If you find a gap between this document and the implementation, the
implementation is wrong — please open an issue.

For the byte-for-byte wire format and an independent reference decoder you
can run yourself, see [`spec/`](spec/README.md).

## TL;DR

**English.** Stiger encrypts a short message (AES-256-GCM, password-
derived via PBKDF2-SHA256-600k) and hides the ciphertext in the
least-significant bits of an ordinary PNG sticker, then sends it through
iMessage. **What it protects:** the message content (unreadable without
the password) and the message length (padded to LSB capacity). **What it
does not:** trained stegoanalysis can detect that *some* LSB modification
happened (without recovering the message); a compromised device, a
forensic Keychain dump, screenshots, or iMessage recompression all defeat
or destroy the payload. **Open mode** (no password) is publicly readable
by anyone with Stiger and is not a privacy feature. **No forward secrecy:**
a password leak retroactively decrypts every prior message. Read the rest
before relying on Stiger for anything serious.

**По-русски.** Stiger шифрует короткое сообщение (AES-256-GCM, пароль
растягивается через PBKDF2-SHA256-600k) и прячет шифротекст в младшие
биты обычного PNG-стикера, отправляемого через iMessage. **Что защищает:**
содержимое сообщения (нечитаемо без пароля) и его длину (паддинг до
полной ёмкости стикера). **Чего не защищает:** обученный стегоанализ
видит сам факт LSB-модификации (без чтения сообщения); компрометация
устройства, форензик-дамп Keychain, скриншоты и пережатие iMessage —
всё это либо обходит, либо уничтожает payload. **Открытый режим** (без
пароля) читается любым, у кого есть Stiger, — это не приватность.
**Forward secrecy нет:** утечка пароля ретроактивно расшифровывает все
предыдущие сообщения. Прочитайте дальше, прежде чем полагаться на Stiger
в серьёзных вещах.

## 1. Scope

Stiger hides short messages (≤ 2 KB of user text) inside PNG sticker
images and ships them through Apple's iMessage as ordinary stickers. There
are two modes:

- **Open mode** — no password set. The carrier is a *public* sticker. The
  payload is framed by a fixed 9-byte header (`STEG` magic + version + length)
  and stored in row-major LSBs. Anyone with Stiger — or anyone with this
  spec and 30 lines of Python — can read it. **Open mode is not a privacy
  feature.** It exists so the app is useful before the user pays.

- **Stealth mode v3** — password set (Pro). The carrier's LSB stream is
  designed to look like uniform random noise to anyone who does not know
  the password: the whole LSB capacity is filled with AES-256-GCM
  ciphertext written through a password-derived pixel permutation, so
  there is no plaintext marker, no length field, and no spatial pattern.
  *We do not claim the resulting PNG is bit-for-bit indistinguishable
  from an unmodified original* — that would require adaptive embedding
  (see §3, "Carrier indistinguishability" and §7.1).

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

Both are computationally indistinguishable from uniform random noise
without the password — a passive observer cannot tell ciphertext from
random LSBs. The LSBs of *natural photographs* would absorb this kind of
modification well; sticker carriers (flat colour areas, sharp edges)
provide weaker cover and are visible to trained stegoanalysis classifiers
even without the password — see §2D and §7.1. The defense in this section
is against simple "look for known magic bytes" scanners, not against
trained statistical analysis.

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
breakable on commodity GPU hardware in hours. A 4-word EFF-diceware
passphrase (~51 bits) is not currently economically attackable — at
PBKDF2-600k it requires roughly years of a 100-GPU farm — but "not
economically attackable today" is not "unbreakable." Below ~40 bits of
entropy, assume the password will eventually fall to a determined
attacker.

### C. Generic stego scanner
Tools that look for known magic bytes (`STEG`, `STG2`, `JPEG comment + base64`,
PNG `tEXt` chunks, etc).

**Defense:** stealth mode has no magic bytes. The first 16 bytes of the LSB
stream are a random salt; the next 4 bytes are an HMAC-derived marker that
varies per message; bytes 20–21 are XOR-masked version and reserved bytes
and are authenticated by the same HMAC. Two encodings of the same message
into the same image produce different LSB streams (the non-LSB pixels are
identical of course; only the LSB layer is randomised).

### D. Corpus stego analysis
An adversary collects many Stiger stickers and runs structural diffs
against the originals (which they may also have, since most stickers are
public emoji).

**Defense (partial):** length-hiding. Stealth mode pads the plaintext block
to fill the *entire* LSB capacity of the carrier, so every encoded carrier of
a given image has the same LSB modification rate (≈100% of opaque blue-channel
LSBs touched). The number of modified LSBs no longer leaks the message length.

**Limit:** the modification *rate* itself is still high (~50% of LSBs flipped
on average vs ~0% for an unmodified PNG of the same source). Detection of
"some LSB stego is present" is feasible — both via diff against the
original and via trained stegoanalysis without the original. See §3
"Trained stegoanalysis classifiers" for the full picture and what still
holds when this detection happens.

## 3. Adversaries we do NOT defend against

The following are out of scope. If your threat model includes any of these,
Stiger is the wrong tool.

### Compromised endpoint
- Malware on the sender's or recipient's iOS device. We have no defense
  against a keylogger, screen recorder, or anything reading the unlocked
  Keychain.
- Jailbroken devices.
- Note on iCloud Keychain: our password uses
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, which physically
  prevents iCloud Keychain sync of *our* item. The user cannot enable
  sync for it. Other Keychain items added by other apps are out of our
  control.

### Coercion
- Rubber-hose cryptanalysis. The app has no plausible-deniability mode and
  no duress password.

### Side channels
- Shoulder surfing while typing the secret or the password.
- Anyone reading the system clipboard while a sticker is being copied (the
  "ghost mode" copies-instead-of-inserts feature trades metadata for clipboard
  exposure — that is the explicit tradeoff documented in `ParanoiaGuideView`).
  iOS 14+ shows a banner whenever any app reads the clipboard, so silent
  snooping by another foreground app is detectable by the user. This is an
  OS-level mitigation, not Stiger's, but worth knowing.
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

### Trained stegoanalysis classifiers
We do not defend against modern statistical or ML-based stegoanalysis
(SPAM, SRM, SRNet, ZhuNet, Yedroudj-Net, and successors). On flat-colour
sticker carriers our ~100% LSB modification rate is detectable by these
tools with high accuracy, and they do not need access to the original
source image — the detection is based on intrinsic statistical features
of the suspect carrier alone. Forensic vendors and state-level toolchains
include such detectors.

What still holds when "this is some LSB carrier" is detected:
- *Content confidentiality* — AES-256-GCM ciphertext is not recoverable
  without the password.
- *Stiger-specific identification* — no magic bytes, no fixed headers,
  no spatial pattern. The carrier looks like any other LSB tool's output.
- *Payload length* — hidden by full-capacity padding.
- *On-the-wire file size* — hidden by per-image size normalization (§3,
  "File-size oracle").

What is lost: the deniability claim "this PNG carries nothing." A
stegoanalysis classifier can say with high confidence that *something*
is hidden in opaque LSBs. Mission-class adversaries should assume this
detection is feasible and design their operational use accordingly.

### File-size oracle on the wire
**Defense:** every PNG sent through the iMessage extension — stealth send,
open send, and plain (no-secret) send — is padded to a per-image normalized
byte size before it leaves the process. The target size is computed from
the source image's pixels (cached in App Group `UserDefaults`) plus a small
per-install jitter, so:

- A network observer or anyone holding the chat history cannot tell, by
  byte count alone, whether a sticker carries a secret.
- Two stealth sends of the same carrier with different payloads are
  byte-identical on the wire.
- A plain send and a stealth send of the same carrier are byte-identical
  on the wire.

Padding is performed by inserting a `tEXt` chunk of random ASCII bytes
before the `IEND` chunk (`StigerCore/PNGPadder.swift`). The chunk is *not*
disguised as another editor's metadata — that would be obscurity over
security and trivially detectable on close inspection. The chunk only
defends the network-observer model, where its contents are invisible.

**Out of scope for this defense:**
- Forensic file-level analysis of an extracted PNG (the pad chunk itself is
  visible and may be flagged as anomalous — see §7).
- LSB-detection by bitwise diff against a known original (unchanged from
  the previous section).

### Cryptanalysis of AES-GCM, PBKDF2, HMAC-SHA256, HKDF-SHA256
We assume the underlying primitives are sound. If AES-256 is broken, this
app is the least of your problems.

### Note: PNG metadata stripping (positive guarantee)
This is not an adversary we defend against — it is a contract we keep. All
outgoing carriers (built-in stickers, custom imports from Photos /
clipboard, Telegram-pack imports) are re-rendered through
`UIGraphicsImageRenderer` and re-encoded with `pngData()`. This pipeline
does **not** carry through EXIF, GPS coordinates, camera make/model,
authoring tool, original timestamps, or any other PNG/JPEG metadata from
the user's source file. Any metadata in an outgoing PNG is generated by
us (the `tEXt` "Comment" pad chunk added by `PNGPadder`, plus whatever
`UIGraphicsImageRenderer` emits). A user importing a beach photo as a
custom sticker does not leak the photo's GPS to chat recipients.

## 4. Guarantees per mode

|                                          | Open mode | Stealth v3 |
|------------------------------------------|-----------|------------|
| Confidentiality of message content       | ❌ none   | ✅ AES-256-GCM |
| Authenticity of message content          | ❌ none   | ✅ GCM tag |
| Hides message length                     | ❌        | ✅ pads to capacity |
| Hides Stiger-specific markers (magic / headers)  | ❌ `STEG` magic in cleartext | ✅ no magic, no fixed bytes |
| Hides "this PNG carries some LSB stego"          | ❌        | ❌ trained stegoanalysis can detect — see §3 / §7.1 |
| Hides PNG file size on the wire          | ✅ pads to per-image target | ✅ pads to per-image target |
| Hides "was this PNG LSB-modified?"       | ❌        | ❌ (out of scope) |
| Survives iMessage lossy recompression    | ❌        | ❌ |
| Survives screenshot                      | ❌        | ❌ |
| Survives device compromise               | ❌        | ❌ |

## 5. Trust assumptions

- The user's password is high entropy and not reused from a leaked corpus.
  *Currently not enforced by the UI* — there is no entropy meter and no
  minimum-strength gate; users can save `123456` and the engine will
  accept it. Adding a strength meter and a minimum-entropy floor in the
  password input is on the roadmap.
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
- `StigerCore/StegoSendPipeline.swift` — single send entry point (encode + pad)
- `StigerCore/SendSizeNormalizer.swift` — per-image normalized byte size
- `StigerCore/PNGPadder.swift` — `tEXt`-chunk-based PNG byte padding

A reference decoder in any language can be written against §Protocol of the
README without reading the Swift source. If you write one and your decoder
disagrees with Stiger on a test vector, the spec is wrong — please report
it.

Tests in `StigerTests/` cover header roundtrips, wrong-password rejection,
length-hiding, the absence of plaintext fingerprints in stealth headers, and
end-to-end encode/decode through the LSB engine.

## 7. Known weaknesses (acknowledged, not fixed)

1. **LSB modification is detectable to trained stegoanalysis.** See §3
   "Trained stegoanalysis classifiers" for what is detectable and what
   is not. Mitigation would require adaptive embedding (HUGO, S-UNIWARD,
   etc.) — not in v3, may revisit if the threat materialises.

2. **Password lives in iOS Keychain.**

   *What protects it:* `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
   means the item is excluded from device backups and never synced via
   iCloud Keychain — it stays only on the device where it was created.
   Items are scoped to our bundle ID, so another App Store app cannot
   read them. On a fresh install of Stiger we wipe any leftover items
   from a previous install (`SharedDefaults.wipeKeychainOnFreshInstall`).

   *What does not protect it:* iOS does **not** purge Keychain items
   when an app is deleted (Apple briefly tried this in iOS 10.3 beta and
   rolled it back; no entitlement, Info.plist key, or accessibility
   constant changes this). If the user deletes Stiger and never
   reinstalls, the password sits in Keychain indefinitely until a
   factory reset or another fresh-install of Stiger triggers our wipe.
   On a non-jailbroken device with no forensic tools, no other process
   can read it; on a jailbroken device or under forensic acquisition
   (Cellebrite, GrayKey) against an AFU device, the item is reachable.

   *Open mitigations not yet implemented:*
   - `kSecAttrAccessControl` with `.userPresence` to require Face ID /
     passcode on every read (closes Cellebrite-AFU acquisition; costs
     UX friction on every decode).
   - Auto-forget after N days of inactivity (closes long-tail residue;
     costs lost access to old chats if the user has not memorised the
     password).
   - A prominent "Forget password" control surfaced wherever the
     password is shown, so users with imminent risk can wipe in one tap.

3. **Open mode exists in the same UI as stealth mode.** A user who forgets
   to set a password sends a publicly readable message. Mitigated by explicit
   in-flow copy: the compose banner, the receive label, the intro flow, and
   the paranoia guide all state that public-mode messages are readable by
   anyone with Stiger. The risk is not zero — a user can still ignore the
   banner — but there is no UI surface left that misleadingly implies
   privacy.

4. **No forward secrecy.** A password leak retroactively decrypts every
   sticker ever sent under that password. *Operational mitigation:*
   removing the password from Settings (or toggling encryption off)
   wipes it from the Keychain; if no copy exists elsewhere, prior
   captures become permanently undecryptable. Useful only when invoked
   *before* compromise — once an attacker has a Keychain dump, the
   wipe comes too late.

5. **No per-recipient keys.** Pro offers a separate contact's password slot, but
   password distribution is still manual.

6. **PBKDF2, not Argon2id.** PBKDF2-SHA256 at 600 000 iterations is OWASP-
   recommended and ships in CommonCrypto. Argon2id would be more memory-
   hard against GPU farms, but the iMessage extension runs under a
   ~120 MB memory cap, which limits realistic `m_cost` to ~32–48 MB —
   roughly 2–3 orders of magnitude slowdown over PBKDF2 instead of the
   4–5 cited in the literature for full-strength parameters. Given the
   cost (third-party crypto dependency, wire-format bump, KDF migration
   in the decoder) the trade is not currently favourable. Preferred path
   is to attack the root cause — weak passwords — via a strength meter
   and minimum-entropy gate in the password input UI (on the roadmap).
   Argon2id is revisited if decode ever moves out of the extension or
   if we observe real evidence of offline brute-force in the wild.

7. **Pad chunk visible to file-level forensic.** The size-normalization
   defense (§3, "File-size oracle") inserts a `tEXt` chunk of random bytes
   to bring every send up to a per-image target size. An adversary who
   opens the PNG file in a hex editor can see the chunk and infer that the
   file was processed by some tool — though not which one, and not whether
   a secret is present. This is a deliberate trade-off: the chunk is
   invisible to a network observer (the model the defense targets), and
   anyone with file-level access to extract the chunk also has the
   installed Stiger app to find. Mitigation would require a different
   padding strategy (e.g. lossless re-encode at fixed compression) that is
   left for future work.

8. **Cross-user overlap on shared imports.** If many Stiger users import
   the same Telegram pack (or the same publicly distributed image set),
   their post-import PNG pixels are identical — our import pipeline runs
   the same rasterization on the same source. An adversary collecting
   Stiger stickers across users could in principle correlate carriers
   across senders. This is a corpus-level signal, not a per-sticker leak,
   and is partially absorbed by send-side size normalization (§3); the
   residual risk is very narrow and not addressed in v3. Importing from
   the public pack does **not** make LSB-detection-with-original easier:
   our import re-encodes the source `.webp` through `UIGraphicsImage-
   Renderer`, so the post-import PNG is no longer pixel-identical to the
   original Telegram file before any LSB modification.
