# Stiger — Threat Model

This document states what Stiger defends against, what it does **not**
defend against, and the assumptions behind those guarantees. Read it before
trusting the app with anything that matters.

If you find a gap between this document and the implementation, the
implementation is wrong — please open an issue.

For the byte-for-byte wire format and an independent reference decoder you
can run yourself, see [`spec/`](spec/README.md).

The body describes the engine as it is in this repository: a random LSB
plane on every send ("uniform cover"), written by ±1 LSB matching. Earlier
builds differed in ways that matter to anyone holding files from them; §8
"History" tells that story once, with dates and build numbers. Every
measurement behind a number here is in `docs/experiment-steganalysis.md`,
cited by section.

## TL;DR

**English.**

- **Protects:** the content of a short message (AES-256-GCM, key derived from
  the password by PBKDF2-SHA256, 600 000 iterations) and its length (the
  ciphertext fills the whole LSB capacity), hidden in the least-significant
  bits of an ordinary PNG sticker and sent through iMessage.
- **Does not protect against:** a trained statistical classifier, which can
  tell that *some* LSB modification happened without reading the message
  (the textbook tests no longer flag it, §3); a compromised device, a
  Keychain extracted by forensic tooling, screenshots or iMessage
  recompression, which defeat the protection or destroy the hidden message.
- **Open mode** (no password) is readable by anyone with Stiger. It is not a
  privacy feature.
- **No forward secrecy:** a leaked password decrypts every earlier message
  sent under it.

**По-русски.**

- **Защищает:** содержимое короткого сообщения (AES-256-GCM, ключ выводится
  из пароля через PBKDF2-SHA256, 600 000 итераций) и его длину (шифротекст
  заполняет всю ёмкость младших битов), спрятанного в младших битах обычного
  стикера в формате PNG и отправленного через iMessage.
- **Не защищает:** обученный статистический классификатор видит сам факт
  изменения младших битов, не читая сообщения (учебные тесты его больше не
  отмечают, §3); взломанное устройство, связка ключей Keychain, снятая
  криминалистическим инструментом, скриншоты и пережатие картинок в
  iMessage либо обходят защиту, либо уничтожают скрытое сообщение.
- **Открытый режим** (без пароля) читает любой, у кого есть Stiger. Это не
  приватность.
- **Прямой секретности нет:** утёкший пароль расшифровывает все прежние
  сообщения, отправленные с ним.

## 1. Scope

Stiger hides short messages (≤ 2 KB of user text) inside PNG sticker images
and ships them through Apple's iMessage as ordinary-looking image
attachments. "Sticker" here means the carrier's *visual* role (a small
expressive PNG), not Apple's `MSSticker` API: carriers go out through
`MSConversation.insertAttachment`, because the sticker pipeline re-encodes
PNGs to HEIC in transit and would destroy the hidden bits. That is observed
platform behaviour, not a guarantee; the failure mode is in §3 "iMessage
transport", the measurements and notes for re-implementers in `README.md`
→ "Carrier transport".

There are two modes:

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
  (§3 "Carrier indistinguishability", §7.1).

A send with no secret at all ("plain") gets the same kind of LSB plane as
the other two, so that nothing about the file says which kind it is (§3
"File-size oracle on the wire").

The two modes share the same engine but have **fundamentally different
threat models**. The rest of this document covers stealth mode unless
otherwise stated.

## 2. Adversaries we defend against

### A. Passive LSB observer
Someone who intercepts the PNG (from an iMessage backup, a forwarded file,
a compromised relay) and runs standard LSB analysis.

**Defense:** the entire LSB stream of opaque pixels is either AES-GCM
ciphertext or header bytes HMAC-derived from the password. Both are
computationally indistinguishable from uniform random noise without the
password, so the observer cannot tell ciphertext from random LSBs. The
engine writes the plane by ±1 LSB matching, which the textbook tests for
LSB replacement (pairs-of-values chi-square, RS) do not flag: on all 133
library stickers through the real engine, chi-square at p ≥ 0.001 flags
plain 1/133, open 0/133 and stealth 2/133, and RS at d ≥ 0.25 flags 2/133
of each — the false-positive floor of an untouched channel (measured
2026-11-04, `docs/experiment-steganalysis.md` §12). Stock `zsteg` and
`StegExpose` at its default threshold report no LSB finding either (§2.C).

**Limit:** sticker carriers (flat colour areas, sharp edges) are weak
cover, and a *trained* classifier still separates a Stiger send from an
unmodified sticker without the original — §3 "Trained stegoanalysis
classifiers" has the numbers and what still holds. Builds through 53 wrote
the plane by replacement, which the textbook tests caught on every send
(§8 "History").

### B. Reverse engineer with a copy of the .ipa
Someone disassembles Stiger, reads the protocol, and tries every captured
sticker against the engine.

**Defense:** Kerckhoffs. We assume the protocol and the binary are public.
Security reduces to: *can you find the password?*

- Password-derived AES key: PBKDF2-SHA256, 600 000 iterations (the OWASP
  2024 figure, as recalled; not re-checked here).
- Password-derived permutation key: same KDF, separate fixed salt.
- The 4-byte stealth marker is
  `HMAC-SHA256(K_mac, salt || maskedVersion || maskedReserved)[0..4]`, verified
  in constant time, so a marker mismatch teaches an attacker nothing but
  "wrong password." The HMAC covers bytes 20–21 of the header, so the masked
  version byte and reserved-flags byte are tamper-evident — flipping any bit
  there makes `parseStealthHeader` return nil.
- There is no oracle. A wrong password produces a GCM authentication failure;
  the engine returns `noPayloadFound` either way.
- The reveal UI extends this ambiguity to the screen. A free user (no Pro,
  no password to try) sees the same "empty-or-encrypted, decryption needs
  Pro and a password" status line plus a Get-Pro link on every
  `noPayloadFound` outcome, truly empty stickers included, so a
  shoulder-surfer or an examiner of a non-Pro recipient's device cannot
  use the screen as an oracle for THIS sticker.

The real defense here is **password entropy** (the figures below are
estimates, not measured). A 6-character password is
breakable on commodity GPU hardware in hours. A 4-word EFF-diceware
passphrase (~51 bits) is not currently economically attackable — at
PBKDF2-600k it requires roughly years of a 100-GPU farm — but "not
economically attackable today" is not "unbreakable." Below ~40 bits of
entropy, assume the password will eventually fall to a determined
attacker.

### C. Generic stego scanner
Tools that look for known magic bytes (`STEG`, `STG2`, `JPEG comment + base64`,
PNG `tEXt` chunks, etc).

**Defense:** stealth mode has no magic bytes. (Open mode does: its carriers
start with a fixed `STEG` header, and this defense does not apply to them —
§1 and §2.D.) The first 16 bytes of the LSB stream are a random salt; the
next 4 bytes are an HMAC-derived marker that varies per message; bytes
20–21 are XOR-masked version and reserved bytes, authenticated by the same
HMAC. Two encodings of the same message into the same image produce
different LSB streams (only the LSB layer is randomised; the other bits are
identical).

**Measured.** On stealth carriers `zsteg` (default and `-a`) and
default-threshold `StegExpose` find no LSB payload, and the files the
engine sends carry no `tEXt` chunk for such a scanner to print
(`docs/experiment-steganalysis.md` §1, §2, §10). The beta builds did carry
one, a size-normalising `Comment` pad that `zsteg` and `exiftool` printed
on every send; §8 "History".

### D. Forensic chat-log reviewer
Someone with access to the recipient's (or sender's) Messages history — an
iCloud Messages backup, an unlocked-device extraction, a `chat.db` dump, an
iTunes backup parsed with off-the-shelf forensic tooling — who reads the
chat as a whole and looks for *patterns of behaviour* rather than analysing
individual PNGs.

**What we deliberately defend (visual mimicry).** At the *rendering* layer
Stiger carriers aim for "indistinguishable at a glance" from ordinary
stickers and jumbo emoji: PNG dimensions are tuned so the in-bubble glyph
matches Apple's native single-emoji jumbo on screen (the size match was
seen on a 2026-10-08 screenshot, `README.md` "Carrier transport"), the
emoji carriers are drawn from Apple's own emoji font, and every send (stealth, open, or
plain) comes out at the same byte size (§3 "File-size oracle on the wire"),
so an analyst skimming a chat list sees the same shape, size and visual
rhythm as the surrounding messages.

**What we do NOT defend.** The carrier reaches the recipient as an **image
attachment**, not as an `MSSticker`. Messages records it with
`attachment_type = image/png` (or similar `UTI = public.png`) in `chat.db`
(recalled from the schema, not checked on a dump here),
and the bubble is the "image bubble" affordance, not the bubble-less
floating sticker. A reviewer who knows what to look for can therefore
tell, without opening the PNG, that the user is exchanging *PNG attachments
positioned where stickers would be more natural* — more visibly when real
stickers from other contacts sit in the same chat. It also shows on
screen: a received carrier gets the save button Messages draws next to
received image attachments, and an old carrier is archived as an
attachment to be downloaded again from iCloud, while native emoji around
it keep rendering as text. "Indistinguishable at a glance" therefore holds
for a recent, sent carrier; not for a received one, nor for an old one.
The observations, the `MSSticker` format limits that put Stiger in the same
image-attachment bucket as benign sticker apps, and the "From Stiger"
long-press finding (that menu is not a one-tap decode oracle) are in
`README.md` → "Carrier transport", `docs/experiment-sticker-transport.md`
and `docs/experiment-from-stiger-tap.md`.

This is a **deliberate trade-off**, not an oversight. `MSSticker`
recompresses to HEIC in transit (verified May 2026, iOS 26 — `README.md`
"Carrier transport"), which destroys any LSB payload, and the receive-side
bytes from the sticker pipeline are not addressable to the reveal flow. We
*cannot* use `MSSticker` and have steganography work at all; the choice is
"PNG-attachment carrier with this exposure" versus "no product." The
artifact ("PNG attachment where a sticker would be more natural") appears
in conversations involving non-Stiger apps too: it is an
"uses an image-attachment carrier" signature, drawn from a population much
wider than Stiger.

What still holds when this pattern is noticed, for **stealth** carriers:
- *Content confidentiality* — the payload is AES-GCM ciphertext as far as a
  reviewer can tell. They see "this user sends PNGs," not "this PNG hides
  text."
- *Sender / recipient unlinking* — the LSB stream of a stealth carrier has
  no app-specific fingerprint, so an analyst cannot identify Stiger from
  that stream of a single carrier (§2.E for what changes with many
  carriers). The beta builds' pad chunk was **not** covered by this (§8).
- *Mode opacity* — plain, open and stealth sends have the same byte size and
  the same LSB statistics (§3 "File-size oracle on the wire"), so the
  chat-level pattern does not betray which mode is in use. In the beta this
  did **not** hold at file level (§8).

**Open carriers break the first two.** An open-mode carrier stores its
payload in plaintext behind the fixed `STEG` header (`spec/open-v1.md` §3),
so any LSB scanner that applies the eligibility rule (`alpha == 255` only,
`spec/lsb-layer.md` §3) reads the message and learns that Stiger was used.
(Stock `zsteg` reads every pixel and misses it on stickers with
transparency — measured, a tooling accident and not a defence.) One open
carrier in a chat also puts the other image attachments in that chat under
suspicion: a stealth carrier next to a known Stiger carrier is attributable
by association, even though it carries no fingerprint of its own
(`docs/release-1.0.md`, "Post-1.0 security design backlog" §2).

Users whose recipients' devices may be examined by parties with
chat-database access should assume this signature is detectable and decide
accordingly.

### E. Corpus stego analysis
An adversary collects many Stiger stickers and runs structural diffs against
the originals (which they may also have, since most stickers are public
emoji).

**Defense (partial):** length-hiding. Stealth mode pads the plaintext block
to fill the *entire* LSB capacity of the carrier, so every encoded carrier
of a given image has the same LSB modification rate (≈100% of opaque
blue-channel LSBs touched). The number of modified LSBs no longer leaks the
message length.

**Limit:** the modification *rate* itself is still high (~50% of LSBs
changed on average vs ~0% for an unmodified PNG of the same source).
Detection of "some LSB stego is present" is feasible — via diff against the
original, and via a trained classifier without it (§3 "Trained
stegoanalysis classifiers").

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
  prevents iCloud Keychain sync of *our* item. The user cannot enable sync
  for it. Other Keychain items added by other apps are out of our control.

### Coercion
- Someone who can force you to unlock the phone or give up the password.
  The app has no plausible-deniability mode and no duress password.

### Side channels
- Shoulder surfing while typing the secret or the password.
- Anyone reading the system clipboard while a sticker is being copied (the
  "ghost mode" copies-instead-of-inserts feature trades metadata for
  clipboard exposure — the explicit tradeoff documented in
  `ParanoiaGuideView`). iOS 14+ shows a banner whenever any app reads the
  clipboard (recalled, not verified here), so silent snooping by another
  foreground app is detectable by the user — an OS-level mitigation, not
  Stiger's. The clipboard write
  itself is `localOnly`, so the bytes never propagate via Universal
  Clipboard to the user's other Apple-ID-paired devices (§3 "Universal
  Clipboard relay").
- Reading by paste (Settings → "Paste instead of drag", on by default below
  iOS 18, where the drag cannot land: `docs/experiment-ios16-read-fallback.md`).
  The received carrier reaches the clipboard through Messages' own Copy,
  which Stiger does not control: the write is not `localOnly`, so the
  carrier may be relayed by Universal Clipboard to the user's other devices,
  and it stays on the clipboard until something else replaces it. The
  `localOnly` guarantee covers the send side only. The drag path never
  touches the clipboard.
- Third-party keyboards with Full Access (Gboard, SwiftKey, etc.) run in
  their own processes and can phone home with every keystroke entered into
  the secret-input text view. Stiger cannot enforce a system-keyboard
  restriction from inside an iMessage extension; users at risk should
  disable Full Access keyboards in iOS Settings before composing secrets.
  Password fields use `isSecureTextEntry`, so iOS forces the system
  keyboard there — only the open secret input is exposed.
- Screenshots of the compose UI sitting in the recents stack.
- Apple Maps sees the map areas Stiger shows, from the device's IP: a map
  preview on reveal (rendered without a tap) and the location picker's tiles
  and place search on send. For a secret that *is* a place, the area Apple
  sees is most of what the secret says; the detail and the decision are in
  §7.9.

### Metadata about the conversation
- iMessage routing metadata (who sent what to whom, when).
- The fact that two people are exchanging Stiger stickers at all.
- Timing analysis on message exchange.

### iMessage transport
- iMessage may recompress or transcode images on some paths (group chats,
  cross-platform forwarding, "save to Photos" then re-share). LSB
  steganography does **not** survive lossy recompression. If the carrier is
  recompressed, the payload is gone — both modes fail closed (decoder
  returns `noPayloadFound`), so this is a reliability issue, not a
  confidentiality one.
- Screenshots of stickers do not preserve LSBs and are not valid carriers.
- **Measured once (2026-10-10, n = 2 carriers, one stealth and one open).**
  Sent from an iPhone 15 Pro Max on iOS 26.6.2 to an iPhone 15 Pro on
  iOS 27.0.1 in a one-to-one chat, the sent and the received file were
  byte-identical (same SHA-256, 477 083 bytes) and both decoded. The "sent"
  copy is what Messages exports, not what the extension handed to
  `insertAttachment`; Low Quality Image Mode and Messages in iCloud were not
  recorded. Still observed platform behaviour, not a guarantee
  (`docs/experiment-steganalysis.md` §4).

### Carrier indistinguishability vs the original PNG
v3 stealth hides *content* and *length*, not *the fact that LSB modification
happened*. An adversary who has the unmodified source PNG and the suspected
carrier can compute the diff and conclude "this PNG was processed by some
LSB tool." They cannot recover the message, identify it as Stiger
specifically (the LSB stream looks the same as any random data), or
distinguish it from any other LSB tool's output. Defending against this
would require model-based or adaptive embedding (HUGO, S-UNIWARD, etc.)
and is not in scope.

### Trained stegoanalysis classifiers
We do not defend against modern statistical or ML-based stegoanalysis
(SPAM, SRM, SRNet, ZhuNet, Yedroudj-Net, and successors). On flat-colour
sticker carriers our full-capacity fill is detectable by these tools with
high accuracy, and they do not need the original source image — the
detection rests on statistical features of the suspect carrier alone.
Commercial forensic suites and well-funded examiners have such detectors.

**Measured, with two small detectors** (a research-grade one was not run,
so the statement about ML tools above remains an assumption). A
SPAM-feature model with logistic regression, trained on patches of the 133
library stickers and tested on stickers it had not seen, tells a Stiger
send from an untouched carrier at whole-image AUC 0.995, and a reduced
spatial rich model at 0.997–1.000 — the same as when the plane was written
by replacement, so ±1 matching removed the textbook signal (§2.A) and not
the trained-classifier one. Plain against stealth, both sent through the
engine, stays at chance (about 50 %): the detector sees "a Stiger send",
not "a secret". A lower embedding rate would reduce this without removing
it: SPAM found low-fill ±1 embedding, which the textbook tests missed, at
whole-image AUC 0.63–0.71 at 1 % fill and 0.8–0.9 at 4–12 %. Aletheia's
pretrained ±1 models score the flat stickers at chance (AUC 0.500–0.512),
replacement included — a cross-source mismatch (photo-trained models on
flat art), not a property of the design, so it is no cover. These
detectors are weak by research standards, and "not detected" by them is
not "safe" (`docs/experiment-steganalysis.md` §11, §12).

What still holds when "this is some LSB carrier" is detected:
- *Content confidentiality* — AES-256-GCM ciphertext is not recoverable
  without the password.
- *Stiger-specific identification* — no magic bytes, no fixed headers, no
  spatial pattern. The carrier looks like any other LSB tool's output.
- *Payload length* — hidden by full-capacity padding.
- *Which sends carry a secret* — plain, open and stealth sends look alike to
  the detector and on the wire (§3 "File-size oracle on the wire").

What is lost: the deniability claim "this PNG carries nothing." A
stegoanalysis classifier can say with high confidence that *something* is
hidden in opaque LSBs — of every Stiger send, not only the secret ones.
Anyone whose safety depends on it should assume this detection is feasible
and plan their use accordingly.

### File-size oracle on the wire
**Defense: uniform cover.** Every PNG sent through the iMessage extension —
stealth, open and plain (no-secret) — leaves with a fully random blue-LSB
plane on its opaque pixels. A plain send is the sticker with fresh random
LSBs (`ImageStegoEngine.coverImage`); an open send is that random plane
with the 9-byte header and the payload laid over it; in a stealth send the
AES-GCM block fills the capacity. Only the blue channel of opaque pixels
changes, by at most 1. The three therefore compress alike and have the same
byte size **without any padding**. Measured on the real engine, 133 library
stickers, no pad (`docs/experiment-steganalysis.md` §9): cover-plain and
cover-open sends are within a median 0.04 % (max 0.44 %) of the stealth
send's size, and one kind against itself differs by a median 0.05 % — the
gap between modes is no larger than the run-to-run spread inside one mode.
The property survived the switch to ±1 matching (§12). So:

- A network observer or anyone holding the chat history cannot tell, by
  byte count alone, whether a sticker carries a secret.
- No pad chunk exists, so there is no pad length or pad share to leak the
  mode and no `Comment` chunk for stock tooling to flag.
- The send-size cache of the beta builds is gone; `SharedDefaults` deletes
  what they left in the App Group defaults at the next launch.

This is not part of the wire spec: the `open-v1` and `stealth-v3` decoders
read only the header and payload. The beta builds padded instead, and the
pad gave the mode away; §8 "History".

**Out of scope for this defense:** a trained classifier flags every Stiger
send as LSB-modified, plain ones included (§3 "Trained stegoanalysis
classifiers"); LSB detection by bitwise diff against a known original
(previous section).

### Cryptanalysis of AES-GCM, PBKDF2, HMAC-SHA256, HKDF-SHA256
We assume the underlying primitives are sound.

### Note: PNG metadata stripping (positive guarantee)
This is not an adversary we defend against — it is a contract we keep. All
outgoing carriers (built-in stickers, custom imports from Photos /
clipboard, Telegram-pack imports) are re-rendered through
`UIGraphicsImageRenderer` and re-encoded with `pngData()`. This pipeline
does **not** carry through EXIF, GPS coordinates, camera make/model,
authoring tool, original timestamps, or any other PNG/JPEG metadata from
the user's source file. Any metadata in an outgoing PNG is generated by the
system image encoder (`UIGraphicsImageRenderer` / `pngData()`). A user
importing a beach photo as a custom sticker does not leak the photo's GPS
to chat recipients.

### Note: Universal Clipboard relay (clipboard-send mode, positive guarantee)
The Settings → "Copy instead of send" mode (Pro) writes the rendered PNG to
the device pasteboard so the user pastes manually into Messages — used to
suppress the "From Stiger" attribution iMessage shows under
extension-inserted stickers. iOS Universal Clipboard would by default
mirror `UIPasteboard.general` to every device on the same Apple ID over
iCloud. Stiger opts out via `UIPasteboard.setItems(_:options:)` with
`.localOnly: true` (`SecretInputViewController.writePNGToLocalPasteboard`),
so neither the PNG bytes nor the metadata fact *"this user has a Stiger
sticker on their clipboard right now"* leave the originating device through
the iCloud channel. Local paste behaviour on the same device is unaffected.

**Out of scope:** a third-party clipboard manager on the same device that
scrapes pasteboard contents; another application on the *same* device
under the *same* user reading `UIPasteboard.general` immediately after the
write. These are device-local threats addressed by the same biometric and
OS-level protections that apply to any data touching the system
pasteboard, not by Stiger specifically.

## 4. Guarantees per mode

|                                          | Open mode | Stealth v3 |
|------------------------------------------|-----------|------------|
| Confidentiality of message content       | ❌ none   | ✅ AES-256-GCM |
| Authenticity of message content          | ❌ none   | ✅ GCM tag |
| Hides message length                     | ❌        | ✅ pads to capacity |
| Hides Stiger-specific markers (magic / headers)  | ❌ `STEG` magic in cleartext | ✅ no magic, no fixed bytes |
| Hides "this PNG carries some LSB stego"          | ❌        | ❌ a trained classifier detects it; the textbook chi-square/RS do not (±1 matching, measured) — see §3 / §7.1 |
| Hides PNG file size on the wire          | ✅ equal compressibility (uniform cover) | ✅ equal compressibility (uniform cover) |
| Hides stealth vs plain from size, chunk lengths and LSB statistics | — | ✅ (the beta builds leaked it, §8) — see §3 / §7.7 / §7.10 |
| Hides "was this PNG LSB-modified?"       | ❌        | ❌ (out of scope) |
| Survives iMessage lossy recompression    | ❌        | ❌ |
| Survives screenshot                      | ❌        | ❌ |
| Survives device compromise               | ❌        | ❌ |

### When the stealth-mode guarantees apply

The "Stealth v3" column applies only when an outgoing send actually takes
the stealth code path. Three independent values decide that: the chat's
password, the user's encryption toggle and the Pro entitlement. They can
disagree, and Stiger composes them into a typed `EncryptionState` with one
rule: **only `.ready` (Pro, encryption on, a password for this chat) sends
stealth; every other state sends open, and the composer says so** — a
labelled "Send unencrypted" button, a banner, or a one-shot confirmation
dialog for a user whose Pro has lapsed with a password still saved.
Nothing auto-mutates one value to "fix" another. The state table, why the
states exist, the Pro-gate invariant (a saved password implies Pro) and
what happens when Pro lapses and returns are in `docs/encryption-state.md`
and the doc-comment of `StigerCore/EncryptionState.swift`.

**Saved passwords.** There is no single "own" password and no "contact's
password". Each chat has its own: the user decides on every send and every
typed reveal whether to keep it ("Save for this chat", which remembers the
last choice). Kept passwords live in one Keychain item (`*ThisDeviceOnly`),
together with which chat each is for. A chat is identified by the set of
remote participant UUIDs Messages gives the extension — device-local values
with no names or handles in them. **They are replaced when the app is
installed again over itself** (measured on iOS 27.2 and 26.7.2 with
developer installs, 2026-11-02) **but kept across a TestFlight update**
(iOS 27.2, build 51 to 52, 2026-11-03; an App Store update is assumed to
behave the same, not measured; `docs/experiment-participant-ids.md`), so
the chat binding is a hint, not a key: a reveal tries the chat's password
first and then up to seven other saved ones, and a saved password that
opens a message is bound to the chat again. What this costs and buys, for
someone holding the phone, is in §7 item 5. The beta builds had one "own"
and one "contact's" password instead (§8 "History").

## 5. Trust assumptions

- The user's password is high entropy and not reused from a leaked corpus.
  *Currently not enforced by the UI* — there is no entropy meter and no
  minimum-strength gate; users can save `123456` and the engine will accept
  it. Adding a strength meter and a minimum-entropy floor in the password
  input is on the roadmap.
- The user shares the password through a channel Stiger does not see
  (in-person, Signal, paper).
- iOS Keychain on a non-jailbroken device is treated as confidential storage.
- Apple's CryptoKit and CommonCrypto implementations of AES-GCM, HMAC-SHA256,
  HKDF, and PBKDF2 are correct.
- `SecRandomCopyBytes` is a CSPRNG.

## 6. How to verify

The protocol is documented in `README.md` §Protocol. The implementation is
~1 200 lines of Swift split across:

- `StigerCore/StegoMarker.swift` — header framing and HKDF/HMAC derivations
- `StigerCore/ImageStegoEngine.swift` — LSB read/write, permutation, padding
- `StigerCore/AESHelper.swift` — AES-GCM and PBKDF2 wrappers
- `StigerCore/StegoSendPipeline.swift` — single send entry point (encode, or
  the random-LSB cover for a plain send)

A reference decoder in any language can be written against §Protocol of the
README without reading the Swift source. If you write one and your decoder
disagrees with Stiger on a test vector, the spec is wrong — please report
it.

Tests in `StigerTests/` cover header roundtrips, wrong-password rejection,
length-hiding, the absence of plaintext fingerprints in stealth headers, and
end-to-end encode/decode through the LSB engine.

## 7. Known weaknesses (acknowledged, not fixed)

1. **LSB modification is detectable to statistical stegoanalysis.** A
   trained classifier detects it (measured); the textbook chi-square/RS no
   longer do, since the engine applies the plane by ±1 matching (§3
   "Trained stegoanalysis classifiers" for what is detectable and what is
   not). Further mitigation would require adaptive embedding (HUGO,
   S-UNIWARD, etc.) or a lower embedding rate, which reduces detectability
   without removing it (§3) — not in v3, may revisit if the threat
   materialises.

2. **Password lives in iOS Keychain.**

   *What protects it:* `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
   means the item is excluded from device backups and never synced via
   iCloud Keychain — it stays only on the device where it was created.
   Items are scoped to our bundle ID, so another App Store app cannot read
   them. On a fresh install of Stiger we wipe any leftover items from a
   previous install (`SharedDefaults.wipeKeychainOnFreshInstallIfNeeded`).

   *What does not protect it:* iOS does **not** purge Keychain items when
   an app is deleted (Apple briefly tried this in iOS 10.3 beta and rolled
   it back; no entitlement, Info.plist key, or accessibility constant
   changes this — recalled, not verified here). If the user deletes Stiger and never reinstalls, the
   password sits in Keychain indefinitely until a factory reset or another
   fresh install of Stiger triggers our wipe. On a non-jailbroken device
   with no forensic tools, no other process can read it; on a jailbroken
   device or under forensic acquisition (Cellebrite, GrayKey) against an
   AFU device, the item is reachable (recalled, not measured).

   *Open mitigations not yet implemented:* `kSecAttrAccessControl` with
   `.userPresence` to require Face ID / passcode on every read (closes
   Cellebrite-AFU acquisition; costs UX friction on every decode);
   auto-forget after N days of inactivity (closes long-tail residue; costs
   lost access to old chats if the user has not memorised the password).
   *Implemented in 1.0:* Forget in Settings → Saved Passwords, one or all,
   and on the reveal screen after a typed password opened a message.

3. **Open mode exists in the same UI as stealth mode.** A user who forgets
   to set a password sends a publicly readable message. Mitigated by
   explicit in-flow copy: the compose banner, the receive label, the intro
   flow, and the paranoia guide all state that public-mode messages are
   readable by anyone with Stiger. The risk is not zero — a user can still
   ignore the banner — but there is no UI surface left that misleadingly
   implies privacy.

4. **No forward secrecy.** A password leak retroactively decrypts every
   sticker ever sent under that password. *Operational mitigation:*
   forgetting the password (Settings → Saved Passwords, or Forget on the
   reveal screen) removes it from the Keychain; if no copy exists
   elsewhere, prior captures become permanently undecryptable. Useful only
   when invoked *before* compromise — once an attacker has a Keychain dump,
   the wipe comes too late.

   Toggling encryption *off* does **not** wipe the saved passwords; pausing
   encryption and forgetting a credential are two intents with two
   affordances (`docs/encryption-state.md`, "Why the ceremony"). Wiping on
   toggle-off gave no extra security: a Keychain dump still recovers the
   wiped value if it happens before the deletion is sealed, and the
   biometric protection on the extension and Settings is the real gate
   against on-device reads.

5. **Per-chat passwords, distributed by hand.** Each chat has its own
   password, so one leaked or coerced password opens one chat, not every
   correspondent's (with one shared password it opened them all, and it
   spread from contact to contact). Distribution is still manual: in
   person through QR pairing (which agrees a new 128-bit password every
   time) or through a channel the user trusts. What it does not change,
   and what it adds:
   - Someone holding the unlocked phone, with the Face ID lock off (the
     default) or knowing the passcode, opens with one drag every chat
     whose password is saved — now possibly several. "Save for this chat"
     off keeps a password out of the phone; the cost is typing it on
     every reveal.
   - The saved list is on-device metadata: how many passwords, when each
     was saved, and any name the user gave it ("Lawyer"). A name is
     optional: when a new password would be saved, a popup asks whether to
     keep it, with an empty "Name (optional)" field ("Don't save" keeps
     nothing and turns "Save for this chat" off), and a password can be
     named later in Settings. The list sits behind the Face ID lock with
     the rest of Settings, which falls back to the passcode.
   - Stiger cannot show which chat a password belongs to (Messages gives
     no names), and the binding is lost on reinstall (§4 "Saved
     passwords"); a reveal then tries up to eight saved passwords, one
     PBKDF2 run each.

6. **PBKDF2, not Argon2id.** PBKDF2-SHA256 at 600 000 iterations is
   OWASP-recommended and ships in CommonCrypto. Argon2id would be more
   memory-hard against GPU farms, but the iMessage extension runs under a
   ~120 MB memory cap, which limits realistic `m_cost` to ~32–48 MB —
   roughly 2–3 orders of magnitude slowdown over PBKDF2 instead of the 4–5
   cited in the literature for full-strength parameters (these figures are
   estimates, not measured). Given the cost
   (third-party crypto dependency, wire-format bump, KDF migration in the
   decoder) the trade is not currently favourable. Preferred path is to
   attack the root cause — weak passwords — via a strength meter and
   minimum-entropy gate in the password input UI (on the roadmap). Argon2id
   is revisited if decode ever moves out of the extension or if we observe
   real evidence of offline brute-force in the wild.

7. **The beta's pad chunk was visible to file-level forensics, and its
   length gave the mode away** (TestFlight builds through 48; removed before
   the public 1.0). An earlier version of this item said the chunk reveals
   neither the tool nor whether a secret is present; the second half is
   false, the first is untested. The numbers, and why padding differently
   could not fix it, are in §8 "History". Files from the beta are still in
   recipients' chats.

8. **Cross-user overlap on shared imports.** If many Stiger users import
   the same Telegram pack (or the same publicly distributed image set),
   their post-import PNG pixels are identical — our import pipeline runs
   the same rasterization on the same source. An adversary collecting
   Stiger stickers across users could in principle correlate carriers
   across senders. This is a corpus-level signal, not a per-sticker leak;
   every send has a fresh random LSB plane, but the other bits still match
   across users, and the residual risk is very narrow and not addressed in
   v3. Importing from the public pack does **not** make
   LSB-detection-with-original easier: our import re-encodes the source
   `.webp` through `UIGraphicsImageRenderer`, so the post-import PNG is no
   longer pixel-identical to the original Telegram file before any LSB
   modification.

9. **Map previews reach Apple Maps without a tap.** MapKit is not offline.
   When a revealed secret carries coordinates — an attached location
   (`geo:`) or a map link with coordinates in it — the reveal screen renders
   a map preview with `MKMapSnapshotter` right away, without a tap, so
   Apple's map servers receive the region around the decrypted coordinates,
   from the recipient's IP, at the moment of reading. On the sending side
   the location picker loads tiles for whatever region is on screen, and
   place search sends the typed query through `MKLocalSearchCompleter` /
   `MKLocalSearch`. Stiger itself sends the coordinates nowhere. A
   tap-to-load preview would close this; it was weighed on 2026-09-29 and
   not taken. What leaks is the recipient's IP and the approximate area, to
   Apple only — for a location secret, that area is the substance of the
   secret. To keep a place away from Apple entirely, send it as plain text
   rather than as an attached location or a map link.

10. **Every send is marked, so that no send stands out.** Uniform cover
    gives plain and open sends the same random LSB plane as stealth sends,
    so an observer cannot tell *which* sends carry a secret (§3 "File-size
    oracle on the wire"; small ML detectors cannot either, §3 "Trained
    stegoanalysis classifiers"). The price: "this PNG carries nothing" is
    lost for every Stiger send, not only the secret ones; a plain send of a
    sticker too large for the engine now fails like a secret one does (the
    beta's plain path had no size cap), which the ingress policy should
    make unreachable; open sends still carry `STEG`; and during a rollout
    the old clients' sends form a visible version cohort in the files —
    padded ones (beta), then replacement-written ones (builds 49–53), §8
    "History". It is not a replacement for lower-rate embedding (item 1),
    which needs a new stealth version.

## 8. History

Dated changes to the engine that a reader of old files, or of old copies of
this document, needs. Each entry says what the engine did, what that
leaked, and when it changed. Measurements: `docs/experiment-steganalysis.md`.

**TestFlight beta, builds through 48 (until 2026-10-14): size padding, LSB
replacement, two passwords.** A plain send left the sticker's LSBs as they
were; a stealth send overwrote the whole blue LSB plane by replacement
(`(B & 0xFE) | bit`). To hide the resulting size difference, every send was
padded to a per-image target (`max(plain, stealth probe) + margin +
jitter`, cached in the App Group `UserDefaults`) by inserting a `tEXt`
`Comment` chunk of random printable ASCII before `IEND`. That equalised
total sizes (identical for 133/133 stickers) but not the chunks that make
them up, and it leaked the mode three ways (measured 2026-10-10 on the beta
pipeline, §5, §6, §8, §11):

- *The pad's share of the file.* A stealth PNG compresses worse than a
  plain one, so the pad that tops it up is shorter — a median 4.9 % of the
  file for stealth against 10.7 % for plain and open, shorter for stealth
  on 133/133 stickers. One threshold on that share separated stealth from
  plain/open with 99.2 % balanced accuracy from chunk lengths alone,
  without decoding pixels or having the original. The share is a symptom
  of the stealth file's lower compressibility, which the LSB tests see
  anyway, so sizing the pad differently could not remove it (sizing from
  the plain PNG would make stealth files exceed the target and the padder
  would no-op).
- *The pad itself.* A `Comment` of 2.4–79 KB (1 KB or more on every one of
  the 133 stickers), where a survey of 28 653 PNGs in system and
  application directories found no `Comment` over 1 KB (that population is
  OS resources, not photos or other apps' stickers). It was the one PNG
  feature stock tooling flagged: `zsteg` printed it on all 201 sampled
  sends from the real pipeline (67 each of stealth, open and plain) and on
  both delivered iMessage files, while reporting nothing in the LSB plane
  of any of them; `exiftool` prints it as a `Comment` tag with the warning
  "Text/EXIF chunk(s) found after PNG IDAT" on both delivered files
  (`pngcheck` and `binwalk` report nothing unusual). Whether file-level
  tooling can attribute a send to Stiger from it was never tested.
- *The LSB statistics.* With plain sends untouched and stealth sends
  overwritten, the textbook tests told them apart outright (next entry),
  and two small ML detectors (SPAM features with logistic regression or
  gradient boosting; a small CNN; a few thousand patches of the 133
  stickers, tested on stickers they had not seen) told beta plain from
  stealth at 98–99 % per sticker.

The beta's `SendSizeNormalizer` also persisted, for every image sent
through the extension — plain sends included — `SHA-256(pixels) → target
size` plus a per-install random seed in the App Group `UserDefaults`: a
record on the phone of which images were sent through Stiger. Release 1.0
deletes those keys at first launch (`SharedDefaults`, covered by a unit
test); that removes them from the defaults store and does not promise the
old bytes are gone from flash. The beta also had one "own" password for
every send and one "contact's" password tried first on reveal; release 1.0
replaced them with a saved password per chat (§4, `docs/chat-passwords.md`).

**Release 1.0, build 49 onward (first submitted 2026-10-14): uniform cover,
no pad, still replacement.** Every send, plain and open included, gets a
random blue-LSB plane, so sizes agree without padding (§3 "File-size oracle
on the wire" has the numbers) and the files are about 5 % smaller than the
beta's padded sends; the reference decoders still read the sends (Python
40/40, TypeScript 152/152 checked). The plane was written by replacement,
which equalises the (2k, 2k+1) value pairs, so the textbook tests flagged
every send with no training and no original: pairs-of-values chi-square at
p ≥ 0.001 flagged 133/133 stealth sends with 0/133 false positives among
the beta's plain and open sends, and under uniform cover 133/133 of plain,
open and stealth alike; RS at d ≥ 0.25 flagged 118–120 of 133. The same
tests on the delivered iMessage files gave p = 0.926 / RS d = 0.364 for
stealth against p = 0 / d = −0.003 for open. The cause is the full-capacity
fill: in a pixel simulation chi-square flagged nothing at 1.4–15 % fill,
and RS flagged nothing for ±1 LSB matching at any size tried — the
length-hiding design bought its property at this price. The same
chi-square rule flagged 19 of 4 043 ordinary PNGs found in system and
application directories (0.47 %, mostly noisy textures) — UI assets, not
photos or other apps' stickers, so a floor and not an estimate for a real
chat (§3, §4, §5, §7, §9, §10). Build 53, submitted 2026-11-03, is the last
with this engine.

**±1 LSB matching (measured and implemented 2026-11-04, in the first build
after 53).** The engine reaches the same bit without equalising the value
pairs: the textbook tests fall to the untouched-channel floor (§2.A), the
trained detectors are unchanged (§3), plain versus stealth stays at chance,
and the size property of uniform cover survives. Cost: about 2 % more bytes
per send (median +1.9 %). No wire-format change — `spec/lsb-layer.md` gained
an encoder note only, the decoders are untouched (the Python reference
reads 133/133 open and 133/133 stealth matched sends; the TypeScript one
266/266) and the four committed test vectors still pass (§12). Old clients'
replacement sends form a visible cohort during the rollout, as the padded
ones did.
