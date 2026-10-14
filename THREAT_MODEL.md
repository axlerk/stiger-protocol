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
does not:** statistical stegoanalysis can detect that *some* LSB modification
happened (without recovering the message) — textbook tests need neither
training nor the original, see §3; a compromised device, a
forensic Keychain dump, screenshots, or iMessage recompression all defeat
or destroy the payload. **Open mode** (no password) is publicly readable
by anyone with Stiger and is not a privacy feature. **No forward secrecy:**
a password leak retroactively decrypts every prior message. Read the rest
before relying on Stiger for anything serious.

**По-русски.** Stiger шифрует короткое сообщение (AES-256-GCM, пароль
растягивается через PBKDF2-SHA256-600k) и прячет шифротекст в младшие
биты обычного PNG-стикера, отправляемого через iMessage. **Что защищает:**
содержимое сообщения (нечитаемо без пароля) и его длину (паддинг до
полной ёмкости стикера). **Чего не защищает:** статистический стегоанализ
(хватает учебных тестов, без обучения и без оригинала) видит сам факт
LSB-модификации (без чтения сообщения); компрометация
устройства, форензик-дамп Keychain, скриншоты и пережатие iMessage —
всё это либо обходит, либо уничтожает payload. **Открытый режим** (без
пароля) читается любым, у кого есть Stiger, — это не приватность.
**Forward secrecy нет:** утечка пароля ретроактивно расшифровывает все
предыдущие сообщения. Прочитайте дальше, прежде чем полагаться на Stiger
в серьёзных вещах.

## 1. Scope

Stiger hides short messages (≤ 2 KB of user text) inside PNG sticker
images and ships them through Apple's iMessage as ordinary-looking PNG
stickers. There are two modes:

> **Note on transport.** Carriers are shipped as ordinary iMessage image
> attachments (`MSConversation.insertAttachment`), **not** through Apple's
> `MSSticker` pipeline — the latter re-encodes PNGs to HEIC in transit
> and would destroy any LSB payload. This is **observed platform
> behaviour, not a security guarantee**; the recompression failure mode
> is covered in §3 ("iMessage transport"). See `README.md` →
> "Carrier transport" for the empirical findings, the receive-side UTI
> situation, and notes for re-implementers. The colloquial word
> "sticker" in this document refers to the carrier's *visual* role
> (small expressive PNG), not to the `MSSticker` API.


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
provide weaker cover and are visible to statistical stegoanalysis
even without the password — see §2E and §7.1. Textbook tests (pairs-of-values
chi-square, RS) tell stealth carriers from unmodified stickers with no
training and no original: 133/133 detected, 0/133 false positives for
chi-square p ≥ 0.001, real engine, library stickers (measured 2026-10-10,
`docs/experiment-steganalysis.md` §3, §5). The defense in this section is
against simple "look for known magic bytes" scanners — stock `zsteg` (default
and `-a`) and `StegExpose` at its default threshold report no LSB finding on
sticker-sized stealth carriers — not against statistical analysis.

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
- The recipient's reveal UI extends this ambiguity to the screen.
  A free user (no Pro, no password to try) sees the same ambient
  "empty-or-encrypted, decryption needs Pro and a password" status
  line plus a Get-Pro link on every `noPayloadFound` outcome — truly
  empty stickers included. The screen's appearance therefore never
  reveals whether THIS particular sticker carries a payload, so a
  shoulder-surfer or an examiner of a non-Pro recipient's device
  cannot use the screen as an oracle.

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

**Defense:** stealth mode has no magic bytes. (Open mode does: its
carriers start with a fixed `STEG` header, and this defense does not
apply to them — see §1 and §2.D.) The first 16 bytes of the LSB
stream are a random salt; the next 4 bytes are an HMAC-derived marker that
varies per message; bytes 20–21 are XOR-masked version and reserved bytes
and are authenticated by the same HMAC. Two encodings of the same message
into the same image produce different LSB streams (the non-LSB pixels are
identical of course; only the LSB layer is randomised).

**Measured (2026-10-10).** On stealth carriers `zsteg` and default-threshold
`StegExpose` find no LSB payload. But this item lists PNG `tEXt` chunks among
what such scanners look for, and on the beta builds (TestFlight, through build 48; the 1.0 submitted to the App Store does not pad) `zsteg` printed the
size-normalizing `Comment` pad as a finding on all 201 sampled sends from the
real pipeline (67 each of stealth, open and plain) and on both delivered
iMessage files, while reporting nothing in the LSB plane of any of them, and
`exiftool` prints the pad as a `Comment` tag with the warning "Text/EXIF chunk(s)
found after PNG IDAT" on both delivered files (`pngcheck` and `binwalk` report
nothing unusual). The pad is gone from the release after 1.0 (§3 "File-size oracle", §7.7, §7.10).

### D. Forensic chat-log reviewer
Someone with access to the recipient's (or sender's) Messages history —
an iCloud Messages backup, an unlocked-device extraction, a `chat.db`
dump, an iTunes backup parsed with off-the-shelf forensic tooling — who
walks through the conversation looking for anomalies.

This adversary doesn't run cryptographic analysis on individual PNGs;
they read the chat as a whole and look for *patterns of behaviour*.

**What we deliberately defend (visual mimicry).** At the *rendering*
layer Stiger carriers aim for "indistinguishable at a glance" from
ordinary stickers and jumbo emoji: PNG dimensions are tuned so the
in-bubble visible glyph matches Apple's native single-emoji jumbo on
screen, the colour palette comes from Apple's own SBIX bitmaps, and
every send (stealth, open, or plain) comes out at the same byte size — by
equal compressibility under uniform cover from the release after 1.0, by
padding in the beta (§3 "File-size oracle") — so an analyst skimming a chat list
sees the same shape, the same size, the same general visual rhythm as the
surrounding messages.

**What we do NOT defend.** The carrier reaches the recipient as an
**image attachment**, not as an `MSSticker`. Apple's Messages stack
records the attachment with `attachment_type = image/png` (or similar
`UTI = public.png`) in `chat.db`, and the rendered bubble is the
"image bubble" UI affordance, not the bubble-less floating sticker UI.
A reviewer who knows what to look for can therefore tell, without ever
opening the PNG, that the user is exchanging *PNG attachments
positioned where stickers would be more natural*. This pattern is more
visible when the same chat contains real stickers from other contacts
alongside Stiger PNGs from the user.

The image-attachment nature also shows **on screen**, not only in
`chat.db`. Two tells, observed by Pavel on his iPhone on 2026-10-08
(screenshot 1179×2556 px: two native 🤐 emoji and two `emoji_zipper`
carriers in one conversation, every fully visible face drawn at
185×185–187 px — the size match itself held):

- **Save button on received carriers.** Messages draws a save button
  (a circled ⬇) next to a *received* image attachment. A received
  carrier gets one; a native emoji, being text, never does. So in the
  received half of a conversation a carrier can be told from an emoji
  at a glance, without opening anything. Sent carriers showed no such
  button in the same screenshot.
- **Archived carriers.** After some time, carriers are archived: they
  appear as a PNG attachment that has to be downloaded again from
  iCloud, not as an emoji-sized picture, while native emoji around
  them keep rendering as text. (The mechanism is presumably Messages
  in iCloud offloading old attachments — inferred, not verified.)
  The payload survives the round trip: Pavel reported on 2026-10-09 that
  an archived carrier, downloaded again from iCloud, still reveals. The
  device, iOS version and how long the carrier had been archived were
  not recorded.

"Indistinguishable at a glance" therefore holds for a recent, sent
carrier. It does not hold for a received one, nor for an old one.

This is a **deliberate trade-off**, not an oversight. `MSSticker`
recompresses to HEIC in transit (verified May 2026, iOS 26 — see
`README.md` "Carrier transport"), which destroys any LSB payload, and
the receive-side bytes from the sticker pipeline are not addressable
to the reveal flow. We *cannot* use `MSSticker` and have steganography
work at all. The choice is "PNG-attachment carrier with this exposure"
versus "no product."

`MSSticker` carries hard format constraints — 300–618 px on the
longest edge, ≤ 500 KB on disk, fragile APNG support — and Apple's own
documented workaround for content that doesn't fit (animated, dynamic,
oversized) is to ship the bytes via
`MSConversation.insertAttachment(_:withAlternateFilename:)` instead
(Apple Developer Forums thread 52931 et seq.). Stiger ships content
that overflows those constraints in both directions: the regular_emoji
pack is 232 px (below the 300-px floor), and several illustrated
stickers are already over 500 KB on disk before any stealth padding
brings them further over the ceiling. Plus we need PNG bytes to
survive end-to-end so the LSB payload arrives intact, which the
recompression path used by `MSSticker` would defeat anyway.

So our use of `insertAttachment` falls into the same documented
"content that doesn't fit MSSticker" bucket as benign sticker apps,
plus an extra Stiger-specific reason. The user-visible artifact ("PNG
attachment where a sticker would be more natural") is the same shape
and appears in conversations involving non-Stiger apps too. It is not
a Stiger-specific signature — it is an "uses an image-attachment
carrier" signature, drawn from a population much wider than Stiger.
See `docs/experiment-sticker-transport.md` for the supporting
findings.

What still holds when this pattern is noticed, for **stealth** carriers:
- *Content confidentiality* — the payload is AES-GCM ciphertext as far
  as a reviewer can tell. They see "this user sends PNGs," not "this
  PNG hides text."
- *Sender / recipient unlinking* — the LSB stream of a stealth carrier
  has no app-specific fingerprint, so an analyst cannot identify Stiger
  from that stream of a single carrier (see §2.E "Corpus stego analysis"
  for what changes when many carriers are available). In the beta builds the
  size-normalizing pad chunk was **not** covered by this: a `Comment` of
  random printable ASCII, 2.4–79 KB across the 133 stickers tested (1 KB or
  more on every one), where a survey of 28 653 PNGs in system and
  application directories found no `Comment` over 1 KB (§3 "File-size
  oracle"; that population is OS resources, not photos or other apps'
  stickers). Whether file-level tooling can attribute a send to Stiger from it
  was never tested. The release after 1.0 has no pad chunk (§7.10).
- *Mode opacity, total size only* — plain, open and stealth sends have the
  same total byte size (identical for 133/133 stickers in the beta; within a median
  0.04 % without any padding after 1.0), so the chat-level pattern doesn't
  betray which mode is in use. In the beta this did **not** hold at file level: the
  length of the pad chunk gave stealth away (§3 "File-size oracle", §7.7).

**Open carriers break the first two.** An open-mode carrier stores its
payload in plaintext behind the fixed `STEG` header (`spec/open-v1.md`
§3), so any LSB scanner that applies the eligibility rule (`alpha == 255` only,
`spec/lsb-layer.md` §3) reads the message and learns that Stiger was used.
(Stock `zsteg` reads every pixel and misses it on stickers with transparency —
measured, a tooling accident and not a defence.) One open carrier in a chat
also puts the other image attachments in that chat under suspicion: a stealth
carrier next to a known Stiger carrier is attributable by association,
even though it carries no fingerprint of its own. See
`docs/release-1.0.md`, "Post-1.0 security design backlog" §2.

Users whose recipients' devices may be examined by parties with
chat-database access should assume this signature is detectable and
decide accordingly.

**Long-press → "From Stiger" menu does not surface per-bubble
metadata to the extension** (verified 2026-05-06, iOS 26, two-device
test, TestFlight build — see `docs/experiment-from-stiger-tap.md`).
Tapping that entry launches the Stiger extension in compact mode
with `MSConversation.selectedMessage = nil` and
`extensionContext.inputItems` containing one empty `NSExtensionItem`
with zero attachments — byte-identical to a regular drawer-launched
activation. The system does not pass a reference to the tapped
bubble. A hostile party holding the recipient's unlocked phone with
Stiger installed therefore cannot use this surface as a one-tap
decode oracle — they would still need to extract the carrier bytes
manually (long-press → save image → drag/share into Stiger), which
falls under the unlocked-phone threat already covered by Stiger's
biometric/passcode lock screen. The behaviour of the inline "From
[App]" attribution label (which iMessage sometimes shows beneath a
bubble) was not cleanly reproducible during this test because Stiger
is not yet published to the App Store; the routing of that surface
on a production-installed receiver remains unverified.

### E. Corpus stego analysis
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
original and via statistical tests without the original (textbook ones
suffice, measured in §3). See §3
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
  OS-level mitigation, not Stiger's, but worth knowing. The clipboard write
  itself is `localOnly` so the bytes never propagate via Universal Clipboard
  to the user's other Apple-ID-paired devices — see §3 "Universal Clipboard
  relay" for the positive guarantee.
- Third-party keyboards with Full Access (Gboard, SwiftKey, etc.)
  run in their own processes and can phone home with every keystroke
  entered into the secret-input text view. Stiger can't enforce a
  system-keyboard restriction from inside an iMessage extension;
  mission users should disable Full Access keyboards in iOS Settings
  before composing secrets. Password fields use `isSecureTextEntry`,
  so iOS forces the system keyboard there automatically — only the
  open secret input is exposed.
- Screenshots of the compose UI sitting in the recents stack.
- Apple Maps sees the map areas Stiger shows, from the device's IP. MapKit
  is not offline. When a revealed secret carries coordinates — an attached
  location (`geo:`) or a map link with coordinates in it — the reveal screen
  renders a map preview with `MKMapSnapshotter` right away, without a tap,
  so Apple's map servers receive the region around the decrypted
  coordinates, from the recipient's IP, at the moment of reading. On the
  sending side the location picker loads tiles for whatever region is on
  screen, and place search sends the typed query through
  `MKLocalSearchCompleter` / `MKLocalSearch`. Stiger itself sends the
  coordinates nowhere, but for a secret that *is* a place, the area Apple
  sees is most of what the secret says. Kept as a deliberate trade-off
  (decided 2026-09-29, see §7). To keep a place away from Apple entirely,
  send it as plain text rather than as an attached location or a map link.

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

**Measured: classical tests and two small ML detectors (a stronger ML detector
was not run, so the statement about ML tools above remains an assumption).** On all 133 library stickers
through the real send pipeline, pairs-of-values chi-square (p ≥ 0.001) flags
133/133 stealth sends and 0/133 plain and 0/133 open sends; RS (`d ≥ 0.25`)
flags 118/133 stealth and none of the others. The same tests on a delivered
iMessage file gave p = 0.926 / RS d = 0.364 for stealth against p = 0 /
d = −0.003 for open. The cause is the full-capacity fill: in a pixel
simulation chi-square flagged nothing at 1.4–15 % fill, and RS flagged nothing
for ±1 LSB matching at any size tried — the length-hiding design buys its
property at this price (`docs/experiment-steganalysis.md` §3, §5, §7). The same
rule flagged 19 of 4 043 ordinary PNGs found in system and application
directories (0.47 %, mostly noisy textures) — a population of UI assets, not of
photos or other apps' stickers, so a floor and not an estimate for a real chat
(`docs/experiment-steganalysis.md` §10). Two small ML detectors (SPAM features with
logistic regression or gradient boosting; a small CNN; a few thousand patches of
the 133 stickers, tested on stickers they had not seen) told beta plain from stealth
at 98–99 % per sticker, and cannot tell shipped plain from shipped stealth (about
50 %). Low-fill ±1 embedding, which the classical tests missed, was still found by
SPAM: whole-image AUC 0.63–0.71 at 1 % slot fill and 0.8–0.9 at 4–12 %. These
detectors are weak by research standards, and "not detected" by them is not "safe"
(`docs/experiment-steganalysis.md` §11).

What still holds when "this is some LSB carrier" is detected:
- *Content confidentiality* — AES-256-GCM ciphertext is not recoverable
  without the password.
- *Stiger-specific identification* — no magic bytes, no fixed headers,
  no spatial pattern. The carrier looks like any other LSB tool's output.
- *Payload length* — hidden by full-capacity padding.
- *On-the-wire file size* — equal across modes by equal compressibility
  (uniform cover; padding in the beta), §3 "File-size oracle".

What is lost: the deniability claim "this PNG carries nothing." A
stegoanalysis classifier can say with high confidence that *something*
is hidden in opaque LSBs. Mission-class adversaries should assume this
detection is feasible and design their operational use accordingly.

### File-size oracle on the wire
**Defense (release after 1.0): uniform cover.** Every PNG sent through the
iMessage extension — stealth, open and plain (no-secret) — leaves with a fully
random blue-LSB plane on its opaque pixels. A plain send is the sticker with
fresh random LSBs (`ImageStegoEngine.coverImage`); an open send is that random
plane with the 9-byte header and the payload laid over it; in a stealth send the
AES-GCM block fills the capacity. The three therefore compress alike and have
the same byte size **without any padding**. Measured on the real engine, 133
library stickers, no pad (`docs/experiment-steganalysis.md` §9): cover-plain and
cover-open sends are within a median 0.04 % (max 0.44 %) of the stealth send's
size, and one kind against itself differs by a median 0.05 % — the gap between
modes is no larger than the run-to-run spread inside one mode. So:

- A network observer or anyone holding the chat history cannot tell, by byte
  count alone, whether a sticker carries a secret.
- No pad chunk exists, so there is no pad length or pad share to leak the mode
  and no `Comment` chunk for stock tooling to flag.
- The send-size cache of 1.0 is gone; `SharedDefaults` deletes what 1.0 left in
  the App Group defaults at the next launch (a hash per image ever sent).

This is not part of the wire spec: the `open-v1` and `stealth-v3` decoders read
only the header and payload (`docs/experiment-steganalysis.md` §9).

**TestFlight beta, builds through 48: padding.** The beta padded every send to a per-image target
(`max(plain, stealth probe) + margin + jitter`, cached in the App Group
`UserDefaults`) by inserting a `tEXt` chunk of random printable ASCII before
`IEND`. That equalised total sizes (identical for 133/133 stickers) but not the
chunks that make them up. Measured 2026-10-10 on the beta pipeline: a stealth PNG
compresses worse than a plain one, so the pad that tops it up is shorter — a
median 4.9 % of the file for stealth against 10.7 % for plain and open, shorter
for stealth on 133/133 stickers. One threshold on that share separated stealth
from plain/open with 99.2 % balanced accuracy from chunk lengths alone, without
decoding pixels or having the original. The share is a symptom of the stealth
file's lower compressibility, which the LSB tests see anyway, so sizing the pad
differently could not remove it (sizing from the plain PNG would make stealth
files exceed the target and the padder would no-op). The pad was also the one PNG
feature stock tooling flagged: `zsteg` printed it on every beta send we sampled.
That is why it was dropped: release 1.0, the first public release (build 49
onward), does not pad. See §7.7, §7.10 and
`docs/experiment-steganalysis.md` §5, §6, §8.

**Out of scope for this defense:**
- Statistical LSB tests: under uniform cover they flag every Stiger send as
  LSB-modified, plain ones included (§3 "Trained stegoanalysis classifiers",
  §7.10).
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
the system image encoder (`UIGraphicsImageRenderer` / `pngData()`; the beta builds
also added a `tEXt` "Comment" pad chunk). A user importing a beach photo as a
custom sticker does not leak the photo's GPS to chat recipients.

### Note: Universal Clipboard relay (clipboard-send mode, positive guarantee)
The Settings → "Copy instead of send" mode (Pro) writes the rendered PNG
to the device pasteboard so the user pastes manually into Messages — used
to suppress the "From Stiger" attribution iMessage shows under
extension-inserted stickers. iOS Universal Clipboard would by default
mirror `UIPasteboard.general` to every device on the same Apple ID over
iCloud. Stiger opts out via `UIPasteboard.setItems(_:options:)` with
`.localOnly: true` (`SecretInputViewController.writePNGToLocalPasteboard`),
so neither the PNG bytes nor the metadata fact *"this user has a Stiger
sticker on their clipboard right now"* leave the originating device
through the iCloud channel. Local paste behaviour on the same device is
unaffected.

**Out of scope:** a third-party clipboard manager installed on the same
device that scrapes pasteboard contents; another iOS/macOS application
on the *same* device under the *same* user reading
`UIPasteboard.general` immediately after the write. These are
device-local threats addressed by the same biometric and OS-level
protections that apply to any data touching the system pasteboard,
not by Stiger specifically.

## 4. Guarantees per mode

|                                          | Open mode | Stealth v3 |
|------------------------------------------|-----------|------------|
| Confidentiality of message content       | ❌ none   | ✅ AES-256-GCM |
| Authenticity of message content          | ❌ none   | ✅ GCM tag |
| Hides message length                     | ❌        | ✅ pads to capacity |
| Hides Stiger-specific markers (magic / headers)  | ❌ `STEG` magic in cleartext | ✅ no magic, no fixed bytes |
| Hides "this PNG carries some LSB stego"          | ❌        | ❌ textbook statistics detect it (measured) — see §3 / §7.1 |
| Hides PNG file size on the wire          | ✅ equal compressibility (1.0: padding) | ✅ equal compressibility (1.0: padding) |
| Hides stealth vs plain from size, chunk lengths and LSB statistics | — | ✅ from release 1.0 (build 49 onward); ❌ in the beta builds (through 48; pad share 99.2 %, textbook tests) — see §3 / §7.7 / §7.10 |
| Hides "was this PNG LSB-modified?"       | ❌        | ❌ (out of scope) |
| Survives iMessage lossy recompression    | ❌        | ❌ |
| Survives screenshot                      | ❌        | ❌ |
| Survives device compromise               | ❌        | ❌ |

### When the stealth-mode guarantees apply (encryption state machine)

The "Stealth v3" column above only applies when outgoing sends actually
take the stealth code path. Three independent storage values determine
that:

- `password` (Keychain, `*ThisDeviceOnly`)
- `encryptionEnabled` (App Group `UserDefaults`, user toggle)
- `isPro` (App Group `UserDefaults`, OR'd at read time with
  `RussianAudience.isRussianSpeaking`)

Each is mutated by a distinct affordance (Settings, ParanoiaGuide,
StoreKit / language gate), and the three are independent — they can
disagree. Stiger composes them into a typed `EncryptionState` (see
`StigerCore/EncryptionState.swift`):

| isPro | encryption | password | State              | Outgoing send mode |
|-------|------------|----------|--------------------|--------------------|
| ✓     | ✓          | set      | `.ready`           | stealth ✅          |
| ✓     | ✓          | empty    | `.needsPassword`   | composer blocks    |
| ✓     | ✗          | set      | `.userDisabled`    | open (banner)      |
| ✓     | ✗          | empty    | `.proIdle`         | open               |
| ✗     | ×          | set      | `.lapsed`          | open + dialog gate |
| ✗     | ×          | empty    | `.free`            | open (upsell)      |

Only `.ready` resolves to an active encryption password. Every other
state encodes outgoing payloads in **open mode** — the user's saved
password is preserved in storage but not used until the state returns
to `.ready`. The composer renders a distinct warning banner for each
disagreement state; the send pipeline blocks plaintext-fallthrough in
the `.lapsed` case behind a one-shot "Send unencrypted?" confirmation
dialog (`SecretInputViewController.presentLapseConfirmation`,
suppressed for the rest of the lapse window via
`SharedDefaults.lapseAcknowledged`, cleared on Pro restoration).

**Why the ceremony.** Earlier versions papered over disagreements
between the three storage values by silently mutating one of them on
entry — defensively re-enabling `encryptionEnabled` whenever a password
existed, wiping the password on toggle-off, and clearing
`encryptionEnabled` whenever Pro lapsed. The combination shipped a
failure mode (`[pro-lapse-1] + [send-1]`) where a lapsed-Pro user
could send a typed secret in plain mode while the composer showed
nothing alarming. Each silent fix-up was correct in isolation;
together they hid a critical hole. The state-machine model is the
remediation: every disagreement is now a first-class value the UI
renders explicitly, and the dialog gates plaintext sends behind
explicit consent.

**Pro-gate invariant**: `password != "" → isPro` (in production).
Setting a non-empty password is a Pro-only operation. Every UI entry
point that writes to `SharedDefaults.password` /
`SharedDefaults.contactPassword` (Settings, ParanoiaGuide,
PairingFlow, the extension's password field, contact-password
auto-save on successful decode) guards on `proAccess.isPro`. A
DEBUG-only `assertionFailure` in the keychain setter catches any
future entry point that misses the gate before merge. Therefore
`.lapsed` (`!isPro && password != ""`) is reachable in production
only by a former-Pro user whose subscription expired.

**Pro-restoration semantics.** When Pro returns (purchase or
restore), `encryptionEnabled` and `password` are unchanged;
`.lapsed` transitions back to whichever state the flags naturally
resolve to (`.ready`, `.userDisabled`, etc). The standing
"plaintext send acknowledged" flag is cleared on restoration so a
*future* lapse re-prompts. The host-app `ProAccess.refreshStatus`
and the extension's `ExtensionProEntitlement.refresh` (called
from `viewDidLoad` to remove the dependency on the host app
having been opened recently) both clear it.

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

1. **LSB modification is detectable to statistical stegoanalysis.** See §3
   "Trained stegoanalysis classifiers" for what is detectable and what
   is not; textbook tests already do it (measured). Mitigation would
   require adaptive embedding (HUGO, S-UNIWARD, etc.) — not in v3, may
   revisit if the threat materialises.

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
   clearing the password field in Settings (or ParanoiaGuide) wipes
   it from the Keychain; if no copy exists elsewhere, prior captures
   become permanently undecryptable. Useful only when invoked
   *before* compromise — once an attacker has a Keychain dump, the
   wipe comes too late.

   Note: toggling encryption *off* does **not** wipe the saved
   password (this used to wipe; see §4 "encryption state machine"
   for why the coupling was removed). Two distinct user intents,
   two distinct affordances:

   - "Pause encryption temporarily, keep the credential" → toggle
     off. Re-enabling restores the same password — no re-pairing,
     no loss of access to old encrypted history.
   - "Forget the credential entirely" → clear the password field
     in Settings (the field is visible while encryption is on; a
     dedicated "forget password" affordance is on the roadmap so
     this works without an enable-then-clear-then-disable dance).

   The previous coupling lost the user's setup on every toggle-off,
   which both broke the re-enable use case and gave no extra
   security (a Keychain dump still recovers the wiped value if it
   happens before the deletion is sealed; biometric protection on
   the extension/Settings is the real gate against on-device
   reads).

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

7. **Pad chunk visible to file-level forensic, and its length gives the mode
   away (beta builds through 48; removed before the public 1.0).** The size-normalization defense of
   1.0 (§3, "File-size oracle") inserted a
   `tEXt` chunk of random printable ASCII to bring every send up to a
   per-image target size. Anyone who parses the PNG sees a `Comment` of
   2.4–79 KB (1 KB or more on all 133 stickers tested), unusual in the PNGs we
   surveyed (§3). More importantly, measured
   on 2026-10-10: the chunk's share of the file is about 5 % for stealth and
   about 11 % for plain and open, enough to tell stealth from the other two
   with 99.2 % balanced accuracy from chunk lengths alone. An earlier version
   of this item said the chunk reveals neither the tool nor whether a secret
   is present; the second half is false, the first is untested. Padding
   differently does not fix it (§3). Fixed by dropping the pad (item 10) in the
   release after 1.0; 1.0 itself keeps the weakness.

8. **Cross-user overlap on shared imports.** If many Stiger users import
   the same Telegram pack (or the same publicly distributed image set),
   their post-import PNG pixels are identical — our import pipeline runs
   the same rasterization on the same source. An adversary collecting
   Stiger stickers across users could in principle correlate carriers
   across senders. This is a corpus-level signal, not a per-sticker leak,
   and in the beta was partially absorbed by send-side size normalization (§3, since
   removed; every send now has a fresh random LSB plane, but the other bits
   still match across users); the residual risk is very narrow and not
   addressed in v3. Importing from
   the public pack does **not** make LSB-detection-with-original easier:
   our import re-encodes the source `.webp` through `UIGraphicsImage-
   Renderer`, so the post-import PNG is no longer pixel-identical to the
   original Telegram file before any LSB modification.

9. **Map previews reach Apple Maps without a tap.** Revealing a secret that
   carries coordinates fetches a map snapshot of that area from Apple
   immediately (§3, "Side channels"). A tap-to-load preview would close
   this; it was weighed on 2026-09-29 and not taken. What leaks is the
   recipient's IP and the approximate area, to Apple only — for a location
   secret, that area is the substance of the secret.

10. **Plain and open sends are statistically cleaner than stealth sends.**
    In the beta a plain send leaves a sticker's LSBs as they were, and a stealth
    send overwrites the whole blue LSB plane, so textbook tests tell them
    apart (§3), as does the pad share (item 7).
    *Implemented after the beta, ships in release 1.0 — uniform cover:*
    every send, plain and open included, gets random blue LSBs on opaque
    pixels (`ImageStegoEngine.coverImage` for plain; open: header and payload
    laid over the random plane), and the pad is gone because sizes agree
    without it.
    Measured on the real engine without any pad, 133 stickers: cover-plain
    and cover-open sends are within a median 0.04 % of stealth size (max
    0.44 %; one mode against itself differs by a median 0.05 %); the LSB
    tests flag them like stealth; only the blue channel of opaque pixels
    changes (|Δ| ≤ 1); the reference decoder still reads open sends (40/40
    checked); and the files are about 5 % smaller than the beta's padded sends
    (`docs/experiment-steganalysis.md` §9). No wire-format change: the
    `open-v1` and `stealth-v3` decoders read only the header and payload.
    *What it does not do:* stealth sends — and after the change plain ones too
    — stay detectable as LSB-modified, so "this PNG carries nothing" is lost
    for every Stiger send, not only secret ones; open sends still carry
    `STEG`; and during the rollout old clients keep padding while new ones
    do not, a version cohort visible in the files; and a plain send of a
    sticker too large for the engine now fails like a secret one does (the
    the beta's plain path had no size cap), which the ingress policy should make
    unreachable. What it buys is that an
    observer cannot tell *which* sends carry a secret (small ML detectors cannot
    either: about 50 %, `docs/experiment-steganalysis.md` §11). It is not a
    replacement for lower-rate embedding (item 1), which needs a new stealth
    version and would reduce detectability without removing it: SPAM found
    low-fill ±1 embedding at whole-image AUC 0.63–0.71 at 1 % fill (§3).
    *Also gone with the pad (1.0 behaviour read from the code, not measured on
    a device):* the beta's `SendSizeNormalizer` persisted, for every image sent
    through the extension — plain sends included — `SHA-256(pixels) → target
    size` plus a per-install random seed in the App Group `UserDefaults`, a
    record on the phone of which images were sent through Stiger. The new
    build deletes those keys at first launch (`SharedDefaults`, covered by a
    unit test); that removes them from the defaults store and does not promise
    the old bytes are gone from flash.
