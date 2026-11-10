# Stiger — Threat Model

This document states what Stiger defends against, what it does **not**
defend against, and the assumptions behind those guarantees. Read it before
trusting the app with anything that matters.

If you find a gap between this document and the implementation, the
implementation is wrong — please open an issue.

For the byte-for-byte wire format and an independent reference decoder you
can run yourself, see [`spec/`](spec/README.md).

The body describes the engine as it is in this repository (formats
`open-v2` and `stealth-v4`, build 56 onward): every send, with a secret or
without, carries a stream of the same size — at most 2 100 bytes — as the
syndrome of a syndrome-trellis code, with the changes placed by
content-adaptive costs and made by ±1 on the blue channel. Earlier builds
differed in ways that matter to anyone holding files from them; §8
"History" tells that story once, with dates and build numbers. The
measurements behind the numbers here are in
`docs/experiment-steganalysis.md` (cited as "v1 §n"; the engines before
build 56) and `docs/experiment-steganalysis-v2.md` ("v2 §n"; this engine).
Where a number was measured on an earlier engine and not repeated on this
one, the text says so.

## TL;DR

**English.**

- **Protects:** the content of a short message (AES-256-GCM, key derived from
  the password by PBKDF2-SHA256, 600 000 iterations) and its length (every
  send carries a stream of the same size, whatever the message), hidden in
  the least-significant bits of an ordinary PNG sticker and sent through
  iMessage.
- **Does not protect against:** anyone who has the original sticker, who
  sees that the file was modified; a trained statistical classifier, which
  finds a send on a drawn emoji almost every time and a send on a library
  sticker somewhat better than a coin flip, without reading the message
  (the textbook tests do not flag it, §3); a compromised device, a
  Keychain extracted by forensic tooling, screenshots or iMessage
  recompression, which defeat the protection or destroy the hidden message.
- **Open mode** (no password) is readable by anyone with Stiger. It is not a
  privacy feature.
- **No forward secrecy:** a leaked password decrypts every earlier message
  sent under it.

**По-русски.**

- **Защищает:** содержимое короткого сообщения (AES-256-GCM, ключ выводится
  из пароля через PBKDF2-SHA256, 600 000 итераций) и его длину (каждая
  отправка несёт поток одного и того же размера, каким бы ни было
  сообщение), спрятанного в младших битах обычного стикера в формате PNG и
  отправленного через iMessage.
- **Не защищает:** тот, у кого есть исходный стикер, видит, что файл
  изменён; обученный статистический классификатор находит отправку на
  нарисованном эмодзи почти всегда, а на стикере из каталога — немного
  лучше, чем подбрасыванием монеты, и сообщения при этом не читает (учебные
  тесты отправку не отмечают, §3); взломанное устройство, связка ключей
  Keychain, снятая
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

- **Open mode** (`open-v2`) — no password set. The carrier is a *public*
  sticker. The payload is framed by a fixed 9-byte header (`STEG` magic +
  version + length) at the start of the stream, and the stream is read
  under a permutation key that is public (`spec/open-v2.md` §1). Anyone
  with Stiger — or anyone with the spec and its reference decoder — can
  read it. **Open mode is not a privacy feature.** It exists so the app is
  useful before the user pays.

- **Stealth mode** (`stealth-v4`) — password set (Pro). The stream is
  designed to look like uniform random bytes to anyone who does not know
  the password: all of it is a random salt, a keyed marker and AES-256-GCM
  ciphertext, and it can only be read out of the image under a
  password-derived pixel permutation, so there is no plaintext marker, no
  length field, and no fixed position. *We do not claim the resulting PNG
  is indistinguishable from an unmodified original:* the engine changes
  few pixels and prefers textured ones, which lowers detection without the
  original and does nothing against a comparison with it (§3 "Carrier
  indistinguishability", §7.1).

**The stream** is what a carrier holds: `S = min(2100, N / 8)` bytes for
`N` opaque pixels, the same for every mode and every message
(`spec/lsb-layer.md` §4). It is not written into the pixels bit by bit; the
receiver computes it as the syndrome of a syndrome-trellis code over the
blue least-significant bits in permuted order, and the sender picks, among
the ways to produce that syndrome, one that changes few pixels (§3
"Trained stegoanalysis classifiers" has what that buys).

A send with no secret at all ("plain") embeds a random stream of the same
size in the same way, so that nothing about the file says which kind it is
(§3 "File-size oracle on the wire").

The two modes share the same engine but have **fundamentally different
threat models**. The rest of this document covers stealth mode unless
otherwise stated.

## 2. Adversaries we defend against

### A. Passive LSB observer
Someone who intercepts the PNG (from an iMessage backup, a forwarded file,
a compromised relay) and runs standard LSB analysis.

**Defense:** the whole stream is either AES-GCM ciphertext or header bytes
HMAC-derived from the password. Both are computationally indistinguishable
from uniform random bytes without the password, and without the password's
permutation key the observer cannot even compute the stream. The engine
changes a few percent of the opaque pixels, by ±1, which the textbook
tests for LSB replacement (pairs-of-values chi-square, RS) do not flag. In
simulation on all 133 library stickers at this stream size, chi-square at
p ≥ 0.001 and RS at d ≥ 0.25 flag 0–1 of 133 (v2 §5); through the real
engine on 24 of them, chi-square flags 0 of 24 and RS 1 of 24 (v2 §8″,
2026-11-09) — the false-positive floor of an untouched channel. Stock
`zsteg` and `StegExpose` at its default threshold reported no LSB finding
on the earlier engines, which changed about half of the pixels (§2.C);
they were not run again on this one.

**Limit:** sticker carriers (flat colour areas, sharp edges) are weak
cover, and a *trained* classifier still separates a Stiger send from an
unmodified sticker without the original on some carriers — almost always
on the drawn emoji. §3 "Trained stegoanalysis classifiers" has the numbers
and what still holds. Builds through 53 wrote a full plane by replacement,
which the textbook tests caught on every send (§8 "History").

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

**Defense:** stealth mode has no magic bytes. (Open mode does: its stream
starts with a fixed `STEG` header, readable under the public permutation
key, and this defense does not apply to it — §1 and §2.D.) The first 16
bytes of the stream are a random salt; the next 4 bytes are an
HMAC-derived marker that varies per message; bytes 20–21 are XOR-masked
version and reserved bytes, authenticated by the same HMAC. Two encodings
of the same message into the same image produce different streams and
change different pixels (each changed pixel moves by 1 in the blue
channel; nothing else differs).

**Measured on the earlier engines, not repeated on this one.** On stealth
carriers `zsteg` (default and `-a`) and default-threshold `StegExpose`
found no LSB payload. The files the engine sends carry no `tEXt` chunk for
such a scanner to print, then and now (v1 §1, §2, §10; chunk layout
re-measured in v2 §1). The beta builds did carry
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
- *Sender / recipient unlinking* — the stream of a stealth carrier has
  no app-specific fingerprint, and it cannot be computed without the
  password, so an analyst cannot identify Stiger from a single stealth
  carrier's bits (§2.E for what changes with many carriers, and with the
  original). The beta builds' pad chunk was **not** covered by this (§8).
- *Mode opacity* — plain, open and stealth sends carry a stream of the same
  size, embedded the same way, and come out at about the same byte size
  (§3 "File-size oracle on the wire"), so the chat-level pattern does not
  betray which mode is in use. In the beta this did **not** hold at file
  level (§8).

**Open carriers break the first two.** An open-mode carrier stores its
payload in plaintext behind the fixed `STEG` header (`spec/open-v2.md` §2),
and the key of its permutation is public, so any tool that implements the
published format reads the message and learns that Stiger was used. (A
generic LSB reader such as stock `zsteg` reads bits in pixel order and
does not compute a syndrome, so it should not find it — inferred from the
format, not measured, and a tooling accident, not a defence.) One open
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

**Defense (partial):** length-hiding. Every send, plain and open included,
is padded to the same stream of 2 100 bytes — the 2 KB message limit plus
overhead — or to the carrier's whole capacity when that is smaller. So
every send of a given image carries the same amount and changes about the
same number of pixels: the count does not leak the message length, which
the app caps at 2 KB, nor the mode.

**Limit:** the changes are still there. A send changes a few percent of
the opaque pixels (3.5 % on average over our 133 stickers in simulation at
this stream size, v2 §5; a real syndrome-trellis code makes 11–18 % more
changes than the simulation, v2 §7) and up to half of them on the smallest
carriers,
against none for an unmodified PNG of the same source. Detection of "this
file was modified" is certain by diff against the original, and feasible
without it for a trained classifier on some carriers (§3 "Trained
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
Stealth mode hides *content* and *length*, not *the fact that the image
was modified*. An adversary who has the unmodified source PNG and the
suspected carrier can compute the diff and conclude "this PNG was
processed by some embedding tool": the changed pixels are there, each off
by one in the blue channel. They cannot recover the message or tell a
secret send from a plain one. The originals are easy to come by for our
own carriers: the library stickers ship in the app, and the drawn emoji
are rendered from the system font, so anyone with the app can rebuild them
(assumed reproducible across devices on the same iOS; not tested across
iOS versions, v2 "Not done").

Adaptive embedding does **not** defend against this. It decides *where*
the changes go (into texture) and how few there are, which is what lowers
detection *without* the original (next section); a diff sees them
wherever they are. Nothing short of leaving the image untouched defeats a
comparison with the original, and that is not in scope.

### Trained stegoanalysis classifiers
We do not defend against modern statistical or ML-based stegoanalysis
(SPAM, SRM, SRNet, ZhuNet, Yedroudj-Net, and successors). These tools do
not need the original source image — the detection rests on statistical
features of the suspect carrier alone. What the engine does is make that
harder on carriers with texture: it embeds a short fixed-size stream
instead of filling the carrier, uses a syndrome-trellis code so that few
pixels change, and places the changes by a content-adaptive cost (HILL).
Commercial forensic suites and well-funded examiners have stronger
detectors than the ones we ran.

**Measured, with two small detectors** (a research-grade one was not run).
With a fixed 2 KB stream embedded by syndrome coding with content-adaptive
(HILL) costs, a SPAM model trained on library stickers separates a send
from an untouched carrier at whole-image AUC 0.54–0.61 on the 103 library
stickers (three seeds; simulated embedding with a real syndrome-trellis
code, v2 §7; a reduced spatial rich model reads 0.55–0.56) and close to
that on a bounded run of the real engine itself (textured library stickers
at chance, 0.53; the eight flattest and most saturated ones at 0.67–0.70;
24 stickers, one seed, v2 §8″). **On the drawn emoji — small, flat, and
the only carriers that do not look like Stiger's own art — it is
0.99–1.00: essentially certain.** We ship them as stealth carriers anyway:
a library sticker is recognisable on sight as ours, so restricting stealth
to the library would remove exactly the carriers that do not announce the
app, for a detector that already needs to suspect Stiger and have trained
on Stiger-like images. A stealth send on a drawn emoji should be treated
as detectable by that adversary; a stealth send on a library sticker, for
the same adversary, as roughly a coin flip to somewhat worse on the
flattest art. Plain against stealth, both sent through the engine, is
alike by construction (every send embeds a stream of the same size the
same way) and was at chance for these detectors on the previous engine
(v1 §12): the detector sees "a Stiger send", not "a secret".

What these figures are not. They are for small detectors trained on a few
thousand patches of 133 flat illustrations; a detector trained on far more
Stiger-like images, or one with the original image, does better, and
content-adaptive schemes are what modern detectors are built against. The
corpus is our own stickers: imported packs, user stickers and photos were
not measured. Aletheia's pretrained ±1 models scored the flat stickers at
chance on the earlier engines (AUC 0.500–0.512) — a cross-source mismatch
(photo-trained models on flat art), not a property of the design, so it is
no cover. "Not detected" by these detectors is not "safe" (v1 §11, §12; v2
"Scope", "Recommendation"). Before build 56 the engine filled the whole
carrier, and the same SPAM model read every send at 0.995 (§8 "History").

What still holds when "this carrier was modified" is detected:
- *Content confidentiality* — AES-256-GCM ciphertext is not recoverable
  without the password.
- *Stiger-specific identification from the bits* — a stealth stream has no
  magic bytes and no fixed headers, and cannot be computed without the
  password. (The carrier's look, the app on the phone and an open carrier
  in the same chat can identify Stiger; §2.D.)
- *Payload length* — hidden within the 2 KB message limit by the
  fixed-size stream.
- *Which sends carry a secret* — plain, open and stealth sends are embedded
  alike and look alike on the wire (§3 "File-size oracle on the wire").

What is lost: the deniability claim "this PNG carries nothing", wherever
the detector works — on the drawn emoji, on flat art, against anyone with
the original — and it is lost for every Stiger send, not only the secret
ones. Anyone whose safety depends on it should assume this detection is
feasible and plan their use accordingly.

### File-size oracle on the wire
**Defense: uniform cover.** Every PNG sent through the iMessage extension —
stealth, open and plain (no-secret) — carries a stream of the same size,
embedded by the same code with the same costs. A plain send embeds random
bytes under a fresh random key (`ImageStegoEngine.coverImage`); an open
send embeds its 9-byte header and payload, then random fill, under the
public key; a stealth send embeds salt, marker and AES-GCM block under the
password's key (`spec/lsb-layer.md` §7). Only the blue channel of opaque
pixels changes, by at most 1, and about as many pixels change in each
mode. The three therefore compress alike and come out at about the same
byte size **without any padding**.

Measured. On the previous engine (a full random plane), 133 library
stickers through the real engine: stealth against plain bytes median
1.0000, p10–p90 0.9992–1.0008, and the chunk layout identical across the
three modes (v2 §1). On this engine the same comparison on the library has
not been repeated; on synthetic carriers (2026-11-10, 40 sends per mode,
recorded in commit `eb32933`) the per-mode median sizes agree within
0.25 % on a 256 × 256 gradient, where a single send varies by about 1.2 %
around the median, and everything lies within 0.4 % at 512 × 512. A send
is now about 1 % larger than the untouched raster (simulated, v2 §5)
rather than 7.6 % (measured on the full plane, v2 §1). So:

- A network observer or anyone holding the chat history cannot tell, by
  byte count alone, whether a sticker carries a secret: the spread between
  modes is inside the spread between two sends of one mode.
- No pad chunk exists, so there is no pad length or pad share to leak the
  mode and no `Comment` chunk for stock tooling to flag.
- The send-size cache of the beta builds is gone; `SharedDefaults` deletes
  what they left in the App Group defaults at the next launch.

The beta builds padded instead, and the pad gave the mode away; §8
"History".

**Out of scope for this defense:** a trained classifier that flags Stiger
sends flags plain ones too (§3 "Trained stegoanalysis classifiers");
detection by diff against a known original (§3 "Carrier
indistinguishability").

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

|                                          | Open mode | Stealth v4 |
|------------------------------------------|-----------|------------|
| Confidentiality of message content       | ❌ none   | ✅ AES-256-GCM |
| Authenticity of message content          | ❌ none   | ✅ GCM tag |
| Hides message length                     | ❌ the header states it | ✅ fixed-size stream, within the 2 KB limit |
| Hides Stiger-specific markers (magic / headers)  | ❌ `STEG` magic, readable under the public key | ✅ no magic, no fixed bytes |
| Hides "this PNG was modified", without the original | ❌        | ❌ a trained classifier finds a drawn emoji almost always and a library sticker at about a coin flip (small detectors, measured); the textbook chi-square/RS do not — see §3 / §7.1 |
| Hides PNG file size on the wire          | ✅ same stream in every mode (uniform cover) | ✅ same stream in every mode (uniform cover) |
| Hides stealth vs plain from size, chunk lengths and pixel statistics | — | ✅ (the beta builds leaked it, §8) — see §3 / §7.7 / §7.10 |
| Hides "was this PNG modified?" from someone with the original | ❌        | ❌ (out of scope) |
| Survives iMessage lossy recompression    | ❌        | ❌ |
| Survives screenshot                      | ❌        | ❌ |
| Survives device compromise               | ❌        | ❌ |

### When the stealth-mode guarantees apply

The "Stealth v4" column applies only when an outgoing send actually takes
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

The wire format is specified in [`spec/`](spec/README.md), with reference
decoders in Python and TypeScript and test vectors. The implementation is
about 1 600 lines of Swift split across:

- `StigerCore/StegoMarker.swift` — header framing and HKDF/HMAC derivations
- `StigerCore/ImageStegoEngine.swift` — pixel read/write, permutation,
  stream assembly
- `StigerCore/STC.swift` — the syndrome-trellis code (syndrome for the
  decoder, Viterbi search for the encoder)
- `StigerCore/HILLCost.swift` — the content-adaptive cost of changing a
  pixel (encoder only; a decoder never needs it)
- `StigerCore/AESHelper.swift` — AES-GCM and PBKDF2 wrappers
- `StigerCore/StegoSendPipeline.swift` — single send entry point (encode, or
  the random-stream cover for a plain send)

A decoder in any language can be written against `spec/` without reading
the Swift source. If you write one and your decoder disagrees with Stiger
on a test vector, the spec is wrong — please report it.

Tests in `StigerTests/` cover header roundtrips, wrong-password rejection,
length-hiding (the number of changed pixels does not follow the message
length), damaged carriers, the absence of plaintext fingerprints in
stealth headers, the code against the Python reference bit for bit, and
end-to-end encode/decode through the engine and the committed vectors.

## 7. Known weaknesses (acknowledged, not fixed)

1. **The modification is detectable to statistical stegoanalysis on some
   carriers, and to anyone with the original on all of them.** The engine
   already embeds at a low rate with a syndrome-trellis code and
   content-adaptive costs; what is left is measured in §3 "Trained
   stegoanalysis classifiers": the drawn emoji are found almost always,
   the flattest library stickers more often than not, the rest at about a
   coin flip, by small detectors. Not done: a research-grade detector
   trained on Stiger-like images (SRNet class), carriers outside our own
   library, other cost functions (S-UNIWARD, MiPOD), a searched code
   matrix. Gating the drawn emoji out of stealth mode was weighed and not
   taken (§3). The textbook chi-square/RS do not flag a send.

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
   OWASP-recommended and ships in CommonCrypto, which offers no other
   password KDF (CryptoKit has none either; checked against the iOS 27.2
   SDK, 2026-11-10). Argon2id would be more memory-hard against GPU farms.
   An earlier version of this item ruled it out by memory: it said the
   iMessage extension runs under a ~120 MB cap. That figure was an
   assumption and does not hold where it was measured: a Messages
   extension has 700 MB on an iPhone 12 mini and 800 MB on an iPhone 15
   Pro (measured for Stecho, 2026-11-05; not measured for Stiger's own
   extension or on older phones). Memory is therefore not what decides
   this. What does: a third-party crypto dependency in the app, in both
   reference decoders and in the site's in-browser decoder; another
   wire-format version; and the time of a reveal, which runs the KDF up to
   twice per password tried (the permutation key of a saved password is
   cached) and may try eight. How much Argon2id would slow an
   attacker at parameters a phone can afford has not been measured. On
   those costs the trade is not currently favourable. Preferred path is to
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
   every send changes its own random choice of pixels, but the rest still match
   across users, and the residual risk is very narrow and not addressed.
   Importing from the public pack does **not** make
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
    gives plain and open sends a random stream of the same size as a
    stealth send's, embedded the same way, so an observer cannot tell
    *which* sends carry a secret (§3 "File-size oracle on the wire"; §3
    "Trained stegoanalysis classifiers"). The price: "this PNG carries nothing" is
    lost for every Stiger send, not only the secret ones; a plain send of a
    sticker too large for the engine now fails like a secret one does (the
    beta's plain path had no size cap), which the ingress policy should
    make unreachable; open sends still carry `STEG`; and during a rollout
    the old clients' sends form a visible version cohort in the files —
    padded ones (beta), then full planes written by replacement (builds
    49–53) and by ±1 matching (builds 54–55), §8 "History".

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

**Fixed-size stream over a syndrome-trellis code: `open-v2` and
`stealth-v4` (2026-11-08, build 56 onward).** Until then every send filled
the whole capacity of the carrier, one bit per opaque pixel, so about half
of the opaque pixels changed and a SPAM model trained on library stickers
told a send from an untouched carrier at whole-image AUC 0.995 (a reduced
rich model at 0.997–1.000; v1 §12). Since the app never accepted more than
2 KB of message, the stream is now 2 100 bytes on every send (or the whole
capacity of a smaller carrier), carried as the syndrome of a
syndrome-trellis code over the permuted blue LSBs, with the changes placed
by HILL costs. Length hiding and the likeness of plain, open and stealth
sends are kept; no carrier lost capacity. On the library stickers the same
detector reads 0.54–0.61; on the drawn emoji nothing changed (0.99–1.00),
because a 2 KB stream is most or all of what they hold (§3 "Trained
stegoanalysis classifiers"; v2 §5, §7, §8″). An encode takes 0.55 s and a
decode 0.14 s on an iPhone 12 mini (Release build, one sticker of 166 911
opaque pixels, 2026-11-09, v2 §8⁗).

This is a wire-format change with no compatibility period: `open-v1` and
`stealth-v3` never reached a release, and builds from 56 on do not read
them. A sticker made by a TestFlight build through 55 does not open in a
later build, and the reverse; it reads as a sticker with nothing in it.
The full planes of builds 49–55 remain a visible cohort in old chats.
