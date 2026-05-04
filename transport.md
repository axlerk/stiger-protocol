# Carrier Transport (informative)

This note is **informative**, not normative — it does not constrain the
on-the-wire bytes that the reference decoder reads. Its purpose is to
document the assumption Stiger makes about how a Stiger-produced PNG
reaches a recipient, so auditors and re-implementers do not have to
reverse-engineer it.

## What the wire format requires

The LSB layer (`lsb-layer.md`) and both mode framings (`open-v1.md`,
`stealth-v3.md`) require the recipient to read the carrier PNG **byte-for-
byte identical** to what the sender produced. Any path that re-encodes,
resizes, or re-quantises the image breaks the payload.

This is unconditional — there is no mode where the wire format tolerates
lossy transit.

## What the shipping iOS app does

Stiger's iMessage extension hands the carrier PNG to iMessage as an
ordinary image attachment via:

```swift
MSConversation.insertAttachment(_:withAlternateFilename:)
```

This is the path the project has verified end-to-end for byte-stable
transit on a current iOS. PNGs sent this way reach the recipient closely
enough for LSB payloads to survive — which is what allows the product to
work at all.

This is **observed platform behaviour, not a contract**. Apple does not
publish a guarantee that image attachments are byte-stable. If a future
iOS version changes this and recompresses image attachments, Stiger
breaks gracefully (`noPayloadFound` on decode), but the product stops
delivering payloads end-to-end.

## What the shipping iOS app deliberately does *not* do

Stiger does **not** route carriers through `MSSticker` or
`MSStickerBrowserViewController`. We empirically verified (May 2026,
iOS 26) that the sticker pipeline re-encodes outgoing PNGs to HEIC and
downsamples them in transit: a 512×512 / 207 KB PNG sent via
`MSConversation.insert(MSSticker)` arrives at the recipient as a
320×320 / 12 KB HEIC, accessible only through iOS 18's
`NSAdaptiveImageGlyph.imageContent` attribute embedded inside an rtfd
container. Both the format change and the resampling destroy LSB
payloads.

Independently, Apple does not register `public.png` or `public.image`
UTIs for a delivered sticker on either `UIPasteboard` (after `Copy`) or
`UIDropInteraction` (after drag). Only text-shaped bubble
representations are exposed
(`com.apple.uikit.attributedstring`, `com.apple.flat-rtfd`,
`public.utf8-plain-text`). A re-implementer of Stiger's reveal flow
therefore has no addressable channel for the original carrier bytes —
even if the sticker pipeline were byte-stable, the receive-side path
would not surface what was sent.

The colloquial word "sticker" used throughout the spec, the README, and
the UI refers to the carrier's *visual* role — a small expressive PNG —
not to the `MSSticker` API. A re-implementer free of MessagesUI (e.g. a
test harness, a CLI exporter) can hand the same PNG bytes to any
transport that preserves them; the wire format is transport-agnostic.

## Implications for re-implementers

- If you write your own sender, route through whatever transport you can
  verify is byte-stable for the PNG bytes you produce. The spec does not
  prescribe one.
- If you write your own receiver, accept any source of PNG bytes the
  user can give you (file picker, share extension, save-to-Files +
  open). Do not assume the bytes arrive via iMessage.
- If you audit the shipping app, the relevant API call is in
  `iMessageExtension/MessagesViewController.swift`.

## Related sections

- `THREAT_MODEL.md` §1 — transport boundary in the threat model.
- `THREAT_MODEL.md` §3 — what fails if iMessage starts recompressing.
- `THREAT_MODEL.md` §7 — known limitations.
