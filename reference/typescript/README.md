# Reference Decoder (TypeScript)

Independent decoder for the Stiger wire format. Around 350 lines, no Stiger
code involved, written from [`../../stealth-v3.md`](../../stealth-v3.md),
[`../../open-v1.md`](../../open-v1.md) and [`../../lsb-layer.md`](../../lsb-layer.md)
only.

Pairs with the [Python reference](../python/) — both decode the same test
vectors. If they ever disagree, the spec is ambiguous.

## Why both Python and TypeScript

Two reference decoders in different runtimes catch different classes of
spec ambiguity. Python's `cryptography` and the browser's WebCrypto API
disagree on edge cases (HKDF empty salt, counter-mode endianness, GCM tag
placement). When both agree on every test vector, the spec is
runtime-agnostic — which is the strongest claim we can make about it
without formal verification.

Concretely:

- **Python** is for CLI verification, forensics, server-side pipelines.
- **TypeScript** is for browsers (drop-in WebCrypto, no extra deps), web
  extensions, Node tooling.

## Setup

```bash
npm install
```

Requires Node ≥ 22 (for `globalThis.crypto.subtle`).

## Decode an open-mode sticker

```ts
import { decode } from './stiger_decode';
import sharp from 'sharp';

const { data } = await sharp('sticker.png').ensureAlpha().raw()
  .toBuffer({ resolveWithObject: true });
const result = await decode(new Uint8Array(data));

if (result.ok) console.log(result.message);
```

## Decode a stealth-mode sticker

```ts
const result = await decode(rgba, 'your passphrase');
```

A wrong password is indistinguishable from "no payload" — that is by
design. See [`../../stealth-v3.md`](../../stealth-v3.md) §4.

## In the browser

The decoder runs unchanged on Canvas pixel data:

```ts
const bitmap = await createImageBitmap(blob);
const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
const ctx = canvas.getContext('2d')!;
ctx.drawImage(bitmap, 0, 0);
const { data } = ctx.getImageData(0, 0, bitmap.width, bitmap.height);
const result = await decode(data, password);
```

PBKDF2 with 600 000 iterations runs in ~1–2 s on the WebCrypto fast path.

## Verify against test vectors

```bash
npm run verify
```

Decodes every PNG listed in `../../test-vectors/manifest.json` and checks
each result against its expected plaintext. Exit status `0` means the
shipping Swift engine produced output that matches this TypeScript
reference exactly.
