# Reference Decoder and Encoder (Python)

Independent decoder for the Stiger wire format, no Stiger code involved,
written from [`../../lsb-layer.md`](../../lsb-layer.md),
[`../../stealth-v4.md`](../../stealth-v4.md) and
[`../../open-v2.md`](../../open-v2.md) only:

- `stiger_transport.py` — the transport layer: eligible pixels, the permuted
  walk, the sub-matrix generator and the syndrome `H · y`. Standard library.
- `stiger_decode.py` — the two modes' framing and cryptography.
- `stiger_encode.py` — a reference **encoder** (Viterbi over the trellis with
  HILL costs, ±1 matching), so the spec can be exercised end to end without
  the Swift engine. The decode path is what the spec makes normative; the
  encoder follows `lsb-layer.md` §7, which is informative.

## Setup

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Decode an open-mode sticker

```bash
python stiger_decode.py path/to/sticker.png
```

## Decode a stealth-mode sticker

```bash
python stiger_decode.py path/to/sticker.png --password 'your passphrase'
```

A wrong password is indistinguishable from "no payload" — that is by
design. See [`../../stealth-v4.md`](../../stealth-v4.md) §4.

## Encode a sticker

```bash
python stiger_encode.py in.png out.png --message 'hello'                   # open-v2
python stiger_encode.py in.png out.png --message 'hello' --password 'pw'   # stealth-v4
python stiger_encode.py in.png out.png                                     # a plain send: random stream
```

A 512×512 sticker takes a few seconds (the Viterbi search is plain numpy).
The encoder checks its own output: the decoder's syndrome of the written
carrier must equal the stream.

## Verify against test vectors

```bash
python verify_test_vectors.py ../../test-vectors
```

Decodes every PNG listed in `test-vectors/manifest.json` and checks each
result against its expected plaintext. Exit status `0` means the shipping
Swift engine produced output that matches this spec exactly.
