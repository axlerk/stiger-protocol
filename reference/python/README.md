# Reference Decoder (Python)

Independent decoder for the Stiger wire format. Roughly 250 lines, no
Stiger code involved, written from [`../../stealth-v3.md`](../../stealth-v3.md)
and [`../../open-v1.md`](../../open-v1.md) only.

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
design. See [`../../stealth-v3.md`](../../stealth-v3.md) §4.

## Verify against test vectors

```bash
python verify_test_vectors.py ../../test-vectors
```

Decodes every PNG listed in `test-vectors/manifest.json` and checks each
result against its expected plaintext. Exit status `0` means the shipping
Swift engine produced output that matches this spec exactly.
