// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Pavel Khudiakov
// Reference Decoder (TypeScript) — independent decoder for the Stiger wire
// format. Written from `../../stealth-v4.md`, `../../open-v2.md` and
// `../../lsb-layer.md` only. No Stiger code involved.
//
// Targets browsers and Node ≥ 22 (both expose globalThis.crypto.subtle).
// Mirrors the structure of the Python reference (`../python/stiger_decode.py`
// and `stiger_transport.py`) so readers can compare the two side-by-side.

const subtle = globalThis.crypto.subtle;
const utf8 = new TextEncoder();

// lsb-layer.md
const H_BITS = 10;
const MAX_STREAM_BYTES = 2100;
const PERM_INFO = utf8.encode('stiger-permutation-v4');
const SUBMATRIX_LABEL = utf8.encode('stiger-stc-v4');
const COLUMN_MASK = (1 << H_BITS) - 1; // 0x3FF
const COLUMN_REQUIRED = 1 | (1 << (H_BITS - 1)); // 0x201

// open-v2.md
const OPEN_MAGIC = new Uint8Array([0x53, 0x54, 0x45, 0x47]); // "STEG"
const OPEN_VERSION = 0x02;
const OPEN_HEADER_SIZE = 9;
const OPEN_MAX_PAYLOAD = 2048;
const OPEN_PERM_LABEL = utf8.encode('stiger-open-v2-perm');

// stealth-v4.md
const PERM_SALT = utf8.encode('stiger-perm-v4-salt');
const HKDF_INFO = utf8.encode('stiger-v4-header');
const STEALTH_HEADER_SIZE = 22;
const STEALTH_GCM_OVERHEAD = 12 + 16;
const STEALTH_LEN_PREFIX = 2;
const STEALTH_VERSION = 0x04;
const STEALTH_MAX_MESSAGE = 2048;
const PBKDF2_ITER = 600_000;

export type DecodeMode = 'open-v2' | 'stealth-v4';

export type DecodeSuccess = {
  ok: true;
  mode: DecodeMode;
  message: string;
  bytes: Uint8Array;
};

export type DecodeFailure = {
  ok: false;
  reason:
    | 'no-payload'
    | 'too-small'
    | 'oversized'
    | 'invalid-utf8'
    | 'crypto-error';
  detail?: string;
};

export type DecodeResult = DecodeSuccess | DecodeFailure;

// ---------- WebCrypto wrappers ----------

async function pbkdf2(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  lengthBytes: number,
): Promise<Uint8Array> {
  const baseKey = await subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    baseKey,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

async function hmacKey(key: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}

async function hmacSha256(key: Uint8Array | CryptoKey, msg: Uint8Array): Promise<Uint8Array> {
  const k = key instanceof Uint8Array ? await hmacKey(key) : key;
  return new Uint8Array(await subtle.sign('HMAC', k, msg));
}

/**
 * HKDF-SHA256 with empty salt (RFC 5869). Matches CryptoKit's
 * `HKDF<SHA256>.deriveKey(inputKeyMaterial:info:outputByteCount:)` when
 * no salt is supplied — see stealth-v4 §4.
 *
 * RFC 5869 says: "if salt is not provided, it is set to a string of
 * HashLen zeros." We pass that explicit zero-filled buffer instead of
 * a zero-length Uint8Array — output is identical, and some WebCrypto
 * implementations (notably older iOS Safari) reject empty BufferSource.
 */
async function hkdfSha256Empty(ikm: Uint8Array, info: Uint8Array, lengthBytes: number): Promise<Uint8Array> {
  const baseKey = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info },
    baseKey,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

async function aesGcmOpen(key: Uint8Array, nonce: Uint8Array, ciphertextWithTag: Uint8Array): Promise<Uint8Array> {
  const k = await subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, k, ciphertextWithTag);
  return new Uint8Array(pt);
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function be16(n: number): Uint8Array {
  return new Uint8Array([(n >>> 8) & 0xff, n & 0xff]);
}

function be32(n: number): Uint8Array {
  const out = new Uint8Array(4);
  out[0] = (n >>> 24) & 0xff;
  out[1] = (n >>> 16) & 0xff;
  out[2] = (n >>> 8) & 0xff;
  out[3] = n & 0xff;
  return out;
}

function readBe32(b: Uint8Array, o = 0): number {
  return ((b[o]! << 24) | (b[o + 1]! << 16) | (b[o + 2]! << 8) | b[o + 3]!) >>> 0;
}

function readBe16(b: Uint8Array, o = 0): number {
  return ((b[o]! << 8) | b[o + 1]!) >>> 0;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// ---------- LSB transport (lsb-layer.md) ----------

/** §3: eligible-pixel indices (alpha === 0xFF), in row-major order. */
function eligibleIndices(rgba: Uint8ClampedArray | Uint8Array): Uint32Array {
  const total = rgba.length / 4;
  const out: number[] = [];
  for (let i = 0; i < total; i++) {
    if (rgba[i * 4 + 3] === 0xff) out.push(i);
  }
  return new Uint32Array(out);
}

/** §4: S = min(2100, floor(N / 8)). */
function streamSize(n: number): number {
  return Math.min(MAX_STREAM_BYTES, Math.floor(n / 8));
}

/** §5: HMAC-SHA256 in counter mode. */
async function keystream(permKey: Uint8Array, lengthBytes: number): Promise<Uint8Array> {
  const out = new Uint8Array(lengthBytes);
  const key = await hmacKey(permKey);
  let off = 0;
  let counter = 0;
  while (off < lengthBytes) {
    const block = await hmacSha256(key, concat(be32(counter), PERM_INFO));
    const take = Math.min(block.length, lengthBytes - off);
    out.set(block.subarray(0, take), off);
    off += take;
    counter += 1;
  }
  return out;
}

/** §5: the walk. pi[t] is the cover index (into `eligibles`) of walk element t. */
async function permutation(permKey: Uint8Array, n: number): Promise<Uint32Array> {
  const indices = new Uint32Array(n);
  for (let i = 0; i < n; i++) indices[i] = i;
  if (n < 2) return indices;
  const ks = await keystream(permKey, n * 4);
  // Fisher–Yates: i = N-1 down to 1, j = uint32_be(ks[i*4..]) mod (i+1)
  for (let i = n - 1; i >= 1; i--) {
    const r = readBe32(ks, i * 4);
    const j = r % (i + 1);
    if (j !== i) {
      const tmp = indices[i]!;
      indices[i] = indices[j]!;
      indices[j] = tmp;
    }
  }
  return indices;
}

const submatrixCache = new Map<number, Uint16Array>();

/** §6.1: `width` distinct 10-bit columns with bits 0 and 9 set, generated from HMAC-SHA256. */
async function submatrix(width: number): Promise<Uint16Array> {
  const cached = submatrixCache.get(width);
  if (cached) return cached;
  if (width < 1 || width > 256) throw new Error('sub-matrix width out of range');
  const key = await hmacKey(SUBMATRIX_LABEL);
  const cols: number[] = [];
  const seen = new Set<number>();
  for (let counter = 0; cols.length < width; counter++) {
    const digest = await hmacSha256(key, concat(be16(width), be32(counter)));
    const v = readBe16(digest, 0) & COLUMN_MASK;
    if ((v & COLUMN_REQUIRED) !== COLUMN_REQUIRED || seen.has(v)) continue;
    seen.add(v);
    cols.push(v);
  }
  const out = Uint16Array.from(cols);
  submatrixCache.set(width, out);
  return out;
}

/**
 * §6: s = H · y (mod 2), packed MSB-first into S bytes. `y(t)` is the blue LSB
 * of walk element t.
 */
async function syndrome(y: (t: number) => number, n: number, m: number): Promise<Uint8Array> {
  const cols = await submatrix(Math.ceil(n / m));
  const s = new Uint8Array(m);
  let j = 0;
  let start = 0;
  let end = Math.floor(n / m);
  for (let t = 0; t < n; t++) {
    while (t >= end) {
      j += 1;
      start = end;
      end = Math.floor(((j + 1) * n) / m);
    }
    if (y(t) === 0) continue;
    let col = cols[t - start]!;
    for (let r = j; col !== 0 && r < m; r++, col >>= 1) {
      if (col & 1) s[r] ^= 1;
    }
  }
  const out = new Uint8Array(m / 8);
  for (let i = 0; i < m; i++) {
    if (s[i]) out[i >> 3] |= 1 << (7 - (i & 7));
  }
  return out;
}

/** §8 steps 2–3: the S-byte stream of the carrier under the walk keyed by `permKey`. */
async function extractStream(
  rgba: Uint8ClampedArray | Uint8Array,
  eligibles: Uint32Array,
  permKey: Uint8Array,
): Promise<Uint8Array> {
  const n = eligibles.length;
  const m = 8 * streamSize(n);
  if (m === 0) return new Uint8Array(0);
  const pi = await permutation(permKey, n);
  return syndrome((t) => rgba[eligibles[pi[t]!]! * 4 + 2]! & 1, n, m);
}

// ---------- Public API ----------

/**
 * Decode a Stiger PNG given its straight (non-premultiplied) RGBA pixels.
 * Tries open-v2 first (no key needed); tries stealth-v4 only if a non-empty
 * password is provided. Wrong password is indistinguishable from "no
 * payload" by design.
 */
export async function decode(
  rgba: Uint8ClampedArray | Uint8Array,
  password?: string,
): Promise<DecodeResult> {
  const eligibles = eligibleIndices(rgba);

  const openResult = await tryOpen(rgba, eligibles);
  if (openResult.ok) return openResult;

  if (password && password.length > 0) {
    return tryStealth(rgba, eligibles, password);
  }

  return {
    ok: false,
    reason: 'no-payload',
    detail: 'open-v2 magic not present, no password provided for stealth-v4',
  };
}

// ---------- open-v2 (open-v2.md) ----------

async function tryOpen(rgba: Uint8ClampedArray | Uint8Array, eligibles: Uint32Array): Promise<DecodeResult> {
  const sBytes = streamSize(eligibles.length);
  if (sBytes < OPEN_HEADER_SIZE + 1) return { ok: false, reason: 'too-small' };
  const permKey = new Uint8Array(await subtle.digest('SHA-256', OPEN_PERM_LABEL));
  const stream = await extractStream(rgba, eligibles, permKey);

  for (let i = 0; i < 4; i++) {
    if (stream[i] !== OPEN_MAGIC[i]) {
      return { ok: false, reason: 'no-payload', detail: 'open magic mismatch' };
    }
  }
  if (stream[4] !== OPEN_VERSION) {
    return { ok: false, reason: 'no-payload', detail: `open version ${stream[4]} unsupported` };
  }
  const payloadLength = readBe32(stream, 5);
  if (payloadLength === 0) {
    return { ok: false, reason: 'no-payload', detail: 'open payloadLength == 0' };
  }
  if (payloadLength > OPEN_MAX_PAYLOAD) {
    return { ok: false, reason: 'oversized', detail: 'open payloadLength > 2048' };
  }
  if (payloadLength > sBytes - OPEN_HEADER_SIZE) {
    return { ok: false, reason: 'oversized', detail: 'open payloadLength > S - 9' };
  }

  const payload = stream.slice(OPEN_HEADER_SIZE, OPEN_HEADER_SIZE + payloadLength);
  return { ok: true, mode: 'open-v2', message: utf8Lossy(payload), bytes: payload };
}

// ---------- stealth-v4 (stealth-v4.md) ----------

async function tryStealth(
  rgba: Uint8ClampedArray | Uint8Array,
  eligibles: Uint32Array,
  password: string,
): Promise<DecodeResult> {
  const sBytes = streamSize(eligibles.length);
  const plaintextSize = sBytes - STEALTH_HEADER_SIZE - STEALTH_GCM_OVERHEAD;
  if (plaintextSize < STEALTH_LEN_PREFIX) {
    return { ok: false, reason: 'too-small', detail: 'carrier too small for stealth-v4' };
  }

  const pwdBytes = utf8.encode(password);

  // §3: the walk is keyed by the password alone (no per-message salt).
  const permKey = await pbkdf2(pwdBytes, PERM_SALT, PBKDF2_ITER, 32);
  const stream = await extractStream(rgba, eligibles, permKey);

  const salt = stream.subarray(0, 16);
  const marker = stream.subarray(16, 20);
  const maskedVersion = stream[20]!;
  const maskedReserved = stream[21]!;

  // §4: per-message keys.
  const mainKey = await pbkdf2(pwdBytes, salt, PBKDF2_ITER, 32);
  const derived = await hkdfSha256Empty(mainKey, HKDF_INFO, 34);
  const macKey = derived.subarray(0, 32);
  const mask = derived.subarray(32, 34);

  // Constant-time marker verification.
  const macInput = concat(salt, new Uint8Array([maskedVersion, maskedReserved]));
  const expected = (await hmacSha256(macKey, macInput)).subarray(0, 4);
  if (!constantTimeEqual(expected, marker)) {
    return {
      ok: false,
      reason: 'no-payload',
      detail: 'marker mismatch (wrong password or not a stealth carrier)',
    };
  }

  const version = (maskedVersion ^ mask[0]!) & 0xff;
  if (version !== STEALTH_VERSION) {
    return { ok: false, reason: 'no-payload', detail: `stealth version ${version} unsupported` };
  }

  // §5: GCM open the rest of the stream.
  const gcmBlob = stream.subarray(STEALTH_HEADER_SIZE, sBytes);
  const nonce = gcmBlob.subarray(0, 12);
  const ctWithTag = gcmBlob.subarray(12);

  let plaintext: Uint8Array;
  try {
    plaintext = await aesGcmOpen(mainKey, nonce, ctWithTag);
  } catch {
    return { ok: false, reason: 'no-payload', detail: 'GCM authentication failed' };
  }

  if (plaintext.length < STEALTH_LEN_PREFIX) {
    return { ok: false, reason: 'no-payload', detail: 'plaintext shorter than length prefix' };
  }
  const length = readBe16(plaintext, 0);
  if (length === 0) return { ok: false, reason: 'no-payload', detail: 'plaintext length == 0' };
  if (length > plaintext.length - STEALTH_LEN_PREFIX) {
    return { ok: false, reason: 'oversized', detail: 'plaintext length exceeds plaintextSize - 2' };
  }
  if (length > STEALTH_MAX_MESSAGE) {
    return { ok: false, reason: 'oversized', detail: 'plaintext length > 2048' };
  }

  const messageBytes = plaintext.slice(STEALTH_LEN_PREFIX, STEALTH_LEN_PREFIX + length);
  return {
    ok: true,
    mode: 'stealth-v4',
    message: utf8Lossy(messageBytes),
    bytes: messageBytes,
  };
}

function utf8Lossy(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}
