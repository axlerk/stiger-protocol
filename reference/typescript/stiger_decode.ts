// Reference Decoder (TypeScript) — independent decoder for the Stiger wire
// format. Written from `../../stealth-v3.md`, `../../open-v1.md` and
// `../../lsb-layer.md` only. No Stiger code involved.
//
// Targets browsers and Node ≥ 22 (both expose globalThis.crypto.subtle).
// Mirrors the structure of the Python reference (`../python/stiger_decode.py`)
// so readers can compare the two side-by-side.

const subtle = globalThis.crypto.subtle;
const utf8 = new TextEncoder();

const PERM_SALT = utf8.encode('stiger-perm-v3-salt');
const PERM_INFO = utf8.encode('stiger-permutation-v3');
const HKDF_INFO = utf8.encode('stiger-v3-header');
const OPEN_MAGIC = new Uint8Array([0x53, 0x54, 0x45, 0x47]); // "STEG"

const OPEN_HEADER_SIZE = 9;
const OPEN_MAX_PAYLOAD = 2048;

const STEALTH_HEADER_SIZE = 22;
const STEALTH_GCM_OVERHEAD = 12 + 16;
const STEALTH_LEN_PREFIX = 2;
const STEALTH_VERSION = 0x03;
const STEALTH_MAX_MESSAGE = 2048;

export type DecodeMode = 'open-v1' | 'stealth-v3';

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
  const baseKey = await subtle.importKey(
    'raw',
    password,
    { name: 'PBKDF2' },
    false,
    ['deriveBits'],
  );
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    baseKey,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

async function hmacSha256(
  key: Uint8Array,
  msg: Uint8Array,
): Promise<Uint8Array> {
  const k = await subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await subtle.sign('HMAC', k, msg);
  return new Uint8Array(sig);
}

/**
 * HKDF-SHA256 with empty salt (RFC 5869). Matches CryptoKit's
 * `HKDF<SHA256>.deriveKey(inputKeyMaterial:info:outputByteCount:)` when
 * no salt is supplied — see stealth-v3 §4.
 *
 * RFC 5869 says: "if salt is not provided, it is set to a string of
 * HashLen zeros." We pass that explicit zero-filled buffer instead of
 * a zero-length Uint8Array — output is identical, and some WebCrypto
 * implementations (notably older iOS Safari) reject empty BufferSource.
 */
async function hkdfSha256Empty(
  ikm: Uint8Array,
  info: Uint8Array,
  lengthBytes: number,
): Promise<Uint8Array> {
  const baseKey = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info },
    baseKey,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

async function aesGcmOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertextWithTag: Uint8Array,
): Promise<Uint8Array> {
  const k = await subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 },
    k,
    ciphertextWithTag,
  );
  return new Uint8Array(pt);
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
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

/** Eligible-pixel indices (alpha === 0xFF), in row-major order. */
function eligibleIndices(rgba: Uint8ClampedArray | Uint8Array): Uint32Array {
  const total = rgba.length / 4;
  const out: number[] = [];
  for (let i = 0; i < total; i++) {
    if (rgba[i * 4 + 3] === 0xff) out.push(i);
  }
  return new Uint32Array(out);
}

/** Read `byteCount` MSB-first bytes through the slot map. */
function readBytes(
  rgba: Uint8ClampedArray | Uint8Array,
  eligibles: Uint32Array,
  slotMap: Uint32Array,
  startSlot: number,
  byteCount: number,
): Uint8Array {
  const out = new Uint8Array(byteCount);
  for (let i = 0; i < byteCount; i++) {
    let b = 0;
    for (let k = 0; k < 8; k++) {
      const logical = startSlot + i * 8 + k;
      const pixelIdx = eligibles[slotMap[logical]!]!;
      const bit = rgba[pixelIdx * 4 + 2]! & 1;
      b |= bit << (7 - k);
    }
    out[i] = b;
  }
  return out;
}

function rowMajorSlotMap(n: number): Uint32Array {
  const out = new Uint32Array(n);
  for (let i = 0; i < n; i++) out[i] = i;
  return out;
}

// ---------- Permutation π (stealth-v3 §3) ----------

async function keystream(permKey: Uint8Array, lengthBytes: number): Promise<Uint8Array> {
  const out = new Uint8Array(lengthBytes);
  let off = 0;
  let counter = 0;
  while (off < lengthBytes) {
    const block = await hmacSha256(permKey, concat(be32(counter), PERM_INFO));
    const take = Math.min(block.length, lengthBytes - off);
    out.set(block.subarray(0, take), off);
    off += take;
    counter += 1;
  }
  return out;
}

async function permutation(password: Uint8Array, N: number): Promise<Uint32Array> {
  const permKey = await pbkdf2(password, PERM_SALT, 600_000, 32);
  const ks = await keystream(permKey, N * 4);
  const indices = new Uint32Array(N);
  for (let i = 0; i < N; i++) indices[i] = i;
  // Fisher–Yates: i = N-1 down to 1, j = uint32_be(ks[i*4..]) mod (i+1)
  for (let i = N - 1; i >= 1; i--) {
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

// ---------- Public API ----------

/**
 * Decode a Stiger PNG given its straight (non-premultiplied) RGBA pixels.
 * Tries open-v1 first; tries stealth-v3 only if a non-empty password is
 * provided. Wrong password is indistinguishable from "no payload" by design.
 */
export async function decode(
  rgba: Uint8ClampedArray | Uint8Array,
  password?: string,
): Promise<DecodeResult> {
  const eligibles = eligibleIndices(rgba);
  const N = eligibles.length;
  const availableBytes = Math.floor(N / 8);

  const openResult = tryOpen(rgba, eligibles, availableBytes);
  if (openResult.ok) return openResult;

  if (password && password.length > 0) {
    return tryStealth(rgba, eligibles, password);
  }

  return {
    ok: false,
    reason: 'no-payload',
    detail: 'open-v1 magic not present, no password provided for stealth-v3',
  };
}

// ---------- open-v1 (open-v1.md) ----------

function tryOpen(
  rgba: Uint8ClampedArray | Uint8Array,
  eligibles: Uint32Array,
  availableBytes: number,
): DecodeResult {
  if (availableBytes < OPEN_HEADER_SIZE) return { ok: false, reason: 'too-small' };
  const slotMap = rowMajorSlotMap(eligibles.length);
  const header = readBytes(rgba, eligibles, slotMap, 0, OPEN_HEADER_SIZE);

  for (let i = 0; i < 4; i++) {
    if (header[i] !== OPEN_MAGIC[i]) {
      return { ok: false, reason: 'no-payload', detail: 'open magic mismatch' };
    }
  }
  if (header[4] !== 0x01) {
    return { ok: false, reason: 'no-payload', detail: `open version ${header[4]} unsupported` };
  }
  const payloadLength = readBe32(header, 5);
  if (payloadLength === 0) {
    return { ok: false, reason: 'no-payload', detail: 'open payloadLength == 0' };
  }
  if (payloadLength > OPEN_MAX_PAYLOAD) {
    return { ok: false, reason: 'oversized', detail: 'open payloadLength > 2048' };
  }
  const cap = availableBytes - OPEN_HEADER_SIZE;
  if (payloadLength > cap) {
    return { ok: false, reason: 'oversized', detail: 'open payloadLength > capacity' };
  }

  const payload = readBytes(rgba, eligibles, slotMap, OPEN_HEADER_SIZE * 8, payloadLength);
  return { ok: true, mode: 'open-v1', message: utf8Lossy(payload), bytes: payload };
}

// ---------- stealth-v3 (stealth-v3.md) ----------

async function tryStealth(
  rgba: Uint8ClampedArray | Uint8Array,
  eligibles: Uint32Array,
  password: string,
): Promise<DecodeResult> {
  const N = eligibles.length;
  const availableBytes = Math.floor(N / 8);
  const plaintextSize = availableBytes - STEALTH_HEADER_SIZE - STEALTH_GCM_OVERHEAD;
  if (plaintextSize < STEALTH_LEN_PREFIX) {
    return { ok: false, reason: 'too-small', detail: 'carrier too small for stealth-v3' };
  }

  const pwdBytes = utf8.encode(password);

  // Permutation π over [0, N), keyed by password alone (no per-message salt).
  const pi = await permutation(pwdBytes, N);

  // Read the 22-byte header through π.
  const header = readBytes(rgba, eligibles, pi, 0, STEALTH_HEADER_SIZE);
  const salt = header.subarray(0, 16);
  const marker = header.subarray(16, 20);
  const maskedVersion = header[20]!;
  const maskedReserved = header[21]!;

  // Per-message keys.
  const mainKey = await pbkdf2(pwdBytes, salt, 600_000, 32);
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

  // GCM open the rest of the LSB stream.
  const gcmBlobLen = availableBytes - STEALTH_HEADER_SIZE;
  const gcmBlob = readBytes(rgba, eligibles, pi, STEALTH_HEADER_SIZE * 8, gcmBlobLen);
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

  const messageBytes = plaintext.subarray(STEALTH_LEN_PREFIX, STEALTH_LEN_PREFIX + length);
  return {
    ok: true,
    mode: 'stealth-v3',
    message: utf8Lossy(messageBytes),
    bytes: messageBytes,
  };
}

function utf8Lossy(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}
