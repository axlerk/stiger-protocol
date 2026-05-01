// Decode every vector listed in `<vectors-dir>/manifest.json` and compare the
// decoded plaintext to `plaintext_utf8`. Mirrors the Python verify script
// next door (`../python/verify_test_vectors.py`). Exit `0` means this TS
// reference is in sync with the shipping Swift engine via the test vectors.
//
// Usage:  npx tsx verify_test_vectors.ts <vectors-dir>

import { readFileSync } from 'node:fs';
import { resolve, basename } from 'node:path';
import sharp from 'sharp';

import { decode } from './stiger_decode.ts';

type Vector = {
  name: string;
  mode: 'open' | 'stealth';
  png: string;
  password?: string;
  plaintext_utf8: string;
};

type Manifest = { vectors: Vector[] };

async function main() {
  const dir = resolve(process.argv[2] ?? '../../test-vectors');
  const manifest: Manifest = JSON.parse(
    readFileSync(resolve(dir, 'manifest.json'), 'utf8'),
  );

  let pass = 0;
  let fail = 0;

  for (const v of manifest.vectors) {
    const pngPath = resolve(dir, v.png);
    const { data, info } = await sharp(pngPath)
      .ensureAlpha()
      .raw()
      .toBuffer({ resolveWithObject: true });
    const rgba = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);

    const result = await decode(rgba, v.password);
    const ok = result.ok && result.message === v.plaintext_utf8;
    const tag = `${v.name} (${info.width}×${info.height})`;
    if (ok) {
      pass++;
      console.log(`✓ ${tag}`);
    } else {
      fail++;
      console.log(`✗ ${tag}`);
      console.log(`  expected: ${JSON.stringify(v.plaintext_utf8.slice(0, 80))}`);
      if (result.ok) {
        console.log(`  got:      ${JSON.stringify(result.message.slice(0, 80))}`);
      } else {
        console.log(`  failed:   ${result.reason}${result.detail ? ' — ' + result.detail : ''}`);
      }
    }
  }

  console.log(`\n${pass} passed, ${fail} failed (${basename(dir)})`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
