"""Verify spec/test-vectors against the reference decoder.

Reads `manifest.json` from the given directory, decodes every PNG entry,
and checks the result against the expected plaintext. Prints PASS/FAIL
per vector and exits non-zero if any vector fails.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from stiger_decode import decode


def run(vectors_dir: Path) -> int:
    manifest_path = vectors_dir / "manifest.json"
    if not manifest_path.is_file():
        print(f"manifest not found: {manifest_path}", file=sys.stderr)
        return 2

    manifest = json.loads(manifest_path.read_text())
    vectors = manifest.get("vectors", [])
    if not vectors:
        print("manifest has no vectors", file=sys.stderr)
        return 2

    failures = 0
    for vec in vectors:
        name = vec["name"]
        png = vectors_dir / vec["png"]
        password = vec.get("password") or None
        expected_mode = vec["mode"]
        expected_plaintext = vec["plaintext_utf8"].encode("utf-8")

        try:
            result = decode(png, password)
        except Exception as e:
            print(f"FAIL  {name}: decode raised {e}")
            failures += 1
            continue

        actual_mode = "stealth" if result.encrypted else "open"
        if actual_mode != expected_mode:
            print(f"FAIL  {name}: mode {actual_mode} != expected {expected_mode}")
            failures += 1
            continue
        if result.data != expected_plaintext:
            print(f"FAIL  {name}: plaintext mismatch")
            print(f"      got:      {result.data!r}")
            print(f"      expected: {expected_plaintext!r}")
            failures += 1
            continue
        print(f"PASS  {name}  ({actual_mode}, {len(result.data)} B)")

    print()
    if failures:
        print(f"{failures} of {len(vectors)} vectors failed")
        return 1
    print(f"all {len(vectors)} vectors passed")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("vectors_dir", type=Path,
                        help="spec/test-vectors directory")
    args = parser.parse_args(argv)
    return run(args.vectors_dir)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
