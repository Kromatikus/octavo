#!/usr/bin/env python3
"""Tests for n3_music.py. Display-only: these do not touch the N3 cipher or vectors.

Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N3_ROOT = HERE.parent
REPO = N3_ROOT.parent
VECTORS = N3_ROOT / "vectors" / "aead_fix2_vectors.txt"

sys.path.insert(0, str(HERE))
import n3_music  # noqa: E402


def expect(cond, msg):
    if not cond:
        raise AssertionError(msg)


def load_blobs():
    blobs = []
    for line in VECTORS.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        blobs.append(bytes.fromhex(parts[-1]))
    return blobs


def main() -> int:
    blobs = load_blobs()
    expect(len(blobs) >= 2, "need at least two published 0x1C vectors")
    a, b = blobs[0], blobs[1]
    expect(a.startswith(b"SN3C/") and a[5] == 0x1C, "vector 0 is not 0x1C")
    expect(b.startswith(b"SN3C/") and b[5] == 0x1C, "vector 1 is not 0x1C")
    expect(a != b, "first two vectors should differ")

    out = n3_music.render(a)
    wav, mid, sid = out["wav"], out["midi"], out["sid"]
    expect(wav[:4] == b"RIFF" and wav[8:12] == b"WAVE", f"bad WAV header: {wav[:16]!r}")
    expect(len(wav) > 44, "WAV is too short")
    expect(mid[:4] == b"MThd", f"bad MIDI header: {mid[:16]!r}")
    expect(len(mid) > 14, "MIDI is too short")
    expect(sid[:4] == b"PSID", f"bad SID header: {sid[:16]!r}")
    expect(int.from_bytes(sid[4:6], "big") == 2, "SID version should be 2")
    expect(int.from_bytes(sid[6:8], "big") == 0x7C, "SID dataOffset should be 0x7C")
    expect(len(sid) > 0x7C + 2, "SID is too short")

    again = n3_music.render(a)
    expect(again["wav"] == wav, "WAV is not deterministic")
    expect(again["midi"] == mid, "MIDI is not deterministic")
    expect(again["sid"] == sid, "SID is not deterministic")
    expect(again["notes"] == out["notes"], "notes are not deterministic")

    other = n3_music.render(b)
    expect(other["wav"] != wav, "different blobs produced the same WAV")
    expect(other["midi"] != mid, "different blobs produced the same MIDI")
    expect(other["sid"] != sid, "different blobs produced the same SID")

    # Music must not depend on importing or running the cipher, and must
    # reject a non-0x1C blob unless --raw is set.
    try:
        n3_music.tune_from_blob(b"SN2" + b"\x00" * 60)
        raise AssertionError("N2-like prefix should be rejected")
    except ValueError as e:
        expect("SN3C/" in str(e) or "format" in str(e).lower(), f"unexpected error: {e}")

    try:
        n3_music.tune_from_blob(b"SN3C/" + bytes([0x1B]) + b"\x00" * 50)
        raise AssertionError("0x1B should be rejected")
    except ValueError as e:
        expect("0x1c" in str(e).lower() or "0x1b" in str(e).lower(), f"unexpected error: {e}")

    # --raw still produces a valid (different) tune from arbitrary bytes.
    raw = n3_music.render(b"not a blob at all", raw=True)
    expect(raw["wav"][:4] == b"RIFF" and raw["sid"][:4] == b"PSID", "raw render failed")
    expect(raw["wav"] != wav, "raw bytes collided with a real blob's WAV")

    print("PASS  N3 music headers, determinism, and distinct blobs")
    print(f"notes (vector 0): {out['notes']}")
    print(f"WAV {len(wav)}  MIDI {len(mid)}  SID {len(sid)}")
    print("Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as e:
        print(f"FAIL  {e}", file=sys.stderr)
        sys.exit(1)
