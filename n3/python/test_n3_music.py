#!/usr/bin/env python3
"""Tests for n3_music.py. Display-only: these do not touch the N3 cipher or vectors.

Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N3_ROOT = HERE.parent
REPO = N3_ROOT.parent
VECTORS = N3_ROOT / "vectors" / "aead_fix2_vectors.txt"

# Published melody for the first 0x1C vector. Must stay unchanged.
VECTOR0_NOTES = "E4 E4 A5 D5- D4 D4 G4- E4- D4 E5 D4- A4- D5 E4 E4 A4-"

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


def wav_peak(wav: bytes) -> int:
    expect(len(wav) > 44, "WAV is too short to measure")
    data = wav[44:]
    n = len(data) // 2
    samples = struct.unpack("<" + "h" * n, data[: n * 2])
    return max(abs(s) for s in samples) if samples else 0


def midi_format_tracks(mid: bytes) -> tuple[int, int]:
    expect(mid[:4] == b"MThd", f"bad MIDI header: {mid[:16]!r}")
    fmt = int.from_bytes(mid[8:10], "big")
    ntrks = int.from_bytes(mid[10:12], "big")
    return fmt, ntrks


def has_program_changes(mid: bytes) -> set[int]:
    """Return channels that have a program-change status byte in the file."""
    found = set()
    # Format-1 file: walk tracks loosely and look for 0xCn status bytes.
    pos = 14
    while pos + 8 <= len(mid) and mid[pos:pos + 4] == b"MTrk":
        ln = int.from_bytes(mid[pos + 4:pos + 8], "big")
        body = mid[pos + 8:pos + 8 + ln]
        i = 0
        while i < len(body):
            # skip a VLQ delta (we only need to find status bytes)
            while i < len(body) and body[i] & 0x80 and i + 1 < len(body):
                # This is too sloppy for general MIDI; after a delta the next
                # byte is often a status. Search for Cx / 9x / 8x patterns.
                break
            i += 1
        for i, b in enumerate(body):
            if b & 0xF0 == 0xC0:
                found.add(b & 0x0F)
        pos += 8 + ln
    return found


def sid_writes_three_freqs(sid: bytes) -> None:
    # STA abs to each voice's frequency registers: $D400/$D401, $D407/$D408, $D40E/$D40F.
    for addr in (0xD400, 0xD401, 0xD407, 0xD408, 0xD40E, 0xD40F):
        pat = bytes([0x8D, addr & 0xFF, addr >> 8])
        expect(pat in sid, f"SID player never writes frequency at ${addr:04X}")
    # Gate / wave control for all three voices.
    for addr in (0xD404, 0xD40B, 0xD412):
        pat = bytes([0x8D, addr & 0xFF, addr >> 8])
        expect(pat in sid, f"SID player never writes control at ${addr:04X}")


def check_no_clash(arr: n3_music.Arrangement, label: str) -> None:
    # Required: no semitone / whole-tone clash with the melody on simultaneous onsets.
    mel_on = {ev.start: ev.midi for ev in arr.melody}
    for name, evs in (("bass", arr.bass), ("harmony", arr.harmony)):
        for ev in evs:
            if ev.start in mel_on:
                expect(
                    not n3_music.clashes(ev.midi, mel_on[ev.start]),
                    f"{label}: {name} {n3_music.midi_name(ev.midi)} clashes with "
                    f"melody {n3_music.midi_name(mel_on[ev.start])} at eighth {ev.start}",
                )
    # Stronger listenability check: no such clash while the voices overlap.
    for t in range(arr.total_eighths):
        m = n3_music._sounding(arr.melody, t)
        b = n3_music._sounding(arr.bass, t)
        h = n3_music._sounding(arr.harmony, t)
        expect(m is not None, f"{label}: melody gap at eighth {t}")
        expect(b is not None, f"{label}: bass gap at eighth {t}")
        expect(h is not None, f"{label}: harmony gap at eighth {t}")
        expect(
            not n3_music.clashes(b, m),
            f"{label}: bass {n3_music.midi_name(b)} clashes with melody "
            f"{n3_music.midi_name(m)} while overlapping at eighth {t}",
        )
        expect(
            not n3_music.clashes(h, m),
            f"{label}: harmony {n3_music.midi_name(h)} clashes with melody "
            f"{n3_music.midi_name(m)} while overlapping at eighth {t}",
        )
        # All voices stay on the C major pentatonic.
        for name, p in (("melody", m), ("bass", b), ("harmony", h)):
            expect(
                (p % 12) in n3_music.PENTATONIC_PCS,
                f"{label}: {name} {n3_music.midi_name(p)} is off the pentatonic",
            )
    # Bass prefers a slow quarter-note grid (even eighths). It may split a
    # held root when no single pitch stays consonant for the whole span.
    for ev in arr.bass:
        expect(
            ev.start % 2 == 0,
            f"{label}: bass onset at eighth {ev.start} is not on a beat",
        )
        expect(
            ev.length >= 1,
            f"{label}: empty bass note at {ev.start}",
        )
        # Bass register: about G1–E3, one or two octaves below mid-register roots.
        expect(
            31 <= ev.midi <= 52,
            f"{label}: bass {n3_music.midi_name(ev.midi)} is outside G1–E3",
        )


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

    expect(out["notes"] == VECTOR0_NOTES, f"melody notes changed: {out['notes']}")
    expect(
        out["voices"].splitlines()[0].split(None, 1)[1] == VECTOR0_NOTES,
        "voices text melody line does not match published notes",
    )

    fmt, ntrks = midi_format_tracks(mid)
    expect(fmt == 1, f"MIDI format should be 1, got {fmt}")
    expect(ntrks == 3, f"MIDI should have 3 tracks, got {ntrks}")
    expect(mid.count(b"MTrk") == 3, "MIDI file does not contain 3 MTrk chunks")
    channels = has_program_changes(mid)
    expect(channels == {0, 1, 2}, f"MIDI program changes should be on channels 0-2, got {channels}")

    sid_writes_three_freqs(sid)

    peak = wav_peak(wav)
    expect(peak < 32767, f"WAV peaks at full scale ({peak})")
    expect(peak > 2000, f"WAV is nearly silent (peak {peak})")

    again = n3_music.render(a)
    expect(again["wav"] == wav, "WAV is not deterministic")
    expect(again["midi"] == mid, "MIDI is not deterministic")
    expect(again["sid"] == sid, "SID is not deterministic")
    expect(again["notes"] == out["notes"], "notes are not deterministic")
    expect(again["voices"] == out["voices"], "voices are not deterministic")

    other = n3_music.render(b)
    expect(other["wav"] != wav, "different blobs produced the same WAV")
    expect(other["midi"] != mid, "different blobs produced the same MIDI")
    expect(other["sid"] != sid, "different blobs produced the same SID")
    expect(other["notes"] != out["notes"] or other["voices"] != out["voices"],
           "different blobs produced the same arrangement")

    check_no_clash(out["arrangement"], "vector 0")
    check_no_clash(other["arrangement"], "vector 1")
    for i, blob in enumerate(blobs):
        arr = n3_music.voices_from_blob(blob)
        check_no_clash(arr, f"vector {i}")
        expect(n3_music.notes_text(arr.tune) == n3_music.notes_text(n3_music.tune_from_blob(blob)),
               f"vector {i}: arrangement melody diverged from tune_from_blob")

    # Extra raw blobs so clash avoidance is not just luck on the published set.
    for k in range(40):
        raw = bytes([k, 0xA5, 0x5A, k * 3 & 0xFF]) + bytes((k * 17 + i) % 256 for i in range(60))
        arr = n3_music.voices_from_blob(raw, raw=True)
        check_no_clash(arr, f"raw {k}")

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
    fmt_r, ntrks_r = midi_format_tracks(raw["midi"])
    expect(fmt_r == 1 and ntrks_r == 3, "raw MIDI is not format 1 with 3 tracks")
    check_no_clash(raw["arrangement"], "raw phrase")

    print("PASS  N3 music headers, 3 voices, determinism, and no melody clashes")
    print(f"notes (vector 0): {out['notes']}")
    print(out["voices"])
    print(f"WAV {len(wav)} peak {peak}  MIDI {len(mid)}  SID {len(sid)}")
    print("Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as e:
        print(f"FAIL  {e}", file=sys.stderr)
        sys.exit(1)
