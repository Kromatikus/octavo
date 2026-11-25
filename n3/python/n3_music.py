#!/usr/bin/env python3
"""N3 earworm: WAV / MIDI / SID from a sealed 0x1C blob (display only).

The tune is derived one-way from the blob bytes with the same 16-note mapping
and the same WAV, MIDI and PSID renderers as N2's `octavo hear` earworm. It
does not use the N3 seed, does not call the N3 cipher, and cannot change a
0x1C blob or its test vectors.

  digest = SHA-256(b"Octavo N3 earworm v1" || blob)
  16 notes from digest[:16], C-major pentatonic, same length rule as N2

Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import sys
from typing import Iterable, List, Optional, Sequence, Tuple

HONEST = (
    "Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium."
)

DOMAIN = b"Octavo N3 earworm v1"

N3_MAGIC = b"SN3C/"
N3_FORMAT = 0x1C
N3_OVERHEAD = 54  # SN3C/ (5) + 0x1C (1) + nonce (16) + tag (32)

NAMES = ["C4", "D4", "E4", "G4", "A4", "C5", "D5", "E5", "G5", "A5"]
# MIDI note numbers of the 10 earworm pitches (C4 = 60). Same table as N2 earworm.rs.
MIDI = [60, 62, 64, 67, 69, 72, 74, 76, 79, 81]
DEFAULT_PROGRAM = 0
MIDI_PPQ = 480

# SID constants, same as N2 rust/crates/octavo-cli/src/sid.rs.
PAL_CLOCK = 985_248.0
FRAMES_PER_EIGHTH = 12
LOAD = 0x1000
INIT = 0x1000
PLAY = 0x1003
LDA_IMM, LDA_ABS, LDA_ABX = 0xA9, 0xAD, 0xBD
STA_ABS, STA_ABX = 0x8D, 0x9D
LDX_IMM, LDX_ABS, STX_ABS = 0xA2, 0xAE, 0x8E
INX, DEX, CPX_IMM, CMP_IMM = 0xE8, 0xCA, 0xE0, 0xC9
BNE, BPL, DEC_ABS, CLC, ADC_ABS = 0xD0, 0x10, 0xCE, 0x18, 0x6D
TAX, JMP_ABS, RTS = 0xAA, 0x4C, 0x60
SID_BASE = 0xD400
PULSE, SAW, GATE = 0x40, 0x20, 0x01
ADSR = [(0x09, 0xA6), (0x08, 0x94), (0x00, 0x70)]
PW = [0x800, 0, 0x400]
WAVE = [PULSE, SAW, PULSE]

Note = Tuple[int, int]  # (pitch index into MIDI/NAMES, length in eighths)


def parse_n3_blob(blob: bytes) -> bytes:
    """Require a well-formed SN3C/ 0x1C blob (at least 54 bytes). Returns the bytes."""
    if not isinstance(blob, (bytes, bytearray)):
        raise ValueError("blob must be bytes")
    blob = bytes(blob)
    if len(blob) < N3_OVERHEAD:
        raise ValueError(
            f"N3 blob is too short ({len(blob)} bytes, need at least {N3_OVERHEAD})"
        )
    if not blob.startswith(N3_MAGIC):
        raise ValueError("N3 blob does not start with SN3C/")
    if blob[5] != N3_FORMAT:
        raise ValueError(f"N3 format is 0x{blob[5]:02x}, expected 0x1C")
    return blob


def tune_from_blob(blob: bytes, *, raw: bool = False) -> List[Note]:
    """16 notes from SHA-256(domain || blob), same mapping as N2 earworm::tune."""
    if raw:
        data = bytes(blob)
    else:
        data = parse_n3_blob(blob)
    digest = hashlib.sha256(DOMAIN + data).digest()
    out: List[Note] = []
    for i, b in enumerate(digest[:16]):
        length = 2 if (i % 4 == 3 or (b >> 6) == 3) else 1
        out.append((b % 10, length))
    return out


def notes_text(t: Sequence[Note]) -> str:
    parts = []
    for n, length in t:
        name = NAMES[n]
        parts.append(name + "-" if length == 2 else name)
    return " ".join(parts)


def wav(t: Sequence[Note]) -> bytes:
    """16-bit mono 22050 Hz WAV of the tune (sine with a short fade per note)."""
    sr = 22050
    eighth = sr // 4  # 120 bpm eighths
    pcm: List[int] = []
    for n, length in t:
        freq = 440.0 * 2.0 ** ((MIDI[n] - 69.0) / 12.0)
        dur = eighth * length
        for i in range(dur):
            tt = i / sr
            env = min(min(i, dur - i) / 400.0, 1.0)
            # Rust `as i16` truncates toward zero; Python int() does the same.
            sample = int(env * 0.3 * math.sin(2.0 * math.pi * freq * tt) * 32767.0)
            pcm.append(sample)
    data_len = len(pcm) * 2
    w = bytearray()
    w += b"RIFF"
    w += (36 + data_len).to_bytes(4, "little")
    w += b"WAVEfmt "
    w += (16).to_bytes(4, "little")
    w += (1).to_bytes(2, "little")  # PCM
    w += (1).to_bytes(2, "little")  # mono
    w += sr.to_bytes(4, "little")
    w += (sr * 2).to_bytes(4, "little")
    w += (2).to_bytes(2, "little")
    w += (16).to_bytes(2, "little")
    w += b"data"
    w += data_len.to_bytes(4, "little")
    for s in pcm:
        w += (s & 0xFFFF).to_bytes(2, "little")
    return bytes(w)


def _vlq(v: int, out: bytearray) -> None:
    buf = [0] * 5
    i = len(buf) - 1
    buf[i] = v & 0x7F
    v >>= 7
    while v > 0:
        i -= 1
        buf[i] = 0x80 | (v & 0x7F)
        v >>= 7
    out.extend(buf[i:])


def midi(t: Sequence[Note], program: int = DEFAULT_PROGRAM) -> bytes:
    """Standard MIDI file (format 0, one track, channel 1) of the same 16 notes."""
    eighth = MIDI_PPQ // 2
    trk = bytearray()
    trk += bytes([0x00, 0xFF, 0x51, 0x03, 0x07, 0xA1, 0x20])  # 120 bpm
    trk += bytes([0x00, 0xFF, 0x58, 0x04, 0x04, 0x02, 0x18, 0x08])  # 4/4
    name = b"Octavo N3 earworm"
    trk += bytes([0x00, 0xFF, 0x03, len(name)])
    trk += name
    trk += bytes([0x00, 0xC0, program & 0x7F])
    for n, length in t:
        key = MIDI[n]
        trk += bytes([0x00, 0x90, key, 90])
        _vlq(eighth * length, trk)
        trk += bytes([0x80, key, 0])
    trk += bytes([0x00, 0xFF, 0x2F, 0x00])
    m = bytearray()
    m += b"MThd"
    m += (6).to_bytes(4, "big")
    m += (0).to_bytes(2, "big")
    m += (1).to_bytes(2, "big")
    m += MIDI_PPQ.to_bytes(2, "big")
    m += b"MTrk"
    m += len(trk).to_bytes(4, "big")
    m += trk
    return bytes(m)


def _rust_round(x: float) -> int:
    """f64::round: half-way cases away from 0.0."""
    if x >= 0:
        return int(math.floor(x + 0.5))
    return int(math.ceil(x - 0.5))


def sid_freq(midi_note: int) -> int:
    """SID frequency register value for a MIDI note at the PAL clock."""
    freq = 440.0 * 2.0 ** ((midi_note - 69.0) / 12.0)
    return _rust_round(freq * 16_777_216.0 / PAL_CLOCK) & 0xFFFF


def _parts(t: Sequence[Note]):
    melody = [MIDI[n] for n, _ in t]
    n = len(melody)
    frames = [FRAMES_PER_EIGHTH * length for _, length in t]
    bass = [melody[i & ~3] - (24 if i % 2 == 0 else 12) for i in range(n)]
    arp = []
    for i in range(n):
        chord = [72 + melody[(i + j) % n] % 12 for j in range(3)]
        chord.sort()
        arp.append(chord)
    return melody, frames, bass, arp


class _Fix:
    __slots__ = ("kind", "at", "label")

    def __init__(self, kind: str, at: int, label: str):
        self.kind = kind
        self.at = at
        self.label = label


class _Asm:
    def __init__(self, org: int):
        self.org = org
        self.b = bytearray()
        self.labels: dict[str, int] = {}
        self.fixes: List[_Fix] = []

    def pc(self) -> int:
        return self.org + len(self.b)

    def label(self, name: str) -> None:
        if name in self.labels:
            raise ValueError(f"duplicate label {name}")
        self.labels[name] = self.pc()

    def imp(self, op: int) -> None:
        self.b.append(op)

    def imm(self, op: int, v: int) -> None:
        self.b.extend((op, v & 0xFF))

    def absn(self, op: int, addr: int) -> None:
        self.b.append(op)
        self.b.extend((addr & 0xFFFF).to_bytes(2, "little"))

    def abs(self, op: int, label: str) -> None:
        self.b.append(op)
        self.fixes.append(_Fix("abs", len(self.b), label))
        self.b.extend(b"\x00\x00")

    def br(self, op: int, label: str) -> None:
        self.b.append(op)
        self.fixes.append(_Fix("rel", len(self.b), label))
        self.b.append(0)

    def bytes_(self, data: Iterable[int]) -> None:
        self.b.extend(data)

    def finish(self) -> bytes:
        for fix in self.fixes:
            addr = self.labels[fix.label]
            if fix.kind == "abs":
                self.b[fix.at : fix.at + 2] = addr.to_bytes(2, "little")
            else:
                delta = addr - (self.org + fix.at + 1)
                if not -128 <= delta <= 127:
                    raise ValueError(f"branch to {fix.label} out of range")
                self.b[fix.at] = delta & 0xFF
        return bytes(self.b)


def player(t: Sequence[Note]) -> bytes:
    """C64 load image (no 2-byte load-address prefix) for one tune. Port of sid.rs player()."""
    melody, frames, bass, arp = _parts(t)
    n = len(melody)
    if not 0 < n <= 64:
        raise ValueError("tune must have 1..64 notes")
    a = _Asm(LOAD)
    a.abs(JMP_ABS, "init")
    a.abs(JMP_ABS, "play")

    a.label("init")
    a.imm(LDX_IMM, 0x18)
    a.imm(LDA_IMM, 0)
    a.label("clr")
    a.absn(STA_ABX, SID_BASE)
    a.imp(DEX)
    a.br(BPL, "clr")
    for v in range(3):
        base = SID_BASE + 7 * v
        a.imm(LDA_IMM, PW[v] & 0xFF)
        a.absn(STA_ABS, base + 2)
        a.imm(LDA_IMM, (PW[v] >> 8) & 0xFF)
        a.absn(STA_ABS, base + 3)
        a.imm(LDA_IMM, ADSR[v][0])
        a.absn(STA_ABS, base + 5)
        a.imm(LDA_IMM, ADSR[v][1])
        a.absn(STA_ABS, base + 6)
    a.imm(LDA_IMM, 0x0F)
    a.absn(STA_ABS, SID_BASE + 0x18)
    a.imm(LDA_IMM, 1)
    a.abs(STA_ABS, "counter")
    a.imm(LDA_IMM, (n - 1) & 0xFF)
    a.abs(STA_ABS, "step")
    a.imm(LDA_IMM, 0)
    a.abs(STA_ABS, "arpbase")
    a.abs(STA_ABS, "arpidx")
    a.imp(RTS)

    a.label("play")
    a.abs(DEC_ABS, "counter")
    a.br(BNE, "held")
    a.abs(LDX_ABS, "step")
    a.imp(INX)
    a.imm(CPX_IMM, n & 0xFF)
    a.br(BNE, "s1")
    a.imm(LDX_IMM, 0)
    a.label("s1")
    a.abs(STX_ABS, "step")
    a.abs(LDA_ABX, "dur")
    a.abs(STA_ABS, "counter")
    a.abs(LDA_ABX, "mlo")
    a.absn(STA_ABS, SID_BASE)
    a.abs(LDA_ABX, "mhi")
    a.absn(STA_ABS, SID_BASE + 1)
    a.abs(LDA_ABX, "blo")
    a.absn(STA_ABS, SID_BASE + 7)
    a.abs(LDA_ABX, "bhi")
    a.absn(STA_ABS, SID_BASE + 8)
    a.abs(LDA_ABX, "step3")
    a.abs(STA_ABS, "arpbase")
    a.imm(LDA_IMM, 0)
    a.abs(STA_ABS, "arpidx")
    for v in range(3):
        a.imm(LDA_IMM, WAVE[v] | GATE)
        a.absn(STA_ABS, SID_BASE + 7 * v + 4)
    a.abs(JMP_ABS, "arp")
    a.label("held")
    a.abs(LDA_ABS, "counter")
    a.imm(CMP_IMM, 2)
    a.br(BNE, "arp")
    for v in range(3):
        a.imm(LDA_IMM, WAVE[v])
        a.absn(STA_ABS, SID_BASE + 7 * v + 4)
    a.label("arp")
    a.abs(LDA_ABS, "arpbase")
    a.imp(CLC)
    a.abs(ADC_ABS, "arpidx")
    a.imp(TAX)
    a.abs(LDA_ABX, "alo")
    a.absn(STA_ABS, SID_BASE + 14)
    a.abs(LDA_ABX, "ahi")
    a.absn(STA_ABS, SID_BASE + 15)
    a.abs(LDX_ABS, "arpidx")
    a.imp(INX)
    a.imm(CPX_IMM, 3)
    a.br(BNE, "a1")
    a.imm(LDX_IMM, 0)
    a.label("a1")
    a.abs(STX_ABS, "arpidx")
    a.imp(RTS)

    def lo(notes: Sequence[int]) -> List[int]:
        return [sid_freq(x) & 0xFF for x in notes]

    def hi(notes: Sequence[int]) -> List[int]:
        return [(sid_freq(x) >> 8) & 0xFF for x in notes]

    arp_flat = [p for chord in arp for p in chord]
    tables = [
        ("dur", frames),
        ("mlo", lo(melody)),
        ("mhi", hi(melody)),
        ("blo", lo(bass)),
        ("bhi", hi(bass)),
        ("step3", [3 * i for i in range(n)]),
        ("alo", lo(arp_flat)),
        ("ahi", hi(arp_flat)),
        ("counter", [0]),
        ("step", [0]),
        ("arpbase", [0]),
        ("arpidx", [0]),
    ]
    for name, data in tables:
        a.label(name)
        a.bytes_(data)
    return a.finish()


def _field(s: str) -> bytes:
    raw = s.encode("ascii")
    f = bytearray(32)
    f[: min(31, len(raw))] = raw[:31]
    return bytes(f)


def psid(t: Sequence[Note]) -> bytes:
    """A PSID v2 file: 0x7C-byte header, then the load address (LE) and the player."""
    h = bytearray()
    h += b"PSID"
    h += (2).to_bytes(2, "big")
    h += (0x7C).to_bytes(2, "big")
    h += (0).to_bytes(2, "big")  # loadAddress is in the data
    h += INIT.to_bytes(2, "big")
    h += PLAY.to_bytes(2, "big")
    h += (1).to_bytes(2, "big")
    h += (1).to_bytes(2, "big")
    h += (0).to_bytes(4, "big")
    h += _field("Octavo N3 earworm")
    h += _field("n3_music (N2 renderer)")
    h += _field("2026 homemade, not for secrets")
    h += (0x0014).to_bytes(2, "big")  # built-in player, PAL, 6581
    h += b"\x00\x00"  # startPage, pageLength
    h += (0).to_bytes(2, "big")  # reserved (v2)
    if len(h) != 0x7C:
        raise RuntimeError(f"PSID header is {len(h)} bytes, expected 0x7C")
    h += LOAD.to_bytes(2, "little")
    h += player(t)
    return bytes(h)


def render(blob: bytes, *, raw: bool = False, program: int = DEFAULT_PROGRAM) -> dict:
    """Return notes / wav / midi / sid for a blob. Display only."""
    t = tune_from_blob(blob, raw=raw)
    return {
        "notes": notes_text(t),
        "tune": t,
        "wav": wav(t),
        "midi": midi(t, program),
        "sid": psid(t),
    }


def _read_blob(path: Optional[str]) -> bytes:
    if path is None or path == "-":
        return sys.stdin.buffer.read()
    with open(path, "rb") as f:
        return f.read()


def _write_out(path: str, data: bytes, force: bool) -> None:
    if (not force) and os.path.lexists(path):
        raise FileExistsError(f"{path} exists (use --force to replace it)")
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description=(
            "Render WAV, MIDI and SID from an N3 0x1C blob. "
            "Display only: this does not change the N3 cipher or format. " + HONEST
        )
    )
    p.add_argument(
        "--blob",
        default="-",
        help="N3 0x1C blob file (default: stdin)",
    )
    p.add_argument("--wav", help="write a 22050 Hz WAV")
    p.add_argument("--midi", help="write a standard MIDI file")
    p.add_argument("--sid", help="write a Commodore 64 PSID v2 file")
    p.add_argument(
        "--program",
        type=int,
        default=DEFAULT_PROGRAM,
        help="General MIDI program for --midi (0..127, default 0 = piano)",
    )
    p.add_argument(
        "--raw",
        action="store_true",
        help="treat the input as raw bytes (skip the SN3C/ 0x1C check)",
    )
    p.add_argument("--force", action="store_true", help="replace existing output files")
    args = p.parse_args(argv)

    try:
        blob = _read_blob(args.blob)
        if not args.raw:
            parse_n3_blob(blob)
        if not (args.wav or args.midi or args.sid):
            # still print the notes so a no-flag run is useful
            pass
        out = render(blob, raw=args.raw, program=args.program)
        print(out["notes"])
        for flag, key in (("--wav", "wav"), ("--midi", "midi"), ("--sid", "sid")):
            path = getattr(args, key)
            if path:
                _write_out(path, out[key], args.force)
                print(f"n3_music: wrote {path}", file=sys.stderr)
        print(HONEST, file=sys.stderr)
        return 0
    except (ValueError, FileExistsError, OSError) as e:
        print(f"n3_music: {e}", file=sys.stderr)
        print(HONEST, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
