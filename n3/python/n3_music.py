#!/usr/bin/env python3
"""N3 earworm: WAV / MIDI / SID from a sealed 0x1C blob (display only).

The melody is derived one-way from the blob with the same 16-note mapping as
before:

  digest = SHA-256(b"Octavo N3 earworm v1" || blob)
  16 notes from digest[:16], C-major pentatonic, same length rule as N2

Bass and harmony are a second, also deterministic arrangement:

  voices = SHA-256(b"Octavo N3 earworm v1" || b"voices" || blob)

All three parts stay on the C major pentatonic. Bass plays slow roots
(half or whole notes, one or two octaves down) of a compact I–vi–IV–V-ish
progression and only moves on strong beats. Harmony plays quieter chord
tones (3rds / 5ths / octaves) that do not form a second against the
melody. This does not use the N3 seed, does not call the N3 cipher, and
cannot change a 0x1C blob or its test vectors.

Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import sys
from typing import Iterable, List, NamedTuple, Optional, Sequence, Tuple

HONEST = (
    "Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium."
)

DOMAIN = b"Octavo N3 earworm v1"
VOICES_TAG = b"voices"

N3_MAGIC = b"SN3C/"
N3_FORMAT = 0x1C
N3_OVERHEAD = 54  # SN3C/ (5) + 0x1C (1) + nonce (16) + tag (32)

NAMES = ["C4", "D4", "E4", "G4", "A4", "C5", "D5", "E5", "G5", "A5"]
# MIDI note numbers of the 10 earworm pitches (C4 = 60). Same table as N2 earworm.rs.
MIDI = [60, 62, 64, 67, 69, 72, 74, 76, 79, 81]
PITCH_NAMES = ["C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B"]
PENTATONIC_PCS = (0, 2, 4, 7, 9)  # C D E G A

# I (C–E–G), vi (A–C–E), IV-ish (D–G–A, a pentatonic II/IV), V (G–D–E, no B).
# Each tuple is (root pc, chord-tone pcs). Tones after the root are the
# 3rd / 5th / color tones used by the harmony line.
CHORDS = (
    (0, (0, 4, 7)),  # I
    (9, (9, 0, 4)),  # vi
    (2, (2, 7, 9)),  # IV-ish
    (7, (7, 2, 4)),  # V
)
CHORD_LABELS = ("I", "vi", "IV", "V")

DEFAULT_PROGRAM = 0  # melody: Acoustic Grand Piano
BASS_PROGRAM = 33  # Electric Bass (finger)
HARMONY_PROGRAM = 48  # String Ensemble 1
MIDI_PPQ = 480

# Mix: melody > harmony > bass, with headroom so three voices cannot clip.
WAV_SR = 22050
AMP_MELODY = 0.28
AMP_HARMONY = 0.16
AMP_BASS = 0.12

# SID constants, same base player as N2 rust/crates/octavo-cli/src/sid.rs.
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
AND_IMM = 0x29
SID_BASE = 0xD400
TRIANGLE, PULSE, SAW, GATE = 0x10, 0x40, 0x20, 0x01
# Voice 1 melody (pulse), voice 2 bass (triangle), voice 3 harmony (saw).
ADSR = [(0x09, 0xA6), (0x0A, 0xA8), (0x29, 0xA6)]
PW = [0x800, 0, 0x400]
WAVE = [PULSE, TRIANGLE, SAW]

Note = Tuple[int, int]  # (pitch index into MIDI/NAMES, length in eighths)


class Event(NamedTuple):
    """One note of a voice: start time in eighths, MIDI pitch, length in eighths."""

    start: int
    midi: int
    length: int


class Arrangement(NamedTuple):
    """Three-voice arrangement derived from a blob. Melody matches tune_from_blob."""

    tune: List[Note]
    melody: List[Event]
    bass: List[Event]
    harmony: List[Event]
    total_eighths: int


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


def midi_name(midi_note: int) -> str:
    """Scientific pitch name for a MIDI number (60 = C4)."""
    return PITCH_NAMES[midi_note % 12] + str(midi_note // 12 - 1)


def interval_class(a: int, b: int) -> int:
    d = abs(a - b) % 12
    return min(d, 12 - d)


def clashes(a: Optional[int], b: Optional[int]) -> bool:
    """True if two MIDI pitches form a semitone or whole-tone (or a 7th)."""
    if a is None or b is None:
        return False
    return interval_class(a, b) in (1, 2)


def _blob_bytes(blob: bytes, raw: bool) -> bytes:
    return bytes(blob) if raw else parse_n3_blob(blob)


def _melody_events(tune: Sequence[Note]) -> List[Event]:
    evs: List[Event] = []
    t = 0
    for idx, length in tune:
        evs.append(Event(t, MIDI[idx], length))
        t += length
    return evs


def _sounding(events: Sequence[Event], eighth: int) -> Optional[int]:
    for ev in events:
        if ev.start <= eighth < ev.start + ev.length:
            return ev.midi
    return None


def _pcs_in_span(melody: Sequence[Event], start: int, end: int) -> List[int]:
    pcs = []
    for ev in melody:
        lo = max(ev.start, start)
        hi = min(ev.start + ev.length, end)
        if lo < hi:
            pc = ev.midi % 12
            if pc not in pcs:
                pcs.append(pc)
    return pcs


def _safe_pcs(against: Sequence[int]) -> List[int]:
    safe = []
    for pc in PENTATONIC_PCS:
        if all(interval_class(pc, other) not in (1, 2) for other in against):
            safe.append(pc)
    return safe


def _bass_midi(pc: int, low: bool) -> int:
    """Place a pentatonic pc in the bass register (about C2 or C3)."""
    # Two octaves down: G1–A2. One octave down: C2–E3 (never into the melody staff).
    lo, hi = (31, 45) if low else (36, 52)
    chosen = None
    for octv in range(0, 8):
        m = pc + 12 * octv
        if lo <= m <= hi:
            if low:
                return m  # lowest matching pitch
            chosen = m  # highest matching pitch
    if chosen is not None:
        return chosen
    return pc + (36 if low else 48)


def _pick_bass_pc(chord: Tuple[int, Tuple[int, ...]], safe: Sequence[int]) -> Optional[int]:
    if not safe:
        return None
    root, tones = chord
    fifth = (root + 7) % 12
    preferred = [root, fifth, *tones]
    for cand in preferred:
        if cand in safe:
            return cand
    return list(safe)[0]


def _tie_adjacent(events: Sequence[Event]) -> List[Event]:
    out: List[Event] = []
    for ev in events:
        if out and ev.midi == out[-1].midi and ev.start == out[-1].start + out[-1].length:
            prev = out[-1]
            out[-1] = Event(prev.start, prev.midi, prev.length + ev.length)
        else:
            out.append(ev)
    return out


def _harmony_midi(
    mel: int,
    bass: Optional[int],
    tones: Tuple[int, ...],
    prev: Optional[int] = None,
) -> int:
    """A mid-register chord tone that does not clash with melody or bass."""

    def ok(m: int) -> bool:
        return (not clashes(m, mel)) and (not clashes(m, bass))

    cands = []
    for octv in range(3, 6):
        for pc in tones:
            m = pc + 12 * (octv + 1)
            if 48 <= m <= 76 and ok(m):
                cands.append(m)
    if not cands:
        for octv in range(3, 6):
            for pc in PENTATONIC_PCS:
                m = pc + 12 * (octv + 1)
                if 48 <= m <= 76 and ok(m):
                    cands.append(m)
    if not cands:
        # Last resort: any in-range pentatonic pitch that misses the melody.
        for m in range(48, 77):
            if (m % 12) in PENTATONIC_PCS and not clashes(m, mel):
                cands.append(m)
    if not cands:
        return max(48, min(76, mel - 7))

    def score(m: int) -> Tuple[int, int, int, int, int, int]:
        pc = m % 12
        if len(tones) >= 3 and pc == tones[2]:
            role = 10
        elif len(tones) >= 2 and pc == tones[1]:
            role = 10
        elif pc == tones[0]:
            role = 6
        else:
            role = 4
        if pc == mel % 12:
            role -= 6
        below = 3 if m < mel else (0 if m == mel else 1)
        mid = 2 if 55 <= m <= 72 else 0
        cons = 3 if interval_class(m, mel) in (3, 4, 5, 7) else 1
        if prev is None:
            near = 0
        else:
            leap = abs(m - prev)
            if leap == 0:
                near = 4
            elif leap <= 5:
                near = 3
            elif leap <= 8:
                near = 2
            elif leap <= 12:
                near = 1
            else:
                near = -2
        return (role, near, below, mid, cons, -abs(m - (mel - 7)))

    return max(cands, key=score)


def _planned_segments(total: int) -> List[Tuple[int, int, int]]:
    """I | vi | IV | V over a short tune: whole bars, then a half-bar turnaround."""
    parts = [
        (0, min(8, total), 0),
        (8, min(16, total), 1),
        (16, min(20, total), 2),
        (20, total, 3),
    ]
    return [(a, b, c) for a, b, c in parts if a < b and a < total]


def _place_bass(
    melody: Sequence[Event],
    total: int,
    low: bool,
) -> List[Event]:
    events: List[Event] = []

    def place(start: int, end: int, chord_i: int) -> None:
        if start >= end:
            return
        chord = CHORDS[chord_i]
        safe = _safe_pcs(_pcs_in_span(melody, start, end))
        pc = _pick_bass_pc(chord, safe)
        if pc is not None:
            events.append(Event(start, _bass_midi(pc, low), end - start))
            return
        if end - start == 1:
            onset = _sounding(melody, start)
            safe_on = _safe_pcs([] if onset is None else [onset % 12])
            pc = _pick_bass_pc(chord, safe_on) or chord[0]
            events.append(Event(start, _bass_midi(pc, low), 1))
            return
        # No single tone is safe for the whole span. Split, preferring a
        # quarter-note beat near the middle so the bass still moves slowly.
        mid_target = (start + end) // 2
        interior = range(start + 1, end)
        even = [t for t in interior if t % 2 == 0]
        strong = [t for t in interior if t % 4 == 0]
        pool = strong or even or list(interior)
        mid = min(pool, key=lambda t: (abs(t - mid_target), t))
        place(start, mid, chord_i)
        place(mid, end, chord_i)

    for start, end, chord_i in _planned_segments(total):
        place(start, end, chord_i)
    return events


def voices_from_blob(blob: bytes, *, raw: bool = False) -> Arrangement:
    """Melody (unchanged) plus bass and harmony, all deterministic from the blob."""
    data = _blob_bytes(blob, raw)
    tune = tune_from_blob(data, raw=True)
    melody = _melody_events(tune)
    total = sum(length for _, length in tune)
    vdigest = hashlib.sha256(DOMAIN + VOICES_TAG + data).digest()
    low = (vdigest[0] & 1) == 0
    bass = _tie_adjacent(_place_bass(melody, total, low))
    harmony: List[Event] = []
    for ev in melody:
        chord_i = 0
        for start, end, idx in _planned_segments(total):
            if start <= ev.start < end:
                chord_i = idx
                break
        tones = CHORDS[chord_i][1]
        bass_now = _sounding(bass, ev.start)
        prev = harmony[-1].midi if harmony else None
        h = _harmony_midi(ev.midi, bass_now, tones, prev)
        harmony.append(Event(ev.start, h, ev.length))
    harmony = _tie_adjacent(harmony)
    return Arrangement(list(tune), melody, bass, harmony, total)


def _event_text(ev: Event) -> str:
    name = midi_name(ev.midi)
    if ev.length == 1:
        return name
    if ev.length == 2:
        return name + "-"
    return f"{name}x{ev.length}"


def voices_text(arr: Arrangement) -> str:
    lines = [
        "melody   " + " ".join(_event_text(ev) for ev in arr.melody),
        "bass     " + " ".join(_event_text(ev) for ev in arr.bass),
        "harmony  " + " ".join(_event_text(ev) for ev in arr.harmony),
    ]
    return "\n".join(lines)


def _sine(freq: float, t: float) -> float:
    return math.sin(2.0 * math.pi * freq * t)


def _triangle(freq: float, t: float) -> float:
    phase = (freq * t) % 1.0
    return 1.0 - 4.0 * abs(phase - 0.5)


def _soft_saw(freq: float, t: float) -> float:
    phase = (freq * t) % 1.0
    saw = 2.0 * phase - 1.0
    return 0.5 * saw + 0.5 * math.sin(2.0 * math.pi * freq * t)


def _render_line(
    events: Sequence[Event],
    total_samples: int,
    eighth: int,
    sr: int,
    wave_fn,
    fade: int,
) -> List[float]:
    pcm = [0.0] * total_samples
    for ev in events:
        start = ev.start * eighth
        dur = ev.length * eighth
        freq = 440.0 * 2.0 ** ((ev.midi - 69.0) / 12.0)
        fade_n = min(fade, max(1, dur // 2))
        for i in range(dur):
            idx = start + i
            if idx >= total_samples:
                break
            env = min(min(i, dur - 1 - i) / float(fade_n), 1.0)
            pcm[idx] += env * wave_fn(freq, i / sr)
    return pcm


def wav(arr: Arrangement) -> bytes:
    """16-bit mono 22050 Hz WAV: sine melody, triangle bass, soft-saw harmony."""
    sr = WAV_SR
    eighth = sr // 4  # 120 bpm eighths
    total_samples = arr.total_eighths * eighth
    mel = _render_line(arr.melody, total_samples, eighth, sr, _sine, 400)
    bass = _render_line(arr.bass, total_samples, eighth, sr, _triangle, 1200)
    harm = _render_line(arr.harmony, total_samples, eighth, sr, _soft_saw, 600)
    pcm: List[int] = []
    for i in range(total_samples):
        mixed = AMP_MELODY * mel[i] + AMP_HARMONY * harm[i] + AMP_BASS * bass[i]
        sample = int(mixed * 32767.0)
        if sample > 32767:
            sample = 32767
        elif sample < -32767:
            sample = -32767
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


def _midi_track(
    events: Sequence[Event],
    channel: int,
    program: int,
    name: bytes,
    velocity: int,
    *,
    tempo: bool = False,
) -> bytes:
    eighth = MIDI_PPQ // 2
    trk = bytearray()
    if tempo:
        trk += bytes([0x00, 0xFF, 0x51, 0x03, 0x07, 0xA1, 0x20])  # 120 bpm
        trk += bytes([0x00, 0xFF, 0x58, 0x04, 0x04, 0x02, 0x18, 0x08])  # 4/4
    trk += bytes([0x00, 0xFF, 0x03, len(name)])
    trk += name
    trk += bytes([0x00, 0xC0 | (channel & 0x0F), program & 0x7F])
    t = 0
    for ev in events:
        _vlq((ev.start - t) * eighth, trk)
        key = ev.midi & 0x7F
        trk += bytes([0x90 | (channel & 0x0F), key, velocity & 0x7F])
        _vlq(ev.length * eighth, trk)
        trk += bytes([0x80 | (channel & 0x0F), key, 0])
        t = ev.start + ev.length
    trk += bytes([0x00, 0xFF, 0x2F, 0x00])
    return bytes(trk)


def midi(arr: Arrangement, program: int = DEFAULT_PROGRAM) -> bytes:
    """Format-1 MIDI: three tracks / channels (melody, bass, harmony). No drums."""
    tracks = [
        _midi_track(
            arr.melody, 0, program & 0x7F, b"Octavo N3 melody", 100, tempo=True
        ),
        _midi_track(arr.bass, 1, BASS_PROGRAM, b"Octavo N3 bass", 64),
        _midi_track(arr.harmony, 2, HARMONY_PROGRAM, b"Octavo N3 harmony", 72),
    ]
    m = bytearray()
    m += b"MThd"
    m += (6).to_bytes(4, "big")
    m += (1).to_bytes(2, "big")  # format 1
    m += (3).to_bytes(2, "big")
    m += MIDI_PPQ.to_bytes(2, "big")
    for trk in tracks:
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


def _grid(events: Sequence[Event], n: int) -> Tuple[List[int], List[int], List[int]]:
    """Per-eighth MIDI pitch, start flags, and release flags."""
    pitch = [0] * n
    start = [0] * n
    release = [0] * n
    for ev in events:
        for i in range(ev.length):
            idx = ev.start + i
            if 0 <= idx < n:
                pitch[idx] = ev.midi
        if 0 <= ev.start < n:
            start[ev.start] = 1
        end = ev.start + ev.length - 1
        if 0 <= end < n:
            release[end] = 1
    return pitch, start, release


def player(arr: Arrangement) -> bytes:
    """C64 load image (no 2-byte load-address prefix) for a 3-voice tune."""
    n = arr.total_eighths
    if not 0 < n <= 64:
        raise ValueError("tune must have 1..64 eighths")
    m_pitch, m_on, m_off = _grid(arr.melody, n)
    b_pitch, b_on, b_off = _grid(arr.bass, n)
    h_pitch, h_on, h_off = _grid(arr.harmony, n)
    starts = [(m_on[i] << 0) | (b_on[i] << 1) | (h_on[i] << 2) for i in range(n)]
    releases = [(m_off[i] << 0) | (b_off[i] << 1) | (h_off[i] << 2) for i in range(n)]
    frames = [FRAMES_PER_EIGHTH] * n

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
    a.abs(LDA_ABX, "hlo")
    a.absn(STA_ABS, SID_BASE + 14)
    a.abs(LDA_ABX, "hhi")
    a.absn(STA_ABS, SID_BASE + 15)
    a.abs(LDA_ABX, "starts")
    a.imm(AND_IMM, 1)
    a.br(0xF0, "nos0")
    a.imm(LDA_IMM, WAVE[0] | GATE)
    a.absn(STA_ABS, SID_BASE + 4)
    a.label("nos0")
    a.abs(LDA_ABX, "starts")
    a.imm(AND_IMM, 2)
    a.br(0xF0, "nos1")
    a.imm(LDA_IMM, WAVE[1] | GATE)
    a.absn(STA_ABS, SID_BASE + 11)
    a.label("nos1")
    a.abs(LDA_ABX, "starts")
    a.imm(AND_IMM, 4)
    a.br(0xF0, "nos2")
    a.imm(LDA_IMM, WAVE[2] | GATE)
    a.absn(STA_ABS, SID_BASE + 18)
    a.label("nos2")
    a.imp(RTS)

    a.label("held")
    a.abs(LDA_ABS, "counter")
    a.imm(CMP_IMM, 2)
    a.br(BNE, "done")
    a.abs(LDX_ABS, "step")
    a.abs(LDA_ABX, "releases")
    a.imm(AND_IMM, 1)
    a.br(0xF0, "nor0")
    a.imm(LDA_IMM, WAVE[0])
    a.absn(STA_ABS, SID_BASE + 4)
    a.label("nor0")
    a.abs(LDA_ABX, "releases")
    a.imm(AND_IMM, 2)
    a.br(0xF0, "nor1")
    a.imm(LDA_IMM, WAVE[1])
    a.absn(STA_ABS, SID_BASE + 11)
    a.label("nor1")
    a.abs(LDA_ABX, "releases")
    a.imm(AND_IMM, 4)
    a.br(0xF0, "done")
    a.imm(LDA_IMM, WAVE[2])
    a.absn(STA_ABS, SID_BASE + 18)
    a.label("done")
    a.imp(RTS)

    def lo(notes: Sequence[int]) -> List[int]:
        return [sid_freq(x) & 0xFF for x in notes]

    def hi(notes: Sequence[int]) -> List[int]:
        return [(sid_freq(x) >> 8) & 0xFF for x in notes]

    tables = [
        ("dur", frames),
        ("mlo", lo(m_pitch)),
        ("mhi", hi(m_pitch)),
        ("blo", lo(b_pitch)),
        ("bhi", hi(b_pitch)),
        ("hlo", lo(h_pitch)),
        ("hhi", hi(h_pitch)),
        ("starts", starts),
        ("releases", releases),
        ("counter", [0]),
        ("step", [0]),
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


def psid(arr: Arrangement) -> bytes:
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
    h += _field("n3_music (3 voices)")
    h += _field("2026 homemade, not for secrets")
    h += (0x0014).to_bytes(2, "big")  # built-in player, PAL, 6581
    h += b"\x00\x00"  # startPage, pageLength
    h += (0).to_bytes(2, "big")  # reserved (v2)
    if len(h) != 0x7C:
        raise RuntimeError(f"PSID header is {len(h)} bytes, expected 0x7C")
    h += LOAD.to_bytes(2, "little")
    h += player(arr)
    return bytes(h)


def render(blob: bytes, *, raw: bool = False, program: int = DEFAULT_PROGRAM) -> dict:
    """Return notes / voices / wav / midi / sid for a blob. Display only."""
    arr = voices_from_blob(blob, raw=raw)
    return {
        "notes": notes_text(arr.tune),
        "voices": voices_text(arr),
        "tune": arr.tune,
        "arrangement": arr,
        "wav": wav(arr),
        "midi": midi(arr, program),
        "sid": psid(arr),
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
            "Render a 3-voice WAV, MIDI and SID from an N3 0x1C blob. "
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
        help="General MIDI program for the melody track (0..127, default 0 = piano)",
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
        print(out["voices"])
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
