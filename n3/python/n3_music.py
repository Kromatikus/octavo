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
melody.

`--style ultima` is an original chiptune arrangement in the *texture* of
1980s Ultima III/IV (plucked lead, slow modal pads, measured bass).
It does not copy or approximate any Ultima melody, bass line, or chord
sequence. `--style castle` is an original bouncy major-key arcade
arrangement in the *texture* of early-1980s Universal games (bright
square lead, oom-pah bass, short stabs). It does not copy or approximate
the Mr. Do's Castle tune or any public-domain melody that game quoted.
Default `--style earworm` is unchanged.

This does not use the N3 seed, does not call the N3 cipher, and
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
    style: str = "earworm"
    bpm: int = 120
    unit: int = 1  # Event start/length unit: 1 = eighth, 2 = sixteenth
    total_units: int = 0  # 0 means total_eighths
    mode_name: str = "C major pentatonic"


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


def _event_text(ev: Event, unit: int = 1) -> str:
    name = midi_name(ev.midi)
    length = ev.length
    # Ultima events are in eighths (quarters and halves). length 2 = quarter ("-").
    if unit == 2 and length % 2 == 0:
        length = length // 2
        unit = 1
    if unit == 2:
        if length == 1:
            return name + "s"
        return f"{name}s{length}"
    if length == 1:
        return name
    if length == 2:
        return name + "-"
    return f"{name}x{length}"


def _ultima_harmony_text(arr: Arrangement) -> str:
    """Compact pad listing, one token per bar."""
    n = grid_len(arr)
    unit = getattr(arr, "unit", 1) or 1
    parts = []
    for ev in arr.harmony:
        parts.append(_event_text(ev, unit))
    return " ".join(parts)


def voices_text(arr: Arrangement) -> str:
    unit = getattr(arr, "unit", 1) or 1
    if getattr(arr, "style", "earworm") == "ultima":
        harm = _ultima_harmony_text(arr)
    else:
        harm = " ".join(_event_text(ev, unit) for ev in arr.harmony)
    lines = [
        "melody   " + " ".join(_event_text(ev, unit) for ev in arr.melody),
        "bass     " + " ".join(_event_text(ev, unit) for ev in arr.bass),
        "harmony  " + harm,
    ]
    if getattr(arr, "style", "earworm") == "ultima":
        lines.append(f"style    ultima {arr.bpm} bpm, {arr.mode_name}")
    elif getattr(arr, "style", "earworm") == "castle":
        lines.append(f"style    castle {arr.bpm} bpm, {arr.mode_name}")
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



# ---------------------------------------------------------------------------
# Ultima-style arrangement (original music, display only)
# ---------------------------------------------------------------------------
# Texture inspired by the calmer *title / loading / intro* music of 1980s
# Ultima III/IV (Kenneth W. Arnold era, Mockingboard / SID): a plucked
# 8th-note lead, slow modal pads, and a measured bass — original music only.
# No Ultima melody, bass line, or chord sequence is copied or approximated.
# ---------------------------------------------------------------------------

STYLES = ("earworm", "ultima", "castle")
ULTIMA_DOMAIN = b"Octavo N3 ultima v2"
ULTIMA_MELODY_PROGRAM = 46  # Orchestral Harp (plucked lead)
ULTIMA_BASS_PROGRAM = 42  # Cello
ULTIMA_HARM_PROGRAM = 89  # Pad 2 (warm)
ULTIMA_ARP_PROGRAM = ULTIMA_HARM_PROGRAM  # backward-compatible name
AEOLIAN = (0, 2, 3, 5, 7, 8, 10)
DORIAN = (0, 2, 3, 5, 7, 9, 10)
# Generic reverent/modal cadences (not from a game): plagal and i-VI-VII-i.
ULTIMA_PROGRESSIONS = (
    ("i", "VI", "VII", "i"),
    ("i", "iv", "i", "i"),
    ("i", "VI", "iv", "i"),
    ("i", "III", "VI", "i"),
)
# Diatonic triads as intervals above the tonic.
ULTIMA_CHORD = {
    "i": (0, 3, 7),
    "III": (3, 7, 10),
    "iv": (5, 8, 0),
    "IV": (5, 9, 0),  # Dorian colour
    "v": (7, 10, 2),
    "VI": (8, 0, 3),
    "VII": (10, 2, 5),
}
ULTIMA_TONICS = (9, 2, 4, 7)  # A, D, E, G
# Per bar: two half-notes (root/fifth/octave) or one whole-note root.
BASS_BAR_PATTERNS = (
    ("root", "fifth"),
    ("root", "root"),
    ("root", "octave"),
    ("fifth", "root"),
)
# Slow harmony: half-note pads (3rd then 5th, or the reverse).
HARM_BAR_PATTERNS = (
    ("third", "fifth"),
    ("fifth", "third"),
    ("third", "octave"),
    ("fifth", "fifth"),
)
ASL_A = 0x0A
INC_ABS = 0xEE
ADC_IMM = 0x69


def parse_style(style: Optional[str]) -> str:
    s = "earworm" if style is None else str(style).strip().lower()
    if s in ("earworm", "default", ""):
        return "earworm"
    if s in ("ultima", "ultima3", "ultima4", "u3", "u4"):
        return "ultima"
    if s in ("castle", "castlestyle", "castle-style"):
        return "castle"
    raise ValueError(f"unknown style {style!r}; use earworm, ultima, or castle")


def grid_len(arr: Arrangement) -> int:
    return arr.total_units or arr.total_eighths


def clashes_ultima(a: Optional[int], b: Optional[int]) -> bool:
    """Minor second / major seventh (including compound), the harsh modal clash."""
    if a is None or b is None:
        return False
    return interval_class(a, b) == 1


def _mode_pool(tonic_pc: int, intervals: Sequence[int], lo: int, hi: int) -> List[int]:
    out = []
    for m in range(lo, hi + 1):
        if ((m % 12) - tonic_pc) % 12 in intervals:
            out.append(m)
    return out


def _mode_table(tonic_pc: int, intervals: Sequence[int], start: int) -> List[int]:
    """Ten mid-register mode pitches, used as a drop-in for the earworm 0..9 index."""
    pool = _mode_pool(tonic_pc, intervals, 55, 84)
    if len(pool) < 10:
        pool = _mode_pool(tonic_pc, intervals, 48, 88)
    if len(pool) < 10:
        pool = _mode_pool(tonic_pc, intervals, 45, 93)
    if not pool:
        return list(MIDI)
    start = start % max(1, len(pool) - 9)
    table = pool[start : start + 10]
    while len(table) < 10:
        table.append(pool[(start + len(table)) % len(pool)])
    return table[:10]


def _place_pc(pc: int, target: int, lo: int, hi: int) -> int:
    pc = pc % 12
    cands = [pc + 12 * octv for octv in range(0, 8) if lo <= pc + 12 * octv <= hi]
    if not cands:
        m = pc + 12 * 3
        return max(lo, min(hi, m))
    return min(cands, key=lambda m: (abs(m - target), -m))


def _chord_pcs(tonic_pc: int, intervals: Sequence[int], name: str) -> Tuple[int, ...]:
    if name == "IV" and 9 not in intervals:
        name = "iv"
    tones = ULTIMA_CHORD[name]
    # Root first, then the other chord tones (do not sort — bass needs the root).
    pcs = []
    for iv in tones:
        pc = (tonic_pc + iv) % 12
        if pc not in pcs:
            pcs.append(pc)
    return tuple(pcs)


def _safe_chord(
    tonic_pc: int,
    intervals: Sequence[int],
    planned: Sequence[str],
    against: Sequence[int],
) -> Tuple[str, Tuple[int, ...]]:
    names = list(planned) + [n for n in ("i", "VII", "VI", "III", "v", "iv", "IV") if n not in planned]
    best = None
    best_score = -1
    for name in names:
        pcs = _chord_pcs(tonic_pc, intervals, name)
        if any(interval_class(pc, a) == 1 for pc in pcs for a in against):
            continue
        contained = sum(1 for a in against if a in pcs)
        score = 10 + contained
        if name == planned[0]:
            score += 3
        if score > best_score:
            best_score = score
            best = (name, pcs)
    if best is not None:
        return best
    # Last resort: drop the clashing chord tone later; still pick i.
    return planned[0], _chord_pcs(tonic_pc, intervals, planned[0])


def _mel_pcs_in(melody, start: int, end: int) -> List[int]:
    pcs = []
    for ev in melody:
        if ev.start < end and ev.start + ev.length > start:
            pc = ev.midi % 12
            if pc not in pcs:
                pcs.append(pc)
    return pcs


def _safe_bass_midi(
    root: int,
    fifth: int,
    target: int,
    lo: int,
    hi: int,
    tonic_pc: int,
    intervals: Sequence[int],
    against: Sequence[int],
    octave: bool = False,
) -> int:
    pc = root if not octave else root
    midi = _place_pc(pc, target + (12 if octave else 0), lo, hi)
    if octave and midi + 12 <= hi:
        midi += 12
    if not any(interval_class(midi, p) == 1 for p in against):
        return midi
    for alt_pc, alt_off in ((root, 0), (fifth, 0), (root, 12), (fifth, 12)):
        alt = _place_pc(alt_pc, target + alt_off, lo, hi)
        if alt_off >= 12 and alt + 12 <= hi:
            alt = alt + 12
        if not any(interval_class(alt, p) == 1 for p in against):
            return alt
    for m in range(lo, hi + 1):
        if ((m % 12) - tonic_pc) % 12 in intervals and not any(
            interval_class(m, p) == 1 for p in against
        ):
            return m
    return midi


def _safe_harm_midi(
    role: str,
    pcs: Tuple[int, ...],
    target: int,
    mel: Optional[int],
    bass: Optional[int],
    tonic_pc: int,
    intervals: Sequence[int],
) -> int:
    root = pcs[0]
    third = pcs[1] if len(pcs) > 1 else (root + 3) % 12
    fifth = next((p for p in pcs if interval_class(p, root) == 5), (root + 7) % 12)
    want = {"third": third, "fifth": fifth, "octave": root, "root": root}[role]
    off = 12 if role == "octave" else 0
    chosen = _place_pc(want, target + off, 55, 76)
    if role == "octave" and chosen + 12 <= 76:
        chosen += 12

    def ok(m: int) -> bool:
        return (not clashes_ultima(m, mel)) and (not clashes_ultima(m, bass))

    if ok(chosen):
        return chosen
    for pc, extra in ((third, 0), (fifth, 0), (root, 0), (root, 12), (fifth, 12)):
        m = _place_pc(pc, target + extra, 55, 76)
        if extra and m + 12 <= 76:
            m = m + 12
        if ok(m):
            return m
    for m in _mode_pool(tonic_pc, intervals, 55, 76):
        if ok(m):
            return m
    return max(55, min(76, (mel - 5) if mel else 64))


def _scale_neighbor(
    midi: int,
    direction: int,
    tonic_pc: int,
    intervals: Sequence[int],
    lo: int = 55,
    hi: int = 84,
) -> Optional[int]:
    m = midi + direction
    while lo <= m <= hi:
        if ((m % 12) - tonic_pc) % 12 in intervals:
            return m
        m += direction
    return None


def _lead_ok(pitch: int, t: int, bass: Sequence[Event], harm: Sequence[Event]) -> bool:
    return (not clashes_ultima(pitch, _sounding(bass, t))) and (
        not clashes_ultima(pitch, _sounding(harm, t))
    )


def _lead_figure_tones(
    pitch: int,
    n: int,
    start: int,
    bass: Sequence[Event],
    harm: Sequence[Event],
    tonic_pc: int,
    intervals: Sequence[int],
    kind: int,
) -> List[int]:
    """n eighth-note pitches starting at `pitch`, lute/harp-like, clash-safe."""
    up = _scale_neighbor(pitch, 1, tonic_pc, intervals)
    down = _scale_neighbor(pitch, -1, tonic_pc, intervals)
    third = _scale_neighbor(pitch, 3, tonic_pc, intervals) or up
    # Prefer chordal skips when kind is odd.
    if kind & 1:
        motif_src = [pitch, third or up, up or pitch, down or pitch]
    else:
        motif_src = [pitch, up or pitch, pitch, down or pitch]
    # Ensure we always have 4 slots.
    motif = []
    for i in range(4):
        cand = motif_src[i] if motif_src[i] is not None else pitch
        motif.append(cand)
    out = []
    for i in range(n):
        t = start + i
        # Cycle a 4-note figure; the first eighth of a span is always the source pitch.
        cand = pitch if i == 0 else motif[i % 4]
        if not _lead_ok(cand, t, bass, harm):
            for alt in (pitch, up, down, third):
                if alt is not None and _lead_ok(alt, t, bass, harm):
                    cand = alt
                    break
            else:
                cand = pitch
        # Avoid a drone: no more than two identical pitches in a row, and
        # never three. If we would repeat a third time, try a neighbor.
        if len(out) >= 2 and out[-1] == cand and out[-2] == cand:
            for alt in (up, down, third, pitch):
                if alt is not None and alt != cand and _lead_ok(alt, t, bass, harm):
                    cand = alt
                    break
        out.append(cand)
    return out


def _break_lead_drones(
    events: Sequence[Event],
    bass: Sequence[Event],
    harm: Sequence[Event],
    tonic_pc: int,
    intervals: Sequence[int],
) -> List[Event]:
    """Ensure no identical lead pitch is sustained more than one beat (2 eighths)."""
    out = list(events)
    for i, ev in enumerate(out):
        if i < 2:
            continue
        if ev.midi == out[i - 1].midi == out[i - 2].midi:
            up = _scale_neighbor(ev.midi, 1, tonic_pc, intervals)
            down = _scale_neighbor(ev.midi, -1, tonic_pc, intervals)
            t = ev.start
            chosen = ev.midi
            for alt in (up, down):
                if alt is not None and _lead_ok(alt, t, bass, harm):
                    chosen = alt
                    break
            else:
                # Step to any safe scale tone nearby.
                for m in range(ev.midi - 7, ev.midi + 8):
                    if m != ev.midi and 55 <= m <= 84 and ((m % 12) - tonic_pc) % 12 in intervals and _lead_ok(m, t, bass, harm):
                        chosen = m
                        break
            out[i] = Event(ev.start, chosen, 1)
    return out


def _articulate_lead(
    skeleton: Sequence[Event],
    bass: Sequence[Event],
    harm: Sequence[Event],
    tonic_pc: int,
    intervals: Sequence[int],
    kind: int,
) -> List[Event]:
    """Turn held skeleton notes into plucked 8th-note figures."""
    out: List[Event] = []
    for ev in skeleton:
        tones = _lead_figure_tones(
            ev.midi, ev.length, ev.start, bass, harm, tonic_pc, intervals, kind
        )
        for i, pitch in enumerate(tones):
            out.append(Event(ev.start + i, pitch, 1))
    return _break_lead_drones(out, bass, harm, tonic_pc, intervals)


def voices_from_blob_ultima(blob: bytes, *, raw: bool = False) -> Arrangement:
    """Original slow modal arrangement in a title/loading spirit.

    The 16-note rhythm comes from the earworm digest, stretched so a short
    earworm eighth becomes a quarter and a long note becomes a half, then
    those values are broken into plucked 8th-note figures (neighbors or
    lute-like chord tones) so the lead never drones. A short plagal or
    modal cadence is appended. Pitches, mode, tempo and patterns come from
    a separate ultima digest.
    """
    data = _blob_bytes(blob, raw)
    tune = tune_from_blob(data, raw=True)
    udigest = hashlib.sha256(ULTIMA_DOMAIN + data).digest()
    tonic_pc = ULTIMA_TONICS[udigest[0] % len(ULTIMA_TONICS)]
    mode_iv = AEOLIAN if (udigest[1] & 1) == 0 else DORIAN
    mode_label = "Aeolian" if mode_iv is AEOLIAN else "Dorian"
    tonic_name = PITCH_NAMES[tonic_pc]
    bpm = 70 + (udigest[2] % 21)  # 70..90
    family = ULTIMA_PROGRESSIONS[udigest[3] % len(ULTIMA_PROGRESSIONS)]
    table = _mode_table(tonic_pc, mode_iv, udigest[4])
    bass_pat = BASS_BAR_PATTERNS[udigest[5] % len(BASS_BAR_PATTERNS)]
    harm_pat = HARM_BAR_PATTERNS[udigest[6] % len(HARM_BAR_PATTERNS)]
    low_bass = (udigest[7] & 1) == 0
    plagal_coda = (udigest[8] & 1) == 0  # iv-i vs VII-i

    # Melody: earworm lengths stretched (1→quarter, 2→half), then padded to a
    # bar line and a two-bar cadence.
    melody: List[Event] = []
    t8 = 0
    for idx, length in tune:
        dur = length * 2
        melody.append(Event(t8, table[idx % len(table)], dur))
        t8 += dur
    if t8 % 8 != 0:
        extra = 8 - (t8 % 8)
        last = melody[-1]
        melody[-1] = Event(last.start, last.midi, last.length + extra)
        t8 += extra
    body_end = t8

    # Coda melody: approach, then a held tonic.
    tonic_mel = _place_pc(tonic_pc, melody[-1].midi if melody else 69, 57, 81)
    # A scale neighbor below the tonic, if it exists; otherwise the fifth.
    below = tonic_mel - 1
    while below >= 55 and ((below % 12) - tonic_pc) % 12 not in mode_iv:
        below -= 1
    approach = below if below >= 55 else _place_pc((tonic_pc + 7) % 12, tonic_mel, 55, 81)
    melody.append(Event(t8, approach, 8))
    melody.append(Event(t8 + 8, tonic_mel, 8))
    t8 += 16
    total_eighths = t8
    total_units = t8
    n_bars = (total_eighths + 7) // 8

    # One chord per bar; last two bars are a cadence (iv-i or VII-i).
    chord_at: List[Tuple[str, Tuple[int, ...]]] = []
    for bar in range(n_bars):
        start8 = bar * 8
        end8 = min(start8 + 8, total_eighths)
        if bar == n_bars - 2:
            planned = "iv" if plagal_coda else "VII"
        elif bar == n_bars - 1:
            planned = "i"
        else:
            planned = family[bar % len(family)]
        against = _mel_pcs_in(melody, start8, end8)
        name, pcs = _safe_chord(tonic_pc, mode_iv, (planned,), against)
        for _ in range(start8, end8):
            chord_at.append((name, pcs))
    while len(chord_at) < total_units:
        chord_at.append(chord_at[-1] if chord_at else ("i", _chord_pcs(tonic_pc, mode_iv, "i")))

    bass_target = 33 if low_bass else 45
    bass_lo, bass_hi = ((31, 45) if low_bass else (36, 52))
    bass: List[Event] = []
    for bar in range(n_bars):
        start8 = bar * 8
        end8 = min(start8 + 8, total_eighths)
        name, pcs = chord_at[start8]
        root = pcs[0]
        fifth = next((p for p in pcs if interval_class(p, root) == 5), (root + 7) % 12)
        # Whole-note root if the pattern repeats the same role and the bar is full.
        roles = list(bass_pat)
        if end8 - start8 < 8:
            roles = roles[:1]
        if len(roles) == 2 and roles[0] == roles[1] and (end8 - start8) == 8:
            against = _mel_pcs_in(melody, start8, end8)
            midi = _safe_bass_midi(
                root, fifth, bass_target, bass_lo, bass_hi, tonic_pc, mode_iv, against,
                octave=(roles[0] == "octave"),
            )
            bass.append(Event(start8, midi, end8 - start8))
        else:
            slot = max(1, (end8 - start8) // max(1, len(roles)))
            # Prefer half notes (4 eighths) on a full bar.
            if end8 - start8 == 8 and len(roles) == 2:
                slot = 4
            t = start8
            for i, role in enumerate(roles):
                length = (end8 - t) if i == len(roles) - 1 else min(slot, end8 - t)
                if length <= 0:
                    break
                against = _mel_pcs_in(melody, t, t + length)
                midi = _safe_bass_midi(
                    root, fifth, bass_target, bass_lo, bass_hi, tonic_pc, mode_iv, against,
                    octave=(role == "octave"),
                )
                if role == "fifth":
                    midi = _safe_bass_midi(
                        fifth, root, bass_target, bass_lo, bass_hi, tonic_pc, mode_iv, against,
                        octave=False,
                    )
                bass.append(Event(t, midi, length))
                t += length

    harm_target = 64
    harmony: List[Event] = []
    for bar in range(n_bars):
        start8 = bar * 8
        end8 = min(start8 + 8, total_eighths)
        name, pcs = chord_at[start8]
        roles = list(harm_pat)
        if end8 - start8 < 8:
            roles = roles[:1]
        slot = 4 if (end8 - start8) == 8 and len(roles) == 2 else max(1, (end8 - start8) // max(1, len(roles)))
        t = start8
        for i, role in enumerate(roles):
            length = (end8 - t) if i == len(roles) - 1 else min(slot, end8 - t)
            if length <= 0:
                break
            mel = _sounding(melody, t)
            bnow = _sounding(bass, t)
            midi = _safe_harm_midi(role, pcs, harm_target, mel, bnow, tonic_pc, mode_iv)
            # Also check the rest of the half-note span.
            for u in range(t, t + length):
                if clashes_ultima(midi, _sounding(melody, u)) or clashes_ultima(midi, _sounding(bass, u)):
                    midi = _safe_harm_midi(
                        role, pcs, harm_target, _sounding(melody, u), _sounding(bass, u), tonic_pc, mode_iv
                    )
                    break
            harmony.append(Event(t, midi, length))
            t += length
    harmony = _tie_adjacent(harmony)
    bass = _tie_adjacent(bass)
    # Pluck the lead: long skeleton values become 8th-note ornaments.
    # Bass and pads stay slow; the lead no longer drones on a held pulse.
    melody = _articulate_lead(melody, bass, harmony, tonic_pc, mode_iv, udigest[9] % 4)

    cadence = "iv-i" if plagal_coda else "VII-i"
    return Arrangement(
        list(tune),
        melody,
        bass,
        harmony,
        total_eighths,
        "ultima",
        bpm,
        1,
        total_units,
        f"{tonic_name} {mode_label} ({' '.join(family)}, coda {cadence})",
    )


def _pulse(freq: float, t: float, width: float) -> float:
    phase = (freq * t) % 1.0
    return 1.0 if phase < width else -1.0


def wav_ultima(arr: Arrangement) -> bytes:
    """Plucked soft-pulse lead, triangle bass, soft pads; 70-90 bpm."""
    sr = WAV_SR
    bpm = arr.bpm
    # Events are in eighths.
    eighth = max(1, int(round(sr * 30.0 / float(bpm))))
    total_samples = grid_len(arr) * eighth
    pcm = [0.0] * total_samples

    def env_pad(i: int, dur: int, fade: int) -> float:
        fade_n = min(fade, max(1, dur // 4))
        return min(min(i, dur - 1 - i) / float(fade_n), 1.0)

    def env_pluck(i: int, dur: int, sr: int) -> float:
        # Quick attack, decay to a low sustain, then release with a gap.
        attack = max(1, int(0.006 * sr))
        decay = max(attack + 1, int(0.45 * dur))
        release = max(1, int(0.22 * dur))
        sustain = 0.16
        if i < attack:
            return i / float(attack)
        if i < decay:
            frac = (i - attack) / float(max(1, decay - attack))
            return 1.0 - frac * (1.0 - sustain)
        if i >= dur - release:
            return sustain * max(0.0, (dur - 1 - i) / float(release))
        return sustain

    def add_note(ev: Event, wave: str, amp: float, duty: float, fade: int, pluck: bool) -> None:
        start = ev.start * eighth
        dur_full = ev.length * eighth
        dur = max(1, int(dur_full * duty))
        base_freq = 440.0 * 2.0 ** ((ev.midi - 69.0) / 12.0)
        for i in range(dur):
            idx = start + i
            if idx >= total_samples:
                break
            tt = i / sr
            env = env_pluck(i, dur, sr) if pluck else env_pad(i, dur, fade)
            if wave == "soft":
                # 25% pulse blended with triangle: lute-like, not a harsh square.
                s = 0.6 * _pulse(base_freq, tt, 0.25) + 0.4 * _triangle(base_freq, tt)
            elif wave == "pulse":
                s = _pulse(base_freq, tt, 0.45)
            else:
                s = _triangle(base_freq, tt)
            pcm[idx] += env * amp * s

    for ev in arr.melody:
        add_note(ev, "soft", 0.26, 0.78, 200, True)
    for ev in arr.bass:
        add_note(ev, "tri", 0.11, 0.96, 900, False)
    for ev in arr.harmony:
        add_note(ev, "pulse", 0.11, 0.97, 1000, False)

    samples: List[int] = []
    for v in pcm:
        sample = int(v * 32767.0)
        if sample > 32767:
            sample = 32767
        elif sample < -32767:
            sample = -32767
        samples.append(sample)
    data_len = len(samples) * 2
    w = bytearray()
    w += b"RIFF"
    w += (36 + data_len).to_bytes(4, "little")
    w += b"WAVEfmt "
    w += (16).to_bytes(4, "little")
    w += (1).to_bytes(2, "little")
    w += (1).to_bytes(2, "little")
    w += sr.to_bytes(4, "little")
    w += (sr * 2).to_bytes(4, "little")
    w += (2).to_bytes(2, "little")
    w += (16).to_bytes(2, "little")
    w += b"data"
    w += data_len.to_bytes(4, "little")
    for s in samples:
        w += (s & 0xFFFF).to_bytes(2, "little")
    return bytes(w)


def midi_ultima(arr: Arrangement, program: int = ULTIMA_MELODY_PROGRAM) -> bytes:
    """Format-1 MIDI, 3 tracks: plucked harp lead, cello bass, warm pad. No drums."""
    eighth = MIDI_PPQ // 2
    us = int(round(60_000_000 / float(arr.bpm)))
    us = max(1, min(0xFFFFFF, us))

    def track(events: Sequence[Event], channel: int, prog: int, name: bytes, velocity: int, *, tempo: bool = False) -> bytes:
        trk = bytearray()
        if tempo:
            trk += bytes([0x00, 0xFF, 0x51, 0x03, (us >> 16) & 0xFF, (us >> 8) & 0xFF, us & 0xFF])
            trk += bytes([0x00, 0xFF, 0x58, 0x04, 0x04, 0x02, 0x18, 0x08])
        trk += bytes([0x00, 0xFF, 0x03, len(name)])
        trk += name
        trk += bytes([0x00, 0xC0 | (channel & 0x0F), prog & 0x7F])
        t = 0
        for ev in events:
            _vlq((ev.start - t) * eighth, trk)
            key = ev.midi & 0x7F
            # Lead is plucked (short); pads and bass stay mostly legato.
            if channel == 0:
                sound = max(1, (ev.length * 5) // 8)  # ~62% of the eighth
            else:
                sound = ev.length if ev.length <= 1 else max(1, (ev.length * 19) // 20)
            trk += bytes([0x90 | (channel & 0x0F), key, velocity & 0x7F])
            _vlq(sound * eighth, trk)
            trk += bytes([0x80 | (channel & 0x0F), key, 0])
            t = ev.start + ev.length
        trk += bytes([0x00, 0xFF, 0x2F, 0x00])
        return bytes(trk)

    tracks = [
        track(arr.melody, 0, program & 0x7F, b"Octavo N3 ultima lead", 92, tempo=True),
        track(arr.bass, 1, ULTIMA_BASS_PROGRAM, b"Octavo N3 ultima bass", 64),
        track(arr.harmony, 2, ULTIMA_HARM_PROGRAM, b"Octavo N3 ultima pad", 70),
    ]
    m = bytearray()
    m += b"MThd"
    m += (6).to_bytes(4, "big")
    m += (1).to_bytes(2, "big")
    m += (3).to_bytes(2, "big")
    m += MIDI_PPQ.to_bytes(2, "big")
    for trk in tracks:
        m += b"MTrk"
        m += len(trk).to_bytes(4, "big")
        m += trk
    return bytes(m)


def _ultima_frames_per_eighth(bpm: int) -> int:
    # PAL CIA play is ~50 Hz in our PSID (flag 0x14).
    return max(8, int(round(50.0 * 30.0 / float(bpm))))


def player_ultima(arr: Arrangement) -> bytes:
    """C64 load image: plucked triangle lead, triangle bass, pulse pad."""
    n = grid_len(arr)
    if not 0 < n <= 128:
        raise ValueError("ultima tune must have 1..128 eighths")
    frames = _ultima_frames_per_eighth(arr.bpm)
    m_pitch, m_on, m_off = _grid(arr.melody, n)
    b_pitch, b_on, b_off = _grid(arr.bass, n)
    h_pitch, h_on, h_off = _grid(arr.harmony, n)
    starts = [(m_on[i] << 0) | (b_on[i] << 1) | (h_on[i] << 2) for i in range(n)]
    releases = [(m_off[i] << 0) | (b_off[i] << 1) | (h_off[i] << 2) for i in range(n)]

    WAVE_U = [TRIANGLE, TRIANGLE, PULSE]
    # Lead: fast attack, decay, low sustain, short release. Pads stay smoother.
    ADSR_U = [(0x09, 0x26), (0x48, 0xA8), (0x69, 0xA8)]
    PW_U = [0x400, 0, 0x600]

    a = _Asm(LOAD)
    a.abs(JMP_ABS, "init")
    a.abs(JMP_ABS, "play")

    a.label("init")
    a.imm(LDX_IMM, 0x18)
    a.imm(LDA_IMM, 0)
    a.label("uclr")
    a.absn(STA_ABX, SID_BASE)
    a.imp(DEX)
    a.br(BPL, "uclr")
    for v in range(3):
        base = SID_BASE + 7 * v
        a.imm(LDA_IMM, PW_U[v] & 0xFF)
        a.absn(STA_ABS, base + 2)
        a.imm(LDA_IMM, (PW_U[v] >> 8) & 0xFF)
        a.absn(STA_ABS, base + 3)
        a.imm(LDA_IMM, ADSR_U[v][0])
        a.absn(STA_ABS, base + 5)
        a.imm(LDA_IMM, ADSR_U[v][1])
        a.absn(STA_ABS, base + 6)
    a.imm(LDA_IMM, 0x0F)
    a.absn(STA_ABS, SID_BASE + 0x18)
    a.imm(LDA_IMM, 1)
    a.abs(STA_ABS, "ucounter")
    a.imm(LDA_IMM, (n - 1) & 0xFF)
    a.abs(STA_ABS, "ustep")
    a.imp(RTS)

    a.label("play")
    a.abs(DEC_ABS, "ucounter")
    a.br(BNE, "uheld")
    a.abs(LDX_ABS, "ustep")
    a.imp(INX)
    a.imm(CPX_IMM, n & 0xFF)
    a.br(BNE, "us1")
    a.imm(LDX_IMM, 0)
    a.label("us1")
    a.abs(STX_ABS, "ustep")
    a.imm(LDA_IMM, frames & 0xFF)
    a.abs(STA_ABS, "ucounter")
    a.abs(LDA_ABX, "umlo")
    a.absn(STA_ABS, SID_BASE)
    a.abs(LDA_ABX, "umhi")
    a.absn(STA_ABS, SID_BASE + 1)
    a.abs(LDA_ABX, "ublo")
    a.absn(STA_ABS, SID_BASE + 7)
    a.abs(LDA_ABX, "ubhi")
    a.absn(STA_ABS, SID_BASE + 8)
    a.abs(LDA_ABX, "uhlo")
    a.absn(STA_ABS, SID_BASE + 14)
    a.abs(LDA_ABX, "uhhi")
    a.absn(STA_ABS, SID_BASE + 15)
    a.abs(LDA_ABX, "ustarts")
    a.imm(AND_IMM, 1)
    a.br(0xF0, "unos0")
    a.imm(LDA_IMM, WAVE_U[0] | GATE)
    a.absn(STA_ABS, SID_BASE + 4)
    a.label("unos0")
    a.abs(LDA_ABX, "ustarts")
    a.imm(AND_IMM, 2)
    a.br(0xF0, "unos1")
    a.imm(LDA_IMM, WAVE_U[1] | GATE)
    a.absn(STA_ABS, SID_BASE + 11)
    a.label("unos1")
    a.abs(LDA_ABX, "ustarts")
    a.imm(AND_IMM, 4)
    a.br(0xF0, "unos2")
    a.imm(LDA_IMM, WAVE_U[2] | GATE)
    a.absn(STA_ABS, SID_BASE + 18)
    a.label("unos2")
    a.imp(RTS)

    a.label("uheld")
    # Pluck the lead: gate off about halfway through the eighth.
    a.abs(LDA_ABS, "ucounter")
    a.imm(CMP_IMM, max(2, frames // 2))
    a.br(BNE, "urel_pads")
    a.imm(LDA_IMM, WAVE_U[0])
    a.absn(STA_ABS, SID_BASE + 4)
    a.label("urel_pads")
    a.abs(LDA_ABS, "ucounter")
    a.imm(CMP_IMM, 2)
    a.br(BNE, "udone")
    a.abs(LDX_ABS, "ustep")
    a.abs(LDA_ABX, "ureleases")
    a.imm(AND_IMM, 2)
    a.br(0xF0, "unor1")
    a.imm(LDA_IMM, WAVE_U[1])
    a.absn(STA_ABS, SID_BASE + 11)
    a.label("unor1")
    a.abs(LDA_ABX, "ureleases")
    a.imm(AND_IMM, 4)
    a.br(0xF0, "udone")
    a.imm(LDA_IMM, WAVE_U[2])
    a.absn(STA_ABS, SID_BASE + 18)
    a.label("udone")
    a.imp(RTS)

    def lo(notes):
        return [sid_freq(x) & 0xFF for x in notes]

    def hi(notes):
        return [(sid_freq(x) >> 8) & 0xFF for x in notes]

    tables = [
        ("umlo", lo(m_pitch)),
        ("umhi", hi(m_pitch)),
        ("ublo", lo(b_pitch)),
        ("ubhi", hi(b_pitch)),
        ("uhlo", lo(h_pitch)),
        ("uhhi", hi(h_pitch)),
        ("ustarts", starts),
        ("ureleases", releases),
        ("ucounter", [0]),
        ("ustep", [0]),
    ]
    for name, data in tables:
        a.label(name)
        a.bytes_(data)
    return a.finish()


def psid_ultima(arr: Arrangement) -> bytes:
    h = bytearray()
    h += b"PSID"
    h += (2).to_bytes(2, "big")
    h += (0x7C).to_bytes(2, "big")
    h += (0).to_bytes(2, "big")
    h += INIT.to_bytes(2, "big")
    h += PLAY.to_bytes(2, "big")
    h += (1).to_bytes(2, "big")
    h += (1).to_bytes(2, "big")
    h += (0).to_bytes(4, "big")
    h += _field("Octavo N3 ultima")
    h += _field("n3_music (original style)")
    h += _field("2026 homemade, not for secrets")
    h += (0x0014).to_bytes(2, "big")
    h += b"\x00\x00"
    h += (0).to_bytes(2, "big")
    if len(h) != 0x7C:
        raise RuntimeError(f"PSID header is {len(h)} bytes, expected 0x7C")
    h += LOAD.to_bytes(2, "little")
    h += player_ultima(arr)
    return bytes(h)


def render_ultima(blob: bytes, *, raw: bool = False, program: int = ULTIMA_MELODY_PROGRAM) -> dict:
    arr = voices_from_blob_ultima(blob, raw=raw)
    return {
        "notes": notes_text(arr.tune),
        "voices": voices_text(arr),
        "tune": arr.tune,
        "arrangement": arr,
        "style": "ultima",
        "mode": arr.mode_name,
        "bpm": arr.bpm,
        "wav": wav_ultima(arr),
        "midi": midi_ultima(arr, program),
        "sid": psid_ultima(arr),
    }


# ---------------------------------------------------------------------------
# Castle-style arrangement (original music, display only)
# ---------------------------------------------------------------------------
# Texture inspired by cheerful early-1980s Universal/arcade title music
# (bright 50% square lead, oom-pah bass, short stabs, 140-170 bpm major).
# Original music only: no Mr. Do's Castle melody, bass line, or quoted
# public-domain tune is copied or approximated.
# ---------------------------------------------------------------------------

CASTLE_DOMAIN = b"Octavo N3 castle v1"
CASTLE_MELODY_PROGRAM = 80  # Square Lead
CASTLE_BASS_PROGRAM = 38  # Synth Bass 1
CASTLE_HARM_PROGRAM = 81  # Saw Lead (short stabs)
MAJOR = (0, 2, 4, 5, 7, 9, 11)
CASTLE_TONICS = (0, 5, 7, 2)  # C, F, G, D
# Generic major progressions (not from a game).
CASTLE_PROGRESSIONS = (
    ("I", "IV", "V", "I"),
    ("I", "V", "vi", "IV"),
    ("I", "vi", "IV", "V"),
    ("I", "IV", "I", "V"),
)
CASTLE_CHORD = {
    "I": (0, 4, 7),
    "ii": (2, 5, 9),
    "IV": (5, 9, 0),
    "V": (7, 11, 2),
    "vi": (9, 0, 4),
}
# 8-eighth bouncy patterns: staccato 8ths and quarter+eighth hops (sum 8).
CASTLE_RHYTHMS = (
    (1, 1, 1, 1, 1, 1, 1, 1),
    (2, 1, 1, 2, 1, 1),
    (1, 1, 2, 1, 1, 2),
    (2, 1, 1, 1, 1, 2),
    (1, 1, 1, 1, 2, 1, 1),
    (2, 2, 1, 1, 1, 1),
    (1, 1, 2, 2, 1, 1),
    (2, 1, 1, 2, 2),
)
CASTLE_BARS = 10
CASTLE_BAR = 8


def clashes_castle(a: Optional[int], b: Optional[int]) -> bool:
    """Seconds and sevenths (harsh against a bright major texture)."""
    return clashes(a, b)


def _castle_scale(tonic_pc: int, lo: int, hi: int) -> List[int]:
    return [m for m in range(lo, hi + 1) if ((m % 12) - tonic_pc) % 12 in MAJOR]


def _castle_degree(tonic_pc: int, degree: int, lo: int = 60, hi: int = 84) -> int:
    """Scale degree 0 = tonic near C4; may span about two octaves."""
    pool = _castle_scale(tonic_pc, lo, hi)
    if not pool:
        return lo
    base = next((m for m in pool if m % 12 == tonic_pc), pool[0])
    idx = pool.index(base)
    return pool[max(0, min(len(pool) - 1, idx + degree))]


def _castle_pc_midi(pc: int, lo: int, hi: int, prefer_low: bool = True) -> int:
    chosen = None
    for octv in range(0, 8):
        m = (pc % 12) + 12 * octv
        if lo <= m <= hi:
            if prefer_low:
                return m
            chosen = m
    if chosen is not None:
        return chosen
    return (pc % 12) + (36 if prefer_low else 60)


def _castle_ok(pitch: int, t: int, bass: Sequence[Event], harm: Sequence[Event]) -> bool:
    return not clashes_castle(pitch, _sounding(bass, t)) and not clashes_castle(
        pitch, _sounding(harm, t)
    )


def _castle_ok_span(
    pitch: int, start: int, length: int, bass: Sequence[Event], harm: Sequence[Event]
) -> bool:
    return all(_castle_ok(pitch, start + i, bass, harm) for i in range(max(1, length)))


def _castle_safe_tone(
    tonic_pc: int,
    chord_pcs: Sequence[int],
    t: int,
    bass: Sequence[Event],
    harm: Sequence[Event],
    prefer: Optional[int] = None,
    lo: int = 60,
    hi: int = 84,
    length: int = 1,
) -> int:
    pool = _castle_scale(tonic_pc, lo, hi)
    preferred: List[int] = []
    if prefer is not None:
        preferred.append(prefer)
    preferred.extend(m for m in pool if (m % 12) in chord_pcs)
    preferred.extend(pool)
    seen = set()
    for m in preferred:
        if m in seen:
            continue
        seen.add(m)
        if _castle_ok_span(m, t, length, bass, harm):
            return m
    return prefer if prefer is not None else pool[0]


def _break_castle_drones(
    melody: Sequence[Event],
    bass: Sequence[Event],
    harmony: Sequence[Event],
    tonic_pc: int,
    bars: Sequence[str],
) -> List[Event]:
    """No identical lead pitch may sound for more than one beat (2 eighths)."""
    total = CASTLE_BARS * CASTLE_BAR
    grid: List[Optional[int]] = [None] * total
    for ev in melody:
        for i in range(ev.length):
            if 0 <= ev.start + i < total:
                grid[ev.start + i] = ev.midi
    for t in range(total):
        if t < 2 or grid[t] is None:
            continue
        if grid[t] == grid[t - 1] == grid[t - 2]:
            # Prefer a neighbor of the drone pitch.
            cur = grid[t]
            cands = []
            for delta in (1, -1, 2, -2, 3, -3, 4, -4, 5, -5, 7, -7):
                cands.append(cur + delta)
            cands.extend(_castle_scale(tonic_pc, 60, 84))
            chosen = cur
            for cand in cands:
                if cand == cur or not (55 <= cand <= 86):
                    continue
                if ((cand % 12) - tonic_pc) % 12 not in MAJOR:
                    continue
                if _castle_ok(cand, t, bass, harmony):
                    chosen = cand
                    break
            grid[t] = chosen
    # Rebuild, tying at most 2 identical eighths.
    out: List[Event] = []
    t = 0
    while t < total:
        pitch = grid[t]
        if pitch is None:
            t += 1
            continue
        length = 1
        if t + 1 < total and grid[t + 1] == pitch:
            length = 2
        out.append(Event(t, pitch, length))
        t += length
    return out


def voices_from_blob_castle(blob: bytes, *, raw: bool = False) -> Arrangement:
    """Original bouncy major arrangement in an early-80s arcade spirit."""
    data = _blob_bytes(blob, raw)
    tune = tune_from_blob(data, raw=True)
    digest = hashlib.sha256(CASTLE_DOMAIN + data).digest()
    tonic_pc = CASTLE_TONICS[digest[0] % len(CASTLE_TONICS)]
    bpm = 140 + (digest[1] % 31)  # 140..170
    prog = CASTLE_PROGRESSIONS[digest[2] % len(CASTLE_PROGRESSIONS)]
    # 8 body bars (two times the 4-bar progression) + 2-bar IV/V–I cadence.
    family = list(prog) + list(prog)
    cadence = ("V", "I") if (digest[3] & 1) == 0 else ("IV", "I")
    bars = family + list(cadence)
    assert len(bars) == CASTLE_BARS

    def chord_pcs(label: str) -> List[int]:
        ivs = CASTLE_CHORD[label]
        return [((tonic_pc + iv) % 12) for iv in ivs]

    # --- bass: oom-pah, root on the beat, fifth/chord on the offbeat ---
    bass: List[Event] = []
    for bar, label in enumerate(bars):
        pcs = chord_pcs(label)
        root, third, fifth = pcs[0], pcs[1], pcs[2]
        # Digitized slight variety: offbeat prefers fifth, sometimes the 3rd.
        off_pc = third if ((digest[(4 + bar) % 32] >> 2) & 1) else fifth
        for e in range(CASTLE_BAR):
            t = bar * CASTLE_BAR + e
            if e % 2 == 0:
                pitch = _castle_pc_midi(root, 36, 48, prefer_low=True)
            else:
                pitch = _castle_pc_midi(off_pc, 43, 55, prefer_low=False)
            bass.append(Event(t, pitch, 1))

    # --- harmony: short 3rd/5th stabs on the four beats, rests offbeat ---
    harmony: List[Event] = []
    for bar, label in enumerate(bars):
        pcs = chord_pcs(label)
        third, fifth = pcs[1], pcs[2]
        for beat, e in enumerate((0, 2, 4, 6)):
            t = bar * CASTLE_BAR + e
            use_fifth = ((digest[(8 + bar + beat) % 32] >> 1) & 1) == 1
            pc = fifth if use_fifth else third
            pitch = _castle_pc_midi(pc, 60, 76, prefer_low=False)
            # If the stab would clash with a later lead we fix after the lead.
            harmony.append(Event(t, pitch, 1))

    # --- melody: bouncy 8ths and hops, chord tones on landings ---
    # 8-degree cell from the digest, then question/answer over 2-bar phrases.
    cell = [digest[16 + i] % 8 for i in range(8)]
    # Nudge the cell so strong beats lean on 1, 3, 5 (degrees 0, 2, 4).
    for i in (0, 2, 4, 6):
        if cell[i] % 2 == 1:
            cell[i] = (cell[i] + 1) % 7  # stay in 0..6 then not always 7

    melody: List[Event] = []
    for bar, label in enumerate(bars):
        pcs = chord_pcs(label)
        rhythm = CASTLE_RHYTHMS[digest[(10 + bar) % 32] % len(CASTLE_RHYTHMS)]
        if bar >= 8:
            # Cadence: simpler hop into the tonic.
            rhythm = (2, 1, 1, 2, 1, 1) if bar == 8 else (2, 2, 1, 1, 2)
        # Phrase answer (odd bars in the body) flips the cell up a step.
        if bar < 8 and bar % 2 == 1:
            degs = [(d + 2) % 7 for d in cell]
        elif bar == 8:
            degs = [4, 4, 2, 2, 5, 6]  # 5–3–6–7, padded by rhythm length
        elif bar == 9:
            degs = [4, 2, 1, 0, 0]  # 5–3–2–1, land on tonic
        else:
            degs = list(cell)
        # Expand degrees to one per rhythm event.
        while len(degs) < len(rhythm):
            degs.append(degs[-1] if degs else 0)
        t = bar * CASTLE_BAR
        for ev_i, (length, deg) in enumerate(zip(rhythm, degs)):
            # Landings (length 2, or beat 1/3) prefer a chord tone close to deg.
            pitch = _castle_degree(tonic_pc, deg)
            if length >= 2 or (t % 8) in (0, 4):
                # Snap toward the nearest chord tone in-range if deg isn't one.
                if (pitch % 12) not in pcs:
                    pitch = _castle_safe_tone(tonic_pc, pcs, t, bass, harmony, prefer=pitch)
            # No three identical eighths in a row.
            if len(melody) >= 2 and melody[-1].midi == melody[-2].midi == pitch:
                up = _castle_degree(tonic_pc, deg + 1)
                down = _castle_degree(tonic_pc, max(0, deg - 1))
                pitch = up if up != pitch else down
            melody.append(Event(t, pitch, length))
            t += length
        if t != (bar + 1) * CASTLE_BAR:
            raise RuntimeError(f"castle bar {bar} rhythm summed to {t - bar * CASTLE_BAR}")

    # Clash repair: move lead, then harmony, over each sounding eighth.
    total = CASTLE_BARS * CASTLE_BAR
    repaired: List[Event] = []
    for ev in melody:
        pitch = ev.midi
        if not _castle_ok_span(pitch, ev.start, ev.length, bass, harmony):
            pcs = chord_pcs(bars[ev.start // CASTLE_BAR])
            pitch = _castle_safe_tone(
                tonic_pc, pcs, ev.start, bass, harmony, prefer=ev.midi, length=ev.length
            )
        repaired.append(Event(ev.start, pitch, ev.length))
    melody = _break_castle_drones(repaired, bass, harmony, tonic_pc, bars)

    harm_fixed: List[Event] = []
    for ev in harmony:
        pitch = ev.midi
        m = _sounding(melody, ev.start)
        b = _sounding(bass, ev.start)
        if clashes_castle(pitch, m) or clashes_castle(pitch, b):
            bar = ev.start // CASTLE_BAR
            pcs = chord_pcs(bars[bar])
            pool = [_castle_pc_midi(pc, 55, 79, prefer_low=False) for pc in pcs]
            pool += _castle_scale(tonic_pc, 55, 79)
            chosen = pitch
            for cand in pool:
                if not clashes_castle(cand, m) and not clashes_castle(cand, b):
                    chosen = cand
                    break
            pitch = chosen
        harm_fixed.append(Event(ev.start, pitch, ev.length))
    harmony = harm_fixed

    tonic_name = PITCH_NAMES[tonic_pc]
    mode_name = f"{tonic_name} major ({' '.join(prog)}, cadence {'-'.join(cadence)})"
    return Arrangement(
        tune=tune,
        melody=melody,
        bass=bass,
        harmony=harmony,
        total_eighths=total,
        style="castle",
        bpm=bpm,
        unit=1,
        total_units=total,
        mode_name=mode_name,
    )


def _pack_wav(samples: Sequence[int], sr: int) -> bytes:
    data_len = len(samples) * 2
    w = bytearray()
    w += b"RIFF"
    w += (36 + data_len).to_bytes(4, "little")
    w += b"WAVEfmt "
    w += (16).to_bytes(4, "little")
    w += (1).to_bytes(2, "little")
    w += (1).to_bytes(2, "little")
    w += sr.to_bytes(4, "little")
    w += (sr * 2).to_bytes(4, "little")
    w += (2).to_bytes(2, "little")
    w += (16).to_bytes(2, "little")
    w += b"data"
    w += data_len.to_bytes(4, "little")
    for s in samples:
        w += (s & 0xFFFF).to_bytes(2, "little")
    return bytes(w)


def wav_castle(arr: Arrangement) -> bytes:
    """Bright 50% square lead, oom-pah bass, short stabs; 140-170 bpm."""
    sr = WAV_SR
    bpm = arr.bpm
    eighth = max(1, int(round(sr * 30.0 / float(bpm))))
    total_samples = grid_len(arr) * eighth
    pcm = [0.0] * total_samples
    swing = max(1, int(0.16 * eighth))

    def env_staccato(i: int, dur: int) -> float:
        attack = max(1, int(0.004 * sr))
        decay = max(attack + 1, int(0.40 * dur))
        release = max(1, int(0.20 * dur))
        sustain = 0.12
        if i < attack:
            return i / float(attack)
        if i < decay:
            frac = (i - attack) / float(max(1, decay - attack))
            return 1.0 - frac * (1.0 - sustain)
        if i >= dur - release:
            return sustain * max(0.0, (dur - 1 - i) / float(release))
        return sustain

    def add_note(ev: Event, wave: str, amp: float, duty: float, do_swing: bool) -> None:
        delay = swing if (do_swing and ev.length == 1 and ev.start % 2 == 1) else 0
        start = ev.start * eighth + delay
        dur_full = ev.length * eighth - delay
        dur = max(1, int(max(1, dur_full) * duty))
        if start + dur > (ev.start + ev.length) * eighth:
            dur = max(1, (ev.start + ev.length) * eighth - start)
        freq = 440.0 * 2.0 ** ((ev.midi - 69.0) / 12.0)
        for i in range(dur):
            idx = start + i
            if idx >= total_samples:
                break
            tt = i / sr
            env = env_staccato(i, dur)
            if wave == "square":
                s = _pulse(freq, tt, 0.50)
            elif wave == "pulse":
                s = _pulse(freq, tt, 0.45)
            else:
                s = _triangle(freq, tt)
            pcm[idx] += env * amp * s

    for ev in arr.melody:
        duty = 0.72 if ev.length >= 2 else 0.52
        add_note(ev, "square", 0.24, duty, True)
    for ev in arr.bass:
        add_note(ev, "tri", 0.13, 0.55, False)
    for ev in arr.harmony:
        add_note(ev, "pulse", 0.12, 0.42, False)

    samples: List[int] = []
    for v in pcm:
        sample = int(v * 32767.0)
        if sample > 32767:
            sample = 32767
        elif sample < -32767:
            sample = -32767
        samples.append(sample)
    return _pack_wav(samples, sr)


def midi_castle(arr: Arrangement, program: int = CASTLE_MELODY_PROGRAM) -> bytes:
    """Format-1 MIDI: square lead, synth bass, saw stabs. No drums."""
    eighth = MIDI_PPQ // 2
    us = int(round(60_000_000 / float(arr.bpm)))
    us = max(1, min(0xFFFFFF, us))

    def track(events: Sequence[Event], channel: int, prog: int, name: bytes, velocity: int, *, tempo: bool = False) -> bytes:
        trk = bytearray()
        if tempo:
            trk += bytes([0x00, 0xFF, 0x51, 0x03, (us >> 16) & 0xFF, (us >> 8) & 0xFF, us & 0xFF])
            trk += bytes([0x00, 0xFF, 0x58, 0x04, 0x04, 0x02, 0x18, 0x08])
        trk += bytes([0x00, 0xFF, 0x03, len(name)])
        trk += name
        trk += bytes([0x00, 0xC0 | (channel & 0x0F), prog & 0x7F])
        t = 0
        for ev in events:
            _vlq((ev.start - t) * eighth, trk)
            key = ev.midi & 0x7F
            # Staccato: hops keep a little more length than 8ths.
            if ev.length >= 2:
                sound = max(1, (ev.length * 5) // 8)
            else:
                sound = max(1, (ev.length * 1) // 2)
            trk += bytes([0x90 | (channel & 0x0F), key, velocity & 0x7F])
            _vlq(sound * eighth, trk)
            trk += bytes([0x80 | (channel & 0x0F), key, 0])
            t = ev.start + ev.length
        trk += bytes([0x00, 0xFF, 0x2F, 0x00])
        return bytes(trk)

    tracks = [
        track(arr.melody, 0, program & 0x7F, b"Octavo N3 castle lead", 100, tempo=True),
        track(arr.bass, 1, CASTLE_BASS_PROGRAM, b"Octavo N3 castle bass", 80),
        track(arr.harmony, 2, CASTLE_HARM_PROGRAM, b"Octavo N3 castle stabs", 70),
    ]
    m = bytearray()
    m += b"MThd"
    m += (6).to_bytes(4, "big")
    m += (1).to_bytes(2, "big")
    m += (3).to_bytes(2, "big")
    m += MIDI_PPQ.to_bytes(2, "big")
    for trk in tracks:
        m += b"MTrk"
        m += len(trk).to_bytes(4, "big")
        m += trk
    return bytes(m)


def _castle_frames_per_eighth(bpm: int) -> int:
    return max(8, int(round(50.0 * 30.0 / float(bpm))))


def player_castle(arr: Arrangement) -> bytes:
    """C64 load image: 50% pulse lead, triangle bass, pulse stabs."""
    n = grid_len(arr)
    if not 0 < n <= 128:
        raise ValueError("castle tune must have 1..128 eighths")
    frames = _castle_frames_per_eighth(arr.bpm)
    m_pitch, m_on, m_off = _grid(arr.melody, n)
    b_pitch, b_on, b_off = _grid(arr.bass, n)
    h_pitch, h_on, h_off = _grid(arr.harmony, n)
    starts = [(m_on[i] << 0) | (b_on[i] << 1) | (h_on[i] << 2) for i in range(n)]
    releases = [(m_off[i] << 0) | (b_off[i] << 1) | (h_off[i] << 2) for i in range(n)]

    WAVE_C = [PULSE, TRIANGLE, PULSE]
    ADSR_C = [(0x08, 0x25), (0x08, 0x36), (0x08, 0x16)]
    PW_C = [0x800, 0, 0x800]

    a = _Asm(LOAD)
    a.abs(JMP_ABS, "init")
    a.abs(JMP_ABS, "play")

    a.label("init")
    a.imm(LDX_IMM, 0x18)
    a.imm(LDA_IMM, 0)
    a.label("cclr")
    a.absn(STA_ABX, SID_BASE)
    a.imp(DEX)
    a.br(BPL, "cclr")
    for v in range(3):
        base = SID_BASE + 7 * v
        a.imm(LDA_IMM, PW_C[v] & 0xFF)
        a.absn(STA_ABS, base + 2)
        a.imm(LDA_IMM, (PW_C[v] >> 8) & 0xFF)
        a.absn(STA_ABS, base + 3)
        a.imm(LDA_IMM, ADSR_C[v][0])
        a.absn(STA_ABS, base + 5)
        a.imm(LDA_IMM, ADSR_C[v][1])
        a.absn(STA_ABS, base + 6)
    a.imm(LDA_IMM, 0x0F)
    a.absn(STA_ABS, SID_BASE + 0x18)
    a.imm(LDA_IMM, 1)
    a.abs(STA_ABS, "ccounter")
    a.imm(LDA_IMM, (n - 1) & 0xFF)
    a.abs(STA_ABS, "cstep")
    a.imp(RTS)

    a.label("play")
    a.abs(DEC_ABS, "ccounter")
    a.br(BNE, "cheld")
    a.abs(LDX_ABS, "cstep")
    a.imp(INX)
    a.imm(CPX_IMM, n & 0xFF)
    a.br(BNE, "cs1")
    a.imm(LDX_IMM, 0)
    a.label("cs1")
    a.abs(STX_ABS, "cstep")
    a.imm(LDA_IMM, frames & 0xFF)
    a.abs(STA_ABS, "ccounter")
    a.abs(LDA_ABX, "cmlo")
    a.absn(STA_ABS, SID_BASE)
    a.abs(LDA_ABX, "cmhi")
    a.absn(STA_ABS, SID_BASE + 1)
    a.abs(LDA_ABX, "cblo")
    a.absn(STA_ABS, SID_BASE + 7)
    a.abs(LDA_ABX, "cbhi")
    a.absn(STA_ABS, SID_BASE + 8)
    a.abs(LDA_ABX, "chlo")
    a.absn(STA_ABS, SID_BASE + 14)
    a.abs(LDA_ABX, "chhi")
    a.absn(STA_ABS, SID_BASE + 15)
    a.abs(LDA_ABX, "cstarts")
    a.imm(AND_IMM, 1)
    a.br(0xF0, "cnos0")
    a.imm(LDA_IMM, WAVE_C[0] | GATE)
    a.absn(STA_ABS, SID_BASE + 4)
    a.label("cnos0")
    a.abs(LDA_ABX, "cstarts")
    a.imm(AND_IMM, 2)
    a.br(0xF0, "cnos1")
    a.imm(LDA_IMM, WAVE_C[1] | GATE)
    a.absn(STA_ABS, SID_BASE + 11)
    a.label("cnos1")
    a.abs(LDA_ABX, "cstarts")
    a.imm(AND_IMM, 4)
    a.br(0xF0, "cnos2")
    a.imm(LDA_IMM, WAVE_C[2] | GATE)
    a.absn(STA_ABS, SID_BASE + 18)
    a.label("cnos2")
    a.imp(RTS)

    a.label("cheld")
    # Staccato: gate off about halfway through the release eighth.
    a.abs(LDA_ABS, "ccounter")
    a.imm(CMP_IMM, max(2, frames // 2))
    a.br(BNE, "cdone")
    a.abs(LDX_ABS, "cstep")
    a.abs(LDA_ABX, "creleases")
    a.imm(AND_IMM, 1)
    a.br(0xF0, "cnor0")
    a.imm(LDA_IMM, WAVE_C[0])
    a.absn(STA_ABS, SID_BASE + 4)
    a.label("cnor0")
    a.abs(LDA_ABX, "creleases")
    a.imm(AND_IMM, 2)
    a.br(0xF0, "cnor1")
    a.imm(LDA_IMM, WAVE_C[1])
    a.absn(STA_ABS, SID_BASE + 11)
    a.label("cnor1")
    a.abs(LDA_ABX, "creleases")
    a.imm(AND_IMM, 4)
    a.br(0xF0, "cdone")
    a.imm(LDA_IMM, WAVE_C[2])
    a.absn(STA_ABS, SID_BASE + 18)
    a.label("cdone")
    a.imp(RTS)

    def lo(notes):
        return [sid_freq(x) & 0xFF for x in notes]

    def hi(notes):
        return [(sid_freq(x) >> 8) & 0xFF for x in notes]

    tables = [
        ("cmlo", lo(m_pitch)),
        ("cmhi", hi(m_pitch)),
        ("cblo", lo(b_pitch)),
        ("cbhi", hi(b_pitch)),
        ("chlo", lo(h_pitch)),
        ("chhi", hi(h_pitch)),
        ("cstarts", starts),
        ("creleases", releases),
        ("ccounter", [0]),
        ("cstep", [0]),
    ]
    for name, data in tables:
        a.label(name)
        a.bytes_(data)
    return a.finish()


def psid_castle(arr: Arrangement) -> bytes:
    h = bytearray()
    h += b"PSID"
    h += (2).to_bytes(2, "big")
    h += (0x7C).to_bytes(2, "big")
    h += (0).to_bytes(2, "big")
    h += INIT.to_bytes(2, "big")
    h += PLAY.to_bytes(2, "big")
    h += (1).to_bytes(2, "big")
    h += (1).to_bytes(2, "big")
    h += (0).to_bytes(4, "big")
    h += _field("Octavo N3 castle")
    h += _field("n3_music (original style)")
    h += _field("2026 homemade, not for secrets")
    h += (0x0014).to_bytes(2, "big")
    h += b"\x00\x00"
    h += (0).to_bytes(2, "big")
    if len(h) != 0x7C:
        raise RuntimeError(f"PSID header is {len(h)} bytes, expected 0x7C")
    h += LOAD.to_bytes(2, "little")
    h += player_castle(arr)
    return bytes(h)


def render_castle(blob: bytes, *, raw: bool = False, program: int = CASTLE_MELODY_PROGRAM) -> dict:
    arr = voices_from_blob_castle(blob, raw=raw)
    return {
        "notes": notes_text(arr.tune),
        "voices": voices_text(arr),
        "tune": arr.tune,
        "arrangement": arr,
        "style": "castle",
        "mode": arr.mode_name,
        "bpm": arr.bpm,
        "wav": wav_castle(arr),
        "midi": midi_castle(arr, program),
        "sid": psid_castle(arr),
    }



def render(blob: bytes, *, raw: bool = False, program: Optional[int] = None, style: str = "earworm") -> dict:
    """Return notes / voices / wav / midi / sid for a blob. Display only.

    Default style is earworm and is byte-identical to the 3-voice renderer.
    style='ultima' selects the original Ultima-textured arrangement.
    style='castle' selects an original cheerful early-80s arcade arrangement.
    """
    style = parse_style(style)
    if program is None:
        if style == "ultima":
            program = ULTIMA_MELODY_PROGRAM
        elif style == "castle":
            program = CASTLE_MELODY_PROGRAM
        else:
            program = DEFAULT_PROGRAM
    if style == "ultima":
        return render_ultima(blob, raw=raw, program=program)
    if style == "castle":
        return render_castle(blob, raw=raw, program=program)
    arr = voices_from_blob(blob, raw=raw)
    return {
        "notes": notes_text(arr.tune),
        "voices": voices_text(arr),
        "tune": arr.tune,
        "arrangement": arr,
        "style": "earworm",
        "wav": wav(arr),
        "midi": midi(arr, program),
        "sid": psid(arr),
    }
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
            "Use --style ultima for an original chiptune texture in the spirit "
            "of 1980s Ultima III/IV (not their tunes). "
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
        default=None,
        help="General MIDI program for the melody track (0..127; default 0 piano, 46 harp for ultima, 80 square for castle)",
    )
    p.add_argument(
        "--style",
        default="earworm",
        help="earworm (default, unchanged), ultima, or castle (original chiptune textures)",
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
        out = render(blob, raw=args.raw, program=args.program, style=args.style)
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
