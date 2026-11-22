#!/usr/bin/env python3
"""Compare WAV renders of an `octavo hear --sid` tune (e.g. ours vs sidplayfp's).
Usage: python3 -B tools/check_sid_render.py "NOTES TEXT" A.wav [B.wav ...]
For each WAV and each melody step (12 PAL frames per eighth, first pass only), checks that the
melody fundamental is a clear spectral peak (>= 20 dB over the window's median), and reports the
per-step spectral cosine similarity of every WAV against the first one."""
import sys, wave
import numpy as np

NAMES = {"C": 0, "D": 2, "E": 4, "F": 5, "G": 7, "A": 9, "B": 11}
def midi(n): return 12 * (int(n[1:]) + 1) + NAMES[n[0]]

notes = [(midi(n.rstrip("-")), 2 if n.endswith("-") else 1) for n in sys.argv[1].split()] * 2  # 2 passes: the loop
FR = 1 / (985248 / 19656)  # PAL frame seconds
def load(p):
    with wave.open(p) as w:
        assert w.getsampwidth() == 2
        x = np.frombuffer(w.readframes(w.getnframes()), dtype="<i2").astype(float)
        if w.getnchannels() > 1: x = x.reshape(-1, w.getnchannels()).mean(1)
        # skip a player's leading silence (sidplayfp starts with ~1 s of it)
        on = int(np.argmax(np.abs(x) > 200))
        return x[on:], w.getframerate(), on

specs, ok_all = [], True
for p in sys.argv[2:]:
    x, sr, on = load(p)
    frame, rows, good = 0, [], 0
    for m, l in notes:
        a, b = int((frame + 3) * FR * sr), int((frame + 12 * l - 3) * FR * sr)
        seg = x[a:b] * np.hanning(b - a)
        n = 1 << 15
        S = np.abs(np.fft.rfft(seg, n))
        f = 440 * 2 ** ((m - 69) / 12)
        k = int(round(f * n / sr))
        pk = S[k - 6:k + 7].max()
        db = 20 * np.log10((pk + 1e-9) / (np.median(S[: int(5000 * n / sr)]) + 1e-9))
        good += db >= 20
        rows.append(S[: int(5000 * n / sr)] / (np.linalg.norm(S[: int(5000 * n / sr)]) + 1e-12))
        frame += 12 * l
    print(f"{p}: {len(x)/sr:.2f} s after {on/sr:.3f} s lead-in, {sr} Hz; melody fundamental is a clear peak in {good}/{len(notes)} steps")
    ok_all &= good == len(notes)
    specs.append(rows)
for i in range(1, len(specs)):
    sims = [float(np.dot(u, v)) for u, v in zip(specs[0], specs[i])]
    print(f"spectral similarity {sys.argv[2]} vs {sys.argv[2+i]}: min {min(sims):.3f}, mean {np.mean(sims):.3f}")
sys.exit(0 if ok_all else 1)
