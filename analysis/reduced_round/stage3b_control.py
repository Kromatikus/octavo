"""Stage 3b: positive control for the linear test (shows the method detects real correlations)."""
import json, os, math, numpy as np
from octavo_np import lab_schedule
rng = np.random.default_rng(int.from_bytes(os.urandom(8), "big"))
PAR = np.array([bin(x).count("1") & 1 for x in range(256)], np.uint8)
N = 1 << 16; lines = []; out = {}
for stop in ("key+S", "butterfly", "shell"):
    ns = lab_schedule(rng); P = rng.integers(0, 256, (N, 128), dtype=np.uint8); Y = ns.enc_frac(P, 0, stop)
    # byte 0 all 255 input masks vs all 1024 output bits
    X = 1 - 2.0 * PAR[np.bitwise_and(P[:, 0:1], np.arange(1, 256, dtype=np.uint8)[None, :])]
    Yb = 1 - 2.0 * np.unpackbits(Y, axis=1, bitorder="little")
    C = (X.T.astype(np.float32) @ Yb.astype(np.float32)) / N
    z = np.abs(C).max() * math.sqrt(N)
    s = f"control r=0 checkpoint '{stop}': max |corr| {np.abs(C).max():.4f} (z {z:.1f}), #z>6: {(np.abs(C)*math.sqrt(N)>6).sum()}"
    print(s); lines.append(s); out[stop] = {"max_abs_corr": float(np.abs(C).max()), "z": float(z)}
open("stage3b_output.txt", "w").write("\n".join(lines) + "\n"); json.dump(out, open("stage3b_results.json", "w"), indent=1)
