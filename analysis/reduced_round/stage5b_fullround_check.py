"""Stage 5b: direct confirmation at full rounds (r=1, 2 peeled) that d=16/20 cubes give no zero-sum bias."""
import json, os, time, numpy as np
from octavo_np import lab_schedule
from stage2b_peeled_lib import cross_unmix
import stage5_lib as L
rng = np.random.default_rng(int.from_bytes(os.urandom(8), "big")); L.rng = rng
lines = []; out = []
t0 = time.time()
for full in (1, 2):
    for flavor in ("packed", "spread"):
        for d in (16, 20):
            fr = []
            for t in range(3):
                ns = lab_schedule(rng); Y = cross_unmix(ns.enc_frac(L.cube_set(d, flavor), full, None))
                fr.append(1 - np.unpackbits(np.bitwise_xor.reduce(Y, axis=0)).mean())
            s = f"r={full} peeled {flavor:6s} d={d}: zero-sum bit fraction {np.mean(fr):.3f} (random 0.5)  [{time.time()-t0:.0f}s]"
            print(s, flush=True); lines.append(s); out.append({"rounds": full, "flavor": flavor, "d": d, "frac": float(np.mean(fr))})
open("stage5b_output.txt", "w").write("\n".join(lines) + "\n"); json.dump(out, open("stage5b_results.json", "w"), indent=1)
