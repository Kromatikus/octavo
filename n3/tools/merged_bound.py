#!/usr/bin/env python3
"""Independent re-check of the N3 trail bound, plus a 'merged S-box' count.

In the round  rk;S;chord;bridges;trip;bow;S_mid;cross;S2  the S2 layer of round r
and the S layer of round r+1 touch the same bytes with only rk_{r+1} XOR between
them, so in a multi-round trail they act as ONE keyed 8-bit S-box. The frozen
model counts them as two. Here: original objective, and objective minus the
round-(r+1) S layer (merged count). Model code is the frozen copy (tools/trail_model).
"""
import json, os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(HERE, "trail_model")); sys.path.insert(0, os.path.join(ROOT, "python"))
import model_tight as M

def run(n, br, mode, merged, lim):
    md, obj, x_in, sb = M.build(n, br, mode=mode, exact=False, restore_smid=True)
    if merged:
        drop = []
        for r in range(1, n):
            drop += sb[r * 384 : r * 384 + 128]  # S layer of round r+1 == S2 of round r
        obj = obj - sum(drop)
    t0 = time.time()
    rec = M.solve(md, obj, time_limit_s=lim, workers=8, dump_vars=sb)
    act = rec.get("activity", {}).get("weights_per_layer")
    return dict(n=n, mode=mode, merged=merged, status=rec["status"], obj=rec.get("objective"),
                bound=rec.get("best_bound"), layers=act, t=round(time.time() - t0, 1))

out = []
nsched = int(sys.argv[1]) if len(sys.argv) > 1 else 3
scheds = M.sample_bridges(n_schedules=nsched, rounds=3, seed_label=b"attack003")
for si, sc in enumerate(scheds):
    for (n, merged, lim) in ((1, False, 30), (2, False, 90), (2, True, 90)):
        for mode in ("diff", "lin"):
            rec = run(n, sc[:n], mode, merged, lim); rec["sched"] = si
            print(json.dumps(rec), flush=True); out.append(rec)
json.dump(out, open(os.path.join(ROOT, "results", "fix1", "merged_bound.json"), "w"), indent=1)
