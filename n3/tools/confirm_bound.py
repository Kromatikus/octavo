#!/usr/bin/env python3
"""Re-run 1- and 2-round trail bounds on the implemented draft-2 wiring.

Uses a local copy of the trail-2 CP-SAT model, pointed at this folder's
Python (S ; ... ; bow ; S_mid ; cross ; S2). Does not edit trail-2, draft-1,
or live N2.

Homemade; for real secrets use AES-GCM-SIV, age, or libsodium.
"""
from __future__ import annotations

import json
import os
import sys
import time

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(HERE, "trail_model"))
sys.path.insert(0, os.path.join(ROOT, "python"))
import model_tight as M  # noqa: E402
import octavo_n3 as n3  # noqa: E402


def one(n_rounds, bridges, mode, tag, time_limit):
    t0 = time.perf_counter()
    print(f"== {tag} R={n_rounds} mode={mode} lim={time_limit}s", flush=True)
    br = [bridges[r] for r in range(n_rounds)]
    md, obj, *_ = M.build(n_rounds, br, mode=mode, exact=False, restore_smid=True)
    rec = M.solve(md, obj, time_limit_s=time_limit, workers=8)
    rec["elapsed_s"] = time.perf_counter() - t0
    rec.update(dict(n_rounds=n_rounds, mode=mode, tag=tag, restore_smid=True))
    print(
        "  ->",
        rec.get("status"),
        "obj",
        rec.get("objective"),
        "bound",
        rec.get("best_bound"),
        f"in {rec['elapsed_s']:.2f}s",
        flush=True,
    )
    return rec


def main():
    # Confirm S_mid is present on the implemented schedule.
    seed = bytes((3 * i + 7) & 255 for i in range(128))
    nonce = bytes(range(16))
    sch = n3.Schedule(seed, nonce)
    r0 = sch.rounds[0]
    assert "SM" in r0 and "SIM" in r0
    assert r0["SM"] != r0["S"] and r0["SM"] != r0["S2"]
    assert r0["S"] != r0["S2"]
    # Spot-check invertibility of S_mid
    for x in range(256):
        assert r0["SIM"][r0["SM"][x]] == x

    t_all = time.perf_counter()
    # Same sampling helper as trail-2 (N3 sponge, SN3/), so results are
    # comparable; Schedule now also draws S_mid after S2, which does not
    # move the bridges.
    scheds = M.sample_bridges(n_schedules=1, rounds=2)
    results = []
    for n, lim in ((1, 30), (2, 60)):
        for mode in ("diff", "lin"):
            rec = one(n, scheds[0], mode, f"draft2-R{n}-{mode}", lim)
            rec["schedule"] = 0
            results.append(rec)

    expected = {(1, "diff"): 18, (1, "lin"): 18, (2, "diff"): 36, (2, "lin"): 36}
    ok = True
    for rec in results:
        key = (rec["n_rounds"], rec["mode"])
        exp = expected[key]
        proved = rec.get("proved") and rec.get("status") == "OPTIMAL"
        obj = rec.get("objective")
        bound = rec.get("best_bound")
        match = proved and obj == exp and bound == exp
        rec["expected"] = exp
        rec["matches_trail2_variant"] = bool(match)
        if not match:
            ok = False
            print(
                f"  NOTE: {rec['tag']} did not match trail-2 {exp} "
                f"(status={rec.get('status')} obj={obj} bound={bound})",
                flush=True,
            )

    out = {
        "draft": "n3-draft2",
        "matches_trail2_variant": ok,
        "expected": {"1": 18, "2": 36},
        "results": [
            {k: rec[k] for k in rec if k not in ("info", "activity", "trace")}
            for rec in results
        ],
        "elapsed_s": time.perf_counter() - t_all,
        "s_mid_present": True,
        "round": "S; chord; bridges; triplets; bow; S_mid; cross; S2",
    }
    dest = os.path.join(ROOT, "vectors", "bound_confirm.json")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print(f"wrote {dest}", flush=True)
    print(f"matches trail-2 variant: {ok}  in {out['elapsed_s']:.1f}s", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
