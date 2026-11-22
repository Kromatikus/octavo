#!/usr/bin/env python3
"""Summarise dudect json results: one row per case (latest rerun wins for the verdict; all runs listed)."""
import json, pathlib, sys
root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).parent / "results")
rows = []
for p in sorted(root.glob("*.json")):
    try:
        d = json.loads(p.read_text())
    except Exception as e:
        print(f"bad {p.name}: {e}"); continue
    d["_file"] = p.stem
    rows.append(d)
print(f"{'case':<34} {'n':>10} {'med0':>9} {'med1':>9} {'t_raw':>8} {'t_crop':>8}  verdict")
for d in rows:
    n = d.get("n0", 0) + d.get("n1", 0)
    print(f"{d['_file']:<34} {n:10d} {d['median0_cycles']:9.0f} {d['median1_cycles']:9.0f} {d['t_raw']:8.2f} {d['t_crop']:8.2f}  {d['verdict']}")
