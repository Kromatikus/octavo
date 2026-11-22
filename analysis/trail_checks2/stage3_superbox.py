"""Stage 3b: exact clustering on Octavo's smallest 2-S-layer piece (S layer -> Latin pair = mix2 + S/S2), real keyed S-boxes,
for several schedules/rounds. Runs ./superbox (C, exact) and writes runs/stage3_superbox.json."""
import sys, json, subprocess, os
sys.dont_write_bytecode = True
import model
onp = model.onp
cases = [(20261121, 0, 0), (20261121, 0, 1), (20261122, 2, 11), (20261122, 5, 3)]
out = []
M2 = bytes(int(onp.MUL[2][x]) for x in range(256))
for seed, sch, r in cases:
    ns = model.schedules(sch + 1, seed)[sch]; rd = ns.rounds[r]
    fn = f"runs/sbox_seed{seed}_s{sch}_r{r}.bin"
    open(fn, "wb").write(bytes(rd.S.tolist()) + bytes(rd.S2.tolist()) + M2)
    res = json.loads(subprocess.run(["./superbox", fn], capture_output=True, text=True, check=True).stdout)
    res.update(seed=seed, sched=sch, round=r); out.append(res); print(json.dumps(res), flush=True)
json.dump(out, open("runs/stage3_superbox.json", "w"), indent=1)
