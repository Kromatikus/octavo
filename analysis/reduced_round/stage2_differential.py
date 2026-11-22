"""Stage 2: empirical differential distinguishers at sub-round / round granularity + S-box DDT bound (OCT-2)."""
import json, os, time, math, numpy as np
import harness
from octavo_np import lab_schedule
m = harness.m
rng = np.random.default_rng(int.from_bytes(os.urandom(8), "big"))
lines = []; out = {"tests": []}
def log(s): print(s, flush=True); lines.append(s)
t0 = time.time()

def wh_z(chi2, k):   # Wilson-Hilferty: chi2(k) -> approx N(0,1)
    return ((chi2 / k) ** (1/3) - (1 - 2/(9*k))) / math.sqrt(2/(9*k))

# --- S-box DDT/LAT check on several keyed S-boxes (inherited from SM4 by affine equivalence)
dd, ll = set(), set()
for _ in range(3):
    sch = harness.schedule(rng.bytes(128), rng.bytes(16))
    for rk in sch.rounds[:2]:
        dd.add(m.ddt_max(rk["S"])); dd.add(m.ddt_max(rk["S2"])); ll.add(m.lat_max(rk["S"])); ll.add(m.lat_max(rk["S2"]))
log(f"keyed S-boxes (12 sampled): DDT max {sorted(dd)} -> max DP {max(dd)}/256 = 2^{math.log2(max(dd)/256):.0f}; LAT max {sorted(ll)} -> max |corr| {max(ll)}/128 = 2^{math.log2(max(ll)/128):.0f}")
out["ddt_max"] = sorted(dd); out["lat_max"] = sorted(ll)

LEVELS = [("0.5", 0, "cross"), ("1", 1, None), ("1.5", 1, "cross"), ("2", 2, None), ("3", 3, None)]
N = 1 << 16; NS = 3
def make_diffs():
    D = []
    for _ in range(4):
        p = int(rng.integers(0, 128)); d = int(rng.integers(1, 256)); v = np.zeros(128, np.uint8); v[p] = d
        D.append((f"byte{p}^{d:02x}", v))
    for _ in range(2):
        b = int(rng.integers(0, 1024)); v = np.zeros(128, np.uint8); v[b // 8] = 1 << (b % 8); D.append((f"bit{b}", v))
    v = np.zeros(128, np.uint8); v[:64] = rng.integers(1, 256, 64, dtype=np.uint8); D.append(("inner-shell all 64", v))
    f = int(rng.integers(0, 16)); v = np.zeros(128, np.uint8); d = int(rng.integers(1, 256)); v[8*f] = d; v[8*f+1] = d
    D.append((f"face{f} beats0,1 equal delta", v))
    return D
DIFFS = make_diffs()
THRESH = 5.0   # ~Bonferroni over ~10^5 statistics
maxr = 0
for lname, full, stop in LEVELS:
    lvl_hits = 0; lvl_max = []
    for dname, dv in DIFFS:
        sum_chi = np.zeros(128); zb_all = []; zc_all = []
        for k in range(NS):
            ns = lab_schedule(rng)
            P = rng.integers(0, 256, (N, 128), dtype=np.uint8); Q = P ^ dv
            D = ns.enc_frac(P, full, stop) ^ ns.enc_frac(Q, full, stop)
            # per-byte difference histogram chi-square (255 dof)
            chi = np.empty(128)
            for j in range(128):
                h = np.bincount(D[:, j], minlength=256); chi[j] = ((h - N/256) ** 2).sum() / (N/256)
            sum_chi += chi
            zc = np.array([wh_z(c, 255) for c in chi]); zc_all.append(zc.max())
            cb = np.unpackbits(D, axis=1).sum(0, dtype=np.int64); zb = np.abs(cb - N/2) / math.sqrt(N/4); zb_all.append(zb.max())
        zsum = max(wh_z(c, 255*NS) for c in sum_chi)   # key-averaged
        zmax = max(max(zc_all), max(zb_all), zsum)
        hit = zmax > THRESH; lvl_hits += hit; lvl_max.append(zmax)
        log(f"  r={lname:3s} {dname:28s}: max byte-chi z {max(zc_all):6.2f}  max bit z {max(zb_all):6.2f}  key-summed chi z {zsum:6.2f}  {'DISTINGUISHED' if hit else '-'}")
        out["tests"].append({"rounds": lname, "diff": dname, "max_byte_chi_z": float(max(zc_all)), "max_bit_z": float(max(zb_all)),
                             "key_summed_chi_z": float(zsum), "distinguished": bool(hit), "pairs_per_schedule": N, "schedules": NS})
    log(f"r={lname}: {lvl_hits}/{len(DIFFS)} differences distinguish (threshold z>{THRESH}); max z {max(lvl_max):.2f}   [{time.time()-t0:.0f}s]")
    if lvl_hits: maxr = lname
    elif float(lname) >= 2: break   # signal lost at two consecutive levels -> stop spending
out["max_distinguished_level"] = maxr
log(f"max distinguished level at 2^16 pairs x {NS} schedules: r = {maxr}")
open("stage2_output.txt", "w").write("\n".join(lines) + "\n"); json.dump(out, open("stage2_results.json", "w"), indent=1)
