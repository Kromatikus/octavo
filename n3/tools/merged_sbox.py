#!/usr/bin/env python3
"""DDT/LAT of the merged box S_{r+1}(S2_r(x) ^ rk_{r+1}[byte]) on real schedules."""
import hashlib, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.join(os.path.dirname(HERE), "python"))
import octavo_n3 as n3
def ddt_max(s):
    m = 0
    for a in range(1, 256):
        c = [0]*256
        for x in range(256): c[s[x]^s[x^a]] += 1
        m = max(m, max(c))
    return m
def lat_max(s):
    # Walsh via fast transform per output mask
    best = 0
    for b in range(1, 256):
        f = [1 - 2*(bin(s[x] & b).count("1") & 1) for x in range(256)]
        h = 1
        while h < 256:
            for i in range(0, 256, 2*h):
                for j in range(i, i+h):
                    u, v = f[j], f[j+h]; f[j], f[j+h] = u+v, u-v
            h *= 2
        best = max(best, max(abs(v) for v in f[1:]) if b else 0, abs(f[0]) if b else 0)
    return best
res = []
for k in range(3):
    seed = hashlib.sha256(b"merged%d" % k).digest()*4; nonce = bytes(16)
    sc = n3.Schedule(seed, nonce)
    single = (ddt_max(sc.rounds[0]["S"]), lat_max(sc.rounds[0]["S"]))
    for r in range(2):
        for pos in (0, 77):
            f, t = divmod(pos, 8)
            kb = sc.rounds[r+1]["rk"][f][t]
            m = [sc.rounds[r+1]["S"][sc.rounds[r]["S2"][x] ^ kb] for x in range(256)]
            rec = dict(sched=k, r=r, pos=pos, ddt_max=ddt_max(m), lat_max_walsh=lat_max(m), single_box=single)
            print(json.dumps(rec), flush=True); res.append(rec)
json.dump(res, open(os.path.join(os.path.dirname(HERE), "results", "merged_sbox.json"), "w"), indent=1)
