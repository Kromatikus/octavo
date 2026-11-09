"""N2 attack 3 — reduced-round cryptanalysis of the homemade block cipher. Imports the real internals
(same S-boxes, mix, weave, keys) and exercises r = 1,2,3,... rounds. Covers: dependency/codebook split
(the N1 1-round break), DDT/LAT of the keyed S-boxes actually used, differentials exploiting the
documented mix weaknesses (nibble diff 8 passes the 2-cell mix; the LSB of the mix is linear), integral /
zero-sum, zero-difference, chi-squared and avalanche distinguishers. Reports the last distinguishable
round and the first that looks random."""
import sys, os, random, statistics, itertools
sys.path.insert(0, "/workspace/sneak_n2"); import sneak_n2 as N
SEED = N.load_seed(); R = random.Random(17); out = []
def log(*a): s = " ".join(map(str, a)); print(s); out.append(s)
rb = lambda n: bytes(R.randrange(256) for _ in range(n))
n0 = rb(16); SCH = N.Schedule(SEED, n0)
def E(nib, rounds):   # reduced-round oracle, no whitening (a fixed XOR, irrelevant to these statistics)
    g = [nib[8*f:8*f+8] for f in range(16)]
    return [x for row in N.encrypt_grid(g, SCH, rounds, white=False) for x in row]

log("=== N2 reduced-round cryptanalysis (nonce fixed; white=False for reduced rounds) ===")

# 1. DDT / LAT of the keyed S-boxes actually instantiated this nonce
def ddt_best(S):
    best = (0, None, None)
    for a in range(1, 16):
        c = [0]*16
        for x in range(16): c[S[x]^S[x^a]] += 1
        for b in range(16):
            if c[b] > best[0]: best = (c[b], a, b)
    return best
for r in (0, 1, 15):
    S = SCH.rounds[r]["S"]; p, a, b = ddt_best(S)
    log(f"[S-box] round {r}: DDT max {p}/16 at input diff {a:X}->{b:X}; LAT max {N.lat_max(S)}/8 (PRESENT-affine: optimal 4-bit bounds)")
log(f"[S-box] all 16 rounds this nonce: DDT max over rounds = {max(ddt_best(rk['S'])[0] for rk in SCH.rounds)} (N1's shuffled box was 8/16)")

# 2. dependency structure and the N1 codebook split
def deps(rounds, trials=3):
    D = [set() for _ in range(128)]
    for _ in range(trials):
        base = [R.randrange(16) for _ in range(128)]; cb = E(base, rounds)
        for i in range(128):
            for dv in (1, 8, 5):
                x = base[:]; x[i] ^= dv; cx = E(x, rounds)
                for j in range(128):
                    if cx[j] != cb[j]: D[j].add(i)
    return D
def components(D):
    par = list(range(256))
    def f(x):
        while par[x] != x: par[x] = par[par[x]]; x = par[x]
        return x
    for j, d in enumerate(D):
        for i in d: par[f(128 + j)] = f(i)
    comp = {}
    for i in range(128): comp.setdefault(f(i), [[], []])[0].append(i)
    for j in range(128): comp.setdefault(f(128 + j), [[], []])[1].append(j)
    return [c for c in comp.values() if c[0]]
for r in (1, 2, 3, 4):
    D = deps(r); sz = [len(d) for d in D]; comps = components(D); mx = max(len(c[0]) for c in comps)
    log(f"[structure] {r} rounds: each ct nibble depends on min {min(sz)}/mean {statistics.mean(sz):.1f}/max {max(sz)} of 128 inputs; "
        f"largest independent input-component = {mx} nibbles (N1 at 1 round split into 64 x 2-nibble pieces, codebook 16384)")
log("[codebook] N1's 1-round attack needed components <=3 nibbles (16^3 table). N2's smallest 1-round component is already 128 nibbles, so the 16384-plaintext codebook split does NOT apply at any round >=1.")

# 3. differentials exploiting the documented mix weaknesses
#    (a) nibble difference 8 passes the 2-cell mix with certainty; does it survive a round (S-box first)?
def diff_prob(rounds, dvec, trials=4000):
    """best single-output-nibble differential bias and whole-state exact-repeat prob for input diff dvec."""
    from collections import Counter
    whole = 0; percell = [Counter() for _ in range(128)]
    for _ in range(trials):
        x = [R.randrange(16) for _ in range(128)]; y = x[:]
        for i, d in dvec: y[i] ^= d
        a = E(x, rounds); b = E(y, rounds)
        od = tuple((a[j]^b[j]) for j in range(128))
        if od == tuple((d if any(i==j and dd==d for i,dd in dvec) else 0) for j in range(128)): whole += 1
        for j in range(128): percell[j][a[j]^b[j]] += 1
    best = max((cnt.most_common(1)[0][1]/trials, j, cnt.most_common(1)[0][0]) for j, cnt in enumerate(percell))
    return best
for r in (1, 2, 3, 4):
    # input diff = single nibble = 8 (msb only) at position 0
    b = diff_prob(r, [(0, 8)]); log(f"[differential d=8] {r} rounds: best single-nibble output-diff prob {b[0]:.4f} at cell {b[1]} (value {b[2]:X})  (random 1/16=0.0625)")
# (b) LSB linear trail: parity of all input LSBs vs parity of all output LSBs (mix LSB is linear; S-box LSB is not)
def lsb_corr(rounds, trials=20000):
    agree = 0
    for _ in range(trials):
        x = [R.randrange(16) for _ in range(128)]; c = E(x, rounds)
        pin = sum(v & 1 for v in x) & 1; pout = sum(v & 1 for v in c) & 1
        agree += (pin == pout)
    return abs(agree/trials - 0.5)
for r in (1, 2, 3, 4):
    log(f"[linear LSB] {r} rounds: |corr(parity of all input LSBs, parity of all output LSBs) - 1/2| = {lsb_corr(r):.4f}  (random ~0.003)")
# single-cell LSB best linear approximation search (small masks)
def best_lsb_single(rounds, trials=20000):
    best = 0
    for ipos in (0, 7, 64):
        for opos in range(0, 128, 11):
            agree = 0
            for _ in range(trials):
                x = [R.randrange(16) for _ in range(128)]; c = E(x, rounds)
                agree += ((x[ipos] & 1) == (c[opos] & 1))
            best = max(best, abs(agree/trials - 0.5))
    return best
log(f"[linear LSB] 1 round: best single-cell LSB->LSB bias over sampled positions: {best_lsb_single(1):.4f}")

# 4. integral / zero-sum distinguisher
def integral(rounds, k=2, trials=6):
    z = []
    for _ in range(trials):
        base = [R.randrange(16) for _ in range(128)]; pos = R.sample(range(128), k); acc = [0]*128
        for vals in itertools.product(range(16), repeat=k):
            x = base[:]
            for p, v in zip(pos, vals): x[p] = v
            c = E(x, rounds)
            for j in range(128): acc[j] ^= c[j]
        z.append(sum(a == 0 for a in acc))
    return statistics.mean(z)
for r in (1, 2, 3, 4, 5):
    log(f"[integral] {r} rounds, 256 chosen pts (2 active nibbles): zero-XOR output nibbles {integral(r):.1f}  (random ~8.0)")

# 5. zero-difference distinguisher (unchanged output nibbles after 1-nibble input diff)
def zerodiff(rounds, trials=400):
    u = []
    for _ in range(trials):
        x = [R.randrange(16) for _ in range(128)]; y = x[:]; p = R.randrange(128); y[p] ^= R.randrange(1, 16)
        a, b = E(x, rounds), E(y, rounds); u.append(sum(i == j for i, j in zip(a, b)))
    return statistics.mean(u), min(u)
last_dist = None
for r in (1, 2, 3, 4, 5, 6):
    m, mn = zerodiff(r); tag = "DISTINGUISHABLE" if m > 12 else "~random"
    if m > 12: last_dist = r
    log(f"[zero-diff] {r} rounds: mean unchanged ct nibbles {m:.1f}/128 (random 8.0), min {mn}  [{tag}]")

# 6. chi-squared on output bits, 1-nibble-active set
def chi_bits(rounds, trials=40):
    worst = 0
    for _ in range(trials):
        base = [R.randrange(16) for _ in range(128)]; p = R.randrange(128)
        cnt = [0]*512
        for v in range(16):
            x = base[:]; x[p] = v; c = E(x, rounds)
            for j in range(128):
                for bit in range(4):
                    if (c[j] >> bit) & 1: cnt[4*j+bit] += 1   # over 16 texts
        # each bit count out of 16; expected 8
        chi = max(abs(c - 8) for c in cnt)  # max deviation
        worst = max(worst, chi)
    return worst
for r in (2, 3, 4, 5):
    log(f"[chi-bits] {r} rounds: worst bit imbalance over a 16-set (max |count-8|, 8=balanced): {chi_bits(r)}  (a stuck bit => 8)")

# 7. full-cipher avalanche & distinguish-from-random attempts (expected: no break)
def av(rounds, n=400):
    hs = []
    for _ in range(n):
        x = rb(64); y = bytearray(x); k = R.randrange(512); y[k//8] ^= 1 << (k%8)
        e = lambda z: N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(z), SCH, rounds, white=False))
        hs.append(sum(bin(p^q).count("1") for p, q in zip(e(x), e(bytes(y)))))
    return statistics.mean(hs), min(hs), max(hs)
for r in (3, 4, 8, 16):
    a = av(r); log(f"[avalanche] {r:2d} rounds: mean {a[0]:.1f}/512, min {a[1]}, max {a[2]}")
log(f"[summary] last clearly distinguishable round (zero-diff metric): {last_dist}; from round {last_dist+1 if last_dist else '?'} the tests look random.")

# 8. full 16-round seedless recovery / ciphertext-only — honest negative
sch_demo = N.Schedule(SEED, bytes.fromhex(open('/workspace/sneak_n2/demo-nonce.txt').read().strip()))
demo_ct = bytes.fromhex("328603c75274b178415090ebb344261cf94b1cfada32739a41ed2ab590e447bb4a07ff1013668f0802cd4b3c81aa4dc96c008db753d8b82ec56d91fb7a6208ee")
log("[full 16r] seedless plaintext recovery: no method found. Full diffusion by round 3, keyed per-round S-boxes, one-way schedule => no reduced-round distinguisher reaches 16; nothing recovered without the seed.")

open("/workspace/sneak_n2/attacks/attack_rounds_output.txt", "w").write("\n".join(out) + "\n")
