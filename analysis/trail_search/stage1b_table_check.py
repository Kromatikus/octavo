"""Stage 1b: validate exact truncated tables against octavo_np: random sparse differences/patterns must map to
(in,out) support pairs present in the table (diff); and every table row has a witness? (sampled)."""
import numpy as np, model
onp = model.onp
ns = model.schedules(1)[0]; R0 = ns.rounds[0]
rng = np.random.default_rng(7); bad = 0; n = 0
for f in (0, 5, 11):
    M = model.butterfly_matrix(R0, f); T = set(map(tuple, model.exact_table(M, "diff")))
    for _ in range(4000):
        k = rng.integers(1, 9); pos = rng.choice(8, k, replace=False)
        x = np.zeros(8, np.int64); x[pos] = rng.integers(1, 256, k)
        s = np.zeros((1, 128), np.uint8); s[0, 8*f:8*f+8] = x
        for A, B in R0.butterfly: s[:, A], s[:, B] = onp.mix2_np(s[:, A], s[:, B])
        y = s[0, 8*f:8*f+8]; key = tuple(int(v > 0) for v in x) + tuple(int(v > 0) for v in y)
        bad += key not in T; n += 1
Tb = set(map(tuple, model.exact_table(model.BARCHAIN, "diff")))
for _ in range(4000):
    k = rng.integers(1, 8); pos = rng.choice(7, k, replace=False)
    x = np.zeros(7, np.int64); x[pos] = rng.integers(1, 256, k)
    y = model._barchain(x.astype(np.uint8)); key = tuple(int(v > 0) for v in x) + tuple(int(v > 0) for v in y)
    bad += key not in Tb; n += 1
# witness direction: low-weight table rows of the face-0 butterfly must be hit by a solved vector
import lincut
M = model.butterfly_matrix(R0, 0); rows = [r for r in model.exact_table(M, "diff") if 0 < sum(r) <= 7]
hit = 0
for r in rows:
    Tin = [i for i in range(8) if r[i]]; Tout = [j for j in range(8) if r[8 + j]]
    B = lincut.kernel([[M[j][i] for i in Tin] for j in range(8) if j not in Tout], len(Tin))
    v = np.zeros(len(Tin), np.int64)
    for b in B:
        cc = int(rng.integers(1, 256)); v ^= np.array([int(lincut.MUL[cc][c]) for c in b])
    x = np.zeros(8, np.uint8); x[Tin] = v
    s = np.zeros((1, 128), np.uint8); s[0, :8] = x
    for A, Bb in R0.butterfly: s[:, A], s[:, Bb] = onp.mix2_np(s[:, A], s[:, Bb])
    hit += [int(v > 0) for v in x] + [int(v > 0) for v in s[0, :8]] == list(r)
print(f"random vectors whose support pair is missing from the exact tables: {bad}/{n} (must be 0)")
print(f"face-0 butterfly table rows of weight 6-7 reproduced by a real vector via octavo_np: {hit}/{len(rows)}")
