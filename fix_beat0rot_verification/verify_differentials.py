"""Bow-alone best differentials for beats 0/6/7 after beat-0rot fix."""
from common import *

t0 = time.time()
print('live_sha', LIVE_SHA, flush=True)
print('validated', validate_fast_bow(), flush=True)
rng = np.random.default_rng(4546)
# Match lab screen scale roughly: 2^13 bases (report used 2^13 in fix_screen, 2^14 in main table)
NBASE = 1 << 13
B = rng.integers(0, 256, (NBASE, 8), dtype=np.int32)
a = u8bow(B)
pack = lambda z: (z.astype(np.int64) * (256 ** np.arange(8, dtype=np.int64))).sum(1)

def best_diff(t):
    best = 0; best_d = None; best_out = None
    for d in range(1, 256):
        H = B.copy(); H[:, t] ^= d
        z = a ^ u8bow(H)
        vals, counts = np.unique(pack(z), return_counts=True)
        m = int(counts.max())
        if m > best:
            best = m; best_d = d; best_out = int(vals[counts.argmax()])
    return {'log2': round(math.log2(best / NBASE), 2), 'count': best, 'delta': best_d,
            'out_pack': best_out, 'bases': NBASE}

res = {'started': now(), 'live_sha': LIVE_SHA, 'pressure_rot': N.BOW_PRESSURE_ROT,
       'pre_fix_live_from_report': PRE_FIX_BEST, 'bases': NBASE}
out = {}
for t in (0, 6, 7):
    out[t] = best_diff(t)
    print('beat', t, out[t], 'pre', PRE_FIX_BEST[t], flush=True)
res['bow_best_diff'] = out
# Also compare against identity-rot baseline on the SAME bases (patched model)
def u8bow_old(x):
    x = np.asarray(x, dtype=np.int32).copy()
    for i, j, p in N.BOW_STROKES:
        pp = x[:, p]
        r1 = 1 + (pp % 7); r2 = 1 + ((pp >> 3) % 7)
        v = x[:, j]; u = (x[:, i] + rotl(v, r1)) & 255
        x[:, i] = u; x[:, j] = v ^ rotl(u, r2)
    return x
a_old = u8bow_old(B)
old = {}
for t in (0, 6, 7):
    best = 0
    for d in range(1, 256):
        H = B.copy(); H[:, t] ^= d
        best = max(best, int(np.unique(pack(a_old ^ u8bow_old(H)), return_counts=True)[1].max()))
    old[t] = round(math.log2(best / NBASE), 2)
    print('old-model beat', t, old[t], flush=True)
res['same_bases_old_model_log2'] = old
res['improved'] = {t: out[t]['log2'] < PRE_FIX_BEST[t] for t in (0, 6, 7)}
res['seconds'] = round(time.time()-t0, 1)
res['finished'] = now()
save('verify_differentials', res)
print('improved', res['improved'], 'sec', res['seconds'], flush=True)
# Soft expectation: all three improved vs report pre-fix numbers
sys.exit(0 if all(res['improved'].values()) else 2)
