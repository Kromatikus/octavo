"""Full even-beat singleton scan after beat-0 pressure-rotation fix. NEW folder only."""
from common import *
from multiprocessing import Pool

t0 = time.time()
print('live_sha', LIVE_SHA, 'BOW_PRESSURE_ROT', N.BOW_PRESSURE_ROT, flush=True)
print('validated', validate_fast_bow(), 'staffs vs live bow_pressure', flush=True)

def scan_chunk(args):
    B, beats, deltas = args
    a = u8bow(B)
    out = {t: {'cases': 0, 'hits': 0, 'wit': [], 'one_pair_both': 0, 'pairs_hist': [0]*5} for t in beats}
    for t in beats:
        o = out[t]
        for d in deltas:
            H = B.copy(); H[:, t] ^= d
            z = a ^ u8bow(H); act = z != 0
            pa = act.reshape(-1, 4, 2).any(2); np_ = pa.sum(1)
            o['pairs_hist'] = [x + int(y) for x, y in zip(o['pairs_hist'], np.bincount(np_, minlength=5))]
            o['cases'] += len(B)
            one = (np_ == 1)
            if one.any():
                for i in (0, 2, 4, 6):
                    m = one & act[:, i] & act[:, i+1]
                    if m.any():
                        o['one_pair_both'] += int(m.sum())
                        k = m & ((z[:, i] == z[:, i+1]) | (z[:, i] == G2[z[:, i+1]]))
                        if k.any():
                            o['hits'] += int(k.sum())
                            for q in np.nonzero(k)[0][:5]:
                                o['wit'].append({'base': B[q].tolist(), 'beat': int(t), 'delta': int(d),
                                                 'bow_delta': z[q].tolist()})
    return out

def merge(parts, beats):
    R = {t: {'cases': 0, 'hits': 0, 'one_pair_both': 0, 'pairs_hist': [0]*5, 'witnesses': []} for t in beats}
    for p in parts:
        for t in beats:
            for k in ('cases', 'hits', 'one_pair_both'):
                R[t][k] += p[t][k]
            R[t]['pairs_hist'] = [x+y for x,y in zip(R[t]['pairs_hist'], p[t]['pairs_hist'])]
            R[t]['witnesses'] += p[t]['wit'][:20 - len(R[t]['witnesses'])]
    return R

def run(B, beats, deltas=range(1, 256), chunk=1<<15):
    jobs = [(B[s:s+chunk], beats, list(deltas)) for s in range(0, len(B), chunk)]
    with Pool(6) as P:
        parts = P.map(scan_chunk, jobs)
    return merge(parts, beats)

res = {'started': now(), 'live_sha': LIVE_SHA, 'strokes': N.BOW_STROKES,
       'pressure_rot': N.BOW_PRESSURE_ROT, 'note': 'post beat-0rot fix verification'}

if __name__ == '__main__':
    rng = np.random.default_rng(66061)
    # A. 2^21 random bases x 255 deltas, even beats
    B = rng.integers(0, 256, (1<<21, 8)).astype(np.int32)
    A = run(B, (0, 2, 4))
    res['A_random_even_2^21'] = A
    print('A', {t: (A[t]['hits'], A[t]['one_pair_both'], A[t]['cases'], A[t]['pairs_hist']) for t in A},
          'sec', round(time.time()-t0), flush=True)
    # B. 2^18 all 8 beats (odd + beat 6 sanity)
    B = rng.integers(0, 256, (1<<18, 8)).astype(np.int32)
    Bb = run(B, tuple(range(8)))
    res['B_random_all_beats_2^18'] = Bb
    print('B', {t: (Bb[t]['hits'], Bb[t]['cases']) for t in Bb}, 'sec', round(time.time()-t0), flush=True)
    # F. forced-change outputs
    B = rng.integers(0, 256, (1<<16, 8)).astype(np.int32)
    a = u8bow(B); F = {}
    for t in range(8):
        always = np.ones(8, bool)
        for d in range(1, 256):
            H = B.copy(); H[:, t] ^= d
            always &= (a != u8bow(H)).all(0)
        F[t] = [int(c) for c in np.nonzero(always)[0]]
    res['F_forced_changes'] = F
    print('F', F, flush=True)
    # any witnesses -> live confirm
    conf = []
    for key in ('A_random_even_2^21', 'B_random_all_beats_2^18'):
        for t, row in res[key].items():
            for w in row.get('witnesses', [])[:3]:
                s, tt, d = w['base'], w['beat'], w['delta']; h = s[:]; h[tt] ^= d
                sch = N.Schedule(N.load_seed(), bytes(16))
                conf.append({**w, 'scan': key,
                    'live_weights_16': [sum(x!=y for x,y in zip(
                        N.odd_restack(N.bow_pressure(s), rk['S'], rk['S2']),
                        N.odd_restack(N.bow_pressure(h), rk['S'], rk['S2']))) for rk in sch.rounds]})
    res['live_confirmation'] = conf
    res['seconds'] = round(time.time()-t0, 1)
    res['finished'] = now()
    total_hits = sum(A[t]['hits'] for t in A) + sum(Bb[t]['hits'] for t in Bb)
    res['total_hits'] = total_hits
    res['PASS'] = total_hits == 0
    save('verify_even_beats', res)
    print('TOTAL_HITS', total_hits, 'PASS' if total_hits==0 else 'FAIL', 'sec', res['seconds'], flush=True)
    sys.exit(0 if total_hits == 0 else 1)
