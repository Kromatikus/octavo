#!/usr/bin/env python3
"""Run the independent Octavo checker against score/vectors.json (79) and score/app_vectors.json.
Usage (from the repo root): python3 independent_check/run_check.py [--quick]   (--quick skips the 70000-byte rehearsal vector)"""
import json, hashlib, sys, time
import ic_core as C, ic_octavo as O
import os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCORE = os.path.join(ROOT, 'score') + os.sep
V = json.load(open(SCORE + 'vectors.json'))
QUICK = '--quick' in sys.argv
MSGS = {'0': b'', '1': b'A', '127': bytes(range(127)), '128': bytes(range(128)),
        '1000': bytes((i * 3 + 1) % 256 for i in range(1000)), '4096': bytes((i * 7 + 13) % 256 for i in range(4096)),
        '70000': bytes((i * 11 + 5) % 256 for i in range(70000)), '11': b'hello world'}
def msg_for(v):
    if 'msg' in v and len(v['msg']) // 2 == v.get('msg_len', len(v['msg']) // 2): return bytes.fromhex(v['msg'])
    m = MSGS[str(v['msg_len'])]; assert hashlib.sha256(m).hexdigest() == v['msg_sha256'], v['id']; return m
def blob_ok(v, blob):
    if 'blob' in v and len(v['blob']) // 2 == v['blob_len']: return blob.hex() == v['blob']
    return len(blob) == v['blob_len'] and hashlib.sha256(blob).hexdigest() == v['blob_sha256']
results = []
def rec(sec, vid, ok, note=''):
    results.append((sec, vid, ok)); print(('PASS' if ok else 'FAIL'), sec, vid, note, flush=True)

def run_seed(seed, sec, vecs):
    for v in vecs:
        mode = v['mode']; ad = bytes.fromhex(v['ad']); t0 = time.time()
        if mode == 'rehearsal' and QUICK and v['msg_len'] > 10000: rec(sec, v['id'], None, 'skipped (--quick)'); continue
        m = msg_for(v)
        pickup = bytes.fromhex(v['pickup']) if 'pickup' in v else bytes.fromhex(v['blob'][8:40])
        if mode in ('etude-block', 'block'):
            if mode == 'block': ctx = O.Ctx(seed)
            else: ctx = O.Ctx(seed, v.get('rounds') or {130: 2, 132: 4, 134: 6, 144: 16}[v['fmt_version']], etude=True)
            b = O.seal_block(ctx, m, pickup, ad); ok = blob_ok(v, b) and O.open_block(ctx, b, ad) == m
        elif mode in ('etude-movements', 'movements'):
            ctx = O.Ctx(seed, v.get('rounds') or {131: 2, 133: 4, 135: 6, 145: 16}.get(v['fmt_version'], 16), etude=(mode == 'etude-movements'))
            b = O.seal_movements(ctx, m, pickup, ad); ok = blob_ok(v, b) and O.open_movements(ctx, b, ad) == m
        elif mode == 'rehearsal':
            nonce = bytes.fromhex(v['nonce']) if 'nonce' in v else bytes.fromhex(v['blob'][40:72])
            cs = v.get('chunk_size') or int(v['id'].split('cs')[-1])
            b, ft = O.seal_rehearsal(seed, m, pickup, nonce, cs, ad)
            ok = blob_ok(v, b) and ('final_tag' not in v or ft.hex() == v['final_tag']) and O.open_rehearsal(seed, b, ad) == m
        else:
            raise SystemExit('unknown mode ' + mode)
        rec(sec, v['id'], ok, '%.1fs' % (time.time() - t0))

seed = bytes.fromhex(V['seed']['hex']); assert hashlib.sha256(seed).hexdigest() == V['seed']['sha256']
assert O.key_sig(seed).hex() == V['key_sig'] and O.rehearsal_sig(seed).hex() == V['rehearsal_sig']
for r in (2, 4, 6, 16): assert hashlib.sha256(O.etude_key(seed, r)).hexdigest() == V['format']['etude_key_sha256'][str(r)]
print('demo seed key_sig / rehearsal_sig / 4 etude keys: OK')
for v in V['block_cipher']:
    sch = C.Schedule(O.etude_key(seed, v['rounds']), bytes.fromhex(v['nonce'])); pt = bytes.fromhex(v['plaintext'])
    ct = C.encrypt_grid(pt, sch, v['rounds']); rec('block_cipher', v['id'], ct.hex() == v['ciphertext'] and C.decrypt_grid(ct, sch, v['rounds']) == pt)
run_seed(seed, 'aead', [dict(v) for v in V['aead']])
run_seed(seed, 'movements', V['movements'])
run_seed(seed, 'rehearsal', V['rehearsal'])
nd = V['nondemo']; nseed = bytes.fromhex(nd['seed']['hex'])
assert nseed == hashlib.shake_256(b"Octavo published non-demo test seed v1").digest(128)
assert O.key_sig(nseed).hex() == nd['key_sig'] and O.rehearsal_sig(nseed).hex() == nd['rehearsal_sig']
print('non-demo seed SHAKE definition / key_sig / rehearsal_sig: OK')
run_seed(nseed, 'nondemo', nd['vectors'])

# app vectors: HKDF-SHA512 key expansion, then open the recorded v6 blobs
A = json.load(open(SCORE + 'app_vectors.json')); app = []
keys = {}
for k in A['keys']:
    s = O.app_seed(bytes.fromhex(k['key'])); keys[k['id']] = s
    ok = s.hex() == k['seed']; app.append(ok); print(('PASS' if ok else 'FAIL'), 'app-key', k['id'])
for b in A['blobs']:
    try:
        m = O.open_block(O.Ctx(keys[b['key_id']]), bytes.fromhex(b['blob']), bytes.fromhex(b.get('ad_hex', '')))
        ok = m.hex() == b['msg_hex']
    except O.Reject as e:
        ok = False
    app.append(ok); print(('PASS' if ok else 'FAIL'), 'app-open', b['id'])
score = [r for r in results if r[2] is not None]
print('\nSCORE: %d/%d of %d vectors match (skipped %d)' % (sum(1 for r in score if r[2]), len(score), len(results), len(results) - len(score)))
for sec in ['block_cipher', 'aead', 'movements', 'rehearsal', 'nondemo']:
    rs = [r for r in score if r[0] == sec]; print('  %-12s %d/%d' % (sec, sum(1 for r in rs if r[2]), len(rs)))
print('APP: %d/%d' % (sum(app), len(app)))
assert not any(m in sys.modules for m in ('sneak_n2', 'octavo', 'etudes', 'common')), 'checker must stay independent'
print('independence: sneak_n2 / octavo / etudes / common were never imported')
sys.exit(0 if all(r[2] for r in score) and all(app) else 1)
