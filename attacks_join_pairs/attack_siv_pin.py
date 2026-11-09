"""SIV nonce binding + deterministic-AE dictionary leftover on the LIVE post-join N2. Demo PIN only, not a real secret."""
from common import *
import time,secrets
log=Log('attack_siv_pin');res={}
# SIV binding
m=b'transfer 10';good=N.siv_nonce(m,SEED);bad=bytes(16)
try:N.encrypt(m,SEED,nonce=bad);r='accepted (BAD)'
except ValueError as e:r='ValueError: '+str(e)
res['caller_nonce_mismatch']=r;log('Caller-chosen nonce:',r)
res['caller_nonce_equal_ok']=N.encrypt(m,SEED,nonce=good)==N.encrypt(m,SEED);log('Caller passes the correct SIV nonce -> same blob:',res['caller_nonce_equal_ok'])
# nonce reuse with different message is impossible via the API: try to force message B under message A's nonce
try:N.encrypt(b'transfer 99',SEED,nonce=good);r='accepted (BAD)'
except ValueError as e:r='ValueError: '+str(e)
res['reuse_nonce_other_msg']=r;log('Reuse nonce of msg A for msg B:',r)
# os.urandom not used
import os;_u=os.urandom;os.urandom=lambda k:(_ for _ in ()).throw(RuntimeError('urandom called'))
try:N.encrypt(b'x',SEED);res['urandom_used']=False
except RuntimeError:res['urandom_used']=True
finally:os.urandom=_u
log('encrypt() calls os.urandom:',res['urandom_used'])
# Determinism => equality leak
res['equal_msgs_equal_blobs']=N.encrypt(b'yes',SEED)==N.encrypt(b'yes',SEED);log('Same message twice -> identical blob (equality leak):',res['equal_msgs_equal_blobs'])
# Inner SIV mismatch: valid-tag blob whose decoded msg != nonce preimage. Construct white-box: encrypt msg B under msg A's nonce bypassing encrypt()
nA=N.siv_nonce(b'A',SEED);sch=N.Schedule(SEED,nA);ct=N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(N.encode_block(b'B')),sch))
forged=b'SN2'+nA+ct+N._tag(sch.mac_key,nA,ct,N.staff_clef(SEED))
try:N.decrypt(forged,SEED);r='accepted (BAD)'
except N.AuthError as e:r='AuthError: '+str(e)
res['whitebox_nonce_reuse_blob']=r;log('White-box nonce-reuse blob (needs the seed) on decrypt:',r)
# PIN dictionary demo
pin=f"{secrets.randbelow(10000):04d}"   # drawn at run time by the script; demo only
target=N.encrypt(('PIN:'+pin).encode(),SEED)
log('Attacker sees only target blob:',target.hex())
t0=time.time();found=None
for g in range(10000):
 if N.encrypt(f'PIN:{g:04d}'.encode(),SEED)==target:found=g;break
dt=time.time()-t0
res['pin_demo']=dict(secret_pin=pin,recovered=f'{found:04d}',guesses=found+1,seconds=round(dt,2),target_blob=target.hex(),
 matching_nonce=target[3:19].hex(),note='Attacker only needs an encryption oracle (or the seed). Equality of deterministic SIV blobs reveals the PIN.')
log('PIN demo:',res['pin_demo'])
log.save(res)
