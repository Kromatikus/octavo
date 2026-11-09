from common import *
log=Log('attack_nonce');rng=np.random.default_rng(199);B=Batch(SCH);log('accelerator live-round checks',B.validate())
# Exact cached-schedule full block oracle, matching live API and final whitening.
def oracle(msg):
 ct=flat(N.encrypt_grid(N.bytes_to_grid(N.encode_block(msg)),SCH))
 return b'SN2'+NONCE+ct+N._tag(SCH.mac_key,NONCE,ct)
a=oracle(b'hello world');log('oracle matches public encrypt',a==N.encrypt(b'hello world',SEED,NONCE));log('repeat equality whole blob',a==oracle(b'hello world'))
p=rng.integers(0,256,(600,128),dtype=np.uint16);p[:,0]=127;c=B.enc(p,white=True);z=c[::2]^c[1::2];dz=p[::2]^p[1::2]
log('keystream xor identity',int(np.all(z==dz,axis=1).sum()),'/300')
weights=np.unpackbits(z.astype(np.uint8),axis=1).sum(axis=1);log('ct xor HW mean/min/max',float(weights.mean()),int(weights.min()),int(weights.max()),'/1024')
p2=p[:300].copy();p2[:,42]^=1;cc=B.enc(p2,white=True);w=np.unpackbits((cc^c[:300]).astype(np.uint8),axis=1).sum(axis=1)
log('one bit message flip ct HW mean/min/max',float(w.mean()),int(w.min()),int(w.max()))
# Oracle PIN confirmation is generic deterministic dictionary, not ciphertext-only recovery.
secret=b'PIN=731';target=oracle(secret);found=None
for q in range(1000):
 guess=f'PIN={q:03d}'.encode()
 if oracle(guess)==target:found=guess;break
log('fixed nonce chosen-message oracle dictionary found',repr(found),'queries',q+1)
log('Wrong guessed message says no; absent an oracle or secret key this comparison says maybe, not yes. Ciphertext-only: no plaintext recovered.')
nonces=[N.encrypt(b'hello world',SEED)[3:19] for _ in range(32)]
log('default encrypt urandom(16), observed distinct fresh nonces',len(set(nonces)),'/32')
log.save(dict(keystream_matches=int(np.all(z==dz,axis=1).sum()),trials=300,oracle_queries=q+1,ct_xor_mean=float(weights.mean()),onebit_mean=float(w.mean())))
