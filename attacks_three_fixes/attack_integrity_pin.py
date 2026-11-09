from common import *
from collections import Counter
import secrets, inspect
R=random.Random(202611089);res={'started':now(),'library_sha256':LIVE_SHA}
def classify(b):
 try:return 'ACCEPTED:'+N.decrypt(b,SEED).hex()
 except Exception as e:return type(e).__name__+': '+str(e)
clef=N.staff_clef(SEED)
pt=N.decrypt(HB,SEED)
res['hello']={'length':len(HB),'plaintext':pt.decode(),'pickup':PICKUP.hex(),'nonce':NONCE.hex(),'tag':TAG.hex(),
 'nonce_formula_ok':hashlib.sha256(clef+PICKUP+N.encode_block(b'hello world')).digest()[:16]==NONCE,
 'tag_recomputed_ok':hmac.new(SCH.mac_key,clef+N.key_signature(SEED)+N.VERSION+PICKUP+NONCE+CT,hashlib.sha256).digest()==TAG,
 'reencrypt_different':N.encrypt(b'hello world',SEED)!=HB,'encrypt_signature':str(inspect.signature(N.encrypt))}
print(res['hello'],flush=True)
c=Counter();payload=0
for bit in range(1560):
 b=bytearray(HB);b[bit//8]^=1<<(bit%8);k=classify(b);c[k]+=1;payload+=k.startswith('ACCEPTED')
res['single_bit_flips']={'count':1560,'results':dict(c),'payloads_returned':payload};print('bitflips',c,flush=True)
c=Counter()
for _ in range(1000):
 b=bytearray(HB);b[R.randrange(35,163)]^=R.randrange(1,256);c[classify(b)]+=1
res['ciphertext_corruption_1000']=dict(c)
blobs=[N.encrypt(R.randbytes(R.randrange(128)),SEED) for _ in range(40)]
c=Counter();pk=Counter()
for a,b in zip(blobs,blobs[1:]+blobs[:1]):
 pk[classify(a[:3]+b[3:19]+a[19:])]+=1
 for mix in [a[:19]+b[19:35]+a[35:],a[:35]+b[35:163]+a[163:],a[:163]+b[163:],a[:99]+b[99:163]+a[163:]]:c[classify(mix)]+=1
res['pickup_swaps_40']=dict(pk);res['other_splices_160']=dict(c)
# same message, two different pickups: swap pickup only
m=b'same message';x=N.encrypt(m,SEED);y=N.encrypt(m,SEED)
res['same_msg_pickup_swap']=classify(x[:3]+y[3:19]+x[19:])
c=Counter()
for _ in range(1000):c[classify(b'SN2'+R.randbytes(192))]+=1
for _ in range(200):c[classify(R.randbytes(195))]+=1
res['random_blobs_1200']=dict(c)
c=Counter()
for L in (0,1,2,3,19,35,163,178,179,180,194,196,211,300):c[f'len{L}: '+classify(HB[:L] if L<195 else HB+bytes(L-195))]+=1
res['wrong_lengths']=list(c)
# legacy blobs
res['legacy']={}
for p in sorted(Path('/tmp').glob('sneak_n2_*'))+[Path('/workspace/testn3')]:
 f=p/'hello-world.txt'
 if not f.exists():continue
 m=re.search(r'blob \((\d+) bytes.*?: ([0-9a-f]+)',f.read_text())
 if not m:res['legacy'][p.name]={'error':'no blob found'};continue
 old=bytes.fromhex(m.group(2));row={'length':len(old),'live_result':classify(old)}
 if (p/'sneak_n2.py').exists():
  try:
   spec=importlib.util.spec_from_file_location('old_'+p.name,p/'sneak_n2.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
   row['old_library_plaintext']=mod.decrypt(old,SEED).decode()
   cc=Counter()
   for i in range(10):cc[classify(mod.encrypt(R.randbytes(R.randrange(min(mod.MAX_MSG,100)+1)),SEED))]+=1
   row['old_library_generated_10_live_results']=dict(cc)
  except Exception as e:row['old_library_error']=repr(e)
 res['legacy'][p.name]=row;print(p.name,row.get('length'),row['live_result'],flush=True)
# well-encoded, valid-tag, wrong synthetic nonce: seed-holder white-box construction
nonce=bytes(16) if bytes(16)!=NONCE else b'\x01'*16
msg=b'hello world';sch=N.Schedule(SEED,nonce);ct=flat(N.encrypt_grid(N.bytes_to_grid(N.encode_block(msg)),sch))
blob=N.VERSION+PICKUP+nonce+ct+N._tag(sch.mac_key,PICKUP,nonce,ct,clef,N.key_signature(SEED))
res['valid_tag_wrong_siv_nonce']={'nonce':nonce.hex(),'result':classify(blob),'note':'constructed with seed (white-box) via live helpers; tag is valid, block well-formed, nonce not synthetic'}
# valid tag, malformed block (DecodeError path exists only for seed holders)
sch=N.Schedule(SEED,NONCE);ct2=R.randbytes(128);blob=N.VERSION+PICKUP+NONCE+ct2+N._tag(sch.mac_key,PICKUP,NONCE,ct2,clef,N.key_signature(SEED))
res['valid_tag_random_ct_seed_holder']=classify(blob)
print('integrity done',flush=True)
# Public PIN matching
pin=f'{secrets.randbelow(10000):04d}';msg=('PIN:'+pin).encode();target=N.encrypt(msg,SEED)
v,tpk,tn,tct,ttag=N.split_blob(target);t=time.perf_counter();samples=[N.encrypt(msg,SEED) for _ in range(512)]
res['public_pin_match']={'pin':pin,'correct_pin_encryptions':len(samples),'matches_to_target':sum(b==target for b in samples),'nonce_matches':sum(b[19:35]==tn for b in samples),'unique_pickups':len({b[3:19] for b in samples}),'seconds':round(time.perf_counter()-t,3),'target_blob':target.hex()}
# also wrong-PIN guesses of whole space once each: matches must be 0
hits=0
for g in range(10000):
 if N.encrypt(f'PIN:{g:04d}'.encode(),SEED)==target:hits+=1
res['public_pin_full_space_one_try_each']={'guesses':10000,'matches':hits}
print(res['public_pin_match']['matches_to_target'],hits,flush=True)
# Seed-holder copied-pickup path (NOT seed-free)
matches=[];t=time.perf_counter();ks=N.key_signature(SEED)
for guess in range(10000):
 m=f'PIN:{guess:04d}'.encode();gn=hashlib.sha256(clef+tpk+N.encode_block(m)).digest()[:16]
 if gn!=tn:continue
 sch=N.Schedule(SEED,gn);gc=flat(N.encrypt_grid(N.bytes_to_grid(N.encode_block(m)),sch));gb=N.VERSION+tpk+gn+gc+N._tag(sch.mac_key,tpk,gn,gc,clef,ks)
 matches.append({'pin':f'{guess:04d}','full_blob_matches':gb==target})
res['seed_holder_copied_pickup']={'guesses':10000,'matches':matches,'seconds':round(time.perf_counter()-t,3),'direct_decrypt':N.decrypt(target,SEED).decode(),
 'warning':'Requires the seed (clef). Possession of the seed already permits decrypt(); NOT a seed-free attack and not a break.'}
res['finished']=now();save('attack_integrity_pin',res)
