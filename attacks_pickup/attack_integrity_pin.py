from common import *
from collections import Counter
import secrets, inspect
R=random.Random(20261108);res={'started':now(),'library_sha256':hashlib.sha256(Path(N.__file__).read_bytes()).hexdigest()}
def classify(b):
 try:return 'ACCEPTED:'+N.decrypt(b,SEED).hex()
 except Exception as e:return type(e).__name__+': '+str(e)
res['hello']={'length':len(HB),'plaintext':N.decrypt(HB,SEED).decode(),'pickup':PICKUP.hex(),'nonce':NONCE.hex(),'tag':TAG.hex(),'reencrypt_different':N.encrypt(b'hello world',SEED)!=HB,'signature':str(inspect.signature(N.encrypt))}
c=Counter()
for bit in range(1560):
 b=bytearray(HB);b[bit//8]^=1<<(bit%8);c[classify(b)]+=1
res['single_bit_flips']=dict(c);print('bitflips',c,flush=True)
blobs=[N.encrypt(R.randbytes(R.randrange(128)),SEED) for _ in range(40)]
c=Counter()
for a,b in zip(blobs,blobs[1:]+blobs[:1]):
 for mix in [a[:3]+b[3:19]+a[19:],a[:19]+b[19:35]+a[35:],a[:35]+b[35:163]+a[163:],a[:163]+b[163:],a[:99]+b[99:163]+a[163:]]:c[classify(mix)]+=1
res['splices_200_including_40_pickup_swaps']=dict(c)
c=Counter()
for _ in range(1000):c[classify(b'SN2'+R.randbytes(192))]+=1
for _ in range(200):c[classify(R.randbytes(195))]+=1
for L in (0,1,3,178,179,194,196,300):c[classify(HB[:L] if L<195 else HB+bytes(L-195))]+=1
res['random_1200_plus_8_wrong_lengths']=dict(c)
c=Counter()
for _ in range(500):
 b=bytearray(HB);b[R.randrange(35,163)]^=R.randrange(1,256);c[classify(b)]+=1
res['ciphertext_corruption_500']=dict(c)
res['legacy']={}
for name in ['pre_pickup','pre_triplet','pre_join_pairs','pre_field_retune','pre_clef_encore_siv','8bit_precolor2','8bit_prebar','4bit_unlooped','testn3']:
 p=Path('/workspace/testn3' if name=='testn3' else '/tmp/sneak_n2_'+name)
 txt=(p/'hello-world.txt').read_text();m=re.search(r'blob \(\d+ bytes.*?: ([0-9a-f]+)',txt)
 if not m:res['legacy'][name]={'error':'archived blob not found'};continue
 old=bytes.fromhex(m.group(1));spec=importlib.util.spec_from_file_location('old_'+name,p/'sneak_n2.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
 row={'length':len(old),'live_result':classify(old),'old_library_plaintext':mod.decrypt(old,SEED).decode()}
 c=Counter()
 for i in range(20):c[classify(mod.encrypt(R.randbytes(R.randrange(mod.MAX_MSG+1)),SEED))]+=1
 row['generated_20']=dict(c);res['legacy'][name]=row
print('integrity complete',flush=True)
# public encrypt-only oracle: correct plaintext is known by experimenter, not attacker
pin=f'{secrets.randbelow(10000):04d}';msg=('PIN:'+pin).encode();target=N.encrypt(msg,SEED)
v,pk,n,ct,tag=N.split_blob(target);t=time.perf_counter();samples=[N.encrypt(msg,SEED) for _ in range(256)]
res['public_pin_match']={'pin':pin,'correct_pin_encryptions':len(samples),'matches_to_target':sum(b==target for b in samples),'unique_pickups':len({b[3:19] for b in samples}),'seconds':round(time.perf_counter()-t,3),'target_blob':target.hex()}
# Seed-holder only: nonce acts as a cheap prefilter; reconstruct every matching candidate in full.
clef=N.staff_clef(SEED);matches=[];t=time.perf_counter()
for guess in range(10000):
 m=f'PIN:{guess:04d}'.encode();gn=hashlib.sha256(clef+pk+N.encode_block(m)).digest()[:16]
 if gn!=n:continue
 sch=N.Schedule(SEED,gn);gc=flat(N.encrypt_grid(N.bytes_to_grid(N.encode_block(m)),sch));gt=hmac.new(sch.mac_key,clef+N.VERSION+pk+gn+gc,hashlib.sha256).digest();gb=N.VERSION+pk+gn+gc+gt
 matches.append({'pin':f'{guess:04d}','nonce':gn.hex(),'pickup':pk.hex(),'full_blob_matches':gb==target})
res['insider_nonce_dictionary']={'all_guesses':10000,'matches':matches,'seconds':round(time.perf_counter()-t,6),'method':'seed-derived clef + copied target pickup; hash nonce prefilter, Schedule/encrypt_grid/HMAC reconstruction for matching candidates. Does not call encrypt() in loop.','direct_seed_decrypt':N.decrypt(target,SEED).decode(),'warning':'Known seed already permits direct decryption. This is not a seed-free attack. siv_nonce(msg,pickup) would itself be a dictionary oracle if exposed by a server.'}
# Same-length changed-mix witness, entirely isolated imported module; no disk/library mutation.
spec=importlib.util.spec_from_file_location('isolated_changed_mixes',N.__file__);alt=importlib.util.module_from_spec(spec);spec.loader.exec_module(alt)
alt.BARS=alt.BARS[1:];alt.TRIPLETS=alt.TRIPLETS[1:];alt_sch=alt.Schedule(SEED,NONCE)
altct=alt.grid_to_bytes(alt.encrypt_grid(alt.bytes_to_grid(alt.encode_block(b'hello world')),alt_sch));alttag=alt._tag(alt_sch.mac_key,PICKUP,NONCE,altct,alt.staff_clef(SEED));altblob=alt.VERSION+PICKUP+NONCE+altct+alttag
res['mix_commitment']={'isolated_change':'skip first BARS and first TRIPLETS entries (forward encryption only)','mac_key_equal':alt_sch.mac_key==SCH.mac_key,'schedule_material_equal':alt_sch.material()==SCH.material(),'clef_equal':alt.staff_clef(SEED)==clef,'changed_ct':altct!=CT,'same_length':len(altblob),'tag_valid_in_live':hmac.compare_digest(alttag,N._tag(SCH.mac_key,PICKUP,NONCE,altct,clef)),'live_result':classify(altblob),'blob':altblob.hex(),'note':'A white-box compatibility witness, not a MAC forgery. No pre-pickup version has the same blob length.'}
res['finished']=now();save('attack_integrity_pin',res)
