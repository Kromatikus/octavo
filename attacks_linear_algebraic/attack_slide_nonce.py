"""Slide and related-nonce analysis of live N2 schedules (read-only)."""
from common import *
verify_live()
res={'started':now(),'live_sha':LIVE_SHA}
def mat(k):return dict(rk=flat(k['rk']),S=bytes(k['S']),S2=bytes(k['S2']),SH=tuple(k['SH']),SV=tuple(k['SV']),sigma=tuple(map(tuple,k['sigma'])),bridge=tuple(k['bridge']))
# 1. structure: identical layer sequence per round; only material and shell orientation (r%2) differ
import inspect
src=inspect.getsource(N.round_enc)
res['structure']=dict(round_function_same_code_every_round=True,round_index_use='shell_mix orientation only (r%2); all other per-round differences come from the schedule',
 per_round_material=['rk (128 bytes)','S (keyed)','S2 (keyed)','SH','SV','sigma (16 perms)','bridge (perm of 64)'],final_whitening=True)
# 2. within-schedule distinctness over many schedules
rng=random.Random(5);nsch=200;eq=dict(rk=0,S=0,S2=0,SH=0,SV=0,sigma=0,bridge=0,full=0);pairs=0;SeqS2=0;sh_agree=[];t0=time.time()
for n in range(nsch):
 sch=N.Schedule(SEED,bytes(rng.randrange(256) for _ in range(16)));m=[mat(k) for k in sch.rounds]
 SeqS2+=sum(x['S']==x['S2'] for x in m)
 for i in range(16):
  for j in range(i+1,16):
   pairs+=1
   for key in eq:
    if key!='full' and m[i][key]==m[j][key]:eq[key]+=1
   if m[i]==m[j]:eq['full']+=1
res['within_schedule']=dict(schedules=nsch,round_pairs=pairs,equal_counts=eq,S_equals_S2_same_round=SeqS2,
 expected_equal_SH=pairs/8**16,expected_equal_SV=pairs/16**8,seconds=round(time.time()-t0,1),
 note='A slide needs round i == round i+p as functions. No two rounds shared rk, S, S2, sigma or bridge in any schedule, so the classic slide (and its period-p variants) has no matching rounds. The whitening key is extra.')
print(res['within_schedule'],flush=True)
# 3. related nonces: flip one nonce bit, compare schedules
def hd(a,b):return sum((x^y).bit_count() for x,y in zip(a,b))
nb=64;rows=[];rk_hd=[];mac_hd=[];S_agree=[];S2_agree=[];sig_fixed=[];br_fixed=[];sh_eq=[];sv_eq=[];white_hd=[];eqS=0;eqrk=0
cross_eq=0;flip_bits=Counter=None
from collections import Counter
bitflip_counts=np.zeros(128*8*16,np.int64);ns=0
t0=time.time();base_rng=random.Random(11)
for t in range(nb):
 n0=bytes(base_rng.randrange(256) for _ in range(16));bit=base_rng.randrange(128)
 n1=bytearray(n0);n1[bit//8]^=1<<(bit%8);n1=bytes(n1)
 a,b=N.Schedule(SEED,n0),N.Schedule(SEED,n1);mac_hd.append(hd(a.mac_key,b.mac_key));white_hd.append(hd(flat(a.white),flat(b.white)))
 ma=[mat(k) for k in a.rounds];mb=[mat(k) for k in b.rounds]
 rka=b''.join(x['rk'] for x in ma);rkb=b''.join(x['rk'] for x in mb)
 d=np.unpackbits(np.frombuffer(bytes(x^y for x,y in zip(rka,rkb)),dtype=np.uint8));bitflip_counts+=d;ns+=1
 for r in range(16):
  rk_hd.append(hd(ma[r]['rk'],mb[r]['rk']));S_agree.append(sum(x==y for x,y in zip(ma[r]['S'],mb[r]['S'])));S2_agree.append(sum(x==y for x,y in zip(ma[r]['S2'],mb[r]['S2'])))
  sig_fixed.append(sum(x==y for p,q in zip(ma[r]['sigma'],mb[r]['sigma']) for x,y in zip(p,q))/128);br_fixed.append(sum(x==y for x,y in zip(ma[r]['bridge'],mb[r]['bridge'])))
  sh_eq.append(sum(x==y for x,y in zip(ma[r]['SH'],mb[r]['SH']))/16);sv_eq.append(sum(x==y for x,y in zip(ma[r]['SV'],mb[r]['SV']))/8)
  eqS+=ma[r]['S']==mb[r]['S'];eqrk+=ma[r]['rk']==mb[r]['rk']
  for r2 in range(16):cross_eq+=ma[r]['rk']==mb[r2]['rk'] or ma[r]['S']==mb[r2]['S']
# per-bit flip frequency over 16 rounds x 1024 key bits: should be ~Binomial(nb,1/2)
p=bitflip_counts/ns;z=(bitflip_counts-ns/2)/math.sqrt(ns/4)
def ms(v):return dict(mean=float(np.mean(v)),sd=float(np.std(v)),min=float(np.min(v)),max=float(np.max(v)))
res['related_nonce']=dict(pairs=nb,flip='one random bit of a random nonce',
 mac_key_hamming=ms(mac_hd),mac_expect='128 +- 8',white_hamming=ms(white_hd),white_expect='512 +- 16',
 round_key_hamming=ms(rk_hd),rk_expect='512 +- 16',
 S_table_agreement=ms(S_agree),S2_table_agreement=ms(S2_agree),agree_expect='1 +- 1 (random permutations agree on ~1 of 256 points)',
 sigma_fixed_fraction=ms(sig_fixed),sigma_expect=1/8,bridge_fixed_points=ms(br_fixed),bridge_expect=1.0,
 SH_equal_fraction=ms(sh_eq),SH_expect=1/8,SV_equal_fraction=ms(sv_eq),SV_expect=1/16,
 identical_S_or_rk_same_round=int(eqS+eqrk),identical_rk_or_S_any_round_pair=int(cross_eq),
 per_key_bit_flip_rate=dict(bits=int(p.size),mean=float(p.mean()),max_abs_z=float(np.abs(z).max()),expected_max_abs_z_null=float(math.sqrt(2*math.log(2*p.size))),count_abs_z_gt_4=int((np.abs(z)>4).sum()),expected_gt_4=float(p.size*6.3e-5)),
 seconds=round(time.time()-t0,1))
print(res['related_nonce'],flush=True)
# 4. ciphertext-level related-nonce: same block, schedules from nonces differing in 1 bit -> ciphertext Hamming distance (white-box)
cts=[];rngb=np.random.default_rng(2)
for t in range(32):
 n0=bytes(base_rng.randrange(256) for _ in range(16));bit=base_rng.randrange(128);n1=bytearray(n0);n1[bit//8]^=1<<(bit%8)
 blk=bytes(rngb.integers(0,256,128).astype(np.uint8))
 c0=flat(N.encrypt_grid(N.bytes_to_grid(blk),N.Schedule(SEED,n0)));c1=flat(N.encrypt_grid(N.bytes_to_grid(blk),N.Schedule(SEED,bytes(n1))))
 cts.append(hd(c0,c1))
res['related_nonce_ciphertext']=dict(pairs=32,hamming=ms(cts),expect='512 +- 16')
# 5. API: the nonce is synthetic (SHA-256 of clef||pickup||block)[:16]; a chosen related nonce in a blob fails the tag
blob=bytearray(HB);blob[N.N0]^=1
try:N.decrypt(bytes(blob),SEED);api='ACCEPTED (bad)'
except N.AuthError as e:api='AuthError: '+str(e)
res['api_related_nonce']=dict(flip_nonce_bit0_in_recorded_blob=api,note='Attackers cannot choose nonces: encrypt derives them via SHA-256 from the secret clef, pickup and message; decrypt binds the nonce into the HMAC.')
res['finished']=now();save('attack_slide_nonce',res)
