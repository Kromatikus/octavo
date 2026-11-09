"""Key schedule, related-seed, weak-seed checks; boomerang (lab, fixed schedule) and rotational probes."""
from common import *
import itertools
verify_live();t0=time.time()
res={'started':now(),'live_sha':LIVE_SHA}
r=random.Random(808);rng=np.random.default_rng(808)
def hd(a,b):return sum(bin(x^y).count('1') for x,y in zip(a,b))
NONCE0=bytes(range(16))
# 1. related seeds: one-bit seed flips, same nonce
rel=[]
for _ in range(32):
 s1=bytes(r.randrange(256) for _ in range(128));b=r.randrange(1024);s2=bytearray(s1);s2[b//8]^=1<<(b%8);s2=bytes(s2)
 A,Bs=N.Schedule(s1,NONCE0),N.Schedule(s2,NONCE0)
 blk=N.bytes_to_grid(N.encode_block(b'hello world'))
 rel.append(dict(rk_hd=np.mean([hd(flat(a['rk']),flat(c['rk'])) for a,c in zip(A.rounds,Bs.rounds)]),S_agree=np.mean([sum(x==y for x,y in zip(a['S'],c['S'])) for a,c in zip(A.rounds,Bs.rounds)]),
  mac_hd=hd(A.mac_key,Bs.mac_key),clef_hd=hd(N.staff_clef(s1),N.staff_clef(s2)),keysig_hd=hd(N.key_signature(s1),N.key_signature(s2)),
  ct_hd_same_nonce=hd(flat(N.encrypt_grid(blk,A)),flat(N.encrypt_grid(blk,Bs)))))
res['related_seed']={k:[round(float(np.mean([x[k] for x in rel])),2),round(float(np.std([x[k] for x in rel])),2)] for k in rel[0]}
res['related_seed']['ideal']=dict(rk_hd=512,S_agree=1,mac_hd=128,clef_hd=64,keysig_hd=64,ct_hd_same_nonce=512);res['related_seed']['pairs']=32
print('related seed',res['related_seed'],flush=True)
# 2. structural weak-key statistics over many schedules (random seeds+nonces) and named weak seeds
def stats(s):
 o=dict(S_fixed=[],S2_fixed=[],SH_zero_rounds=0,SV_zero_rounds=0,sigma_identity_faces=0,bridge_identity_rounds=0,bridge_fixed=[],rk_zero_bytes=0,S2_is_S_xor_const=0,A1_identity=0)
 for k in s.rounds:
  o['S_fixed'].append(sum(k['S'][x]==x for x in range(256)));o['S2_fixed'].append(sum(k['S2'][x]==x for x in range(256)))
  o['SH_zero_rounds']+=all(v==0 for v in k['SH']);o['SV_zero_rounds']+=all(v==0 for v in k['SV'])
  o['sigma_identity_faces']+=sum(sg==list(range(8)) for sg in k['sigma']);o['bridge_identity_rounds']+=k['bridge']==list(range(64))
  o['bridge_fixed'].append(sum(k['bridge'][c]==c for c in range(64)));o['rk_zero_bytes']+=sum(x==0 for x in flat(k['rk']))
  o['S2_is_S_xor_const']+=len({a^b for a,b in zip(k['S'],k['S2'])})==1;o['A1_identity']+=k['A1']==[1<<i for i in range(8)]
 return o
agg=dict(S_fixed=[],S2_fixed=[],bridge_fixed=[]);cnt={k:0 for k in ('SH_zero_rounds','SV_zero_rounds','sigma_identity_faces','bridge_identity_rounds','rk_zero_bytes','S2_is_S_xor_const','A1_identity')}
NS=300
for _ in range(NS):
 o=stats(N.Schedule(bytes(r.randrange(256) for _ in range(128)),bytes(r.randrange(256) for _ in range(16))))
 for k in agg:agg[k]+=o[k]
 for k in cnt:cnt[k]+=o[k]
res['schedule_structure']=dict(schedules=NS,rounds=NS*16,S_fixed_mean=round(float(np.mean(agg['S_fixed'])),3),S_fixed_max=max(agg['S_fixed']),S2_fixed_mean=round(float(np.mean(agg['S2_fixed'])),3),
 bridge_fixed_mean=round(float(np.mean(agg['bridge_fixed'])),3),counts=cnt,expected=dict(S_fixed_mean=1,bridge_fixed_mean=1,rk_zero_bytes=NS*16*128/256,sigma_identity_faces=NS*16*16/40320))
named={'all_zero':bytes(128),'all_ff':b'\xff'*128,'repeat_01':b'\x01'*128,'int_1':1,'alternating_55aa':b'\x55\xaa'*64}
nw={}
for k,sd in named.items():
 o=stats(N.Schedule(sd,NONCE0));b=N.encrypt(b'hello world',sd)
 nw[k]=dict(accepted_as_seed=True,S_fixed_mean=round(float(np.mean(o['S_fixed'])),2),SH_zero_rounds=o['SH_zero_rounds'],sigma_identity_faces=o['sigma_identity_faces'],rk_zero_bytes=o['rk_zero_bytes'],
  roundtrip=N.decrypt(b,sd)==b'hello world')
res['named_weak_seeds']=dict(results=nw,note='SHA-256 sponge makes these schedules look random; but the API accepts trivially guessable seeds (int 0/1, all-zero bytes) without complaint: key-management weakness, not a cipher weakness.')
print('weak',res['schedule_structure'],nw,flush=True)
# per-seed-bit influence on round-0 key (64 seed bits sampled)
fl=[]
s1=bytes(r.randrange(256) for _ in range(128));base=flat(N.Schedule(s1,NONCE0).rounds[0]['rk'])
for b in r.sample(range(1024),64):
 s2=bytearray(s1);s2[b//8]^=1<<(b%8);fl.append(hd(base,flat(N.Schedule(bytes(s2),NONCE0).rounds[0]['rk']))/1024)
res['seed_bit_influence_round0_rk']=dict(bits=64,mean=round(float(np.mean(fl)),4),min=round(min(fl),4),max=round(max(fl),4))
# 3. boomerang (lab, fixed hello schedule): P2=P1^alpha (one cell); C3=C1^delta, C4=C2^delta (one cell); P3^P4 vs alpha
B=Batch(SCH)
def dec(c,R):
 g=N.bytes_to_grid(tobytes(c))
 for rr in range(R-1,-1,-1):g=N.round_dec(g,SCH.rounds[rr],rr)
 return np.frombuffer(flat(g),dtype=np.uint8).astype(np.int64)
boom=[]
for R,nq in ((1,8192),(2,4096),(3,2048)):
 ret=0;zc=[];conf=0
 for q in range(nq):
  ci,co=r.randrange(128),r.randrange(128);a,d=r.randrange(1,256),r.randrange(1,256)
  P1=rng.integers(0,256,(1,128));P2=P1.copy();P2[0,ci]^=a;C=B.enc(np.vstack([P1,P2]),R)
  C[:,co]^=d;P3=dec(C[0],R);P4=dec(C[1],R);D=P3^P4
  ret+=bool(D[ci]==a and (np.count_nonzero(D)==1));zc.append(int((D==0).sum()));conf+=bool(np.count_nonzero(D)<=8 and (np.nonzero(D)[0]//8==ci//8).all())
 boom.append(dict(rounds=R,quartets=nq,exact_return=ret,mean_zero_cells=round(float(np.mean(zc)),3),max_zero_cells=max(zc),random_mean_zero=0.5,returned_inside_one_staff=conf))
 print('boomerang',boom[-1],flush=True)
res['boomerang_lab']=boom
# 4. rotational probes: component and full round, rotl8 of every byte by k
rot=lambda x,k:((x<<k)|(x>>(8-k)))&255
rp={}
X=rng.integers(0,256,(1<<16,8))
for k in (1,2,3,4):
 rp[f'bow_k{k}']=round(float(np.all(bow_staff(rot(X,k))==rot(bow_staff(X),k),axis=1).mean()),5)
 Y=rng.integers(0,256,(1<<14,128));A1=B.enc(rot(Y,k),1);A2=rot(B.enc(Y,1),k)
 rp[f'round1_k{k}_mean_equal_cells']=round(float((A1==A2).sum(1).mean()),3)
 Z=rng.integers(0,256,(1<<14,128));rp[f'trips_k{k}_mean_equal_cells']=round(float((trips(rot(Z,k))==rot(trips(Z),k)).sum(1).mean()),3)
 rp[f'cross_k{k}_mean_equal_cells']=round(float((cross(rot(Z,k))==rot(cross(Z),k)).sum(1).mean()),3)
res['rotational']=dict(probs=rp,random_equal_cells_per_block=0.5,note='rotational pairs need related (rotated) keys too; keys come from SHA-256 so the attacker cannot choose them. Probes only check whether unkeyed layers commute with byte rotation.')
print('rot',rp,flush=True)
# 5. staff-shift symmetry of unkeyed layers: does cross_staff_mix commute with a staff permutation f->f^8 (inner<->outer) or f->f+4 mod 8 within shells?
def perm_staff(x,pi):
 x=x.reshape(-1,16,8);return x[:,pi,:].reshape(-1,128)
sym={}
for name,pi in (('inner<->outer',[(f+8)%16 for f in range(16)]),('rotate4_within_shell',[(f//8)*8+(f%8+4)%8 for f in range(16)]),('swap_pairs',[f^1 for f in range(16)])):
 Z=rng.integers(0,256,(4096,128));sym[name]=bool(np.array_equal(cross(perm_staff(Z,pi)),perm_staff(cross(Z),pi)))
res['cross_layer_staff_symmetry']=dict(commutes=sym,note='A commuting unkeyed layer is only a weak structure: round keys, S-box tables, weave, sigma and bridge differ per staff and per round.')
print('sym',sym,flush=True)
res['seconds']=round(time.time()-t0,1);res['finished']=now();save('attack_keysched_misc',res)
