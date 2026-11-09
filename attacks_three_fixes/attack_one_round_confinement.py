from common import *
res={'started':now(),'schedule_nonce':NONCE.hex()};B=Batch(SCH);rng=np.random.default_rng(2026110813)
# Deterministic staff footprint per input cell (structural: weave/butterfly/bridges are schedule-fixed; later layers stay within staffs)
foot={}
for c in range(128):
 x=rng.integers(0,256,(4096,128),dtype=np.uint16);y=x.copy();y[:,c]^=rng.integers(1,256,4096,dtype=np.uint16)
 d=(B.enc(x,1)^B.enc(y,1)).reshape(-1,16,8)!=0;foot[c]=sorted(np.nonzero(d.any(2).any(0))[0].tolist())
sizes=[len(v) for v in foot.values()];res['footprint_staff_counts']={str(k):sizes.count(k) for k in sorted(set(sizes))}
c=min(foot,key=lambda k:len(foot[k]));S=foot[c];inside=[s*8+t for s in S for t in range(8)];outside=[i for i in range(128) if i not in inside]
n=200000;conf=0;mn=128;fully_all_staffs=0
for st in range(0,n,8192):
 k=min(8192,n-st);x=rng.integers(0,256,(k,128),dtype=np.uint16);y=x.copy();y[:,c]^=rng.integers(1,256,k,dtype=np.uint16)
 d=B.enc(x,1)^B.enc(y,1);conf+=int((~d[:,outside].any(1)).sum());mn=min(mn,int((d!=0).sum(1).min()));fully_all_staffs+=int(((d.reshape(-1,16,8)!=0).any(2)[:,S].all(1)).sum())
x0=bytes(rng.integers(0,256,128,dtype=np.uint8));y0=bytearray(x0);y0[c]^=0x5a;a=live_round_bytes(x0,SCH,1);b=live_round_bytes(bytes(y0),SCH,1)
res['strongest_probability_one_truncated_trail']={'input_cell':c,'output_staffs':S,'output_bytes':inside,'pairs_random_delta':n,'confined':conf,'min_active_bytes':mn,'pairs_where_every_listed_staff_active':fully_all_staffs,
 'random_permutation_probability':f'about 2^-{8*len(outside)}','live_witness':{'x':x0.hex(),'y':bytes(y0).hex(),'delta':'0x5a at cell %d'%c,'active_positions':[i for i in range(128) if a[i]!=b[i]],'confined_live':all(a[i]==b[i] for i in outside)}}
# two rounds: does any staff stay untouched?
x=rng.integers(0,256,(65536,128),dtype=np.uint16);y=x.copy();pos=rng.integers(0,128,65536);y[np.arange(65536),pos]^=rng.integers(1,256,65536,dtype=np.uint16)
d=(B.enc(x,2)^B.enc(y,2)).reshape(-1,16,8)!=0;res['two_round_inactive_staff_pairs']={'pairs':65536,'pairs_with_any_staff_unchanged':int((~d.any(2)).any(1).sum()),'expected_random':65536*16*2**-64}
res['footprints']={str(k):v for k,v in foot.items()}
res['note']='Probability-1 one-round truncated differential from incomplete one-round diffusion (a single cell reaches only the staffs its butterfly face and bridges touch; S2, pairs, triplets and bow stay within each staff). This is generic 1-round structure, not specific to the three fixes; it does not survive to 2 rounds in these tests.'
res['finished']=now();save('attack_one_round_confinement',res)
print(json.dumps({k:v for k,v in res.items() if k!='footprints'},indent=1))
