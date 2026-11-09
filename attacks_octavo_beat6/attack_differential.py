"""Round-level differential: sparse-output scans 1-4 and 16 rounds, avalanche/SAC, truncated (activity) differentials,
half-round minimum active S-boxes live vs previous bow, best-trail bounds, bow+rehair best differential."""
from common import *
import common
verify_live();t0=time.time()
res={'started':now(),'live_sha':LIVE_SHA}
B=Batch(SCH);res['batch_validated_round_calls']=B.validate()
rng=np.random.default_rng(777)
def enc(X,R):
 return np.concatenate([B.enc(X[s:s+16384],R) for s in range(0,len(X),16384)])
# 1. sparse-output scans
def sparse(R,per_cell):
 hits=mx=tot=zs=0;wit=None
 for c0 in range(0,128,16):
  X=rng.integers(0,256,(16*per_cell,128));cells=np.repeat(np.arange(c0,c0+16),per_cell);d=rng.integers(1,256,16*per_cell)
  Y=X.copy();Y[np.arange(len(Y)),cells]^=d;D=enc(X,R)^enc(Y,R);z=(D==0).sum(1)
  tot+=len(z);zs+=int(z.sum());hits+=int((z>=8).sum())
  if z.max()>mx:mx=int(z.max());i=int(z.argmax());wit=dict(cell=int(cells[i]),delta=int(d[i]),unchanged=mx)
 return dict(rounds=R,pairs=tot,hits_ge8_unchanged=hits,max_unchanged=mx,mean_unchanged=round(zs/tot,4),random_mean=0.5,witness=wit)
res['sparse']=[sparse(1,2048),sparse(2,2048),sparse(3,1024),sparse(4,512),sparse(16,128)]
for s in res['sparse']:print('sparse',s,flush=True)
# 2. avalanche + SAC at 1 and 16 rounds, plus 2-round SAC matrix extremes
def aval(R,n=4096):
 X=rng.integers(0,256,(n,128));bit=rng.integers(0,1024,n);Y=X.copy();Y[np.arange(n),bit//8]^=1<<(bit%8)
 D=enc(X,R)^enc(Y,R);w=np.unpackbits(D.astype(np.uint8),axis=1).sum(1)
 return dict(rounds=R,pairs=n,mean=round(float(w.mean()),2),min=int(w.min()),max=int(w.max()),std=round(float(w.std()),2),ideal='512 +- 16')
res['avalanche']=[aval(1),aval(2),aval(16)]
def sac(R,n=256):
 # every input bit, n samples each: flip prob of every output bit; report max |p-0.5| and its z-score
 M=np.zeros((1024,1024))
 for ib in range(1024):
  X=rng.integers(0,256,(n,128));Y=X.copy();Y[:,ib//8]^=1<<(ib%8)
  M[ib]=np.unpackbits((enc(X,R)^enc(Y,R)).astype(np.uint8),axis=1).mean(0)
 dev=np.abs(M-0.5);z=dev.max()/(0.5/math.sqrt(n))
 return dict(rounds=R,samples_per_input_bit=n,max_abs_dev=round(float(dev.max()),4),max_z=round(float(z),2),expected_null_max_z=round(math.sqrt(2*math.log(2**20)),2),mean_abs_dev=round(float(dev.mean()),4),null_mean_abs_dev=round(0.5/math.sqrt(n)*math.sqrt(2/math.pi),4))
res['sac']=[sac(1),sac(2)];print('aval',res['avalanche'],res['sac'],flush=True)
# 3. truncated differentials: activity pattern after each sub-layer of round 0 for single-byte input deltas (all 128 cells x 64 bases x all 255 deltas sampled)
def halfsteps(x,r,strokes):
 S,S2=B.S[r],B.S2[r];out={}
 x=B.S[r][x^B.rk[r]];out['S']=x;x=B.linear(x,r);out['weave+butterfly+shell']=x
 x=bars(x,S,S2);out['bars']=x;x=trips(x);out['trips']=x;x=bow(x,strokes);out['bow']=x;x=rehair(x,S,S2);out['rehair']=x;x=cross(x);out['cross (=S2 inputs)']=x
 x=S2[x];x=bars(x,S,S2);x=trips(x);x=bow(x,strokes);x=rehair(x,S,S2);out['rehair2']=x;x=cross(x);out['round out']=x
 return out
trunc={}
for lab,st in (('new',N.BOW_STROKES),('old',OLD_STROKES)):
 mins={};means={};staffmin={}
 for c in range(128):
  X=rng.integers(0,256,(4096,128));d=rng.integers(1,256,4096);Y=X.copy();Y[:,c]^=d
  ox=halfsteps(X,0,st);oy=halfsteps(Y,0,st)
  for k in ox:
   a=(ox[k]!=oy[k]);w=a.sum(1);ws=a.reshape(-1,16,8).any(2).sum(1)
   mins[k]=min(mins.get(k,999),int(w.min()));means.setdefault(k,[]).append(float(w.mean()));staffmin[k]=min(staffmin.get(k,99),int(ws.min()))
 trunc[lab]={k:dict(min_active_cells=mins[k],mean_active_cells=round(float(np.mean(means[k])),2),min_active_staffs=staffmin[k]) for k in mins}
 print('trunc',lab,{k:v['min_active_cells'] for k,v in trunc[lab].items()},flush=True)
res['truncated_round0_single_byte']=dict(samples='128 cells x 4096 random (base,delta)',layouts=trunc)
# 4. best-trail bound (sound, relaxed) with DDT max 4/256 per S-box and branch 6 of the cross layer
ddt=[N.ddt_max(k['S']) for k in SCH.rounds[:4]]+[N.ddt_max(k['S2']) for k in SCH.rounds[:4]]
res['trail_bound']=dict(ddt_max_sampled_tables=ddt,per_sbox_prob='4/256 = 2^-6',
 rows=[dict(rounds=R,min_active_sboxes=(2*R-1)*6+2,max_trail_prob_log2=-6*((2*R-1)*6+2)) for R in (1,2,3,4,8,16)],
 note='Same relaxed model as attacks_linear_algebraic: triplets+bow treated as an arbitrary staff-local bijection, so the bow change cannot weaken this bound. Single-trail bound; differentials (clustering) not bounded.')
# 5. best differential through bow+rehair for each input beat (S-box tables of round 0), new vs old
k0=SCH.rounds[0];S0=np.array(k0['S']);S20=np.array(k0['S2'])
pack=lambda z:(z*(256**np.arange(8))).sum(1)
bd={}
for lab,st in (('new',N.BOW_STROKES),('old',OLD_STROKES)):
 X=rng.integers(0,256,(1<<14,8));a=rehair_staff(bow_staff(X,st),S0,S20);row=[]
 for t in range(8):
  best=(0,0)
  for d in range(1,256):
   H=X.copy();H[:,t]^=d;c=np.unique(pack(a^rehair_staff(bow_staff(H,st),S0,S20)),return_counts=True)[1].max()
   if c>best[0]:best=(int(c),d)
  row.append(dict(beat=t,count=best[0],of=1<<14,delta=best[1],prob_log2=round(math.log2(best[0]/(1<<14)),2)))
 bd[lab]=row;print('bow+rehair bestdiff',lab,[(r['beat'],r['prob_log2']) for r in row],flush=True)
res['bow_rehair_best_differential']=bd
# 6. one-round single-cell output-value bias: for each input cell, max frequency of one (output cell, output delta) over 2^14 pairs
X=rng.integers(0,256,(1<<14,128));Y0=enc(X,1);mxs=[]
for c in range(0,128,8):
 d=rng.integers(1,256);Y=X.copy();Y[:,c]^=d;D=Y0^enc(Y,1)
 mxs.append(max(int(np.bincount(D[:,o],minlength=256).max()) for o in range(128)))
res['one_round_cell_delta_bias']=dict(pairs=1<<14,input_cells=list(range(0,128,8)),max_count=max(mxs),expected=1<<6,note='max over 128 output cells x 256 values; null max for Binomial(16384,1/256) across 32768 tests ~ 64+4.5*8 ~ 100')
print('1r bias',max(mxs),flush=True)
res['seconds']=round(time.time()-t0,1);res['finished']=now();save('attack_differential',res)
