"""Follow-up to attack_bow_cube: bow+rehair cube sums on beats 5-7 are above random (0.66 at d=12) with the live layout.
Where does it come from (which output beats), and does it survive cross + S2 and the next half-round? Live vs previous layout.
Lab copy, round-0 tables of the hello schedule; cube positions random among the 24 bits of beats 5,6,7 of ONE staff, or spread over all 16 staffs."""
from common import *
verify_live();t0=time.time();rng=np.random.default_rng(9191)
B=Batch(SCH);B.validate();S0,S20=B.S[0],B.S2[0]
LAY={'live':tuple(N.BOW_STROKES),'previous_(4,5,6)':OLD_STROKES}
def stage(st,X):
 a=bow(X,st);r=rehair(a,S0,S20);c=cross(r);s2=S20[c];h=cross(rehair(bow(trips(bars(s2,S0,S20)),st),S0,S20))
 return {'bow':a,'rehair':r,'cross':c,'S2':s2,'next_half':h}
def zf(Y,cells):acc=np.bitwise_xor.reduce(Y,axis=0)[cells];return np.unpackbits(acc.astype(np.uint8))==0
def run(st,d,spread,trials):
 out={k:[0,0] for k in ('bow','rehair','cross','S2','next_half')};byb=np.zeros(8);nb=0
 for _ in range(trials):
  staffs=list(range(16)) if spread else [int(rng.integers(16))]
  pool=[f*8+c for f in staffs for c in (5,6,7)];pos=rng.choice([p*8+b for p in pool for b in range(8)],d,replace=False)
  X=np.repeat(rng.integers(0,256,(1,128)),1<<d,0);idx=np.arange(1<<d)
  for k,b in enumerate(pos):X[:,b//8]^=((idx>>k)&1)<<(b%8)
  Y=stage(st,X);act=sorted(set(p//8 for p in pos//8)) if False else staffs
  for k,v in Y.items():
   cells=[f*8+c for f in act for c in range(8)] if k in ('bow','rehair') else list(range(128))
   z=zf(v,cells);out[k][0]+=int(z.sum());out[k][1]+=len(z)
  if not spread:
   f=staffs[0];r=Y['rehair'][:,f*8:f*8+8];byb+=np.array([zf(r,[c]).mean() for c in range(8)]);nb+=1
 o={k:round(a/b,3) for k,(a,b) in out.items()}
 if nb:o['rehair_zero_frac_by_out_beat_active_staff']=(byb/nb).round(3).tolist()
 return o
res={'started':now(),'metric':'fraction of output bits with zero cube sum (random 0.5); bow/rehair counted on the active staff(s) only, later stages on all 128 cells'}
for lab,st in LAY.items():
 res[lab]={}
 for spread in (False,True):
  for d in (8,12,16):
   res[lab][f'{"all16staffs" if spread else "one_staff"}_d{d}']=run(st,d,spread,24 if d<16 else 8)
 print(lab,json.dumps(res[lab]),flush=True)
# dependency: which bow outputs can an input beat reach (live vs previous)
dep={}
X=rng.integers(0,256,(1<<14,8))
for lab,st in LAY.items():
 a=bow_staff(X,st);m=np.zeros((8,8),bool)
 for t in range(8):
  for d in range(1,256,7):
   H=X.copy();H[:,t]^=d;m[t]|=(a!=bow_staff(H,st)).any(0)
 dep[lab]={t:[int(c) for c in np.nonzero(m[t])[0]] for t in range(8)}
res['bow_input_to_output_dependency']=dep;print('dep',dep,flush=True)
res['seconds']=round(time.time()-t0,1);res['finished']=now();save('attack_cube_survival',res)
