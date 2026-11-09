"""Refined conditional cubes on the bow alone: cube bits in beats 5-7 (beats 0-4 constant), sums over output beats 5-7 only.
In the live layout beat 0 is constant here, so strokes (6,7,0) and (5,6,0) have FIXED rotations; the old layout's (5,6,7) did not."""
from common import *
verify_live();t0=time.time();rng=np.random.default_rng(5150)
res={'started':now(),'metric':'fraction of output bits of beats 5,6,7 whose cube sum is 0 (random function: 0.5; degree < d: 1.0)'}
def run(st,cells,outcells,d,trials=200):
 z=0;tot=0;allzero=0
 for _ in range(trials):
  pos=rng.choice([c*8+b for c in cells for b in range(8)],d,replace=False);base=rng.integers(0,256,(1,8));idx=np.arange(1<<d);X=np.repeat(base,1<<d,0)
  for k,b in enumerate(pos):X[:,b//8]^=((idx>>k)&1)<<(b%8)
  acc=np.bitwise_xor.reduce(bow_staff(X,st),axis=0)[list(outcells)]
  bb=np.unpackbits(acc.astype(np.uint8))==0;z+=int(bb.sum());tot+=len(bb);allzero+=bool(bb.all())
 return dict(zero_frac=round(z/tot,3),cubes_with_all_out_bits_zero=allzero,trials=trials)
out={}
for lab,st in (('new',N.BOW_STROKES),('old',OLD_STROKES)):
 out[lab]={}
 for cells in ((5,6,7),(6,7),(7,)):
  for d in (2,4,6,8,12,16):
   if d>8*len(cells):continue
   out[lab][f'cube{cells}_d{d}']=run(st,cells,(5,6,7),d)
 print(lab,{k:v['zero_frac'] for k,v in out[lab].items()},flush=True)
res['layouts']=out
# and through bow+rehair (keyed S-boxes) to show the S-boxes restore full degree
k0=SCH.rounds[0];S0=np.array(k0['S']);S20=np.array(k0['S2'])
def run2(st,d,trials=100):
 z=0;tot=0
 for _ in range(trials):
  pos=rng.choice([c*8+b for c in (5,6,7) for b in range(8)],d,replace=False);base=rng.integers(0,256,(1,8));idx=np.arange(1<<d);X=np.repeat(base,1<<d,0)
  for k,b in enumerate(pos):X[:,b//8]^=((idx>>k)&1)<<(b%8)
  acc=np.bitwise_xor.reduce(rehair_staff(bow_staff(X,st),S0,S20),axis=0)[[4,5,6,7]];bb=np.unpackbits(acc.astype(np.uint8))==0;z+=int(bb.sum());tot+=len(bb)
 return round(z/tot,3)
res['bow_plus_rehair_out_beats_4_7']={lab:{f'd{d}':run2(st,d) for d in (4,8,12)} for lab,st in (('new',N.BOW_STROKES),('old',OLD_STROKES))}
print(res['bow_plus_rehair_out_beats_4_7'])
res['seconds']=round(time.time()-t0,1);res['finished']=now();save('attack_bow_cube',res)
