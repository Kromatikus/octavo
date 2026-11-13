"""LAB ONLY (nothing applied): candidate fix for the three-way shared rotation. Keep BOW_STROKES as live, but derive each
beat-0 reader's rotations from a different view of beat 0 so the three strokes no longer share (r1,r2).
The singleton arguments only use 'pressure byte unchanged => rotations fixed', which holds for ANY per-stroke function of p."""
from common import *
verify_live();t0=time.time();rng=np.random.default_rng(4545)
LIVE=tuple(N.BOW_STROKES);k0=SCH.rounds[0];S0=np.array(k0['S']);S20=np.array(k0['S2'])
def rot8(p,k):return ((p<<k)|(p>>(8-k)))&255 if k else p
VAR={'live':{},
 'A_bitslice_rotl_p_by_0_3_5':{2:lambda p:p,3:lambda p:rot8(p,3),6:lambda p:rot8(p,5)},
 'B_xor_consts_00_5A_C3':{2:lambda p:p,3:lambda p:p^0x5A,6:lambda p:p^0xC3},
 'C_add_consts_0_3_5_mod7_offsets':{2:lambda p:p,3:lambda p:p+3,6:lambda p:p+5}}
def gbow(x,var):
 x=np.asarray(x,dtype=np.int64).copy()
 for n,(i,j,p) in enumerate(LIVE):
  pp=x[:,p];pp=var[n](pp) if n in var else pp
  r1=1+(pp%7);r2=1+((pp>>3)%7)
  u=(x[:,i]+rotl(x[:,j],r1))&255;x[:,i]=u;x[:,j]=x[:,j]^rotl(u,r2)
 return x
assert np.array_equal(gbow(rng.integers(0,256,(999,8)),{}),bow_staff(_:=rng.integers(0,256,(999,8)))) or True
X=rng.integers(0,256,(4000,8));assert np.array_equal(gbow(X,{}),bow_staff(X))
res={'started':now(),'note':'lab copy only; live code untouched','variants':list(VAR)}
out={}
for lab,var in VAR.items():
 r={}
 # inverse exists (pressure read before write; beat 0 unchanged after stroke 1) - check
 # kernel scan (singletons) all beats
 B=rng.integers(0,256,(1<<14,8));a=gbow(B,var);hits=[0]*8
 for t in range(8):
  for d in range(1,256):
   H=B.copy();H[:,t]^=d;z=a^gbow(H,var);act=z!=0;w=act.sum(1)
   for i in (0,2,4,6):hits[t]+=int(((w==2)&act[:,i]&act[:,i+1]&((z[:,i]==z[:,i+1])|(z[:,i]==GF[2,z[:,i+1]]))).sum())
 r['rehair_singletons_by_beat_4.18M']=hits
 # forced changes (arguments)
 B=rng.integers(0,256,(2048,8));a=gbow(B,var);alw={}
 for t in (0,4,6):
  m=np.ones(8,bool)
  for d in range(1,256):H=B.copy();H[:,t]^=d;m&=(a!=gbow(H,var)).all(0)
  alw[t]=np.nonzero(m)[0].tolist()
 r['forced_changes']=alw
 # best single-beat bow differential, beats 4..7 (2^13 bases, all deltas)
 B=rng.integers(0,256,(1<<13,8));a=gbow(B,var);pack=lambda z:(z*(256**np.arange(8, dtype=np.int64))).sum(1);bd={}
 for t in (0,4,5,6,7):
  best=0
  for d in range(1,256):
   H=B.copy();H[:,t]^=d;best=max(best,int(np.unique(pack(a^gbow(H,var)),return_counts=True)[1].max()))
  bd[t]=round(math.log2(best/len(B)),2)
 r['bow_best_diff_log2']=bd
 # rehair integral beat 6 -> (4,5); beat 7 -> (4,5)
 zi={}
 for t in (6,7):
  c=0
  for _ in range(32):
   Xa=np.repeat(rng.integers(0,256,(1,8)),256,0);Xa[:,t]=np.arange(256);c+=all(np.bitwise_xor.reduce(rehair_staff(gbow(Xa,var),S0,S20),0)[[4,5]]==0)
  zi[t]=c
 r['rehair_integral_zero_on_4_5_of_32']=zi
 # bow+rehair cube d=12 on beats 5-7, zero frac on out beats 4-7
 z=0;tot=0
 for _ in range(48):
  pos=rng.choice(np.arange(40,64),12,replace=False);idx=np.arange(1<<12);Xc=np.repeat(rng.integers(0,256,(1,8)),1<<12,0)
  for k,b in enumerate(pos):Xc[:,b//8]^=((idx>>k)&1)<<(b%8)
  bb=np.unpackbits(np.bitwise_xor.reduce(rehair_staff(gbow(Xc,var),S0,S20),0)[[4,5,6,7]].astype(np.uint8))==0;z+=int(bb.sum());tot+=len(bb)
 r['bow_rehair_cube_d12_zero_frac']=round(z/tot,3)
 # linear 0.039 / 0.145
 Xl=rng.integers(0,256,(1<<20,8));Y=gbow(Xl,var)
 r['corr_c6b0_c7b4']=round(float(1-2*(((Xl[:,6]&1)^((Y[:,7]>>4)&1)).mean())),4)
 out[lab]=r;print(lab,json.dumps(r),flush=True)
res['screen']=out;res['seconds']=round(time.time()-t0,1);res['finished']=now();save('attack_fix_screen',res)
