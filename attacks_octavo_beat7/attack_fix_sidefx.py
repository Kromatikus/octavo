"""Side effects of the proposed (4,5,0) layout vs live and old, same metrics as attack_bow.py (lab only)."""
from common import *
verify_live();t0=time.time();rng=np.random.default_rng(9090)
PROP=((0,1,2),(2,3,4),(4,5,0),(6,7,0),(1,2,3),(3,4,5),(5,6,0))
res={'started':now()}
pack=lambda z:(z*(256**np.arange(8))).sum(1)
def bits(x):return np.unpackbits(x.astype(np.uint8)[:,:,None],axis=2,bitorder='little').reshape(len(x),-1).astype(np.float32)*2-1
for lab,st in (('live',N.BOW_STROKES),('old',OLD_STROKES),('proposed',PROP)):
 X=rng.integers(0,256,(1<<21,8));C=bits(X).T@bits(bow_staff(X,st))/len(X);A=np.abs(C)
 Bq=rng.integers(0,256,(1<<14,8));a=bow_staff(Bq,st);best=[]
 for t in range(8):
  m=(0,0)
  for d in range(1,256):
   H=Bq.copy();H[:,t]^=d;c=int(np.unique(pack(a^bow_staff(H,st)),return_counts=True)[1].max())
   if c>m[0]:m=(c,d)
  best.append(round(math.log2(m[0]/len(Bq)),2))
 # bow-alone singletons on the test-style 512 bases odd beats + all beats on 4096 random
 B2=rng.integers(0,256,(4096,8));a2=bow_staff(B2,st);bs=0
 for t in range(8):
  for d in range(1,256):
   H=B2.copy();H[:,t]^=d;bs+=int(((a2^bow_staff(H,st))!=0).sum(1).__eq__(1).sum())
 res[lab]=dict(strokes=st,max_single_bit_corr=round(float(A.max()),4),cell6b0_cell7b4=round(float(C[48,60]),4),best_diff_log2_by_beat=best,bow_alone_singletons_all_beats_4096x255x8=bs,reads_of_beat0=sum(p==0 for *_,p in st))
 print(lab,res[lab],flush=True)
res['seconds']=round(time.time()-t0,1);res['finished']=now();save('attack_fix_sidefx',res)
