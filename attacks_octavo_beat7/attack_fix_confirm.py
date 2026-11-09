"""Lab-only confirmation scan of the proposed bow layout (4,5,6)->(4,5,0) vs live, 2^16 bases x 8 beats x 255 deltas (133.7M cases each).
Also checks the proposed layout is invertible with the live unbow logic. sneak_n2.py is NOT modified."""
from common import *
verify_live();t0=time.time()
rng=np.random.default_rng(424242)
LIVE=N.BOW_STROKES;PROP=((0,1,2),(2,3,4),(4,5,0),(6,7,0),(1,2,3),(3,4,5),(5,6,0))
res={'started':now(),'proposed':PROP,'live':LIVE}
B=rng.integers(0,256,(1<<16,8))
def count(st):
 a=bow_staff(B,st);per=[0]*8;wit=[]
 for t in range(8):
  for d in range(1,256):
   H=B.copy();H[:,t]^=d;z=a^bow_staff(H,st);act=z!=0;w=act.sum(1)
   for i in (0,2,4,6):
    m=(w==2)&act[:,i]&act[:,i+1]&((z[:,i]==z[:,i+1])|(z[:,i]==GF[2,z[:,i+1]]));per[t]+=int(m.sum())
    for k in np.nonzero(m)[0][:max(0,3-len(wit))]:wit.append(dict(base=B[k].tolist(),beat=t,delta=d,bow_delta=z[k].tolist()))
 return dict(cases=len(B)*255*8,by_beat=per,total=sum(per),witnesses=wit)
for lab,st in (('live',LIVE),('proposed',PROP)):
 res[lab+'_scan']=count(st);print(lab,res[lab+'_scan']['by_beat'],flush=True)
# invertibility of the proposed layout: reverse-order unbow (pressure cell never written by its own stroke)
X=rng.integers(0,256,(1<<16,8));Y=bow_staff(X,PROP);Z=Y.copy()
for i,j,p in reversed(PROP):
 pp=Z[:,p];r1=1+pp%7;r2=1+(pp>>3)%7;Z[:,j]=Z[:,j]^rotl(Z[:,i],r2);Z[:,i]=(Z[:,i]-rotl(Z[:,j],r1))&255
res['proposed_invertible_65536']=bool(np.array_equal(X,Z))
res['proposed_bijective_note']='each stroke is invertible given p, and p is not i or j, so the layout is a bijection'
res['seconds']=round(time.time()-t0,1);res['finished']=now();save('attack_fix_confirm',res)
