"""Extra: additive (mod 256) integral through the Z/256Z triplets, since XOR sums die at the triplets."""
from common import *
verify_live();B=Batch(SCH);res={'started':now(),'live_sha':LIVE_SHA}
def pre_bow(x):return trips(bars(B.linear(B.S[0][np.asarray(x)^B.rk[0]],0),B.S[0],B.S2[0]))
def pre_rehair(x):return bow(pre_bow(x))
FUN={'..+bars+triplets (before bow)':pre_bow,'..+bow (before rehair)':pre_rehair,'1 round':lambda x:B.enc(x,1),'2 rounds':lambda x:B.enc(x,2)}
rng=np.random.default_rng(77);out=[]
for name,fn in FUN.items():
 hist=np.zeros(256,np.int64);xz=0;cases=0
 for c in range(0,128,4):
  for b in range(2):
   X=np.repeat(rng.integers(0,256,128)[None,:],256,0);X[:,c]=np.arange(256);Y=fn(X)
   s=Y.sum(0)%256;hist+=np.bincount(s,minlength=256);xz+=int((np.bitwise_xor.reduce(Y,axis=0)==0).sum());cases+=1
 tot=hist.sum();top=np.argsort(-hist)[:3]
 out.append(dict(function=name,cases=cases,output_cells=int(tot),additive_sum_top_values={int(v):int(hist[v]) for v in top},
  share_sum_0_or_128=float((hist[0]+hist[128])/tot),random_share=2/256,xor_zero_sum_share=xz/tot,random_xor_share=1/256))
 print(out[-1],flush=True)
res['additive_integral']=out;res['finished']=now();save('attack_additive_integral',res)
