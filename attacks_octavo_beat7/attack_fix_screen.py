"""Lab-only screen of candidate bow pressure layouts for the remaining beat-6 rehair singletons (table-independent).
Nothing in sneak_n2.py is changed; candidates are evaluated with an independent NumPy bow."""
from common import *
verify_live();t0=time.time()
res={'started':now(),'note':'Rehair singleton <=> bow delta = two cells of one pair (i,i+1), i even, with du==dv or du==2*dv in GF(2^8)/0x1F5. Table-independent.'}
rng=np.random.default_rng(31337)
def count(strokes,nb,beats=range(8)):
 B=rng.integers(0,256,(nb,8));a=bow_staff(B,strokes);per=[0]*8;bowsingle=0
 for t in beats:
  for d in range(1,256):
   H=B.copy();H[:,t]^=d;z=a^bow_staff(H,strokes);act=z!=0;w=act.sum(1);bowsingle+=int((w==1).sum())
   for i in (0,2,4,6):
    m=(w==2)&act[:,i]&act[:,i+1];per[t]+=int((m&((z[:,i]==z[:,i+1])|(z[:,i]==GF[2,z[:,i+1]]))).sum())
 return per,bowsingle
cands=[('live',N.BOW_STROKES)]
for k,(i,j,p) in enumerate(N.BOW_STROKES):
 for q in range(8):
  if q in (i,j,p):continue
  st=list(N.BOW_STROKES);st[k]=(i,j,q);cands.append((f'stroke{k} ({i},{j},{p})->({i},{j},{q})',tuple(st)))
stage1=[]
for lab,st in cands:
 per,bs=count(st,2048);stage1.append(dict(label=lab,strokes=st,rehair_singletons_by_beat=per,total=sum(per),bow_alone_singletons=bs,cases=2048*255*8))
 print(lab,per,bs,flush=True)
res['stage1']=stage1
zero=[c for c in stage1 if c['total']==0]
# stage 2: zero-hit candidates, 32,768 bases all beats (66.8M cases), with side effects
def sidefx(st):
 X=rng.integers(0,256,(1<<20,8));Y=bow_staff(X,st)
 bx=np.unpackbits(X.astype(np.uint8)[:,:,None],axis=2,bitorder='little').reshape(len(X),-1).astype(np.float32)*2-1
 by=np.unpackbits(Y.astype(np.uint8)[:,:,None],axis=2,bitorder='little').reshape(len(X),-1).astype(np.float32)*2-1
 C=np.abs(bx.T@by/len(X))
 Bq=rng.integers(0,256,(1<<13,8));a=bow_staff(Bq,st);best=0
 pack=lambda z:(z*(256**np.arange(8))).sum(1)
 for t in range(8):
  for d in range(1,256,2):
   H=Bq.copy();H[:,t]^=d;best=max(best,int(np.unique(pack(a^bow_staff(H,st)),return_counts=True)[1].max()))
 return dict(bow_max_single_bit_corr=round(float(C.max()),4),bow_best_single_beat_diff_log2=round(math.log2(best/(1<<13)),2),reads_of_beat0=sum(p==0 for _,_,p in st))
stage2=[]
for c in sorted(zero,key=lambda c:c['bow_alone_singletons'])[:6]+[stage1[0]]:
 per,bs=count(c['strokes'],1<<15);row=dict(label=c['label'],strokes=c['strokes'],cases=(1<<15)*255*8,rehair_singletons_by_beat=per,total=sum(per),bow_alone_singletons=bs,**sidefx(c['strokes']))
 stage2.append(row);print('stage2',row,flush=True)
res['stage2']=stage2
res['seconds']=round(time.time()-t0,1);res['finished']=now();save('attack_fix_screen',res)
