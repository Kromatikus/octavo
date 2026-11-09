from common import *
verify_live()
from collections import Counter
res={'started':now(),'source_sha256':LIVE_SHA}
res['batch_live_crosschecks']=Batch(SCH).validate(8)
# Exhaustive B0 image/inverse, and all one-input XOR derivatives.
invbad=sum(N.b0_unapply(*N.b0_apply(u,v))!=(u,v) or N.b0_apply(*N.b0_unapply(u,v))!=(u,v) for u in range(256) for v in range(256))
def b0(u,v):
 a=(u+rotl(v,3))&255
 return a,v^rotl(a,5)
u=np.repeat(np.arange(256,dtype=np.uint16),256);v=np.tile(np.arange(256,dtype=np.uint16),256)
a,b=b0(u,v);base_witness=[x^y for x,y in zip(N.b0_apply(0,0),N.b0_apply(5,1))]
c,d=b0(u^5,v^1);old=np.stack([a^c,b^d],1)
res['B0']={'inverse_failures_all_65536':invbad,'distinct_images':len(set(zip(a.tolist(),b.tolist()))),'wrap_witness':{'base':[0,0],'other':[0,1],'outputs':[list(N.b0_apply(0,0)),list(N.b0_apply(0,1))]},'old_delta_5_1':{'bases':65536,'zero_base_derivative':base_witness,'distinct_derivatives':len(np.unique(old,axis=0)),'first_output_zeros':int((old[:,0]==0).sum()),'second_output_zeros':int((old[:,1]==0).sum())}}
ex=[]
for col in (0,1):
 counts=[]
 for dd in range(1,256):
  c,d=b0(u^(dd if col==0 else 0),v^(dd if col==1 else 0));w=((a^c)!=0).astype(int)+((b^d)!=0)
  counts.append(int((w==1).sum()))
 ex.append({'input_column':col,'derivatives':65536*255,'singletons':sum(counts),'per_delta_singletons':counts})
res['B0']['exhaustive_single_input']=ex
# Reproduce exact seeded 40k protocol, retaining PRNG state for bow bases.
rr=random.Random(4419);sample=Counter()
for _ in range(20000):
 uu,vv,dd=rr.randrange(256),rr.randrange(256),rr.randrange(1,256);z=N.b0_apply(uu,vv)
 for col,other in enumerate((N.b0_apply(uu^dd,vv),N.b0_apply(uu,vv^dd))):
  if sum(x!=y for x,y in zip(z,other))==1:sample[col]+=1
res['B0']['sample_40000']={'singletons':sum(sample.values()),'by_column':dict(sample)}
rows=[[i]*8 for i in range(256)]+[[rr.randrange(256) for _ in range(8)] for _ in range(20000)]
res['odd_restack_inverse']={'staffs':len(rows),'failures':sum(N.unodd_restack(N.odd_restack(s))!=s or N.odd_restack(N.unodd_restack(s))!=s for s in rows)}
def bow8(z):
 z=z.copy()
 for i,j,p in N.BOW_STROKES:
  pp=z[:,p];r1=N.BOW_ROT_BASE+pp%N.BOW_ROT_MOD;r2=N.BOW_ROT_BASE+((pp>>N.BOW_R2_SHIFT)%N.BOW_ROT_MOD)
  z[:,i]=(z[:,i]+rotl(z[:,j],r1))&255;z[:,j]^=rotl(z[:,i],r2)
 return z
def rehair8(z):
 z=z.copy()
 for t in (1,3,5,7):z[:,t-1]=(z[:,t-1]+rotl(z[:,t],2))&255;z[:,t]^=rotl(z[:,t-1],6)
 return z
x=np.array(rows[:512],dtype=np.uint16)
assert all(list(bow8(x)[i])==N.bow_pressure(list(map(int,x[i]))) and list(rehair8(x)[i])==N.odd_restack(list(map(int,x[i]))) for i in range(512))
scan=[]
for t in range(8):
 xx=np.repeat(x,255,axis=0);yy=xx.copy();ds=np.tile(np.arange(1,256,dtype=np.uint16),512);yy[:,t]^=ds
 a=bow8(xx);b=bow8(yy);da=a^b;dr=rehair8(a)^rehair8(b);w=(da!=0).sum(1);wr=(dr!=0).sum(1)
 out={'beat':t,'cases':len(xx),'before_singletons':int((w==1).sum()),'after_singletons':int((wr==1).sum()),'before_min':int(w.min()),'after_min':int(wr.min()),'highbit_cases':512,'highbit_before_singletons':int(((w==1)&(ds==128)).sum()),'highbit_after_singletons':int(((wr==1)&(ds==128)).sum())}
 if (wr==1).any():
  i=int(np.nonzero(wr==1)[0][0]);out['witness']={'base':xx[i].tolist(),'input_delta':int(ds[i]),'output_delta':dr[i].tolist()}
 scan.append(out)
s=[192]*8;h=s.copy();h[3]^=128;a=N.odd_restack(N.bow_pressure(s));b=N.odd_restack(N.bow_pressure(h))
res['bow_rehair']={'bases':'256 uniform + first 256 random staffs from Random(4419) after the B0 sample','per_beat':scan,'odd_summary':{k:sum(row[k] for row in scan[1::2]) for k in ('cases','before_singletons','after_singletons','highbit_cases','highbit_before_singletons','highbit_after_singletons')},'even_summary':{k:sum(row[k] for row in scan[::2]) for k in ('cases','before_singletons','after_singletons','highbit_cases','highbit_before_singletons','highbit_after_singletons')},'c0_witness':{'base':s,'other':h,'output_delta':[x^y for x,y in zip(a,b)]}}
print('B0 and bow scans done',now(),flush=True)
res['field_pairs']=[]
for name,_,ij,M in N.BARS[1:]:
 canc=[(p,q) for p in range(1,256) for q in range(1,256) if 0 in N.bar_apply(M,p,q)]
 p,q=canc[0]
 res['field_pairs'].append({'name':name,'matrix':M,'single_input_singletons_of_510':sum(sum(z!=0 for z in N.bar_apply(M,dd if c==0 else 0,dd if c==1 else 0))==1 for c in (0,1) for dd in range(1,256)),'two_input_cancellations':len(canc),'kernel_witness':{'delta':[p,q],'output':list(N.bar_apply(M,p,q))}})
res['mix2']={'single_input_singletons_of_510':sum(sum(z!=0 for z in N.mix2(dd if c==0 else 0,dd if c==1 else 0))==1 for c in (0,1) for dd in range(1,256)),'delta_v80':list(N.mix2(0,128)),'two_input_cancellations':sum(0 in N.mix2(p,q) for p in range(1,256) for q in range(1,256))}
res['triplets']=[]
for name,ijk,M in N.TRIPLETS:
 cols=[]
 # Exhaust all 256 bases and 255 XOR deltas in each input; other bases zero.
 # Additive constants from other cells do not change equality/inequality of each output.
 for c in range(3):
  cases=single=0;minw=3
  for base in range(256):
   z=[0]*3;z[c]=base;a=N.triplet_apply(M,*z)
   for dd in range(1,256):
    z[c]=base^dd;b=N.triplet_apply(M,*z);w=sum(i!=j for i,j in zip(a,b));single+=w==1;cases+=1;minw=min(minw,w)
  z=[0]*3;z[c]=128;cols.append({'input':c,'cases':cases,'singletons':single,'min_active':minw,'delta80_zero_base':N.triplet_apply(M,*z)})
 res['triplets'].append({'name':name,'columns':cols})
# Cross graph connectivity independent of schedule.
seen={0}
while True:
 nxt=seen|{v for layer in N.CROSS_LAYERS for u,v in layer if u in seen}|{u for layer in N.CROSS_LAYERS for u,v in layer if v in seen}
 if nxt==seen:break
 seen=nxt
res['cross_graph']={'component_from_0':sorted(seen),'bridge_pairs':N.CROSS_BRIDGE,'bridge_vertices':len({x for p in N.CROSS_BRIDGE for x in p}),'bridge_is_perfect_matching':len({x for p in N.CROSS_BRIDGE for x in p})==16}
res['finished']=now();save('attack_structure',res)
