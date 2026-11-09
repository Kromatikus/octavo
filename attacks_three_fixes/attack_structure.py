from common import *
res={'started':now()};Bt=Batch(SCH);res['accelerator_live_crosschecks']=Bt.validate(8)
rng=np.random.default_rng(2026110810)
# --- mix2 exhaustive
u=np.repeat(np.arange(256),256);v=np.tile(np.arange(256),256)
a0,a1=mix2v(u,v);b0,b1=mix2v(u,v^128);d=np.stack([a0^b0,a1^b1],1)
c0,c1=mix2v(u^128,v);du=np.stack([a0^c0,a1^c1],1)
res['mix2']={'matrix':N.MIX2_MATRIX,'field_poly':hex(N.FIELD_POLY),'live_mix2_0_0_xor_0_0x80':[x^y for x,y in zip(N.mix2(0,0),N.mix2(0,0x80))],
 'v_delta80_all_65536_bases_distinct_outputs':np.unique(d,axis=0).tolist(),'v_delta80_never_(0x80,0)':bool(not ((d[:,0]==128)&(d[:,1]==0)).any()),
 'u_delta80_all_65536_bases':np.unique(du,axis=0).tolist()}
sing=0
for col in (0,1):
 for dd in range(1,256):
  z=[0,0];z[col]=dd;sing+=sum(x!=0 for x in N.mix2(*z))==1
res['mix2']['singleton_events_all_510_single_input_deltas']=sing
# cancellation of mix2 itself (two-input deltas giving one zero output)
canc=[(du_,dv_) for du_ in range(1,256) for dv_ in range(1,256) if 0 in N.mix2(du_,dv_)]
res['mix2']['two_input_deltas_cancelling_one_output']=len(canc);res['mix2']['example']=[list(canc[0]),list(N.mix2(*canc[0]))]
# --- named pairs
res['named_pairs']=[];tot=0
for name,_,ij,M in N.BARS:
 s=0
 for col in (0,1):
  for dd in range(1,256):
   z=[0,0];z[col]=dd;s+=sum(x!=0 for x in N.bar_apply(M,*z))==1
 tot+=s;canc=sum(1 for p in range(1,256) for q in range(1,256) if 0 in N.bar_apply(M,p,q))
 res['named_pairs'].append({'name':name,'det':N.bar_det(M),'singleton_events_of_510':s,'two_input_cancelling_deltas':canc})
res['named_pairs_total_singletons']=f'{tot}/{7*510}'
M=N.BARS[0][3];res['B0_cancellation']={'input_delta':[5,1],'output_delta':list(N.bar_apply(M,5,1)),'base_independent':all(tuple(x^y for x,y in zip(N.bar_apply(M,a,b),N.bar_apply(M,a^5,b^1)))==(0,3) for a in range(0,256,7) for b in range(0,256,5))}
# --- triplets alone (integer) Δ0x80 and random deltas
res['triplets_alone']=[]
for name,ij,M in N.TRIPLETS:
 cols=[]
 for col in range(3):
  z=[0,0,0];z[col]=128;dl=N.triplet_apply(M,*z)
  minw=min(sum(x!=0 for x in N.triplet_apply(M,*[dd if k==col else 0 for k in range(3)])) for dd in range(1,256))
  cols.append({'input':col,'delta80_out':list(dl),'active':sum(x!=0 for x in dl),'min_active_any_delta':minw})
 res['triplets_alone'].append({'name':name,'det':N.triplet_det(M),'columns':cols})
# --- stacks on one staff; many bases including edge ones
rows=np.vstack([np.zeros((1,8),dtype=np.uint16),np.full((1,8),255,dtype=np.uint16),np.repeat(np.arange(256,dtype=np.uint16)[:,None],8,axis=1),rng.integers(0,256,(16384,8),dtype=np.uint16)])
x=np.tile(rows,(1,16))
stacks={'triplets_only':lambda z:trips(z),'bars_only':lambda z:bars(z),'bars+triplets':lambda z:trips(bars(z)),'bars+triplets+bow (one stack, = encore stack)':lambda z:bow(trips(bars(z))),'bow_only':lambda z:bow(z)}
res['stacks']={}
for label,fn in stacks.items():
 base=fn(x);out=[]
 for kind in ('delta80','random_delta'):
  for c in range(8):
   y=x.copy();y[:,c]^=128 if kind=='delta80' else rng.integers(1,256,len(x),dtype=np.uint16);dlt=(base^fn(y))[:,:8];w=(dlt!=0).sum(1);i=int(w.argmin())
   out.append({'kind':kind,'beat':c,'min_active':int(w.min()),'mean_active':round(float(w.mean()),3),'singleton_events':int((w==1).sum()),'min_witness':{'base':rows[i].tolist(),'delta_in':int(x[i,c]^y[i,c]),'delta_out':dlt[i].tolist()}})
 res['stacks'][label]={'bases':len(x),'rows':out,'total_singletons':sum(r['singleton_events'] for r in out)}
 print(label,res['stacks'][label]['total_singletons'],[r['min_active'] for r in out],flush=True)
# --- butterfly & bridges (field-linear => base independent; check zero base + random bases)
res['butterfly_bridges']={}
for rr in (0,1):
 k=SCH.rounds[rr];zero=np.zeros((1,128),dtype=np.uint16)
 def bf(z):
  z=np.asarray(z,dtype=np.uint16).copy()
  for a,b in Bt.staff[rr]:uu=z[:,a].copy();vv=z[:,b].copy();z[:,a],z[:,b]=mix2v(uu,vv)
  return z
 def sh(z):
  z=np.asarray(z,dtype=np.uint16).copy();a,b=Bt.shell[rr];uu=z[:,a].copy();vv=z[:,b].copy();z[:,a],z[:,b]=mix2v(uu,vv);return z
 rr_={}
 for label,fn in (('butterfly',bf),('bridges',sh),('butterfly+bridges',lambda z:sh(bf(z)))):
  ws={'delta80':[],'all_deltas_min':[]}
  for c in range(128):
   e=zero.copy();e[0,c]=128;ws['delta80'].append(int((fn(zero)^fn(e)!=0).sum()))
   ee=np.zeros((255,128),dtype=np.uint16);ee[:,c]=np.arange(1,256);ws['all_deltas_min'].append(int((fn(np.zeros((255,128),dtype=np.uint16))^fn(ee)!=0).sum(1).min()))
  rr_[label]={'delta80_min_weight':min(ws['delta80']),'delta80_singleton_cells':[c for c,w in enumerate(ws['delta80']) if w==1],'any_delta_min_weight':min(ws['all_deltas_min']),'any_delta_singleton_cells':[c for c,w in enumerate(ws['all_deltas_min']) if w==1]}
 res['butterfly_bridges'][f'round{rr}']=rr_
print('butterfly',res['butterfly_bridges'],flush=True)
# --- full middle layer (weave->butterfly->bridges->bars->triplets[->bow]), Δ0x80 in every cell, 257 bases
res['middle']={}
for rr in (0,1):
 xx=np.vstack([np.zeros((1,128),dtype=np.uint16),rng.integers(0,256,(256,128),dtype=np.uint16)])
 for wb in (False,True):
  a=Bt.middle(xx,rr,wb);mins=[];sing=[]
  for c in range(128):
   y=xx.copy();y[:,c]^=128;w=((a^Bt.middle(y,rr,wb))!=0).sum(1);mins.append(int(w.min()))
   if (w==1).any():sing.append({'cell':c,'count':int((w==1).sum())})
  res['middle'][f'round{rr}_bow={wb}']={'bases':len(xx),'min_weight':min(mins),'max_of_min':max(mins),'singleton_cells':sing}
print('middle',{k:(v['min_weight'],len(v['singleton_cells'])) for k,v in res['middle'].items()},flush=True)
# --- B0 cancellation and bow restack
def rest_of_stack_after_B0(z):
 z=z.reshape(-1,16,8).copy()
 for _,_,(i,j),M in N.BARS[1:]:
  uu=z[:,:,i].copy();vv=z[:,:,j].copy();z[:,:,i]=GF[M[0][0],uu]^GF[M[0][1],vv];z[:,:,j]=GF[M[1][0],uu]^GF[M[1][1],vv]
 return z.reshape(-1,128)
n=20000;xs=rng.integers(0,256,(n,8),dtype=np.uint16);X=np.tile(xs,(1,16));Y=X.copy();Y[:,0]^=5;Y[:,1]^=1
r={}
dB=bars(X)^bars(Y);w=(dB[:,:8]!=0).sum(1);r['after_all_7_pairs_weight_hist']={str(k):int((w==k).sum()) for k in np.unique(w)}
dT=trips(bars(X))^trips(bars(Y));w=(dT[:,:8]!=0).sum(1);r['after_pairs+triplets_weight_hist']={str(k):int((w==k).sum()) for k in np.unique(w)}
dW=bow(trips(bars(X)))^bow(trips(bars(Y)));w=(dW[:,:8]!=0).sum(1);r['after_pairs+triplets+bow_weight_hist']={str(k):int((w==k).sum()) for k in np.unique(w)};r['after_bow_gt1']=f'{int((w>1).sum())}/{n}'
# singleton Δ=0x03 at beat 1 straight into bow (parent's measurement)
Z=X.copy();Z[:,1]^=3;w=((bow(X)^bow(Z))[:,:8]!=0).sum(1);r['singleton_beat1_delta03_into_bow_gt1']=f'{int((w>1).sum())}/{n}';r['singleton_beat1_delta03_into_bow_hist']={str(k):int((w==k).sum()) for k in np.unique(w)}
# all singletons into bow: min output weight per beat, any delta
bw=[]
for c in range(8):
 Z=X.copy();Z[:,c]^=rng.integers(1,256,n,dtype=np.uint16);w=((bow(X)^bow(Z))[:,:8]!=0).sum(1);bw.append({'beat':c,'min':int(w.min()),'mean':round(float(w.mean()),3),'singleton_events':int((w==1).sum())})
r['bow_singleton_inputs_random_delta']=bw
r['note']='B0 cancellation is base-independent at the field mix (linear). Bow is applied only after pairs+triplets, so the restack measured is of the stack output difference.'
res['B0_restack']=r;print('B0',r,flush=True)
# --- bow invertibility
edge=[[0]*8,[255]*8]+[[1<<b if i==j else 0 for i in range(8)] for j in range(8) for b in range(8)]+[[255^(1<<b) if i==j else 255 for i in range(8)] for j in range(8) for b in range(8)]+[[i]*8 for i in range(256)]
rnd=[list(map(int,s)) for s in rng.integers(0,256,(100000,8))]
bad=sum(N.unbow_pressure(N.bow_pressure(s))!=s for s in edge+rnd)
img=len({tuple(N.bow_pressure(s)) for s in rnd})
res['bow_invertibility']={'edge_staffs':len(edge),'random_staffs':len(rnd),'failures':bad,'distinct_images_of_random':img,'distinct_random_inputs':len({tuple(s) for s in rnd}),'fixed_points_in_sample':sum(N.bow_pressure(s)==s for s in edge+rnd),'bow(all-zero)':N.bow_pressure([0]*8),'bow(all-ff)':N.bow_pressure([255]*8)}
# bow linear? check is it XOR-linear: bow(a^b)^bow(0) == bow(a)^bow(b)?
lin=sum(1 for _ in range(2000) if (lambda a,b:[p^q^r_^s for p,q,r_,s in zip(N.bow_pressure([x^y for x,y in zip(a,b)]),N.bow_pressure([0]*8),N.bow_pressure(a),N.bow_pressure(b))]==[0]*8)(list(map(int,rng.integers(0,256,8))),list(map(int,rng.integers(0,256,8)))))
res['bow_invertibility']['xor_affine_relation_holds_in_2000']=lin
print('bow',res['bow_invertibility'],flush=True)
res['finished']=now();save('attack_structure',res)
