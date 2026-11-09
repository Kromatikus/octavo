from common import *
res={'started':now()};B=Batch(SCH);res['accelerator_live_round_crosschecks']=B.validate(8)
rng=np.random.default_rng(202611081)
res['named_pairs']=[]
for name,_,ij,M in N.BARS:
 singleton=0
 for col in (0,1):
  for d in range(1,256):
   v=[0,0];v[col]=d;out=N.bar_apply(M,*v);singleton+=sum(x!=0 for x in out)==1
 # field linearity makes above exhaustive for all base pairs; separately check live helper with random nonzero bases
 checks=0
 for _ in range(512):
  u,v=map(int,rng.integers(0,256,2));col=int(rng.integers(2));d=int(rng.integers(1,256));w=[u,v];w[col]^=d
  a=N.bar_apply(M,u,v);b=N.bar_apply(M,*w);delta=[a[i]^b[i] for i in range(2)];z=[0,0];z[col]=d
  assert tuple(delta)==N.bar_apply(M,*z);checks+=1
 res['named_pairs'].append({'name':name,'det':N.bar_det(M),'nonzero_single_input_deltas':510,'singleton_events':singleton,'random_base_linearity_checks':checks})
M=N.BARS[0][3];a,b=M[0];du=b;dv=a;out=N.bar_apply(M,du,dv)
res['cancellation']={'pair':'B0','input_xor_difference':[du,dv],'output_xor_difference':list(out),'witness':'[5,1] cancels first output exactly, second stays nonzero; valid at every base'}
res['isolated_triplet_highbit']=[]
for name,ij,M in N.TRIPLETS:
 w=[]
 for col in range(3):
  v=[0,0,0];v[col]=128;delta=N.triplet_apply(M,*v);w.append({'input':col,'delta':list(delta),'active_outputs':sum(x!=0 for x in delta)})
 res['isolated_triplet_highbit'].append({'name':name,'det':N.triplet_det(M),'columns':w})
# integer layers' high-bit derivatives are independent of bases, verify on sampled bases, not GF argument
zero=np.zeros((128,128),dtype=np.uint16);hi=zero.copy();hi[np.arange(128),np.arange(128)]=128
for name,fn in [('triplet_stack',lambda x:trips(x)),('butterfly',lambda x:np.array([sum(N.staff_mix(N.bytes_to_grid(bytes(v.astype(np.uint8))),SCH.rounds[0]['sigma']),[]) for v in x],dtype=np.uint16))]:
 d=fn(zero)^fn(hi);weights=(d!=0).sum(1)
 res[name]={'highbit_weights_first_staff':weights[:8].tolist(),'singleton_inputs':np.nonzero(weights==1)[0].tolist(),'singleton_count':int((weights==1).sum())}
res['mix2']={'u_delta80':list(N.mix2(128,0)),'v_delta80':list(N.mix2(0,128)),'v_singleton_all_65536_bases':all((N.mix2(u,v)[0]^N.mix2(u,v^128)[0],N.mix2(u,v)[1]^N.mix2(u,v^128)[1])==(128,0) for u in range(256) for v in range(256))}
# Single staff suffices: repeated independently on 16 staffs. Include all-zero, all constant byte values and random bases.
rows=np.vstack([np.zeros((1,8),dtype=np.uint16),np.repeat(np.arange(256,dtype=np.uint16)[:,None],8,axis=1),rng.integers(0,256,(8192,8),dtype=np.uint16)])
x=np.tile(rows,(1,16));base=trips(bars(x));rows_out=[];witness=None
for c in range(8):
 y=x.copy();y[:,c]^=128;d=(base^trips(bars(y)))[:,:8];w=(d!=0).sum(1);i=int(w.argmin())
 rows_out.append({'beat':c,'bases':len(x),'min_active':int(w.min()),'max_active':int(w.max()),'singleton_events':int((w==1).sum()),'zero_base_delta':d[0].tolist(),'weight_hist':{str(k):int((w==k).sum()) for k in np.unique(w)},'min_witness':{'base':rows[i].tolist(),'delta':d[i].tolist()}})
res['combined_bars_triplets_and_identical_encore']={'bases_per_input':len(x),'rows':rows_out,'warning':'empirical over multiple bases; field-pair + integer-triplet composition is NOT mod256-linear. Do not infer from odd columns.'}
# Full middle: every input location at zero and 256 nonzero random bases for each, capture worst/singletons.
res['middle_highbit']={}
for label,sch in [('current_demo_nonce',SCH),('historical_join_report_nonce',N.Schedule(SEED,bytes.fromhex('b98b9c3815374fac6048ec47c9760eb3')))]:
 batch=Batch(sch);rr={}
 for r in (0,1):
  x=np.vstack([np.zeros((1,128),dtype=np.uint16),rng.integers(0,256,(256,128),dtype=np.uint16)]);a=batch.middle(x,r);mins=[];sing=[];special=None
  for c in range(128):
   y=x.copy();y[:,c]^=128;d=a^batch.middle(y,r);w=(d!=0).sum(1);mins.append(int(w.min()))
   if (w==1).any():sing.append({'cell':c,'count':int((w==1).sum())})
   if c==18:special={'zero_base_output_cells':np.nonzero(d[0])[0].tolist(),'min_weight':int(w.min()),'max_weight':int(w.max())}
  rr[r]={'bases_per_cell':len(x),'min_over_all_cells_bases':min(mins),'singleton_cells':sing,'cell18':special,'min_weights':mins}
 res['middle_highbit'][label]=rr
# Exact highbit input trail to S: choose all x values that yield S difference128, compare target truncated set.
res['one_round_old_truncated_test']={}
for label,sch in [('current_demo_nonce',SCH),('historical_join_report_nonce',N.Schedule(SEED,bytes.fromhex('b98b9c3815374fac6048ec47c9760eb3')))]:
 batch=Batch(sch);n=32768;x=rng.integers(0,256,(n,128),dtype=np.uint16);y=x.copy();s=sch.rounds[0]['S'];si=sch.rounds[0]['SI'];rk=flat(sch.rounds[0]['rk'])[18]
 y[:,18]=np.array(si,dtype=np.uint16)[np.array(s,dtype=np.uint16)[x[:,18]^rk]^128]^rk
 d=batch.enc(x,1)^batch.enc(y,1);w=(d!=0).sum(1);outside=[i for i in range(128) if i not in (37,38,39)]
 res['one_round_old_truncated_test'][label]={'pairs_conditioned_on_S_delta80':n,'confined_to_old_37_38_39':int((~d[:,outside].any(1)).sum()),'min_active':int(w.min()),'max_active':int(w.max())}
res['finished']=now();save('attack_structure',res)
