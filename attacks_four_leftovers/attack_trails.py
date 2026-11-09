from common import *
verify_live()
res={'started':now(),'schedule_nonce':NONCE.hex(),'white_box':'Raw-block fixed known-seed schedule; not public encrypt() oracle'}
B=Batch(SCH);res['crosschecks']=B.validate(8);rng=np.random.default_rng(2026110811)
res['cell2_300']={}
for label,sch in [('current',SCH),('demo',N.Schedule(SEED,DEMO_NONCE))]:
 rr=random.Random(20261108);bb=Batch(sch);xx=[];yy=[]
 for trial in range(300):
  x=[rr.randrange(256) for _ in range(128)];y=x.copy();y[2]^=0x5a if trial==0 else rr.randrange(1,256);xx.append(x);yy.append(y)
 d=bb.enc(np.array(xx,dtype=np.uint16),1)^bb.enc(np.array(yy,dtype=np.uint16),1);w=(d!=0).sum(1);st=(d.reshape(-1,16,8)!=0).any(2).sum(1)
 res['cell2_300'][label]={'pairs':300,'min_active_bytes':int(w.min()),'max_active_bytes':int(w.max()),'min_active_staffs':int(st.min()),'max_active_staffs':int(st.max())}
# 3. new 1-round truncated-trail search: every input cell x every S-output difference, 64 bases each (current schedule)
b=B;sch=b.sch;S=np.array(sch.rounds[0]['S'],dtype=np.uint16);SI=np.array(sch.rounds[0]['SI'],dtype=np.uint16);rkb=np.frombuffer(flat(sch.rounds[0]['rk']),dtype=np.uint8)
best=None;per_cell=[];nb=64;weights_all=np.zeros(129,dtype=np.int64);staff_all=np.zeros(17,dtype=np.int64);footprints={};partial_pairs=0
for c in range(128):
 ds=np.repeat(np.arange(1,256,dtype=np.uint16),nb);x=rng.integers(0,256,(len(ds),128),dtype=np.uint16);y=x.copy();y[:,c]=SI[S[x[:,c]^rkb[c]]^ds]^rkb[c]
 d=b.enc(x,1)^b.enc(y,1);w=(d!=0).sum(1);st=(d.reshape(-1,16,8)!=0).any(2).sum(1)
 footprints[str(c)]=np.nonzero((d.reshape(-1,16,8)!=0).any(2).any(0))[0].tolist();partial_pairs+=int((st<16).sum())
 weights_all+=np.bincount(w,minlength=129);staff_all+=np.bincount(st,minlength=17)
 i=int(w.argmin());per_cell.append({'cell':c,'min_active_bytes':int(w.min()),'min_active_staffs':int(st.min()),'mean_active_bytes':round(float(w.mean()),2)})
 # per-ΔS max confinement: union of active bytes across 64 bases for each ΔS
 act=(d!=0).reshape(255,nb,128).any(1).sum(1)
 j=int(act.argmin())
 cand={'cell':c,'S_delta':j+1,'union_active_bytes_over_64_bases':int(act[j]),'single_pair_min_bytes':int(w.min()),'single_pair_witness':{'x':bytes(x[i].astype(np.uint8)).hex(),'y':bytes(y[i].astype(np.uint8)).hex(),'S_delta':int(ds[i]),'active_positions':np.nonzero(d[i])[0].tolist()}}
 if best is None or cand['single_pair_min_bytes']<best['single_pair_min_bytes']:best=cand
 if c%32==31:print('1-round search cells',c+1,now(),flush=True)
w=best['single_pair_witness'];a=live_round_bytes(bytes.fromhex(w['x']),sch,1);bb=live_round_bytes(bytes.fromhex(w['y']),sch,1)
w['live_verified']=[i for i in range(128) if a[i]!=bb[i]]==w['active_positions']
res['one_round_search']={'pairs_with_inactive_staff':partial_pairs,'per_cell_staff_footprint_unions':footprints,'configs':'128 cells x 255 S-output deltas x 64 random bases = 2,088,960 pairs','active_byte_histogram':{str(i):int(v) for i,v in enumerate(weights_all) if v},'active_staff_histogram':{str(i):int(v) for i,v in enumerate(staff_all) if v},
 'global_min_active_bytes':min(p['min_active_bytes'] for p in per_cell),'global_min_active_staffs':min(p['min_active_staffs'] for p in per_cell),'strongest':best,'per_cell':per_cell,
 'random_comparison':'Random permutation average 127.5 active bytes, so some zero bytes are EXPECTED. Compare distributions, not merely a difference below 128.'}
print('1-round strongest',best['cell'],best['single_pair_min_bytes'],res['one_round_search']['global_min_active_staffs'],flush=True)
# Old two-round witness from the pickup report, rechecked under multiple nonces.
old=json.loads(Path('/workspace/sneak_n2/attacks_pickup/attack_sparse_results.json').read_text())['results']['2']['witness']
ox=bytes.fromhex(old['x']);oy=bytes.fromhex(old['y']);res['old_2round_witness']={'cell':old['cell'],'delta':ox[old['cell']]^oy[old['cell']],'old_zero_positions':old['zero_positions'],'x':old['x'],'y':old['y'],'live_replays':{}}
for label,sch in [('current',SCH),('pickup_era',N.Schedule(SEED,PICKUP_ERA_NONCE)),('demo',N.Schedule(SEED,DEMO_NONCE))]:
 a=live_round_bytes(ox,sch,2);b=live_round_bytes(oy,sch,2);z=[i for i in range(128) if a[i]==b[i]];res['old_2round_witness']['live_replays'][label]={'zero_bytes':len(z),'zero_positions':z}
res['finished']=now();save('attack_trails',res)
