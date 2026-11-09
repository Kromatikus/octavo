from common import *
res={'started':now(),'primary_schedule':'Schedule(seed, recorded hello-world nonce db8839e7...) = live current demo','white_box':'raw blocks under one fixed known-seed schedule; not reachable through randomized public encrypt()'}
schedules={'current_hello_nonce':SCH,'pickup_era_hello_nonce_4ea3':N.Schedule(SEED,PICKUP_ERA_NONCE),'demo_nonce_b98b':N.Schedule(SEED,DEMO_NONCE)}
batches={k:Batch(v) for k,v in schedules.items()}
for b in batches.values():b.validate(2)
rng=np.random.default_rng(2026110811)
def cond_pairs(sch,c,n,sdelta):
 S=np.array(sch.rounds[0]['S'],dtype=np.uint16);SI=np.array(sch.rounds[0]['SI'],dtype=np.uint16);rk=flat(sch.rounds[0]['rk'])[c]
 x=rng.integers(0,256,(n,128),dtype=np.uint16);y=x.copy();y[:,c]=SI[S[x[:,c]^rk]^sdelta]^rk;return x,y
# 1. old cell-18 trail
res['old_cell18_trail']={}
for k,b in batches.items():
 x,y=cond_pairs(b.sch,18,32768,128);d=b.enc(x,1)^b.enc(y,1);w=(d!=0).sum(1);out=[i for i in range(128) if i not in (37,38,39)]
 res['old_cell18_trail'][k]={'pairs_conditioned_S_delta80':32768,'confined_to_37_38_39':int((~d[:,out].any(1)).sum()),'min_active':int(w.min()),'max_active':int(w.max())}
print('cell18',res['old_cell18_trail'],flush=True)
# 2. pickup-era cell-34 trail, three modes, on current and pickup-era schedules
C=list(range(56,64));notC=[i for i in range(128) if i not in C]
res['cell34_trail']={}
for k in ('current_hello_nonce','pickup_era_hello_nonce_4ea3'):
 b=batches[k];sch=b.sch;S=sch.rounds[0]['S'];rk=flat(sch.rounds[0]['rk'])[34]
 row=[sum(S[x]^S[x^d]==128 for x in range(256)) for d in range(256)];best=max(range(1,256),key=lambda d:row[d]);modes={}
 for mode in ('random_delta','best_fixed_delta','conditioned_on_S_delta80'):
  n=200000;conf=0;high=0;mn=128;mx=0;st=[]
  for start in range(0,n,8192):
   kk=min(8192,n-start)
   if mode=='conditioned_on_S_delta80':x,y=cond_pairs(sch,34,kk,128)
   else:
    x=rng.integers(0,256,(kk,128),dtype=np.uint16);y=x.copy();y[:,34]^=(rng.integers(1,256,kk,dtype=np.uint16) if mode=='random_delta' else best)
   Sa=np.array(S,dtype=np.uint16);high+=int(((Sa[x[:,34]^rk]^Sa[y[:,34]^rk])==128).sum())
   d=b.enc(x,1)^b.enc(y,1);w=(d!=0).sum(1);conf+=int((~d[:,notC].any(1)).sum());mn=min(mn,int(w.min()));mx=max(mx,int(w.max()))
   st.append(((d.reshape(-1,16,8)!=0).any(2)).sum(1))
  st=np.concatenate(st)
  modes[mode]={'pairs':n,'S_delta80_count':high,'confined_to_56_63':conf,'min_active_bytes':mn,'max_active_bytes':mx,'min_active_staffs':int(st.min()),'mean_active_staffs':round(float(st.mean()),3)}
 res['cell34_trail'][k]={'best_fixed_delta_for_S80':best,'DDT_count':row[best],'modes':modes}
 print('cell34',k,res['cell34_trail'][k],flush=True)
# 3. new 1-round truncated-trail search: every input cell x every S-output difference, 64 bases each (current schedule)
b=batches['current_hello_nonce'];sch=b.sch;S=np.array(sch.rounds[0]['S'],dtype=np.uint16);SI=np.array(sch.rounds[0]['SI'],dtype=np.uint16);rkb=np.frombuffer(flat(sch.rounds[0]['rk']),dtype=np.uint8)
best=None;per_cell=[];nb=64;weights_all=np.zeros(129,dtype=np.int64);staff_all=np.zeros(17,dtype=np.int64)
for c in range(128):
 ds=np.repeat(np.arange(1,256,dtype=np.uint16),nb);x=rng.integers(0,256,(len(ds),128),dtype=np.uint16);y=x.copy();y[:,c]=SI[S[x[:,c]^rkb[c]]^ds]^rkb[c]
 d=b.enc(x,1)^b.enc(y,1);w=(d!=0).sum(1);st=(d.reshape(-1,16,8)!=0).any(2).sum(1)
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
res['one_round_search']={'configs':'128 cells x 255 S-output deltas x 64 random bases = 2,088,960 pairs','active_byte_histogram':{str(i):int(v) for i,v in enumerate(weights_all) if v},'active_staff_histogram':{str(i):int(v) for i,v in enumerate(staff_all) if v},
 'global_min_active_bytes':min(p['min_active_bytes'] for p in per_cell),'global_min_active_staffs':min(p['min_active_staffs'] for p in per_cell),'strongest':best,'per_cell':per_cell,
 'random_comparison':'For a random 1024-bit permutation, a nonzero output difference has <=k active bytes with probability about C(128,k)*2^(-8*(128-k)); anything < 128 active bytes is a white-box structural distinguisher at 1 round.'}
print('1-round strongest',best['cell'],best['single_pair_min_bytes'],res['one_round_search']['global_min_active_staffs'],flush=True)
# 4. old 2-round witness replay
old=json.loads(Path('/workspace/sneak_n2/attacks_pickup/attack_sparse_results.json').read_text())['results']['2']['witness']
ox=bytes.fromhex(old['x']);oy=bytes.fromhex(old['y']);rep={'old_witness':{'cell':old['cell'],'delta':ox[old['cell']]^oy[old['cell']],'zero_bytes':old['zero_bytes'],'zero_positions':old['zero_positions']}}
for k,s in schedules.items():
 a=live_round_bytes(ox,s,2);bb=live_round_bytes(oy,s,2);z=[i for i in range(128) if a[i]==bb[i]];rep[f'current_cipher_{k}']={'zero_bytes':len(z),'zero_positions':z}
spec=importlib.util.spec_from_file_location('pre_three_fixes_readonly','/tmp/sneak_n2_pre_three_fixes/sneak_n2.py');old_mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(old_mod)
s=old_mod.Schedule(SEED,PICKUP_ERA_NONCE);a=old_mod.grid_to_bytes(old_mod.encrypt_grid(old_mod.bytes_to_grid(ox),s,2,False));bb=old_mod.grid_to_bytes(old_mod.encrypt_grid(old_mod.bytes_to_grid(oy),s,2,False))
z=[i for i in range(128) if a[i]==bb[i]];rep['pre_three_fixes_library_pickup_era_nonce_reproduces']={'zero_bytes':len(z),'zero_positions':z,'matches_old_report':z==old['zero_positions']}
res['old_two_round_witness_replay']=rep;print('replay',rep,flush=True)
res['finished']=now();save('attack_trails',res)
