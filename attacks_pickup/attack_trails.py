from common import *
res={'started':now()};B=Batch(SCH);rng=np.random.default_rng(202611083);c=34;C=list(range(56,64));S=SCH.rounds[0]['S'];SI=SCH.rounds[0]['SI'];rk=flat(SCH.rounds[0]['rk'])[c]
row=[sum(S[x]^S[x^d]==128 for x in range(256)) for d in range(256)];best=max(range(1,256),key=lambda d:row[d]);res['new_one_round_trail']={'input_cell':c,'output_confined_set':C,'best_input_xor_delta':best,'S_DDT_to_0x80_count':row[best],'modes':{}}
for mode in ('random_delta','best_fixed_delta','conditioned_on_S_delta80'):
 n=200000;counts=0;high=0;minact=128;maxact=0;witness=None
 for start in range(0,n,4096):
  k=min(4096,n-start);x=rng.integers(0,256,(k,128),dtype=np.uint16);y=x.copy()
  if mode=='random_delta':y[:,c]^=rng.integers(1,256,k,dtype=np.uint16)
  elif mode=='best_fixed_delta':y[:,c]^=best
  else:y[:,c]=np.array(SI,dtype=np.uint16)[np.array(S,dtype=np.uint16)[x[:,c]^rk]^128]^rk
  sd=np.array(S,dtype=np.uint16)[x[:,c]^rk]^np.array(S,dtype=np.uint16)[y[:,c]^rk];high+=int((sd==128).sum());d=B.enc(x,1)^B.enc(y,1);w=(d!=0).sum(1);conf=~d[:,[i for i in range(128) if i not in C]].any(1);counts+=int(conf.sum());minact=min(minact,int(w.min()));maxact=max(maxact,int(w.max()))
  assert ((sd==128)<=conf).all()
  if witness is None and conf.any():
   i=int(np.nonzero(conf)[0][0]);a=bytes(x[i].astype(np.uint8));b=bytes(y[i].astype(np.uint8));da=flat(N.encrypt_grid(N.bytes_to_grid(a),SCH,1,False));db=flat(N.encrypt_grid(N.bytes_to_grid(b),SCH,1,False));witness={'x':a.hex(),'y':b.hex(),'S_delta':int(sd[i]),'active_output_cells':np.nonzero(d[i])[0].tolist(),'live_verified':bytes(d[i].astype(np.uint8))==bytes(a^b for a,b in zip(da,db))}
 res['new_one_round_trail']['modes'][mode]={'pairs':n,'S_delta80_count':high,'confined_count':counts,'rate':counts/n,'min_active':minact,'max_active':maxact,'witness':witness}
res['random_permutation_comparison']='A nonzero random 1024-bit output difference lies in a specified 8-byte set with probability (2^64-1)/(2^1024-1), about 2^-960. White-box conditioning is not itself an attack; random/fixed-delta trials demonstrate the truncated trail.'
# Trace a genuine 2-round sparse witness through live helpers (no linear-matrix surrogate).
w=json.loads((HERE/'attack_sparse_results.json').read_text())['results']['2']['witness'];x=N.bytes_to_grid(bytes.fromhex(w['x']));y=N.bytes_to_grid(bytes.fromhex(w['y']));trace=[]
def record(label,x,y):
 a=flat(x);b=flat(y);d=bytes(a^b for a,b in zip(a,b));trace.append({'stage':label,'active_count':sum(t!=0 for t in d),'positions':{str(i):t for i,t in enumerate(d) if t}})
record('input',x,y)
for r in range(2):
 k=SCH.rounds[r]
 funcs=[('XOR_rk',lambda g:N.xor_grid(g,k['rk'])),('S',lambda g:[[k['S'][v] for v in row] for row in g]),('weave',lambda g:N.weave(g,k['SH'],k['SV'])),('butterfly',lambda g:N.staff_mix(g,k['sigma'])),('shell',lambda g:N.shell_mix(g,k['bridge'],r)),('bars',N.bar_mix),('triplets',N.triplet_mix),('S2',lambda g:[[k['S2'][v] for v in row] for row in g]),('encore_bars',N.bar_mix),('encore_triplets',N.triplet_mix)]
 for name,fn in funcs:x=fn(x);y=fn(y);record(f'round{r+1}:{name}',x,y)
res['two_round_witness_trace']=trace
res['two_round_witness_description']={'input_cell':w['cell'],'zero_bytes':w['zero_bytes'],'zero_positions':w['zero_positions'],'live_verified':w['verified_live']}
# Authenticate SM4 table by the existing read-only reference checker, not just the label/head.
spec=importlib.util.spec_from_file_location('sm4_readonly_check','/workspace/sneak_n2/sm4_vector_check.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
res['SM4_reference_vectors_pass']=mod.sm4_table_ok(N.SM4_SBOX)
res['finished']=now();save('attack_trails',res)
