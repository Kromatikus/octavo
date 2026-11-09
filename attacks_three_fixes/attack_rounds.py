from common import *
res={'started':now(),'fixed_schedule_nonce':NONCE.hex(),'white_box':'Raw blocks with one fixed known-seed schedule (current hello-world nonce); not the public randomized encrypt(). Whitening cancels in XOR differences.'}
B=Batch(SCH);res['crosschecks']=B.validate(4)
rng=np.random.default_rng(2026110812);Rs=(1,2,3,4,16)
p_rand=sum(math.comb(128,j)*(1/256)**j*(255/256)**(128-j) for j in range(8,129));res['p_random_ge8_zero_bytes']=p_rand
ag={r:{'dep':np.zeros((128,128),bool),'hws':[],'bitcounts':np.zeros(1024,dtype=np.int64),'zero_pos':np.zeros(128,dtype=np.int64),'sparse':0,'maxzero':0,'witness':None} for r in Rs}
K=32;nd=128*K;na=8192;nz=65536
for kind,n in [('dependence',nd),('avalanche',na),('zero',nz)]:
 for start in range(0,n,4096):
  cnt=min(4096,n-start);x=rng.integers(0,256,(cnt,128),dtype=np.uint16);y=x.copy();ox=x.copy()
  if kind=='dependence':pos=np.arange(start,start+cnt)//K;y[np.arange(cnt),pos]^=rng.integers(1,256,cnt,dtype=np.uint16)
  elif kind=='avalanche':bits=rng.integers(0,1024,cnt);y[np.arange(cnt),bits//8]^=(1<<(bits%8)).astype(np.uint16)
  else:pos=rng.integers(0,128,cnt);y[np.arange(cnt),pos]^=rng.integers(1,256,cnt,dtype=np.uint16)
  oy=y.copy()
  for r in range(1,17):
   x=B.round(x,r-1);y=B.round(y,r-1)
   if r not in Rs:continue
   a=ag[r];d=x^y
   if kind=='dependence':
    for p in np.unique(pos):a['dep'][p]|=(d[pos==p]!=0).any(0)
   elif kind=='avalanche':
    bo=np.unpackbits(d.astype(np.uint8),axis=1);a['hws'].extend(bo.sum(1).tolist());a['bitcounts']+=bo.sum(0).astype(np.int64)
   else:
    z=d==0;zw=z.sum(1);a['zero_pos']+=z.sum(0);a['sparse']+=int((zw>=8).sum());a['maxzero']=max(a['maxzero'],int(zw.max()))
    if a['witness'] is None and (zw>=8).any():
     i=int(zw.argmax());a['witness']={'x':bytes(ox[i].astype(np.uint8)).hex(),'y':bytes(oy[i].astype(np.uint8)).hex(),'zero_bytes':int(zw[i]),'zero_positions':np.nonzero(z[i])[0].tolist()}
 print('dataset',kind,now(),flush=True)
stats={}
for r,a in ag.items():
 h=np.array(a['hws']);z=a['zero_pos']
 stats[r]={'byte_dependence':{'pairs_seen':int(a['dep'].sum()),'of':16384,'bases_per_input':K,'min_outputs_per_input':int(a['dep'].sum(1).min()),'min_inputs_per_output':int(a['dep'].sum(0).min())},
  'bit_avalanche':{'pairs':na,'mean':round(float(h.mean()),3),'sd':round(float(h.std()),3),'min':int(h.min()),'max':int(h.max()),'ideal_mean':512,'ideal_sd':16,'worst_bit_rate_deviation':round(float(abs(a['bitcounts']/na-.5).max()),4)},
  'zero_difference_random_single_cell':{'pairs':nz,'mean_zero_bytes':round(float(z.sum()/nz),4),'random_mean':0.5,'ge8_zero_pairs':a['sparse'],'expected_random':nz*p_rand,'max_zero':a['maxzero'],'witness_note':'1-round witness is structural (diffusion incomplete) and expected' if r==1 else None}}
 if r>1 and a['witness']:stats[r]['zero_difference_random_single_cell']['witness']=a['witness']
res['rounds']=stats;save('attack_rounds',res)
# Per-input sparse scan, same size as pickup report: 128 cells x 4096 random-delta pairs, 2 and 3 rounds
sp={r:{'total':0,'max_zero':0,'cells':[],'witness':None,'zero_hist':np.zeros(129,dtype=np.int64)} for r in (2,3)}
for c in range(128):
 n=4096;x=rng.integers(0,256,(n,128),dtype=np.uint16);y=x.copy();y[:,c]^=rng.integers(1,256,n,dtype=np.uint16);ox=x.copy();oy=y.copy()
 for r in range(1,4):
  x=B.round(x,r-1);y=B.round(y,r-1)
  if r<2:continue
  z=(x==y);zw=z.sum(1);sp[r]['zero_hist']+=np.bincount(zw,minlength=129);hits=int((zw>=8).sum());sp[r]['total']+=hits;sp[r]['max_zero']=max(sp[r]['max_zero'],int(zw.max()))
  if hits:
   sp[r]['cells'].append({'cell':c,'hits':hits})
   i=int(zw.argmax())
   if sp[r]['witness'] is None or zw[i]>sp[r]['witness']['zero_bytes']:sp[r]['witness']={'cell':c,'x':bytes(ox[i].astype(np.uint8)).hex(),'y':bytes(oy[i].astype(np.uint8)).hex(),'delta':int(ox[i,c]^oy[i,c]),'zero_bytes':int(zw[i]),'zero_positions':np.nonzero(z[i])[0].tolist()}
 if c%32==31:print('sparse cells',c+1,now(),flush=True)
for r in sp:
 sp[r]['zero_hist']={str(i):int(v) for i,v in enumerate(sp[r]['zero_hist']) if v}
 sp[r].update(pairs=128*4096,expected_random=128*4096*p_rand)
 w=sp[r]['witness']
 if w:
  a=live_round_bytes(bytes.fromhex(w['x']),SCH,r);b=live_round_bytes(bytes.fromhex(w['y']),SCH,r);w['verified_live']=[i for i in range(128) if a[i]==b[i]]==w['zero_positions']
print({r:(sp[r]['total'],sp[r]['expected_random'],sp[r]['max_zero']) for r in sp},flush=True)
# Broad scans at 4 and 16 rounds, 65536 random single-cell pairs each (also covered above); plus 524288 at 4 rounds
big={'pairs':0,'ge8':0,'max_zero':0,'witness':None}
for start in range(0,524288,8192):
 x=rng.integers(0,256,(8192,128),dtype=np.uint16);y=x.copy();pos=rng.integers(0,128,8192);y[np.arange(8192),pos]^=rng.integers(1,256,8192,dtype=np.uint16)
 zw=(B.enc(x,4)==B.enc(y,4)).sum(1);big['pairs']+=8192;big['ge8']+=int((zw>=8).sum());big['max_zero']=max(big['max_zero'],int(zw.max()))
big['expected_random']=big['pairs']*p_rand
save('attack_sparse',{'started':res['started'],'finished':now(),'schedule_nonce':NONCE.hex(),'per_input_scan':sp,'four_round_broad_524288':big})
