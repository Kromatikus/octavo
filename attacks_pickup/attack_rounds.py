from common import *
import math
res={'started':now(),'fixed_schedule_nonce':NONCE.hex(),'white_box':'Raw blocks with one fixed schedule; not public randomized encrypt(). Whitening cancels in XOR differences.'};B=Batch(SCH);res['crosschecks']=B.validate(4)
rng=np.random.default_rng(202611082);Rs=(1,2,3,4,16);stats={r:{} for r in Rs};p_rand=sum(math.comb(128,j)*(1/256)**j*(255/256)**(128-j) for j in range(8,129))
# All datasets advanced once through the rounds; chunked to bound memory.
K=32;nd=128*K;na=4096;nz=65536;nh=65536;total=nd+na+nz+nh
ag={r:{'dep':np.zeros((128,128),bool),'hws':[],'zero_pos':np.zeros(128,dtype=np.int64),'sparse':0,'maxzero':0,'hist':np.zeros(256,dtype=np.int64),'hist80':np.zeros(128,dtype=np.int64),'hzero':0,'witness':None,'bitcounts':np.zeros(1024,dtype=np.int64)} for r in Rs}
# Separate dataset runs ensure labels/reproduction straightforward.
for kind,n in [('dependence',nd),('avalanche',na),('zero',nz),('highbit18',nh)]:
 for start in range(0,n,4096):
  count=min(4096,n-start);x=rng.integers(0,256,(count,128),dtype=np.uint16);y=x.copy();orig=x.copy()
  if kind=='dependence':pos=np.arange(start,start+count)//K;y[np.arange(count),pos]^=rng.integers(1,256,count,dtype=np.uint16)
  elif kind=='avalanche':bits=rng.integers(0,1024,count);y[np.arange(count),bits//8]^=(1<<(bits%8)).astype(np.uint16)
  elif kind=='zero':pos=rng.integers(0,128,count);y[np.arange(count),pos]^=rng.integers(1,256,count,dtype=np.uint16)
  else:y[:,18]^=128
  origy=y.copy()
  for r in range(1,17):
   x=B.round(x,r-1);y=B.round(y,r-1)
   if r not in Rs:continue
   a=ag[r];d=x^y
   if kind=='dependence':
    for p in np.unique(pos):a['dep'][p]|=(d[pos==p]!=0).any(0)
   elif kind=='avalanche':
    bitsout=np.unpackbits(d.astype(np.uint8),axis=1);a['hws'].extend(bitsout.sum(1).tolist());a['bitcounts']+=bitsout.sum(0).astype(np.int64)
   elif kind=='zero':
    z=d==0;zw=z.sum(1);a['zero_pos']+=z.sum(0);a['sparse']+=int((zw>=8).sum());a['maxzero']=max(a['maxzero'],int(zw.max()))
    if a['witness'] is None and (zw>=8).any():
     i=int(zw.argmax());a['witness']={'x':bytes(orig[i].astype(np.uint8)).hex(),'y':bytes(origy[i].astype(np.uint8)).hex(),'zero_bytes':int(zw[i]),'zero_positions':np.nonzero(z[i])[0].tolist()}
   else:a['hist']+=np.bincount(d[:,38],minlength=256);a['hist80']+=(d==128).sum(0);a['hzero']+=int((d==0).sum())
 print('finished dataset',kind,now(),flush=True)
for r,a in ag.items():
 h=np.array(a['hws']);z=a['zero_pos'];hist=a['hist'];w=a['witness']
 if w:
  wx=flat(N.encrypt_grid(N.bytes_to_grid(bytes.fromhex(w['x'])),SCH,rounds=r,white=False));wy=flat(N.encrypt_grid(N.bytes_to_grid(bytes.fromhex(w['y'])),SCH,rounds=r,white=False));w['verified_live']=sum(x==y for x,y in zip(wx,wy))==w['zero_bytes']
 stats[r]={'byte_dependence':{'empirical_pairs':int(a['dep'].sum()),'of':16384,'bases_per_input':K,'min_output_dependencies':int(a['dep'].sum(0).min()),'min_outputs_per_input':int(a['dep'].sum(1).min())},'bit_avalanche':{'pairs':na,'mean':round(float(h.mean()),3),'sd':round(float(h.std()),3),'min':int(h.min()),'max':int(h.max()),'worst_bit_rate_deviation':float(abs(a['bitcounts']/na-.5).max())},'zero_difference':{'pairs':nz,'mean_zero_bytes':float(z.sum()/nz),'chi2_128pos':float(((z-nz/256)**2/(nz/256)).sum()),'chi2_note':'128 marginal zero counts; diagnostic only, not a multinomial df127 test; correlations can affect calibration.','ge8_zero_pairs':a['sparse'],'expected_random':nz*p_rand,'max_zero':a['maxzero'],'witness':w},'delta80_cell18':{'pairs':nh,'byte38_histogram_chi2_df255':float(((hist-nh/256)**2/(nh/256)).sum()),'max_position_count_0x80':int(a['hist80'].max()),'mean_zero_rate':a['hzero']/(nh*128)}}
res['rounds']=stats
save('attack_rounds',res)
# Higher-powered direct comparison to old report: same 128*4096 trial count, r2 and r3.
sp={2:{'total':0,'max_zero':0,'cells':[],'witness':None},3:{'total':0,'max_zero':0,'cells':[],'witness':None}}
for c in range(128):
 n=4096;x=rng.integers(0,256,(n,128),dtype=np.uint16);y=x.copy();y[:,c]^=rng.integers(1,256,n,dtype=np.uint16);ox=x.copy();oy=y.copy()
 for r in range(1,4):
  x=B.round(x,r-1);y=B.round(y,r-1)
  if r<2:continue
  z=(x==y);zw=z.sum(1);hits=int((zw>=8).sum());sp[r]['total']+=hits;sp[r]['max_zero']=max(sp[r]['max_zero'],int(zw.max()))
  if hits:
   sp[r]['cells'].append({'cell':c,'hits':hits})
   if sp[r]['witness'] is None:
    i=int(zw.argmax());w={'cell':c,'x':bytes(ox[i].astype(np.uint8)).hex(),'y':bytes(oy[i].astype(np.uint8)).hex(),'zero_bytes':int(zw[i]),'zero_positions':np.nonzero(z[i])[0].tolist()};sp[r]['witness']=w
 if c%16==15:print('sparse cells done',c+1,now(),flush=True)
for r in sp:
 sp[r].update(pairs=128*4096,expected_random=128*4096*p_rand)
 w=sp[r]['witness']
 if w:
  a=flat(N.encrypt_grid(N.bytes_to_grid(bytes.fromhex(w['x'])),SCH,r,False));b=flat(N.encrypt_grid(N.bytes_to_grid(bytes.fromhex(w['y'])),SCH,r,False));w['verified_live']=sum(x==y for x,y in zip(a,b))==w['zero_bytes']
save('attack_sparse',{'started':res['started'],'finished':now(),'results':sp})
