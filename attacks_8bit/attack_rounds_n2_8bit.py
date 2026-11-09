from common import *
log=Log('attack_rounds');rng=np.random.default_rng(177);B=Batch(SCH);log('Live accelerator checks',B.validate(64),'per-round states through all16 rounds')
results={}
# DDT and LAT are measured, not merely inherited assertions.
boxes=[]
for r,k in enumerate(SCH.rounds):
 for name in ['S','S2']:
  d,l=N.ddt_max(k[name]),N.lat_max(k[name]);boxes.append([r,name,d,l]);log('Sbox',r+1,name,'DDT',d,'/256 LAT absolute bias',l,'/256 Walsh',2*l)
results['sboxes']=boxes
# Empirical dependency witnesses; existence of a change proves dependence for that schedule.
D=[np.zeros((128,128),dtype=bool) for _ in range(3)]
for t in range(8):
 base=rng.integers(0,256,(1,128),dtype=np.uint16);x=np.repeat(base,385,axis=0)
 for i in range(128):
  for j,d in enumerate([1,128,53]):x[1+3*i+j,i]^=d
 for r in range(3):
  x=B.round(x,r)
  for i in range(128):D[r][:,i]|=np.any(x[1+3*i:1+3*i+3]!=x[0],axis=0)
def components(d):
 seen=set();sz=[]
 for i in range(128):
  if i in seen:continue
  inp={i};outs=set();prev=-1
  while prev!=len(inp):
   prev=len(inp);outs=set(np.flatnonzero(np.any(d[:,list(inp)],axis=1)));inp|=set(np.flatnonzero(np.any(d[list(outs)],axis=0))) if outs else set()
  seen|=inp;sz.append(len(inp))
 return sorted(sz)
results['dependencies']=[]
for r,d in enumerate(D):
 sizes=d.sum(axis=1);row=dict(round=r+1,min=int(sizes.min()),mean=float(sizes.mean()),max=int(sizes.max()),components=components(d));results['dependencies'].append(row);log('Dependency witnesses',row)
# Same pairs tracked each round; one-byte random nonzero difference for truncated differential,
# and one-bit differences independently for avalanche. Statistical errors reported via sample SD/sqrt(n).
n=8192;x=rng.integers(0,256,(n,128),dtype=np.uint16);y=x.copy();pos=rng.integers(0,128,n);y[np.arange(n),pos]^=rng.integers(1,256,n,dtype=np.uint16)
z=x.copy();z[np.arange(n),pos]^=(1<<rng.integers(0,8,n)).astype(np.uint16)
# A fixed single-cell 0x80 difference and unrelated baseline pairs.
f=x.copy();f[:,0]^=128;un=rng.integers(0,256,(n,128),dtype=np.uint16)
results['pairs']=[]
for r in range(16):
 x=B.round(x,r);y=B.round(y,r);z=B.round(z,r);f=B.round(f,r);un=B.round(un,r)
 if r+1 not in [1,2,3,4,5,8,16]:continue
 same=(x==y).sum(axis=1);h=np.unpackbits((x^z).astype(np.uint8),axis=1).sum(axis=1);hist=np.zeros((128,256),dtype=int);histbase=np.zeros_like(hist)
 for j in range(128):hist[j]=np.bincount(x[:,j]^f[:,j],minlength=256);histbase[j]=np.bincount(x[:,j]^un[:,j],minlength=256)
 idx=np.unravel_index(hist.argmax(),hist.shape)
 row=dict(round=r+1,n=n,unchanged_mean=float(same.mean()),unchanged_se=float(same.std(ddof=1)/np.sqrt(n)),avalanche_mean=float(h.mean()),avalanche_se=float(h.std(ddof=1)/np.sqrt(n)),avalanche_min=int(h.min()),avalanche_max=int(h.max()),best_delta128_prob=float(hist.max()/n),best_delta128_cell=int(idx[0]),best_delta128_value=int(idx[1]),random_multiple_search_max=float(histbase.max()/n))
 results['pairs'].append(row);log('Pair metrics',row)
# LSB parity approximations with independent random plaintexts, all 1024 bits not just active sets.
n=32768;a=rng.integers(0,256,(n,128),dtype=np.uint16);pin=(a&1).sum(axis=1)&1;inbits=a[:,[0,7,64]]&1;lsb=[]
for r in range(16):
 a=B.round(a,r)
 if r+1 not in [1,2,3,4,8,16]:continue
 pout=(a&1).sum(axis=1)&1;bias=abs(float((pin==pout).mean())-.5)
 best=max(abs(float((inbits[:,i]==(a[:,j]&1)).mean())-.5) for i in range(3) for j in range(128))
 row=dict(round=r+1,n=n,global_parity_bias=bias,best_of_384_lsb_bias=best);lsb.append(row);log('LSB',row,'single test sigma',.5/np.sqrt(n),'Bonferroni 1% approx bias threshold 0.012')
results['lsb']=lsb
# One active byte, exhaustive 256 values in each of 64 independent chosen sets.
sets=64;count=256;bases=rng.integers(0,256,(sets,128),dtype=np.uint16);a=np.repeat(bases,count,axis=0)
for i in range(sets):a[i*count:(i+1)*count,int(rng.integers(128))]=np.arange(256)
results['integral1']=[]
for r in range(16):
 a=B.round(a,r)
 if r+1 not in [1,2,3,4,5,8,16]:continue
 sh=a.reshape(sets,count,128);zero=(np.bitwise_xor.reduce(sh,axis=1)==0).sum(axis=1)
 bits=np.unpackbits(a.astype(np.uint8),axis=1).reshape(sets,count,1024).sum(axis=1);dev=np.abs(bits.astype(int)-128)
 row=dict(round=r+1,sets=sets,texts_per_set=count,zero_xor_mean=float(zero.mean()),zero_xor_min=int(zero.min()),zero_xor_max=int(zero.max()),stuck_bits=int(((bits==0)|(bits==256)).sum()),max_bit_deviation=int(dev.max()))
 results['integral1'].append(row);log('Integral/chi 1byte',row,'random zeroXOR mean 0.5, max-bit dev compared with matched baseline below')
rand=rng.integers(0,256,(sets,count,128),dtype=np.uint8);bits=np.unpackbits(rand,axis=2).sum(axis=1);log('Matched random 64x256 chi-bit max deviation',int(np.abs(bits.astype(int)-128).max()),'stuck',int(((bits==0)|(bits==256)).sum()))
# Two active bytes (65536 texts), eight independent sets. Results at selected rounds only.
integ={r:[] for r in [1,2,3,4,5,8,16]}
for t in range(8):
 base=rng.integers(0,256,(1,128),dtype=np.uint16);a=np.repeat(base,65536,axis=0);p,q=rng.choice(128,2,replace=False);a[:,p]=np.repeat(np.arange(256,dtype=np.uint16),256);a[:,q]=np.tile(np.arange(256,dtype=np.uint16),256)
 for r in range(16):
  a=B.round(a,r)
  if r+1 in integ:integ[r+1].append(int((np.bitwise_xor.reduce(a,axis=0)==0).sum()))
 log('Integral2 trial',t+1,{r:integ[r][-1] for r in integ})
results['integral2']={r:dict(sets=8,texts_per_set=65536,counts=v,mean=statistics.mean(v)) for r,v in integ.items()}
for r,v in results['integral2'].items():log('Integral 2byte round',r,v,'random mean 0.5 zero-XOR bytes, but sets/output bytes may correlate')
log('No full16-round recovery demonstrated. Smallest avalanche outlier is a sample minimum, not a differential bound. No exhaustive trail/key-recovery search performed.')
log.save(results)
