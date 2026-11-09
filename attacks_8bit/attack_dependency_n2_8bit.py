from common import *
log=Log('attack_dependency');rng=np.random.default_rng(309);results=[]
def lin(g,k,r):return N.bar_mix(N.shell_mix(N.staff_mix(N.weave(g,k['SH'],k['SV']),k['sigma']),k['bridge'],r))
def matrix(k,r):
 rows=[]
 for i in range(128):
  v=bytearray(128);v[i]=1;rows.append(np.frombuffer(flat(lin(N.bytes_to_grid(v),k,r)),dtype=np.uint8))
 return np.array(rows).T
# Structural upper bound unions exact nonzero Z256 coefficients between nonlinear layers.
for t,nonce in enumerate([NONCE]+[rng.bytes(16) for _ in range(16)]):
 s=SCH if nonce==NONCE else N.Schedule(SEED,nonce);support=np.eye(128,dtype=bool);mins=[];means=[]
 for r in range(3):
  L=matrix(s.rounds[r],r);support=((L!=0).astype(np.uint16)@support.astype(np.uint16))!=0
  mins.append(int(support.sum(axis=1).min()));means.append(float(support.sum(axis=1).mean()))
 row=dict(schedule=t,min_inputs=mins,mean_inputs=means,nonce=nonce.hex());results.append(row);log('Exact structural support upper bound',row)
# Strengthen demo dependence witness with 128 independent base points and random nonzero deltas.
B=Batch(SCH);D=np.zeros((128,128),dtype=bool)
for _ in range(128):
 base=rng.integers(0,256,(1,128),dtype=np.uint16);a=np.repeat(base,129,axis=0)
 for i in range(128):a[i+1,i]^=int(rng.integers(1,256))
 a=B.enc(a,2)
 D|=(a[1:]!=a[0]).T
sizes=D.sum(axis=1);log('Demo 2round128base empirical min/mean/max',int(sizes.min()),float(sizes.mean()),int(sizes.max()),'missing pairs',int((~D).sum()))
L0=matrix(SCH.rounds[0],0)!=0;L1=matrix(SCH.rounds[1],1)!=0
struct=(L1.astype(np.uint16)@L0.astype(np.uint16))!=0
j,i=map(int,np.argwhere(~struct)[0]);texts=np.zeros((256,128),dtype=np.uint16);texts[:,i]=np.arange(256);outputs=B.enc(texts,2)
log('Exact two-round missing path witness input/output',i,j,'unique output byte over all256 input values',len(set(map(int,outputs[:,j]))))
assert len(set(map(int,outputs[:,j])))==1
log.save(dict(schedules=results,demo_2round_witness=dict(min=int(sizes.min()),mean=float(sizes.mean()),max=int(sizes.max()),missing_pairs=int((~D).sum()))))
