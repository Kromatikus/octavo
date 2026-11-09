from common import *
log=Log('attack_dependency');rng=np.random.default_rng(9309);results=[]
def lin(g,k,r):return N.bar_mix(N.shell_mix(N.staff_mix(N.weave(g,k['SH'],k['SV']),k['sigma']),k['bridge'],r))
def matrix(fn):
 rows=[]
 for i in range(128):
  v=bytearray(128);v[i]=1;rows.append(np.frombuffer(flat(fn(N.bytes_to_grid(bytes(v)))),dtype=np.uint8))
 return np.array(rows).T
ENC=matrix(N.bar_mix)!=0
# Structural support (upper bound): per round, Encore_support @ Lin_support (S, S2 are per-cell). Union over Z/256 nonzero coefficients.
for t,nonce in enumerate([NONCE]+[rng.bytes(16) for _ in range(16)]):
 s=SCH if nonce==NONCE else N.Schedule(SEED,nonce);sup=np.eye(128,dtype=bool);mins=[];means=[];missing=[]
 for r in range(3):
  L=matrix(lambda g:lin(g,s.rounds[r],r))!=0;R1=((ENC.astype(np.uint16)@L.astype(np.uint16))!=0)
  sup=((R1.astype(np.uint16)@sup.astype(np.uint16))!=0)
  mins.append(int(sup.sum(axis=1).min()));means.append(round(float(sup.sum(axis=1).mean()),4));missing.append(int((~sup).sum()))
 row=dict(schedule=t,min_inputs=mins,mean_inputs=means,missing_pairs=missing);results.append(row);log('Structural support (with encore) rounds 1..3',row)
full2=sum(r['missing_pairs'][1]==0 for r in results);log('Schedules with FULL structural 2-round coverage',full2,'/',len(results),'| full at 3 rounds',sum(r['missing_pairs'][2]==0 for r in results),'/',len(results))
# Empirical witnesses on demo schedule, 128 bases, random nonzero deltas
B=Batch(SCH);emp={}
for R in (1,2,3):
 D=np.zeros((128,128),dtype=bool)
 for _ in range(128 if R<3 else 16):
  base=rng.integers(0,256,(1,128),dtype=np.uint16);a=np.repeat(base,129,axis=0)
  for i in range(128):a[i+1,i]^=int(rng.integers(1,256))
  a=B.enc(a,R);D|=(a[1:]!=a[0]).T
 sz=D.sum(axis=1);emp[R]=dict(min=int(sz.min()),mean=float(sz.mean()),max=int(sz.max()),missing_pairs=int((~D).sum()));log('Demo empirical dependency after',R,'rounds',emp[R])
# If any structural 2-round hole exists on demo schedule, exhaustively confirm one
L0=ENC.astype(np.uint16)@(matrix(lambda g:lin(g,SCH.rounds[0],0))!=0).astype(np.uint16)!=0
L1=ENC.astype(np.uint16)@(matrix(lambda g:lin(g,SCH.rounds[1],1))!=0).astype(np.uint16)!=0
st=(L1.astype(np.uint16)@L0.astype(np.uint16))!=0;wit=None
if (~st).any():
 j,i=map(int,np.argwhere(~st)[0]);texts=rng.integers(0,256,(1,128),dtype=np.uint16).repeat(256,axis=0);texts[:,i]=np.arange(256);o=B.enc(texts,2)
 wit=dict(input=i,output=j,unique_output_values=len(set(map(int,o[:,j]))));log('Exhaustive 256-value witness of a 2-round missing pair',wit)
log.save(dict(schedules=results,demo_empirical=emp,witness=wit))
