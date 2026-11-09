"""Delta=0x80 even-coefficient leakage turned into a 1-round truncated differential on the LIVE post-join N2 (reduced rounds,
raw chosen blocks, no whitening needed since XOR keys do not change differences). 2-round extension is estimated, not demonstrated."""
from common import *
import math
log=Log('attack_highbit_trail');res={}
B=Batch(SCH);log('NumPy accelerator cross-checked vs N.round_enc on',B.validate(16),'round evaluations')
def lin(fn):
 L=np.zeros((128,128),dtype=np.int64)
 for c in range(128):
  g=[[0]*8 for _ in range(16)];g[c//8][c%8]=1;L[:,c]=sum(fn(g),[])
 return L
E=lin(N.bar_mix)
Lm=[lin(lambda g,k=k,r=r:N.bar_mix(N.shell_mix(N.staff_mix(N.weave(g,k['SH'],k['SV']),k['sigma']),k['bridge'],r))) for r,k in enumerate(SCH.rounds[:2])]
def p80(L,A):
 v=np.zeros(128,dtype=np.int64);v[list(A)]=1;return set(np.nonzero((L@v)%2)[0].tolist())
def reach(L,A):return set(np.nonzero((L[:,list(A)]%256).any(1))[0].tolist())
S0=SCH.rounds[0]['S']
def ddtrow(S,b):return [sum(1 for x in range(256) if S[x]^S[x^a]==b) for a in range(256)]
row=ddtrow(S0,0x80);dbest=max(range(1,256),key=lambda a:row[a])
rng=np.random.default_rng(1108);NP=200000
out={}
for start in [18,37,9,0,64]:
 s2=p80(Lm[0],{start});C=sorted(reach(E,s2)) if len(s2)==1 else None
 cnts={}
 for mode in ('random_delta','whitebox_best_delta'):
  x=rng.integers(0,256,(NP,128),dtype=np.uint16);y=x.copy()
  d=rng.integers(1,256,NP,dtype=np.uint16) if mode=='random_delta' else np.full(NP,dbest if start==18 else max(range(1,256),key=lambda a:ddtrow(S0,0x80)[a]),dtype=np.uint16)
  y[:,start]^=d
  dx=(B.enc(x,1)^B.enc(y,1))!=0;act=dx.sum(1)
  conf=int(np.count_nonzero(~dx[:,[c for c in range(128) if C is None or c not in C]].any(1))) if C else None
  cnts[mode]=dict(pairs=NP,min_active=int(act.min()),hist_le8={k:int((act==k).sum()) for k in range(0,9)},confined_to_predicted=conf,
   confined_rate=(conf/NP if conf is not None else None),log2_rate=(round(math.log2(conf/NP),2) if conf else None))
 out[start]=dict(S2_cells_hit_by_0x80=sorted(s2),predicted_output_cells=C,results=cnts)
 log(f'start cell {start} (face {start//8} beat {start%8}): 0x80 at its S output hits S2 cells {sorted(s2)}; predicted 1-round output cells {C}')
 for m,v in cnts.items():log('   ',m,v)
res['one_round_truncated']=out
res['ddt_S0_to_0x80_best']=dict(delta=hex(dbest),count=row[dbest])
res['random_baseline']='For a random 1024-bit permutation, P(output diff confined to 3 given bytes) ~ 2^-(125*8) = 2^-1000.'
# 2-round estimate for start 18
s2=next(iter(p80(Lm[0],{18})));A=reach(E,{s2});Bs=p80(Lm[1],A);C2=reach(E,Bs)
est=math.log2(4/256)+len(A)*math.log2(1/255)
res['two_round_estimate']=dict(start=18,round1_S_inputs_active=len(A),need_all_to_output_0x80=True,round1_S2_active=len(Bs),round2_output_cells=len(C2),
 log2p_whitebox_estimate=round(est,1),log2p_blackbox_estimate=round(math.log2(1/255)*(1+len(A)),1),status='estimated only, not demonstrated (needs ~2^30+ pairs)')
log('2-round truncated estimate:',res['two_round_estimate'])
log.save(res)
