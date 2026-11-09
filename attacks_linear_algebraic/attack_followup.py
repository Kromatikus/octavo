"""Follow-up re-tests of the largest outliers from attack_linear / attack_algebraic with fresh samples."""
from common import *
verify_live()
res={'started':now(),'live_sha':LIVE_SHA};B=Batch(SCH)
lin=json.loads((HERE/'attack_linear_results.json').read_text());alg=json.loads((HERE/'attack_algebraic_results.json').read_text())
fu=[]
for R in (1,2):
 a=lin['empirical'][f'{R}_round']['argmax'];ic=a['in_cell']*8+a['in_bit'];oc=a['out_cell']*8+a['out_bit'];n=1<<20;acc=0.0
 rng=np.random.default_rng(900+R)
 for s in range(n//16384):
  X=rng.integers(0,256,(16384,128));Y=B.enc(X,R);acc+=float(np.sum(1-2*(((X[:,a['in_cell']]>>a['in_bit'])&1)^((Y[:,a['out_cell']]>>a['out_bit'])&1))))
 fu.append(dict(test=f'{R}-round argmax single-bit approximation re-measured',original=a,fresh_samples=n,fresh_corr=acc/n,noise_floor=1/math.sqrt(n),sigmas=acc/n*math.sqrt(n)))
 print(fu[-1],flush=True)
# cube outliers: zero_all >= 2x expectation -> re-run with 32 fresh bases
import importlib.util
spec=importlib.util.spec_from_file_location('alg',HERE/'attack_algebraic.py')
def tobits(y):return ((y[:,:,None]>>np.arange(8))&1).reshape(y.shape[0],-1)
def cube_sum(fn,positions,base):
 d=len(positions);idx=np.arange(1<<d);X=np.repeat(base[None,:],1<<d,0).copy()
 for t,(c,b) in enumerate(positions):
  X[:,c]&=~(1<<b)&255;X[:,c]|=((idx>>t)&1)<<b
 acc=np.zeros(128,np.int64)
 for s in range(0,1<<d,16384):acc^=np.bitwise_xor.reduce(fn(X[s:s+16384]),axis=0)
 return acc
CUBES={'cell0 bits0..0 (d=1)':[(0,0)],'bit0 of 8 cells across staffs (d=8)':[(c*17%128,0) for c in range(8)]}
for fname,R,cname in (('1 round',1,'cell0 bits0..0 (d=1)'),('3 rounds',3,'bit0 of 8 cells across staffs (d=8)')):
 bases=np.random.default_rng(31337+R).integers(0,256,(32,128));sums=np.array([cube_sum(lambda x:B.enc(x,R),CUBES[cname],b) for b in bases]);sb=tobits(sums)
 # per-bit zero rate across 32 bases; a structural zero would be 32/32
 rate=(sb==0).mean(0)
 fu.append(dict(test=f'cube outlier re-run: {fname}, {cname}',bases=32,bits_zero_on_all_32=int((rate==1).sum()),random_expect=1024/2**32,max_zero_rate=float(rate.max()),mean_zero_rate=float(rate.mean())))
 print(fu[-1],flush=True)
res['followups']=fu;res['finished']=now();save('attack_followup',res)
