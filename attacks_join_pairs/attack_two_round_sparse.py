"""Follow-up to the r=2 outliers in attack_rounds_diffusion.py: per input byte, how often is the 2-round output difference sparse?
Random 1024-bit permutation: #zero diff bytes ~ Binomial(128, 1/256); P(>=8 zero bytes) ~ 1e-8."""
from common import *
import math
log=Log('attack_two_round_sparse');res={}
B=Batch(SCH);B.validate(4)
rng=np.random.default_rng(4242);n=4096;rows=[]
for R in (2,3):
 tot=0;hits=[]
 for c in range(128):
  x=rng.integers(0,256,(n,128),dtype=np.uint16);y=x.copy();y[:,c]^=rng.integers(1,256,n,dtype=np.uint16)
  z=((B.enc(x,R)^B.enc(y,R))==0).sum(1);k=int((z>=8).sum());tot+=k
  if k:hits.append(dict(cell=c,pairs_with_ge8_zero_bytes=k,max_zero=int(z.max()),rate=round(k/n,5)))
 hits.sort(key=lambda h:-h['pairs_with_ge8_zero_bytes'])
 p_rand=sum(math.comb(128,j)*(1/256)**j*(255/256)**(128-j) for j in range(8,30))
 res[R]=dict(pairs=128*n,sparse_pairs_total=tot,expected_random=round(128*n*p_rand,4),top_cells=hits[:10])
 log(f'{R} rounds: pairs with >=8 zero output-diff bytes: {tot} of {128*n} (random expectation {128*n*p_rand:.2e}); top cells',hits[:6])
# witness: one sparse 2-round pair
if res[2]['top_cells']:
 c=res[2]['top_cells'][0]['cell']
 for _ in range(200):
  x=rng.integers(0,256,(4096,128),dtype=np.uint16);y=x.copy();y[:,c]^=rng.integers(1,256,4096,dtype=np.uint16)
  d=B.enc(x,2)^B.enc(y,2);z=(d==0).sum(1);i=int(z.argmax())
  if z[i]>=8:
   w=dict(cell=c,x=bytes(x[i].astype(np.uint8)).hex(),y=bytes(y[i].astype(np.uint8)).hex(),zero_bytes=int(z[i]),zero_positions=np.nonzero(d[i]==0)[0].tolist())
   gx=N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(bytes.fromhex(w['x'])),SCH,rounds=2,white=False));gy=N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(bytes.fromhex(w['y'])),SCH,rounds=2,white=False))
   w['verified_with_live_library']=sum(a==b for a,b in zip(gx,gy))==w['zero_bytes'];res['witness_2round']=w;log('2-round sparse witness (verified with N.encrypt_grid):',{k:v for k,v in w.items() if k not in('x','y')});break
log.save(res)
