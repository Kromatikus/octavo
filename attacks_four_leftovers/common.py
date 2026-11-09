"""Read-only import of LIVE N2 (four-leftovers era); independent NumPy batching, validated against live round_enc."""
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,'/workspace/sneak_n2')
from pathlib import Path
import hashlib
assert hashlib.sha256(Path('/workspace/sneak_n2/sneak_n2.py').read_bytes()).hexdigest()=='991ae8f61ee53ec899003b57bc143d70dc9fcdb37de6bd2b334a18f020ebdf5f'
import sneak_n2 as N
import numpy as np
from pathlib import Path
import json, random, re, hashlib, hmac, time, datetime, importlib.util, math
from zoneinfo import ZoneInfo
HERE=Path(__file__).resolve().parent
EXPECTED_SHA='991ae8f61ee53ec899003b57bc143d70dc9fcdb37de6bd2b334a18f020ebdf5f'
LIVE_SHA=hashlib.sha256(Path(N.__file__).read_bytes()).hexdigest()
assert N.__file__=='/workspace/sneak_n2/sneak_n2.py' and LIVE_SHA==EXPECTED_SHA,(N.__file__,LIVE_SHA)
def verify_live():
 current=hashlib.sha256(Path('/workspace/sneak_n2/sneak_n2.py').read_bytes()).hexdigest()
 assert N.__file__=='/workspace/sneak_n2/sneak_n2.py' and current==EXPECTED_SHA,('STOP: wrong live target',current)
 return current
verify_live()
SEED=N.load_seed()
HB=bytes.fromhex(re.search(r'blob \(195 bytes.*?: ([0-9a-f]+)',Path('/workspace/sneak_n2/hello-world.txt').read_text()).group(1))
_,PICKUP,NONCE,CT,TAG=N.split_blob(HB)
SCH=N.Schedule(SEED,NONCE)          # live schedule from the recorded hello-world nonce
DEMO_NONCE=bytes.fromhex(Path('/workspace/sneak_n2/demo-nonce.txt').read_text().strip())
PICKUP_ERA_NONCE=bytes.fromhex('4ea3cefffeabc7257c7f26181a63f08a')
def now():return datetime.datetime.now(ZoneInfo('America/New_York')).strftime('%Y-%m-%d %I:%M:%S %p %Z (America/New_York)')
def save(name,obj):
 text=json.dumps(obj,indent=2,default=str)+'\n';(HERE/(name+'_results.json')).write_text(text);(HERE/(name+'_output.txt')).write_text(now()+'\n'+text);print(name,'saved',flush=True)
def hw(a,b):return sum((x^y).bit_count() for x,y in zip(a,b))
def flat(g):return N.grid_to_bytes(g)
GF=np.array([list(x) for x in N._GF_MUL],dtype=np.uint16)
M2=N.MIX2_MATRIX
def bars(x):
 x=x.reshape(-1,16,8).copy()
 for name,_,(i,j),M in N.BARS:
  u=x[:,:,i].copy();v=x[:,:,j].copy()
  if name=='B0 start':
   x[:,:,i]=(u+rotl(v,N.B0_ROT_R1))&255;x[:,:,j]=v^rotl(x[:,:,i],N.B0_ROT_R2)
  else:x[:,:,i]=GF[M[0][0],u]^GF[M[0][1],v];x[:,:,j]=GF[M[1][0],u]^GF[M[1][1],v]
 return x.reshape(-1,128)
def trips(x):
 x=x.reshape(-1,16,8).copy()
 for _,(i,j,k),M in N.TRIPLETS:
  u=x[:,:,i].copy();v=x[:,:,j].copy();w=x[:,:,k].copy()
  for pos,(a,b,c) in zip((i,j,k),M):x[:,:,pos]=(a*u+b*v+c*w)&255
 return x.reshape(-1,128)
def rotl(x,r):return ((x<<r)|(x>>(8-r)))&255
def bow(x):
 x=x.reshape(-1,16,8).copy()
 for i,j,p in N.BOW_STROKES:
  pp=x[:,:,p];r1=N.BOW_ROT_BASE+(pp%N.BOW_ROT_MOD);r2=N.BOW_ROT_BASE+((pp>>N.BOW_R2_SHIFT)%N.BOW_ROT_MOD)
  u=(x[:,:,i]+rotl(x[:,:,j],r1))&255;x[:,:,i]=u;x[:,:,j]=x[:,:,j]^rotl(u,r2)
 return x.reshape(-1,128)
def rehair(x):
 x=x.reshape(-1,16,8).copy()
 for t in (1,3,5,7):
  u=(x[:,:,t-1]+rotl(x[:,:,t],N.ODD_RESTACK_R1))&255;x[:,:,t-1]=u;x[:,:,t]^=rotl(u,N.ODD_RESTACK_R2)
 return x.reshape(-1,128)
def cross(x):
 x=x.reshape(-1,16,8).copy()
 for layer in N.CROSS_LAYERS:
  for i,j in layer:
   u=x[:,i,:].copy();v=x[:,j,:].copy();x[:,i,:],x[:,j,:]=mix2v(u,v)
 return x.reshape(-1,128)
def mix2v(u,v):return GF[M2[0][0],u]^GF[M2[0][1],v],GF[M2[1][0],u]^GF[M2[1][1],v]
class Batch:
 def __init__(self,sch):
  self.sch=sch;self.perms=[];self.staff=[];self.shell=[]
  for r,k in enumerate(sch.rounds):
   self.perms.append(np.array(N.weave([list(range(i*8,i*8+8)) for i in range(16)],k['SH'],k['SV'])).reshape(128))
   layers=[]
   for m in N.LAYERS:
    pairs=[(f*8+s[i],f*8+s[i|m]) for f,s in enumerate(k['sigma']) for i in range(8) if not i&m]
    layers.append(tuple(np.array(t) for t in zip(*pairs)))
   self.staff.append(layers)
   a=np.arange(64)
   fo=np.array(k['bridge'])//8+8;to=np.array(k['bridge'])%8;b=fo*8+to
   self.shell.append((b,a) if r%2 else (a,b))
 def linear(self,x,r):
  """weave -> butterfly -> bridges (field mix2)."""
  x=np.asarray(x,dtype=np.uint16)[:,self.perms[r]].copy()
  for a,b in self.staff[r]+[self.shell[r]]:
   u=x[:,a].copy();v=x[:,b].copy();x[:,a],x[:,b]=mix2v(u,v)
  return x
 def middle(self,x,r,with_bow=True):
  x=trips(bars(self.linear(x,r)))
  return cross(rehair(bow(x))) if with_bow else x
 def round(self,x,r):
  k=self.sch.rounds[r];x=np.array(k['S'],dtype=np.uint16)[np.asarray(x,dtype=np.uint16)^np.frombuffer(flat(k['rk']),dtype=np.uint8)]
  x=self.middle(x,r);x=np.array(k['S2'],dtype=np.uint16)[x]
  return cross(rehair(bow(trips(bars(x)))))
 def enc(self,x,rounds=16,white=False):
  for r in range(rounds):x=self.round(x,r)
  return x^np.frombuffer(flat(self.sch.white),dtype=np.uint8) if white else x
 def validate(self,count=8,seed=713):
  rng=np.random.default_rng(seed);x=rng.integers(0,256,(count,128),dtype=np.uint16);y=x.copy()
  for r in range(16):
   x=self.round(x,r)
   for i in range(count):y[i]=np.frombuffer(flat(N.round_enc(N.bytes_to_grid(bytes(y[i].astype(np.uint8))),self.sch.rounds[r],r)),dtype=np.uint8)
   assert np.array_equal(x,y),(r,'batch mismatch')
  raw=rng.integers(0,256,(1,128),dtype=np.uint16)
  assert bytes(self.enc(raw,16,True)[0].astype(np.uint8))==flat(N.encrypt_grid(N.bytes_to_grid(bytes(raw[0].astype(np.uint8))),self.sch))
  # bow helper vs live
  for i in range(200):
   s=list(rng.integers(0,256,8));assert list(bow(np.array([s*16],dtype=np.uint16))[0][:8])==N.bow_pressure(s)
  for i in range(200):
   s=list(map(int,rng.integers(0,256,8)));assert list(rehair(np.array([s*16],dtype=np.uint16))[0][:8])==N.odd_restack(s)
  return count*16
def live_round_bytes(b,sch,rounds):return flat(N.encrypt_grid(N.bytes_to_grid(b),sch,rounds,False))
