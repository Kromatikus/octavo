"""Read-only import of live N2; independent NumPy batching, validated against live rounds."""
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,'/workspace/sneak_n2')
import sneak_n2 as N
import numpy as np
from pathlib import Path
import json, random, re, hashlib, hmac, time, datetime, importlib.util
from zoneinfo import ZoneInfo
HERE=Path(__file__).resolve().parent
SEED=N.load_seed()
HB=bytes.fromhex(re.search(r'blob \(195 bytes.*?: ([0-9a-f]+)',Path('/workspace/sneak_n2/hello-world.txt').read_text()).group(1))
_,PICKUP,NONCE,CT,TAG=N.split_blob(HB)
SCH=N.Schedule(SEED,NONCE)
def now():return datetime.datetime.now(ZoneInfo('America/New_York')).strftime('%Y-%m-%d %I:%M:%S %p %Z (America/New_York)')
def save(name,obj):
 text=json.dumps(obj,indent=2,default=str)+'\n';(HERE/(name+'_results.json')).write_text(text);(HERE/(name+'_output.txt')).write_text(now()+'\n'+text);print(name,text,flush=True)
def hw(a,b):return sum((x^y).bit_count() for x,y in zip(a,b))
def flat(g):return N.grid_to_bytes(g)
GF=np.array([list(x) for x in N._GF_MUL],dtype=np.uint16)
def bars(x):
 x=x.reshape(-1,16,8).copy()
 for _,_,(i,j),M in N.BARS:
  u=x[:,:,i].copy();v=x[:,:,j].copy()
  x[:,:,i]=GF[M[0][0],u]^GF[M[0][1],v];x[:,:,j]=GF[M[1][0],u]^GF[M[1][1],v]
 return x.reshape(-1,128)
def trips(x):
 x=x.reshape(-1,16,8).copy()
 for _,(i,j,k),M in N.TRIPLETS:
  u=x[:,:,i].copy();v=x[:,:,j].copy();w=x[:,:,k].copy()
  for pos,(a,b,c) in zip((i,j,k),M):x[:,:,pos]=(a*u+b*v+c*w)&255
 return x.reshape(-1,128)
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
   a=np.arange(64);b=np.array(k['bridge'])+64;self.shell.append((b,a) if r%2 else (a,b))
 def middle(self,x,r):
  x=np.asarray(x,dtype=np.uint16)[:,self.perms[r]].copy()
  for a,b in self.staff[r]+[self.shell[r]]:
   u=x[:,a].copy();v=x[:,b].copy();x[:,a]=(u+v)&255;x[:,b]=(u+2*v)&255
  return trips(bars(x))
 def round(self,x,r):
  k=self.sch.rounds[r];x=np.array(k['S'],dtype=np.uint16)[np.asarray(x,dtype=np.uint16)^np.frombuffer(flat(k['rk']),dtype=np.uint8)]
  x=self.middle(x,r);x=np.array(k['S2'],dtype=np.uint16)[x]
  return trips(bars(x))
 def enc(self,x,rounds=16,white=False):
  for r in range(rounds):x=self.round(x,r)
  return x^np.frombuffer(flat(self.sch.white),dtype=np.uint8) if white else x
 def validate(self,count=8):
  rng=np.random.default_rng(713);x=rng.integers(0,256,(count,128),dtype=np.uint16);y=x.copy()
  for r in range(16):
   x=self.round(x,r)
   for i in range(count):y[i]=np.frombuffer(flat(N.round_enc(N.bytes_to_grid(bytes(y[i].astype(np.uint8))),self.sch.rounds[r],r)),dtype=np.uint8)
   assert np.array_equal(x,y),(r,'batch mismatch')
  # direct encrypt_grid cross-check with whitening
  raw=rng.integers(0,256,(1,128),dtype=np.uint16)
  assert bytes(self.enc(raw,16,True)[0].astype(np.uint8))==flat(N.encrypt_grid(N.bytes_to_grid(bytes(raw[0].astype(np.uint8))),self.sch))
  return count*16
