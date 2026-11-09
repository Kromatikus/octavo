"""Local attack helpers. No changes to target; NumPy accelerator checked against live rounds."""
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,'/workspace/sneak_n2')
import sneak_n2 as N
import numpy as np
from pathlib import Path
import json, random, statistics
HERE=Path(__file__).resolve().parent
SEED=N.load_seed()
NONCE=bytes.fromhex('e573fbdf1e63278498735dfce435611e')
SCH=N.Schedule(SEED,NONCE)
class Log:
 def __init__(self,name):self.name=name;self.lines=[]
 def __call__(self,*a):
  s=' '.join(map(str,a));print(s,flush=True);self.lines.append(s)
 def save(self,obj=None):
  (HERE/(self.name+'_output.txt')).write_text('\n'.join(self.lines)+'\n')
  if obj is not None:(HERE/(self.name+'_results.json')).write_text(json.dumps(obj,indent=2)+'\n')
def hw(a,b):return sum((x^y).bit_count() for x,y in zip(a,b))
def flat(g):return N.grid_to_bytes(g)
class Batch:
 def __init__(self,sch):
  self.sch=sch;self.perms=[]
  for k in sch.rounds:
   g=N.weave([list(range(i*8,i*8+8)) for i in range(16)],k['SH'],k['SV'])
   self.perms.append(np.array(g).reshape(128))
 def round(self,x,r):
  k=self.sch.rounds[r];x=np.asarray(x,dtype=np.uint16)
  x=np.array(k['S'],dtype=np.uint16)[x ^ np.frombuffer(flat(k['rk']),dtype=np.uint8)]
  x=x[:,self.perms[r]].copy()
  for f,s in enumerate(k['sigma']):
   for m in N.LAYERS:
    for i in range(8):
     if not i&m:
      a,b=f*8+s[i],f*8+s[i|m];u=x[:,a].copy();v=x[:,b].copy();x[:,a]=(u+v)&255;x[:,b]=(u+2*v)&255
  for c,p in enumerate(k['bridge']):
   a,b=c,p+64
   if r%2:a,b=b,a
   u=x[:,a].copy();v=x[:,b].copy();x[:,a]=(u+v)&255;x[:,b]=(u+2*v)&255
  for f in range(16):
   for _,_,(i,j),M in N.BARS:
    a,b=f*8+i,f*8+j;u=x[:,a].copy();v=x[:,b].copy();x[:,a]=(M[0][0]*u+M[0][1]*v)&255;x[:,b]=(M[1][0]*u+M[1][1]*v)&255
  return np.array(k['S2'],dtype=np.uint16)[x]
 def enc(self,x,rounds=16,white=False):
  for r in range(rounds):x=self.round(x,r)
  return x ^ np.frombuffer(flat(self.sch.white),dtype=np.uint8) if white else x
 def validate(self,count=32):
  rng=np.random.default_rng(713);x=rng.integers(0,256,(count,128),dtype=np.uint16);y=x.copy()
  for r in range(16):
   x=self.round(x,r)
   for i in range(count):
    g=N.round_enc(N.bytes_to_grid(bytes(y[i].astype(np.uint8))),self.sch.rounds[r],r)
    y[i]=np.frombuffer(flat(g),dtype=np.uint8)
   assert np.array_equal(x,y),(r,'accelerator mismatch')
  return count*16
