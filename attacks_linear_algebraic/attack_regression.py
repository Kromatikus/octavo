"""Regression of the usual checks on live N2: integrity, sparse-output differential scans, avalanche, singleton counts."""
from common import *
verify_live()
res={'started':now(),'live_sha':LIVE_SHA}
def outcome(blob):
 try:return 'ACCEPTED:'+repr(N.decrypt(blob,SEED))
 except N.AuthError as e:return 'AuthError: '+str(e)
 except N.DecodeError as e:return 'DecodeError: '+str(e)
 except Exception as e:return type(e).__name__+': '+str(e)
from collections import Counter
t0=time.time();assert N.decrypt(HB,SEED)==b'hello world'
flips=Counter()
for i in range(len(HB)*8):
 b=bytearray(HB);b[i//8]^=1<<(i%8);flips[outcome(bytes(b))]+=1
prev=outcome(PREV_BLOB)
fields=lambda x:N.split_blob(x)
fa,fb=fields(HB),fields(PREV_BLOB);spl=Counter()
import itertools
for choice in itertools.product((0,1),repeat=4):
 if choice in ((0,0,0,0),(1,1,1,1)):continue
 parts=[(fa,fb)[c][i+1] for i,c in enumerate(choice)];spl[outcome(N.VERSION+b''.join(parts))]+=1
lens=Counter(outcome(HB[:n]) for n in range(len(HB)));lens.update(outcome(HB+x) for x in (b'\0',b'\0'*5,HB))
r=random.Random(21);rnd=Counter(outcome(N.VERSION+bytes(r.randrange(256) for _ in range(192))) for _ in range(100))
res['integrity']=dict(hello_decrypts=True,hello_pickup=PICKUP.hex(),single_bit_flips=len(HB)*8,flip_outcomes=dict(flips),
 previous_sample_pickup=PREV_BLOB[3:19].hex(),previous_sample=prev,splices_with_previous=dict(spl),wrong_lengths=dict(lens),random_SN2_blobs=dict(rnd),
 any_accepted=any(k.startswith('ACCEPTED') or k.startswith('DecodeError') for c in (flips,spl,lens,rnd) for k in c) or not prev.startswith('AuthError'),seconds=round(time.time()-t0,1))
print(res['integrity'],flush=True)
B=Batch(SCH);B.validate()
# sparse-output differential scans: single-cell random nonzero deltas
def scan(R,per_cell,seed):
 rng=np.random.default_rng(seed);hits=0;mx=0;wit=None;tot=0;zsum=0
 for c0 in range(0,128,16):
  X=rng.integers(0,256,(16*per_cell,128));cells=np.repeat(np.arange(c0,c0+16),per_cell);d=rng.integers(1,256,16*per_cell)
  Y=X.copy();Y[np.arange(len(Y)),cells]^=d
  out=[];outy=[]
  for s in range(0,len(X),16384):out.append(B.enc(X[s:s+16384],R));outy.append(B.enc(Y[s:s+16384],R))
  D=np.concatenate(out)^np.concatenate(outy);z=(D==0).sum(1);tot+=len(z);zsum+=int(z.sum())
  hits+=int((z>=8).sum())
  if z.max()>mx:mx=int(z.max());i=int(np.argmax(z));wit=dict(cell=int(cells[i]),delta=int(d[i]),unchanged_bytes=mx)
 return dict(rounds=R,pairs=tot,ge8_unchanged_hits=hits,max_unchanged=mx,mean_unchanged=zsum/tot,random_mean=0.5,witness_max=wit,
  random_expect_hits=tot*8.0e-8)
sp=[];t0=time.time()
for R,pc in ((1,2048),(2,2048),(3,1024),(4,512),(16,128)):
 sp.append(scan(R,pc,40+R));print(sp[-1],round(time.time()-t0),flush=True)
res['sparse_scans']=sp
# avalanche
av={}
for R,n in ((1,4096),(16,4096)):
 rng=np.random.default_rng(60+R);X=rng.integers(0,256,(n,128));bit=rng.integers(0,1024,n);Y=X.copy();Y[np.arange(n),bit//8]^=1<<(bit%8)
 D=B.enc(X,R)^B.enc(Y,R);hwv=np.unpackbits(D.astype(np.uint8),axis=1).sum(1)
 av[f'{R}_round']=dict(pairs=n,mean_bits_changed=float(hwv.mean()),min=int(hwv.min()),max=int(hwv.max()),ideal=512,sd=float(hwv.std()))
res['avalanche']=av;print(av,flush=True)
# singletons
sch0=N.Schedule(SEED,DEMO_NONCE);TS=(sch0.rounds[0]['S'],sch0.rounds[0]['S2'])
uu=np.repeat(np.arange(256),256);vv=np.tile(np.arange(256),256)
def b0_singletons(S,S2):
 S=np.array(S);S2=np.array(S2);a=latin(uu,vv,S,S2);c=[0,0]
 for d in range(1,256):
  for col,(u2,v2) in enumerate(((uu^d,vv),(uu,vv^d))):
   b=latin(u2,v2,S,S2);c[col]+=int((((a[0]!=b[0]).astype(int)+(a[1]!=b[1]))==1).sum())
 return c
b0=dict(demo_round0_test_tables=b0_singletons(*TS),hello_schedule_all_16_rounds=[b0_singletons(k['S'],k['S2']) for k in SCH.rounds],cases_per_table=2*255*65536)
# bow + restack: replicate the test's 512-staff scan (random.Random(4419) stream)
rr4=random.Random(4419)
for _ in range(20000):rr4.randrange(256);rr4.randrange(256);rr4.randrange(1,256)
staffs=[[v]*8 for v in range(256)]+[[rr4.randrange(256) for _ in range(8)] for _ in range(20000)]
single=0;cases=0;wits=[]
for s in staffs[:512]:
 a=N.odd_restack(N.bow_pressure(s),*TS)
 for t in (1,3,5,7):
  for d in range(1,256):
   h=s[:];h[t]^=d;b=N.odd_restack(N.bow_pressure(h),*TS);w=sum(x!=y for x,y in zip(a,b));cases+=1
   if w==1:single+=1;wits.append(dict(staff=s,beat=t,delta=d,changed_output_beats=[i for i in range(8) if a[i]!=b[i]]))
res['singletons']=dict(b0_latin=b0,b0_all_zero=all(x==[0,0] for x in [b0['demo_round0_test_tables']]+b0['hello_schedule_all_16_rounds']),
 bow_restack=dict(cases=cases,singletons=single,witnesses=wits,tables='demo-nonce schedule round 0 (same as the test suite)'))
print(res['singletons']['b0_all_zero'],single,cases,flush=True)
res['finished']=now();save('attack_regression',res)
