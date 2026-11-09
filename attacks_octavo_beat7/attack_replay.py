"""Quick replay of the key Octavo (sneak_n2) beat-7-era witnesses. Read-only; prints PASS/FAIL per check."""
import time;T0=time.time()
from common import *
import types
verify_live();ok=[]
def check(name,cond,info=''):
 ok.append(bool(cond));print(('PASS ' if cond else 'FAIL ')+name+(' | '+str(info) if info!='' else ''),flush=True)
rng=np.random.default_rng(1)
check('live target sha256',LIVE_SHA=='aa975c951dce9200f6dc2812b59bde90b47b7bd28f13acef6bbbbd65da2aab6d',LIVE_SHA[:16])
check('recorded hello-world decrypts',N.decrypt(HB,SEED)==b'hello world',PICKUP.hex())
outs=set()
for i in list(range(0,1560,37)):
 b=bytearray(HB);b[i//8]^=1<<(i%8)
 try:N.decrypt(bytes(b),SEED);outs.add('ACCEPTED')
 except N.AuthError as e:outs.add(str(e))
check('43 sampled single-bit flips rejected (AuthError only)',outs<= {'tag mismatch','bad version prefix'},outs)
try:N.decrypt(PREV_BLOB,SEED);r='accepted'
except N.AuthError as e:r=str(e)
check('pre-beat-7 sample (pickup 76908595...) -> tag mismatch',r=='tag mismatch')
# test-protocol singleton replica
rr4=random.Random(4419)
for _ in range(20000):rr4.randrange(256),rr4.randrange(256),rr4.randrange(1,256)
bases=np.array([[v]*8 for v in range(256)]+[[rr4.randrange(256) for _ in range(8)] for _ in range(256)])
TS=N.Schedule(SEED,DEMO_NONCE).rounds[0];S,S2=np.array(TS['S']),np.array(TS['S2'])
a=bow_staff(bases);ar=rehair_staff(a,S,S2);b1=b2=0
for t in (1,3,5,7):
 for d in range(1,256):
  H=bases.copy();H[:,t]^=d;b=bow_staff(H);b1+=int(((a!=b).sum(1)==1).sum());b2+=int(((ar!=rehair_staff(b,S,S2)).sum(1)==1).sum())
check('test protocol: bow-alone singletons 1083/522,240, bow+rehair 0',(b1,b2)==(1083,0),(b1,b2))
# NEW: beat-6 bow+rehair singleton witnesses (table-independent)
W=[([90,8,17,194,106,100,92,5],6,28),([61,184,68,8,147,13,127,98],6,14),([121,234,152,46,28,121,240,211],6,18)]
ws=[[sum(x!=y for x,y in zip(N.odd_restack(N.bow_pressure(s),k['S'],k['S2']),N.odd_restack(N.bow_pressure([c^(d if i==t else 0) for i,c in enumerate(s)]),k['S'],k['S2']))) for k in SCH.rounds] for s,t,d in W]
check('NEW: 3 beat-6 inputs leave exactly 1 changed byte after bow+rehair under all 16 round tables',all(w==[1]*16 for w in ws))
s,t,d=W[0];h=s[:];h[t]^=d;db=[x^y for x,y in zip(N.bow_pressure(s),N.bow_pressure(h))]
check('NEW: mechanism: bow delta (..,36,18) sits in pair (6,7) with du = 2*dv in GF(2^8)/0x1F5',db==[0,0,0,0,0,0,36,18] and N.gf_mul(2,18)==36,db)
# proposed fix (lab only): (4,5,6)->(4,5,0) removes them
PROP=((0,1,2),(2,3,4),(4,5,0),(6,7,0),(1,2,3),(3,4,5),(5,6,0))
Wn=np.array([w[0] for w in W]);pw=[]
for (s,t,d) in W:
 x=np.array([s]);y=x.copy();y[0,t]^=d;pw.append(int((rehair_staff(bow_staff(x,PROP),S,S2)!=rehair_staff(bow_staff(y,PROP),S,S2)).sum()))
B=rng.integers(0,256,(2048,8));ap=bow_staff(B,PROP);hits=0
for t in range(8):
 for d in range(1,256):
  H=B.copy();H[:,t]^=d;z=ap^bow_staff(H,PROP);act=z!=0;w=act.sum(1)
  for i in (0,2,4,6):hits+=int(((w==2)&act[:,i]&act[:,i+1]&((z[:,i]==z[:,i+1])|(z[:,i]==GF[2,z[:,i+1]]))).sum())
check('proposed (4,5,0) layout (lab copy): witnesses now >=2 bytes, 0 kernel hits in 4.18M quick cases (full run: 0/133.7M)',min(pw)>=2 and hits==0,(pw,hits))
# NEW: beat-7 bow-alone differential 2^-4.8 (live) vs about 2^-8 (old layout)
X=rng.integers(0,256,(1<<14,8));tgt=np.array([0,0,0,0,0,128,34,136])
def p(st):
 H=X.copy();H[:,7]^=8;return float(np.all((bow_staff(X,st)^bow_staff(H,st))==tgt,axis=1).mean())
pn,po=p(N.BOW_STROKES),p(OLD_STROKES)
check('NEW: bow beat7^0x08 -> (0,0,0,0,0,80,22,88) prob ~2^-4.9 live vs far lower old',pn>2**-5.5 and po<2**-7,(round(math.log2(pn),2),round(math.log2(po),2) if po else '-inf'))
X=rng.integers(0,256,(1<<12,8))
check('NEW: strokes (6,7,0) and (5,6,0) always share (r1,r2) (beat 0 never written after stroke 1)',all(i!=0 and j!=0 for i,j,_ in N.BOW_STROKES[1:]))
# integral: beat 7 all 256 values -> beats 5,6,7 bow outputs XOR-sum to 0 (live), not in old layout
def zs(st,base):
 Xa=np.repeat(np.array([base]),256,0);Xa[:,7]=np.arange(256);return int((np.bitwise_xor.reduce(bow_staff(Xa,st),axis=0)[5:8]==0).sum())
bb=rng.integers(0,256,(64,8)).tolist();zn=sum(zs(N.BOW_STROKES,b)==3 for b in bb);zo=sum(zs(OLD_STROKES,b)==3 for b in bb)
check('NEW: bow-local integral: beat-7 256-set gives zero sums on beats 5-7 for 64/64 bases (live) vs few (old)',zn==64 and zo<32,(zn,zo))
# known biases still present
X=rng.integers(0,256,(1<<20,8));Y=bow_staff(X);c=float(1-2*(((X[:,6]&1)^((Y[:,7]>>4)&1)).mean()))
check('bow cell6.bit0 -> cell7.bit4 corr ~0.039 (unchanged)',0.033<c<0.045,round(c,4))
Z=rng.integers(0,256,(5000,128));Tz=trips(Z).reshape(-1,16,8)&1;Zs=Z.reshape(-1,16,8)&1
L=np.zeros((8,8),int)
for j in range(8):
 e=np.zeros((1,128),np.int64);e[0,j]=1;L[:,j]=trips(e).reshape(16,8)[0]&1
check('triplet bit 0 is exactly GF(2)-linear',np.all((Zs@L.T)%2==Tz))
# key-signature blind spot (in-process): same source text, foreign globals
live_sig=N.key_signature(SEED);orig=N.bow_stroke;evil=dict(vars(N));evil['BOW_ROT_MOD']=5
N.bow_stroke=types.FunctionType(orig.__code__,evil,'bow_stroke')
try:
 sig=N.key_signature(SEED);beh=flat(N.encrypt_grid(N.bytes_to_grid(N.encode_block(b'hello world')),SCH))!=CT
finally:N.bow_stroke=orig
check('NEW: key_signature blind spot: bow_stroke rebuilt with foreign globals changes behaviour, signature unchanged',sig==live_sig and beh and N.key_signature(SEED)==live_sig)
idm=N.staff_mix;N.staff_mix=lambda g,sigma:[r[:] for r in g]
try:sig2=N.key_signature(SEED)
finally:N.staff_mix=idm
check('prior identity staff_mix demo now changes key_sig (closed)',sig2!=live_sig)
el=time.time()-T0
print(f'{sum(ok)}/{len(ok)} PASS in {el:.1f} s');print('REPLAY','PASS' if all(ok) else 'FAIL')
