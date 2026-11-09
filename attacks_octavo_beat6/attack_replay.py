"""Quick replay of the key Octavo (sneak_n2) beat-6-fix-era witnesses. Read-only; pinned to SHA 922a29d8...; prints PASS/FAIL per check."""
import time;T0=time.time()
from common import *
import types
verify_live();ok=[]
def check(name,cond,info=''):
 ok.append(bool(cond));print(('PASS ' if cond else 'FAIL ')+name+(' | '+str(info) if info!='' else ''),flush=True)
rng=np.random.default_rng(1);LIVE=tuple(N.BOW_STROKES)
check('live target sha256',LIVE_SHA=='922a29d89be68b29a2be08873ff5a99a7cf264afebe1ece0387aa0f4fe56fe10',LIVE_SHA[:16])
check('live BOW_STROKES = (0,1,2),(2,3,4),(4,5,0),(6,7,0),(1,2,3),(3,4,5),(5,6,0)',LIVE==((0,1,2),(2,3,4),(4,5,0),(6,7,0),(1,2,3),(3,4,5),(5,6,0)))
check('recorded hello-world (pickup d450337d...) decrypts',N.decrypt(HB,SEED)==b'hello world' and PICKUP.hex().startswith('d450337d'),PICKUP.hex()[:8])
outs=set()
for i in range(0,1560,37):
 b=bytearray(HB);b[i//8]^=1<<(i%8)
 try:N.decrypt(bytes(b),SEED);outs.add('ACCEPTED')
 except N.AuthError as e:outs.add(str(e))
check('43 sampled single-bit flips rejected (AuthError only)',outs<={'tag mismatch','bad version prefix'},outs)
rs=[]
for blob in (PREV_BLOB,PREV7_BLOB):
 try:N.decrypt(blob,SEED);rs.append('accepted')
 except N.AuthError as e:rs.append(str(e))
check('older samples ee95ddb2... (beat-7 era) and 76908595... -> tag mismatch',rs==['tag mismatch']*2 and PREV_BLOB[3:7].hex()=='ee95ddb2',rs)
# test-protocol replica (odd beats)
rr4=random.Random(4419)
for _ in range(20000):rr4.randrange(256),rr4.randrange(256),rr4.randrange(1,256)
bases=np.array([[v]*8 for v in range(256)]+[[rr4.randrange(256) for _ in range(8)] for _ in range(256)])
TS=N.Schedule(SEED,DEMO_NONCE).rounds[0];S,S2=np.array(TS['S']),np.array(TS['S2'])
a=bow_staff(bases);ar=rehair_staff(a,S,S2);b1=b2=0
for t in (1,3,5,7):
 for d in range(1,256):
  H=bases.copy();H[:,t]^=d;b=bow_staff(H);b1+=int(((a!=b).sum(1)==1).sum());b2+=int(((ar!=rehair_staff(b,S,S2)).sum(1)==1).sum())
check('test protocol (odd beats): bow-alone singletons 1148/522,240, bow+rehair 0',(b1,b2)==(1148,0),(b1,b2))
# old beat-6 witnesses now >= 2 bytes under all 16 round tables
W=[([90,8,17,194,106,100,92,5],6,28),([61,184,68,8,147,13,127,98],6,14),([121,234,152,46,28,121,240,211],6,18)]
ws=[min(sum(x!=y for x,y in zip(N.odd_restack(N.bow_pressure(s),k['S'],k['S2']),N.odd_restack(N.bow_pressure([c^(d if i==t else 0) for i,c in enumerate(s)]),k['S'],k['S2']))) for k in SCH.rounds) for s,t,d in W]
check('old beat-6 singleton witnesses now change >=2 bytes under all 16 round tables',min(ws)>=2,ws)
# written arguments, empirically: forced-change bow outputs
B=rng.integers(0,256,(4096,8));a=bow_staff(B);alw={}
for t in (0,4,6):
 m=np.ones(8,bool)
 for d in range(1,256):H=B.copy();H[:,t]^=d;m&=(a!=bow_staff(H)).all(0)
 alw[t]=np.nonzero(m)[0].tolist()
check('NEW: forced changes: beat0 -> bow out {0,1,2} always change; beat4 -> {5,6}; beat6 -> {5,7} (two pairs => no singleton)',alw=={0:[0,1,2],4:[5,6],6:[5,7]},alw)
# kernel scan, all beats, quick (full run: 0 in 1.6 G even-beat cases + 535 M all-beat cases)
hits=0;B=rng.integers(0,256,(2048,8));a=bow_staff(B)
for t in range(8):
 for d in range(1,256):
  H=B.copy();H[:,t]^=d;z=a^bow_staff(H);act=z!=0;w=act.sum(1)
  for i in (0,2,4,6):hits+=int(((w==2)&act[:,i]&act[:,i+1]&((z[:,i]==z[:,i+1])|(z[:,i]==GF[2,z[:,i+1]]))).sum())
check('quick all-beat kernel scan: 0 bow+rehair singletons in 4.18 M cases',hits==0,hits)
check('NEW: strokes (4,5,0),(6,7,0),(5,6,0) all read beat 0, which nothing writes after stroke 1',[s for s in LIVE[1:] if s[2]==0]==[(4,5,0),(6,7,0),(5,6,0)] and all(0 not in s[:2] for s in LIVE[1:]))
X=rng.integers(0,256,(1<<14,8))
def p(st,t,d,tgt):H=X.copy();H[:,t]^=d;return float(np.all((bow_staff(X,st)^bow_staff(H,st))==np.array(tgt),axis=1).mean())
pn=p(LIVE,6,128,[0,0,0,0,0,8,0,8]);po=p(OLD_STROKES,6,128,[0,0,0,0,0,8,0,8])
check('NEW: bow-alone beat6^0x80 -> (..,08,00,08) ~2^-5.6 live (previous layout: far lower); different pairs, rehair spreads it',pn>2**-6.2 and po<2**-9,(round(math.log2(pn),2),round(math.log2(po),2) if po else '-inf'))
def zr(st,t,cells,base):
 Xa=np.repeat(np.array([base]),256,0);Xa[:,t]=np.arange(256);return all(np.bitwise_xor.reduce(rehair_staff(bow_staff(Xa,st),S,S2),axis=0)[list(cells)]==0)
bb=rng.integers(0,256,(32,8)).tolist();zn=sum(zr(LIVE,6,(4,5),b) for b in bb);zo=sum(zr(OLD_STROKES,6,(4,5),b) for b in bb)
check('NEW: half-round-local integral: beat-6 256-set gives zero sums on rehair out (4,5) in 32/32 bases live (previous few)',zn==32 and zo<8,(zn,zo))
X=rng.integers(0,256,(1<<20,8));Y=bow_staff(X)
c2=float(1-2*((((X[:,0]&1)^((X[:,1]>>7)&1))^(Y[:,0]&1)).mean()));c1=float(1-2*(((X[:,6]&1)^((Y[:,7]>>4)&1)).mean()))
check('bow linear: |corr| (c0.b0^c1.b7)->c0.b0 ~0.145 (reported as -0.145 in the +-1 bit convention) and c6.b0->c7.b4 ~0.039 (unchanged by the layout)',0.138<abs(c2)<0.152 and 0.033<c1<0.045,(round(c2,4),round(c1,4)))
Z=rng.integers(0,256,(5000,128));Tz=trips(Z).reshape(-1,16,8)&1;Zs=Z.reshape(-1,16,8)&1;L=np.zeros((8,8),int)
for j in range(8):e=np.zeros((1,128),np.int64);e[0,j]=1;L[:,j]=trips(e).reshape(16,8)[0]&1
check('triplet bit 0 is exactly GF(2)-linear',np.all((Zs@L.T)%2==Tz))
live_sig=N.key_signature(SEED);orig=N.bow_stroke;evil=dict(vars(N));evil['BOW_ROT_MOD']=5
N.bow_stroke=types.FunctionType(orig.__code__,evil,'bow_stroke')
try:sig=N.key_signature(SEED);beh=flat(N.encrypt_grid(N.bytes_to_grid(N.encode_block(b'hello world')),SCH))!=CT
finally:N.bow_stroke=orig
check('key_signature in-process blind spot still open (foreign-globals bow_stroke: behaviour changes, signature does not)',sig==live_sig and beh and N.key_signature(SEED)==live_sig)
idm=N.staff_mix;N.staff_mix=lambda g,sigma:[r[:] for r in g]
try:sig2=N.key_signature(SEED)
finally:N.staff_mix=idm
check('identity staff_mix demo changes key_sig (still closed)',sig2!=live_sig)
el=time.time()-T0
print(f'{sum(ok)}/{len(ok)} PASS in {el:.1f} s');print('REPLAY','PASS' if all(ok) else 'FAIL')
