"""Fast replay (~1 min) of the concrete witnesses in REPORT.md. Read-only; does not alter the cipher.
Run: python3 /workspace/sneak_n2/attacks_linear_algebraic/attack_replay.py"""
from common import *
verify_live()
t0=time.time()
# integrity
assert N.decrypt(HB,SEED)==b'hello world' and PICKUP.hex()=='76908595dcdc8f11ff9e045ac25c080c'
try:N.decrypt(PREV_BLOB,SEED);raise SystemExit('previous sample accepted')
except N.AuthError as e:assert str(e)=='tag mismatch' and PREV_BLOB[3:19].hex()=='24d554eb3d22f0b6412d7da59e504df1'
for i in (0,30,300,1300,1559):
 b=bytearray(HB);b[i//8]^=1<<(i%8)
 try:N.decrypt(bytes(b),SEED);raise SystemExit('flip accepted')
 except N.AuthError:pass
# S-box algebra: LAT max 32/256 (corr 2^-3), degree 7, 23 bi-affine / 39 quadratic equations
PAR=np.array([bin(i).count('1')&1 for i in range(256)])
def lat(S):S=np.array(list(S));A=np.arange(256);return (1-2*PAR[np.bitwise_and.outer(A,A)])@(1-2*PAR[np.bitwise_and.outer(S,A)])
for k in (SCH.rounds[0],SCH.rounds[15]):
 for t in ('S','S2'):assert np.abs(lat(k[t])[1:,1:]).max()==32
import attack_algebraic_lib as AL
assert AL.quad_counts(SCH.rounds[0]['S'])==dict(bi_affine=23,full_quadratic=39,monomials_bi_affine=81,monomials_full=137)
assert AL.degrees(SCH.rounds[0]['S'])[:2]==(7,7)
# triplet LSB plane is exactly GF(2)-linear: out bit0 of cell 0 = in bit0 of cells 0^1^2
rng=np.random.default_rng(1);X=rng.integers(0,256,(5000,128));Y=trips(X)
assert np.all((Y[:,0]&1)==((X[:,0]^X[:,1]^X[:,2])&1))
# cross layer branch number 6 (differential and linear) witnesses, beat 0
g=[[0]*8 for _ in range(16)];g[0][0]=1;g[1][0]=250
assert [r[0] for r in N.cross_staff_mix(g)]==[251,0,0,0]*4                       # 2 -> 4 staffs (diff weight 6)
CX=np.array([[0]*16]*16)
for j in range(16):
 g=[[0]*8 for _ in range(16)];g[j][0]=1;CX[:,j]=[r[0] for r in N.cross_staff_mix(g)]
def gfmv(M,x):
 out=[0]*16
 for i in range(16):
  for j in range(16):out[i]^=N.gf_mul(int(M[i][j]),x[j])
 return out
beta=[1,0,0,0,1]+[0]*11;alpha=gfmv(CX.T,beta)
assert [i for i,v in enumerate(alpha) if v]==[4,5,12,13] and all(alpha[i]==3 for i in (4,5,12,13))   # linear mask 2 -> 4 (weight 6)
# exact check of that linear mask relation on the real cross layer: Tr(beta.out)=Tr(alpha.in)
def tr(x):
 t=x;s=x
 for _ in range(7):t=N.gf_mul(t,t);s^=t
 return s&1
rr=random.Random(5)
for _ in range(200):
 x=[rr.randrange(256) for _ in range(16)];g=[[x[f]]+[0]*7 for f in range(16)];y=[r[0] for r in N.cross_staff_mix(g)]
 assert (sum(tr(N.gf_mul(b,v)) for b,v in zip(beta,y))&1)==(sum(tr(N.gf_mul(a,v)) for a,v in zip(alpha,x))&1)
# Latin pair: one-output approximation corr exactly LAT_S/256 = 2^-3 at the best mask
S,S2=SCH.rounds[0]['S'],SCH.rounds[0]['S2'];L=lat(S);a1,b1=np.unravel_index(np.argmax(np.abs(L[1:,1:])),(255,255));a1+=1;b1+=1
uu=np.repeat(np.arange(256),256);vv=np.tile(np.arange(256),256);o1,_=latin(uu,vv,np.array(S),np.array(S2))
c=np.mean(1-2*(PAR[(uu^vv)&a1]^PAR[o1&b1]));assert abs(c)==0.125
# bow local relation: in cell 6 bit 0 -> out cell 7 bit 4, corr ~0.04 (2^-4.6), noise 2^-9 at 2^18 samples
X=rng.integers(0,256,(1<<18,128));Yb=bow(X);cb=np.mean(1-2*((X[:,6]&1)^((Yb[:,7]>>4)&1)));assert 0.03<cb<0.05,cb
# integral: one active cell -> all 128 XOR sums zero before triplets, ~random after 1 round
B=Batch(SCH);X=np.repeat(rng.integers(0,256,128)[None,:],256,0);X[:,5]=np.arange(256)
pre=bars(B.linear(B.S[0][X^B.rk[0]],0),B.S[0],B.S2[0]);assert (np.bitwise_xor.reduce(pre,axis=0)==0).all()
z1=int((np.bitwise_xor.reduce(B.enc(X,1),axis=0)==0).sum());assert z1<=4,z1
# B0 / Latin singletons 0; bow+restack 5 beat-7 singletons (demo schedule round 0 tables, as in the tests)
sch0=N.Schedule(SEED,DEMO_NONCE);TS=(sch0.rounds[0]['S'],sch0.rounds[0]['S2'])
for s,t,d,ch in [([26]*8,7,36,[7]),([53]*8,7,225,[7]),([117]*8,7,78,[6]),([142,151,20,118,251,3,37,161],7,39,[6]),([91,12,141,148,97,40,0,144],7,177,[6])]:
 a=N.odd_restack(N.bow_pressure(s),*TS);h=s[:];h[t]^=d;b=N.odd_restack(N.bow_pressure(h),*TS);assert [i for i in range(8) if a[i]!=b[i]]==ch
for d in (1,0x80,0xff):
 for u,v in ((0,0),(17,200)):
  p=N.b0_apply(u,v,*TS);assert all(x!=y for x,y in zip(p,N.b0_apply(u^d,v,*TS))) and all(x!=y for x,y in zip(p,N.b0_apply(u,v^d,*TS)))
# related nonce: one-bit nonce flip -> unrelated round keys
n1=bytearray(NONCE);n1[0]^=1;s1=N.Schedule(SEED,bytes(n1))
hd=sum((x^y).bit_count() for x,y in zip(flat(SCH.rounds[0]['rk']),flat(s1.rounds[0]['rk'])));assert 440<hd<584,hd
assert SCH.rounds[0]['S']!=s1.rounds[0]['S']
print('PASS: hello decrypts; previous 24d554eb fails tag; LAT max 2^-3; degree 7; 23 bi-affine/39 quadratic; triplet LSB linear;',
 'cross branch 6 (diff 2->4, linear mask 2->4); Latin one-output corr 2^-3; bow cell6b0->cell7b4 corr %.4f;'%cb,
 'integral dies inside round 1 (%d zero sums);'%z1,'5 bow+restack beat-7 singletons; B0 spot checks; related-nonce rk HD %d.'%hd,'%.1fs'%(time.time()-t0),'Source:',LIVE_SHA)
