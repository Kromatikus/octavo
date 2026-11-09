"""Algebraic analysis of live N2: S-box ANF degree, quadratic equation counts, cube / higher-order differential
tests over reduced rounds, integral (square) tests, and an honest system-size estimate (white-box, fixed schedule)."""
from common import *
verify_live()
res={'started':now(),'live_sha':LIVE_SHA}
B=Batch(SCH);res['batch_validated_round_calls']=B.validate()
def moebius(f):  # f: array of 0/1 length 256 -> ANF coefficients
 a=np.array(f,dtype=np.int64).copy();h=1
 while h<256:
  a=a.reshape(-1,2,h);a[:,1,:]^=a[:,0,:];a=a.reshape(256);h*=2
 return a
WT=np.array([bin(i).count('1') for i in range(256)])
def degrees(S):
 S=np.array(list(S));comp=[]
 for b in range(1,256):
  f=np.array([bin(b&y).count('1')&1 for y in S]);an=moebius(f);comp.append(int(WT[an!=0].max()))
 return min(comp),max(comp),[int(WT[moebius((S>>i)&1)!=0].max()) for i in range(8)]
def gf2_rank(rows):
 rows=[int(r) for r in rows];rank=0;piv=[]
 basis=[]
 for r in rows:
  for b in basis:r=min(r,r^b)
  if r:basis.append(r);rank+=1
 return rank
def quad_counts(S):
 S=list(S);x=[[a>>i&1 for i in range(8)] for a in range(256)];y=[[S[a]>>i&1 for i in range(8)] for a in range(256)]
 def count(monos):
  # columns are monomials; rank over the 256 evaluation points; equations = #monos - rank
  cols=[]
  for m in monos:
   v=0
   for a in range(256):
    if m(x[a],y[a]):v|=1<<a
   cols.append(v)
  return len(monos)-gf2_rank(cols)
 lin=[lambda X,Y:1]+[lambda X,Y,i=i:X[i] for i in range(8)]+[lambda X,Y,i=i:Y[i] for i in range(8)]
 bi=[lambda X,Y,i=i,j=j:X[i]&Y[j] for i in range(8) for j in range(8)]
 xx=[lambda X,Y,i=i,j=j:X[i]&X[j] for i in range(8) for j in range(i+1,8)]
 yy=[lambda X,Y,i=i,j=j:Y[i]&Y[j] for i in range(8) for j in range(i+1,8)]
 return dict(bi_affine=count(lin+bi),full_quadratic=count(lin+bi+xx+yy),monomials_bi_affine=len(lin+bi),monomials_full=len(lin+bi+xx+yy))
sb={'SM4_base':dict(degree_min_max_components=degrees(N.SM4_SBOX)[:2],**quad_counts(N.SM4_SBOX))}
rows=[]
for r,k in enumerate(SCH.rounds):
 for t in ('S','S2','SI'):
  dmin,dmax,bitdeg=degrees(k[t]);q=quad_counts(k[t]) if t!='SI' else {}
  rows.append(dict(round=r,table=t,component_degree_min=dmin,component_degree_max=dmax,bit_degrees=bitdeg,**q))
sb['keyed_tables']=rows
sb['all_degree_7']=all(x['component_degree_min']==7==x['component_degree_max'] for x in rows)
sb['quadratic_counts_set']=sorted({(x.get('bi_affine'),x.get('full_quadratic')) for x in rows if 'bi_affine' in x})
res['sbox_algebra']=sb;print('sbox algebra',sb['SM4_base'],sb['all_degree_7'],sb['quadratic_counts_set'],flush=True)
# ---------------- reduced-round functions (fixed schedule, white-box)
def P_lin(x):      # round-1 key add, S, weave, butterfly, shell (positive control: degree 7 per cell)
 x=B.S[0][np.asarray(x)^B.rk[0]];return B.linear(x,0)
def P_prebar(x):   # + field bars only (no B0? B0 is Latin -> keep live bars), before triplets
 return bars(P_lin(x),B.S[0],B.S2[0])
def R(n):return lambda x:B.enc(np.asarray(x),n)
FUN={'S+weave+butterfly+shell':P_lin,'..+bars (before triplets)':P_prebar,'1 round':R(1),'2 rounds':R(2),'3 rounds':R(3)}
def tobits(y):return ((y[:,:,None]>>np.arange(8))&1).reshape(y.shape[0],-1)
def cube_sum(fn,positions,base):
 """positions: list of (cell,bit); returns XOR over the cube of fn outputs (128 bytes)."""
 d=len(positions);idx=np.arange(1<<d);X=np.repeat(base[None,:],1<<d,0).copy()
 for t,(c,b) in enumerate(positions):
  X[:,c]&=~(1<<b)&255;X[:,c]|=((idx>>t)&1)<<b
 acc=np.zeros(128,np.int64)
 for s in range(0,1<<d,16384):acc^=np.bitwise_xor.reduce(fn(X[s:s+16384]),axis=0)
 return acc
CUBES={f'cell0 bits0..{d-1} (d={d})':[(0,b) for b in range(d)] for d in (1,2,4,6,7,8)}
CUBES.update({'bit0 of cells 0,9,18,27 (d=4)':[(c,0) for c in (0,9,18,27)],
 'bit0 of 8 cells across staffs (d=8)':[(c*17%128,0) for c in range(8)],
 'cells 0,1 all bits (d=16)':[(c,b) for c in (0,1) for b in range(8)],
 'bit7 of 12 cells (d=12)':[(c*11%128,7) for c in range(12)],
 'cells 0 and 64 all bits (d=16, across shells)':[(c,b) for c in (0,64) for b in range(8)]})
T=8;rng=np.random.default_rng(7);bases=rng.integers(0,256,(T,128))
cube=[];t0=time.time()
plan=[(f,c) for f in FUN for c in CUBES if not (f in ('2 rounds','3 rounds') and len(CUBES[c])>=16 and f=='3 rounds')]
for fname,cname in plan:
 pos=CUBES[cname];d=len(pos)
 if fname=='3 rounds' and d>8:continue
 sums=np.array([cube_sum(FUN[fname],pos,b) for b in bases]);sb_=tobits(sums)
 zero_all=int((sb_==0).all(0).sum());const=int((sb_==sb_[0]).all(0).sum())
 cube.append(dict(function=fname,cube=cname,dim=d,bases=T,output_bits_zero_on_all_bases=zero_all,output_bits_constant_superpoly=const,
  random_expect_zero=1024/2**T,random_expect_const=1024/2**(T-1),zero_bytes_any_base=int((sums==0).sum())))
 print(cube[-1],round(time.time()-t0),flush=True)
res['cube_tests']=cube
# ---------------- integral / square
def integral(fn,cells_fn,base,nvals=256):
 X=np.repeat(base[None,:],nvals,0).copy();v=np.arange(nvals)
 for c,f in cells_fn:X[:,c]=f(v)
 Y=np.concatenate([fn(X[s:s+16384]) for s in range(0,nvals,16384)])
 xs=np.bitwise_xor.reduce(Y,axis=0);bal=sum(len(np.unique(Y[:,j]))==min(256,nvals) and nvals==256 for j in range(128))
 return int((xs==0).sum()),int(bal),xs
integ=[];t0=time.time()
for fname in FUN:
 zs=[];bs=[];ncase=0
 for c in range(128):
  for b in range(2):
   base=rng.integers(0,256,128);z,bal,_=integral(FUN[fname],[(c,lambda v:v)],base);zs.append(z);bs.append(bal);ncase+=1
 integ.append(dict(function=fname,kind='one cell takes all 256 values (every cell, 2 bases)',cases=ncase,
  mean_zero_sum_output_cells=float(np.mean(zs)),max_zero_sum_output_cells=int(max(zs)),cases_with_all128_zero_sum=int(sum(z==128 for z in zs)),
  mean_balanced_output_cells=float(np.mean(bs)),random_expect_zero_sum=0.5,random_expect_balanced=0.0))
 print(integ[-1],round(time.time()-t0),flush=True)
 # staff integrals: staff f gets x on all 8 beats (diagonal) or x+37j (shifted)
 for kind,mk in (('staff diagonal: 8 cells = x',lambda f:[(f*8+j,lambda v:v) for j in range(8)]),
                 ('staff shifted: cell j = x+37j mod 256',lambda f:[(f*8+j,lambda v,j=j:(v+37*j)&255) for j in range(8)])):
  zs=[];bs=[]
  for f in range(16):
   base=rng.integers(0,256,128);z,bal,_=integral(FUN[fname],mk(f),base);zs.append(z);bs.append(bal)
  integ.append(dict(function=fname,kind=kind,cases=16,mean_zero_sum_output_cells=float(np.mean(zs)),max_zero_sum_output_cells=int(max(zs)),
   cases_with_all128_zero_sum=int(sum(z==128 for z in zs)),mean_balanced_output_cells=float(np.mean(bs))))
# 16-bit integrals (two cells take all 65536 values) at 1 and 2 rounds
for fname in ('1 round','2 rounds'):
 for (c1,c2) in ((0,1),(0,64),(7,120),(3,4)):
  base=rng.integers(0,256,128);v=np.arange(65536)
  z,_,xs=integral(FUN[fname],[(c1,lambda v:v&255),(c2,lambda v:v>>8)],base,65536)
  integ.append(dict(function=fname,kind=f'two cells ({c1},{c2}) take all 65536 values',zero_sum_output_cells=z,random_expect=0.5,zero_sum_output_bits=int((tobits(xs[None,:])==0).sum()),random_expect_bits=512))
  print(integ[-1],flush=True)
res['integral']=integ
# ---------------- system size estimate
SB_PER_ROUND=128+128+2*16*2+2*16*4*2
def adds_triplet():
 n=0
 for _,_,M in N.TRIPLETS:
  for row in M:n+=sum(bin(a).count('1') for a in row)-1
 return n
ta=adds_triplet()*16*2;ba=len(N.BOW_STROKES)*16*2
q=sb['quadratic_counts_set'][0][1] if sb['quadratic_counts_set'] else None
key_bits_round=1024+2*(64+64+16)+16*3+8*4+16*math.log2(math.factorial(8))+math.log2(math.factorial(64))
res['system_size']=dict(sboxes_per_round=SB_PER_ROUND,sboxes_16_rounds=16*SB_PER_ROUND,
 quadratic_eqs_per_sbox=q,sbox_equations_16_rounds=16*SB_PER_ROUND*q,sbox_state_vars_16_rounds=16*SB_PER_ROUND*8,
 mod256_additions_per_round_triplets=ta,mod256_additions_per_round_bow=ba,
 carry_vars_16_rounds=16*(ta+ba)*7,carry_quadratic_eqs_16_rounds=16*(ta+ba)*7*2,
 bow_rotation_selectors='each bow stroke picks r1=1+p%7 and r2=1+(p>>3)%7 from the data byte p: p%7 is a high-degree Boolean function of 8 bits, so each stroke needs a 7-way multiplexer (~14 selector vars + their defining equations) or degree-8 relations',
 bow_strokes_16_rounds=16*ba,
 unknown_key_material_bits_per_round_approx=round(key_bits_round),unknown_key_bits_16_rounds_plus_white_approx=round(16*key_bits_round+1024),
 known_equations_from_one_block=1024,
 note=('Rough count, not an optimised encoding. Keyed S-boxes are A2*S_SM4(A1*x+b1)+b2 with unknown A1,A2,b1,b2: treating the table as known is impossible without the schedule, '
  'and treating A1,A2 as unknowns raises the degree (products of matrix entries and state bits). The schedule is SHA-256(seed||nonce) output, so algebra cannot reach the seed; '
  'and because every message gets a fresh schedule, one block (1024 output bits) faces ~%d unknown schedule bits: the per-schedule system is hugely underdetermined, so round-key-level algebraic key recovery has no unique solution. Algebraic distinguishers would need many blocks under one schedule (white-box lab model only).')%round(16*key_bits_round+1024))
res['finished']=now();save('attack_algebraic',res)
