"""Algebraic: ANF degree of all tables, quadratic equation counts, integral/cube by sub-layer and by round (live vs previous bow),
conditional cubes on the bow (beat 0 frozen => fixed rotations in the last two strokes), additive integral."""
from common import *
verify_live();t0=time.time()
res={'started':now(),'live_sha':LIVE_SHA}
B=Batch(SCH);B.validate();rng=np.random.default_rng(99)
def anf_deg(T):
 T=np.asarray(T);deg=0;wt=np.array([bin(i).count('1') for i in range(256)])
 for b in range(1,256):
  f=np.array([bin(b&v).count('1')&1 for v in T],dtype=np.uint8)
  h=1
  while h<256:
   f=f.reshape(-1,2*h);f[:,h:]^=f[:,:h];f=f.reshape(-1);h*=2
  deg=max(deg,int(wt[f==1].max()))
 return deg
degs=[]
for k in SCH.rounds:degs+= [anf_deg(k['S']),anf_deg(k['S2']),anf_deg(k['SI']),anf_deg(k['SI2'])]
res['anf_degree']=dict(tables=len(degs),degrees=sorted(set(degs)))
def quad_count(T,biaffine):
 xs=[[(x>>i)&1 for i in range(8)] for x in range(256)];ys=[[(T[x]>>i)&1 for i in range(8)] for x in range(256)]
 cols=[]
 for x in range(256):
  v=xs[x]+ys[x];row=[1]+v
  if biaffine:row+=[xs[x][i]&ys[x][j] for i in range(8) for j in range(8)]
  else:row+=[v[i]&v[j] for i in range(16) for j in range(i+1,16)]
  cols.append(row)
 M=np.array(cols,dtype=np.uint8)  # 256 x m ; equations = nullspace dim of M (columns)
 A=M.copy();r=0;m=A.shape[1]
 for c in range(m):
  p=np.nonzero(A[r:,c])[0]
  if len(p)==0:continue
  p=p[0]+r;A[[r,p]]=A[[p,r]];nz=np.nonzero(A[:,c])[0];nz=nz[nz!=r];A[nz]^=A[r];r+=1
  if r==A.shape[0]:break
 return m-r,m
res['quadratic_equations']={'sm4_base_biaffine':quad_count(list(N.SM4_SBOX),True),'sm4_base_full_quadratic':quad_count(list(N.SM4_SBOX),False),
 'round0_S_biaffine':quad_count(SCH.rounds[0]['S'],True),'round0_S_full_quadratic':quad_count(SCH.rounds[0]['S'],False)}
print(res['anf_degree'],res['quadratic_equations'],flush=True)
# integral by sub-layer of round 0: one cell takes all 256 values (others random constant); count balanced (bijective) and zero-XOR-sum cells
def sub(x,strokes):
 S,S2=B.S[0],B.S2[0];o={}
 x=B.S[0][x^B.rk[0]];x=B.linear(x,0);o['linear']=x;x=bars(x,S,S2);o['bars']=x;x=trips(x);o['trips']=x;x=bow(x,strokes);o['bow']=x
 x=rehair(x,S,S2);o['rehair']=x;x=cross(x);o['cross']=x;x=S2[x];x=bars(x,S,S2);o['bars2']=x;x=trips(x);o['trips2']=x;x=bow(x,strokes);o['bow2']=x;x=rehair(x,S,S2);o['rehair2']=x;x=cross(x);o['round1']=x
 return o
integ={}
for lab,st in (('new',N.BOW_STROKES),('old',OLD_STROKES)):
 acc={}
 for c in range(128):
  for rep in range(2):
   X=np.repeat(rng.integers(0,256,(1,128)),256,0);X[:,c]=np.arange(256);o=sub(X,st)
   for k,v in o.items():
    bal=sum(len(np.unique(v[:,j]))==256 for j in range(128));zs=int((np.bitwise_xor.reduce(v,axis=0)==0).sum())
    a=acc.setdefault(k,[0,0,0]);a[0]+=bal;a[1]+=zs;a[2]+=1
 integ[lab]={k:dict(mean_balanced_cells=round(a[0]/a[2],2),mean_zero_sum_cells=round(a[1]/a[2],2)) for k,a in acc.items()}
 print('integral',lab,integ[lab],flush=True)
res['integral_sublayers_round0']=dict(sets='128 cells x 2 bases, 256 texts each',random_zero_sum=0.5,layouts=integ)
# integral by full rounds: 1-cell and 2-cell sets
def zsum(R,cells,nb):
 out=[]
 for _ in range(nb):
  base=rng.integers(0,256,(1,128));
  if len(cells)==1:X=np.repeat(base,256,0);X[:,cells[0]]=np.arange(256)
  else:X=np.repeat(base,65536,0);X[:,cells[0]]=np.repeat(np.arange(256),256);X[:,cells[1]]=np.tile(np.arange(256),256)
  acc=np.zeros(128,dtype=np.int64)
  for s in range(0,len(X),16384):acc^=np.bitwise_xor.reduce(B.enc(X[s:s+16384],R),axis=0)
  out.append(int((acc==0).sum()))
 return out
res['integral_rounds']=dict(one_cell={R:zsum(R,[int(rng.integers(128))],16) for R in (1,2,3)},two_cells={R:zsum(R,[3,77],3) for R in (1,2)},random_expect_zero_sum_cells=0.5)
print('integral rounds',res['integral_rounds'],flush=True)
# cube sums by rounds: d-dimensional cubes of random bits; count output bits that sum to zero for all 4 bases (random expect 1024/16=64)
def cube(R,d,nb=4,trials=4):
 res_=[]
 for _ in range(trials):
  bitsidx=rng.choice(1024,d,replace=False);zero=np.ones(1024,bool)
  for _ in range(nb):
   base=rng.integers(0,256,(1,128));idx=np.arange(1<<d);X=np.repeat(base,1<<d,0)
   for k,b in enumerate(bitsidx):X[:,b//8]^=((idx>>k)&1)<<(b%8)
   acc=np.zeros(128,dtype=np.int64)
   for s in range(0,len(X),16384):acc^=np.bitwise_xor.reduce(B.enc(X[s:s+16384],R),axis=0)
   zero&=np.unpackbits(acc.astype(np.uint8),bitorder='little')==0
  res_.append(int(zero.sum()))
 return res_
res['cube_rounds']={f'R{R}_d{d}':cube(R,d) for R in (1,2) for d in (4,8,12,16)}
res['cube_rounds_note']='always-zero bits over 4 bases; random expectation 1024/16 = 64'
print('cubes',res['cube_rounds'],flush=True)
# conditional cubes on the bow ALONE: degree estimate of each output bit as the smallest d where all random cubes sum to 0
def bow_cube(strokes,cells,d,trials=64):
 zeros=0;tot=0
 for _ in range(trials):
  pos=rng.choice([c*8+b for c in cells for b in range(8)],d,replace=False);base=rng.integers(0,256,(1,8));idx=np.arange(1<<d)
  X=np.repeat(base,1<<d,0)
  for k,b in enumerate(pos):X[:,b//8]^=((idx>>k)&1)<<(b%8)
  acc=np.bitwise_xor.reduce(bow_staff(X,strokes),axis=0);zeros+=int((np.unpackbits(acc.astype(np.uint8),bitorder='little')==0).sum());tot+=64
 return round(zeros/tot,3)
bc={}
for lab,st in (('new',N.BOW_STROKES),('old',OLD_STROKES)):
 bc[lab]={f'cells{cs}_d{d}':bow_cube(st,cs,d) for cs in ((5,6,7),(6,7),(0,1,2,3,4,5,6,7)) for d in (2,4,6,8,10,12)}
 print('bowcube',lab,bc[lab],flush=True)
res['bow_conditional_cubes']=dict(metric='fraction of output bits with zero cube sum (random 0.5)',layouts=bc,
 note='Cubes on beats 5-7 leave beat 0 constant, so in the NEW layout the last two strokes use fixed rotations; compare with the old layout where (5,6,7) read beat 7.')
# additive (mod 256) integral through the round: one cell all 256 values, ADD-sum of outputs
add=[]
for R in (1,2):
 cnt=0;tot=0
 for c in range(0,128,4):
  X=np.repeat(rng.integers(0,256,(1,128)),256,0);X[:,c]=np.arange(256);Y=B.enc(X,R);s=Y.sum(0)&255;cnt+=int((s==0).sum());tot+=128
 add.append(dict(rounds=R,zero_add_sum_frac=round(cnt/tot,4),random=round(1/256,4)))
res['additive_integral']=add
res['system_size_16_rounds']=dict(sboxes_per_round=6*128,note='per round: S(128)+bars B0(32 S-box lookups per pass x2)+rehair(128 per pass x2)+S2(128) = 128+64+256+128 = 576 S-box evaluations; x16 = 9216; with 39 quadratic equations each ~359k equations over ~74k state bits plus ARX carries; unchanged by the beat-7 constant')
print('add',add,flush=True)
res['seconds']=round(time.time()-t0,1);res['finished']=now();save('attack_algebraic',res)
