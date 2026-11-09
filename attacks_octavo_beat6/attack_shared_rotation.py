"""Focus 2+3: beat-0 shared-rotation structure (strokes (4,5,0),(6,7,0),(5,6,0) read beat 0) and bow linear relations.
Bow-only integrals per beat and per beat pair, through rehair and the cross layer; related-rotation differentials on beat 0;
rotational pairs; 2-bit-input relations and best pair-output masks (Walsh) through bow+rehair."""
from common import *
verify_live();t0=time.time()
rng=np.random.default_rng(7171)
LIVE=tuple(N.BOW_STROKES);LAY={'live':LIVE,'previous_(4,5,6)':OLD_STROKES,'pre_beat7_(5,6,7)':OLD7_STROKES}
k0=SCH.rounds[0];S0=np.array(k0['S']);S20=np.array(k0['S2'])
res={'started':now(),'live_sha':LIVE_SHA,'layouts':LAY}
# 1. single-beat integrals, bow only: beat t takes all 256 values, 128 bases. Constant outputs XOR-sum to 0 trivially,
# so we report: constant fraction, and among NON-constant output beats the zero-sum and balanced (permutation) fractions; same after rehair.
def stats(Y,nset):
 const=(Y==Y[:1]).all(0);zs=np.bitwise_xor.reduce(Y,0)==0
 bal=np.array([np.bincount(Y[:,c],minlength=256).max()==nset//256 for c in range(Y.shape[1])])
 return const,zs&~const,bal&~const
I1={}
for lab,st in LAY.items():
 row={}
 for t in range(8):
  C=np.zeros(8);Z=np.zeros(8);Bl=np.zeros(8);Cr=np.zeros(8);Zr=np.zeros(8)
  for _ in range(128):
   X=np.repeat(rng.integers(0,256,(1,8)),256,0);X[:,t]=np.arange(256);Y=bow_staff(X,st);c,z,b=stats(Y,256);C+=c;Z+=z;Bl+=b
   c,z,_=stats(rehair_staff(Y,S0,S20),256);Cr+=c;Zr+=z
  nc=np.maximum(128-C,1);ncr=np.maximum(128-Cr,1)
  row[t]={'const_frac':(C/128).round(3).tolist(),'nonconst_zero_sum_frac':(Z/nc).round(3).tolist(),'nonconst_balanced_frac':(Bl/nc).round(3).tolist(),
   'rehair_const_frac':(Cr/128).round(3).tolist(),'rehair_nonconst_zero_sum_frac':(Zr/ncr).round(3).tolist()}
 I1[lab]=row
res['integral_single_beat_bow']={'note':'random non-constant cell: zero-sum 1/256 ~0.004, balanced ~0','sets_per_beat':128,**I1}
for lab in LAY:print('I1',lab,{t:I1[lab][t]['nonconst_zero_sum_frac'] for t in range(8)},'| rehair nonconst max',max(max(I1[lab][t]['rehair_nonconst_zero_sum_frac']) for t in range(8)),flush=True)
# 2. two-beat integrals (2^16 texts) with beat 0 constant: pairs among beats 1..7, 8 bases each (non-constant outputs only)
I2={}
g=np.stack(np.meshgrid(np.arange(256),np.arange(256),indexing='ij'),-1).reshape(-1,2)
for lab,st in (('live',LIVE),('previous_(4,5,6)',OLD_STROKES)):
 row={}
 for a in range(1,8):
  for b in range(a+1,8):
   Z=np.zeros(8);Bl=np.zeros(8);C=np.zeros(8);Zr=np.zeros(8);Cr=np.zeros(8)
   for _ in range(8):
    X=np.repeat(rng.integers(0,256,(1,8)),65536,0);X[:,a]=g[:,0];X[:,b]=g[:,1];Y=bow_staff(X,st)
    c,z,bb=stats(Y,65536);C+=c;Z+=z;Bl+=bb;c,z,_=stats(rehair_staff(Y,S0,S20),65536);Cr+=c;Zr+=z
   row[f'{a},{b}']={'bow_nonconst_zero':(Z/np.maximum(8-C,1)).tolist(),'bow_nonconst_balanced':(Bl/np.maximum(8-C,1)).tolist(),'rehair_nonconst_zero':(Zr/np.maximum(8-Cr,1)).tolist()}
 I2[lab]=row
res['integral_two_beats_bow_beat0_const']=I2
res['two_beat_summary']={lab:{'bow_always_zero_nonconst':{p:[o for o in range(8) if v['bow_nonconst_zero'][o]==1.0] for p,v in I2[lab].items() if any(x==1.0 for x in v['bow_nonconst_zero'])},
 'bow_always_balanced_nonconst':{p:[o for o in range(8) if v['bow_nonconst_balanced'][o]==1.0] for p,v in I2[lab].items() if any(x==1.0 for x in v['bow_nonconst_balanced'])},
 'max_rehair_nonconst_zero_frac':max(max(v['rehair_nonconst_zero']) for v in I2[lab].values())} for lab in I2}
print('I2',res['two_beat_summary'],flush=True)
# 3. does any bow integral survive rehair+cross? full 128-cell state, one staff's beat set active, cross layer applied
def thru_cross(st,cells,nb=16):
 out=[]
 for _ in range(nb):
  n=256**len(cells);X=np.repeat(rng.integers(0,256,(1,128)),n,0)
  f=rng.integers(16)
  for q,c in enumerate(cells):X[:,f*8+c]=(np.arange(n)>>(8*q))&255
  x=X.reshape(-1,16,8).copy();x[:,f,:]=rehair_staff(bow_staff(x[:,f,:],st),S0,S20);x2=cross(x.reshape(-1,128))
  out.append((int((np.bitwise_xor.reduce(x.reshape(-1,128),0)==0).sum()),int((np.bitwise_xor.reduce(x2,0)==0).sum())))
 return {'zero_cells_after_rehair_mean':float(np.mean([o[0] for o in out])),'zero_cells_after_cross_mean':float(np.mean([o[1] for o in out])),'note':'127 other cells constant -> after rehair 120 trivially zero; after cross random ~0.5'}
res['integral_through_cross']={str(c):thru_cross(LIVE,c) for c in ((7,),(6,),(5,),(4,),(0,),(6,7),(4,5))}
print('cross',res['integral_through_cross'],flush=True)
# 4. related-rotation on beat 0: deltas that keep the three shared rotations (computed from beat 0 after stroke 1)
B=rng.integers(0,256,(1<<16,8));a=bow_staff(B);ar=rehair_staff(a,S0,S20)
def u1(X):pp=X[:,2];return (X[:,0]+rotl(X[:,1],1+pp%7))&255
rot=lambda v:(1+v%7)*8+1+(v>>3)%7
RR={'by_delta':{}}
same_tot=0;cases=0;best=(0,None);bestr=(0,None)
pack=lambda z:(z*(256**np.arange(8))).sum(1)
for d in range(1,256):
 H=B.copy();H[:,0]^=d;same=rot(u1(H))==rot(u1(B));same_tot+=int(same.sum());cases+=len(B)
 z=pack(a^bow_staff(H)[:]);zs=z[same]
 if len(zs):
  u,c=np.unique(zs,return_counts=True);k=c.argmax();p=c[k]/len(B)
  if c[k]>best[0]:best=(int(c[k]),d,[(int(u[k])>>(8*i))&255 for i in range(8)])
 zr=pack(ar^rehair_staff(bow_staff(H),S0,S20));u,c=np.unique(zr,return_counts=True);k=c.argmax()
 if c[k]>bestr[0]:bestr=(int(c[k]),d)
RR['shared_rotations_unchanged_prob']=same_tot/cases
RR['best_bow_diff_beat0_within_rotation_preserving_cases']={'count':best[0],'of':len(B),'log2':round(math.log2(best[0]/len(B)),2) if best[0] else None,'delta':best[1],'out':best[2]}
RR['best_bow_rehair_diff_beat0']={'count':bestr[0],'of':len(B),'log2':round(math.log2(max(bestr[0],1)/len(B)),2),'delta':bestr[1],'sample_floor_log2':-16}
res['related_rotation_beat0']=RR;print('RR',RR,flush=True)
# 5. rotational pairs: bow(rotl_k each byte) vs rotl_k(bow); overall and with condition 'beat-0-driven strokes fixed'
ROT={}
X=rng.integers(0,256,(1<<20,8))
for kk in (1,2,3,4):
 for lab,st in (('live',LIVE),('previous_(4,5,6)',OLD_STROKES)):
  e=(bow_staff(rotl(X,kk),st)==rotl(bow_staff(X,st),kk));ROT[f'{lab}_k{kk}']={'all8':float(e.all(1).mean()),'mean_equal_cells':round(float(e.sum(1).mean()),3),'per_cell':e.mean(0).round(3).tolist()}
res['rotational_bow']=ROT;print('ROT',{k:(v['all8'],v['mean_equal_cells']) for k,v in ROT.items()},flush=True)
# 6. linear: 2-bit input masks -> single output bit through bow+rehair (2^22), and best pair-output masks by Walsh transform
def bits(x):return ((x[:,:,None]>>np.arange(8))&1).reshape(len(x),64).astype(np.float32)*2-1
def corr2(Y,X):
 bx=bits(X);by=bits(Y);top=[]
 for i in range(63):
  P=bx[:,i:i+1]*bx[:,i+1:];C=P.T@by/len(X);A=np.abs(C);k=np.unravel_index(A.argmax(),A.shape);top.append((float(A[k]),i,i+1+k[0],k[1],float(C[k])))
 top.sort(reverse=True);return [{'in':f'c{a//8}b{a%8}^c{b//8}b{b%8}','out':f'c{o//8}b{o%8}','corr':round(c,5)} for _,a,b,o,c in top[:5]]
LIN={}
X=rng.integers(0,256,(1<<21,8))
for lab,st in (('live',LIVE),('previous_(4,5,6)',OLD_STROKES)):
 Y=bow_staff(X,st);Z=rehair_staff(Y,S0,S20)
 LIN[lab]={'two_bit_in_bow':corr2(Y[:1<<20],X[:1<<20]),'two_bit_in_bow_rehair':corr2(Z,X),'sigma_rehair':2**-10.5}
 print('LIN',lab,LIN[lab]['two_bit_in_bow'][:2],LIN[lab]['two_bit_in_bow_rehair'][:2],flush=True)
def fwht(a):
 a=a.astype(np.float64).copy();h=1
 while h<len(a):
  a=a.reshape(-1,2,h);a=np.stack([a[:,0]+a[:,1],a[:,0]-a[:,1]],1).reshape(-1);h*=2
 return a
def best_pair_mask(inbit,Yc,ycells):
 v=Yc[:,ycells[0]]|(Yc[:,ycells[1]]<<8);s=np.bincount(v,weights=1-2*inbit,minlength=65536);W=fwht(s)/len(v);W[0]=0;k=int(np.abs(W).argmax())
 return {'best_out_mask':f'cells{ycells} mask {k:#06x}','corr':round(float(W[k]),5),'max_abs':round(float(np.abs(W).max()),5)}
X=rng.integers(0,256,(1<<22,8))
WAL={}
for lab,st in (('live',LIVE),('previous_(4,5,6)',OLD_STROKES)):
 Y=bow_staff(X,st);Z=rehair_staff(Y,S0,S20);row={}
 for name,ib in (('c0b0^c1b7',(X[:,0]&1)^((X[:,1]>>7)&1)),('c0b0^c1b4',(X[:,0]&1)^((X[:,1]>>4)&1)),('c6b0',X[:,6]&1)):
  row[name]={'bow':{str(c):best_pair_mask(ib,Y,c) for c in ((0,1),(6,7))},'bow_rehair':{str(c):best_pair_mask(ib,Z,c) for c in ((0,1),(2,3),(4,5),(6,7))}}
 WAL[lab]=row;print('WAL',lab,json.dumps(row)[:600],flush=True)
res['bow_linear']={'two_bit':LIN,'walsh_best_pair_output_masks_2^22':WAL,'sigma_2^22':2**-11}
res['seconds']=round(time.time()-t0,1);res['finished']=now();save('attack_shared_rotation',res)
