"""Linear cryptanalysis of live N2: S-box LATs, per-layer linear approximations, branch numbers,
relaxed-model trail bound, and empirical correlation matrices (white-box, fixed schedule)."""
from common import *
verify_live()
res={'started':now(),'live_sha':LIVE_SHA}
B=Batch(SCH);res['batch_validated_round_calls']=B.validate()
bits8=np.array([[x>>i&1 for i in range(8)] for x in range(256)])
PAR=np.array([bin(i).count('1')&1 for i in range(1<<16)],dtype=np.int64)
H=1-2*PAR[np.bitwise_and.outer(np.arange(256),np.arange(256))]   # H[a,x]=(-1)^{a.x}
def lat(S):
 S=np.array(list(S),dtype=np.int64);F=1-2*PAR[np.bitwise_and.outer(S,np.arange(256))]   # F[x,b]
 return H@F            # LAT[a,b]=sum_x (-1)^{a.x+b.S(x)}  (correlation = LAT/256)
def spec(L):v=np.abs(L[1:,1:]).ravel();u,c=np.unique(v,return_counts=True);return dict(zip(map(int,u),map(int,c)))
# ---------------- 1. S-box LATs
base=lat(N.SM4_SBOX);bspec=spec(base)
lt=[]
for name,sch in (('hello',SCH),('demo',N.Schedule(SEED,DEMO_NONCE))):
 for r,k in enumerate(sch.rounds):
  for t in ('S','S2'):
   L=lat(k[t]);m=int(np.abs(L[1:,1:]).max());lt.append(dict(schedule=name,round=r,table=t,max_abs_LAT=m,max_corr=m/256,log2_max_corr=math.log2(m/256),
     entries_at_max=int((np.abs(L[1:,1:])==m).sum()),spectrum_equals_SM4=spec(L)==bspec,zero_mask_rows_ok=bool(np.all(L[0,1:]==0) and np.all(L[1:,0]==0))))
res['sbox_lat']={'sm4_base_max_abs_LAT':int(np.abs(base[1:,1:]).max()),'sm4_spectrum':bspec,'tables_checked':len(lt),
 'all_max_corr_2^-3':all(x['max_corr']==0.125 for x in lt),'all_spectrum_equal_SM4':all(x['spectrum_equals_SM4'] for x in lt),'per_table':lt,
 'note':'LAT entry 32 = |#agree-128|*2 => correlation 32/256 = 2^-3 (bias 2^-4). Keyed tables are affine-equivalent to SM4, so the spectrum is identical; key choice only moves where the 2^-3 entries sit.'}
print('LAT done',res['sbox_lat']['all_max_corr_2^-3'],flush=True)
# ---------------- 2. layer approximations
def gf2_matrix_pair(fn):
 """16x16 GF(2) matrix of a GF(2)-linear 2-cell map (input bits u0..7,v0..7)."""
 cols=[]
 for i in range(16):
  u,v=(1<<i,0) if i<8 else (0,1<<(i-8));a,b=fn(u,v);cols.append(a|b<<8)
 return cols
def mask_transpose(cols,beta):   # input mask alpha with alpha.x = beta.M x : alpha_i = parity(beta & col_i)
 return sum((bin(beta&c).count('1')&1)<<i for i,c in enumerate(cols))
def pair_branch(cols):
 best=99;dbest=99;
 for beta in range(1,1<<16):
  a=mask_transpose(cols,beta);w=(beta&255>0)+(beta>>8>0)+(a&255>0)+(a>>8>0);best=min(best,w)
 for x in range(1,1<<16):
  y=0
  for i,c in enumerate(cols):
   if x>>i&1:y^=c
  dbest=min(dbest,(x&255>0)+(x>>8>0)+(y&255>0)+(y>>8>0))
 return best,dbest
pairs={}
for name,_,(i,j),M in N.BARS[1:]:
 cols=gf2_matrix_pair(lambda u,v,M=M:N.bar_apply(M,u,v));lb,db=pair_branch(cols)
 pairs[name]=dict(cells=(i,j),matrix=M,exact_linear_corr=1.0,linear_branch=lb,diff_branch=db)
cols=gf2_matrix_pair(N.mix2);lb,db=pair_branch(cols);pairs['mix2 (butterfly/shell/cross/latin field step)']=dict(matrix=N.MIX2_MATRIX,exact_linear_corr=1.0,linear_branch=lb,diff_branch=db)
# latin pair: corr(alpha_in;(b1,b2)) = LAT_S(a1,b1)*LAT_S2(a2,b2)/2^16 with (a1,a2) the unique (x,y)-mask s.t. alpha_in = L^T(a1,a2)
k0=SCH.rounds[0];S,S2=k0['S'],k0['S2'];LS,LS2=lat(S)/256,lat(S2)/256
Lcols=gf2_matrix_pair(lambda u,v:(u^v,u^N.gf_mul(2,v)))
inv={mask_transpose(Lcols,a1|a2<<8):(a1,a2) for a1 in range(256) for a2 in range(256)}
assert len(inv)==65536
rng=random.Random(1);uu=np.repeat(np.arange(256),256);vv=np.tile(np.arange(256),256)
o1=np.array(S)[uu^vv];o2=np.array(S2)[uu^GF[2,vv]];checks=0;maxdev=0
for _ in range(300):
 ain=rng.randrange(1,1<<16);b1=rng.randrange(256);b2=rng.randrange(256)
 if rng.random()<0.3:   # force a strong mask
  a1=rng.randrange(1,256);b1=int(np.argmax(np.abs(LS[a1])));b2=0;ain=mask_transpose(Lcols,a1)
 emp=np.mean(1-2*((PAR[(uu&ain&255)]^PAR[vv&(ain>>8)]^PAR[o1&b1]^PAR[o2&b2])))
 a1,a2=inv[ain];pred=LS[a1,b1]*LS2[a2,b2];maxdev=max(maxdev,abs(emp-pred));checks+=1
lat_pair=dict(formula='corr = LAT_S(a1,b1)/256 * LAT_S2(a2,b2)/256, (a1,a2)=(L^T)^-1(input mask), L=mix2 field step',
 brute_force_checks=checks,max_abs_deviation=float(maxdev),
 best_one_output_cell_corr=float(np.abs(LS[1:,1:]).max()),best_two_output_cells_corr=float(np.abs(LS[1:,1:]).max()*np.abs(LS2[1:,1:]).max()),
 active_sboxes_equals_active_output_cells=True,
 note='Output mask on u-prime only forces a2=0 (S2 inactive) => |corr|<=2^-3; both outputs masked => <=2^-6. The field step L has linear branch 3, but which input cells are masked does not change the S-box count, which equals the number of masked output cells.')
print('pairs done',flush=True)
# triplets mod 2^k (closed under reduction mod 2^k)
def trip_mod(xs,mod):
 x=list(xs)
 for _,(i,j,k),M in N.TRIPLETS:
  u,v,w=x[i],x[j],x[k];x[i],x[j],x[k]=[(a*u+b*v+c*w)%mod for a,b,c in M]
 return x
def wht(f):
 f=f.astype(np.float64).copy();n=f.size;h=1
 while h<n:
  f=f.reshape(-1,2,h);a=f[:,0,:]+f[:,1,:];b=f[:,0,:]-f[:,1,:];f=np.stack([a,b],1).reshape(n);h*=2
 return f
trip={}
# bit 0: exact GF(2) linear map; output bit0 of cell c = parity(row c & input LSB vector)
P=[[1 if (i==j) else 0 for j in range(8)] for i in range(8)]
lsb_rows=[]
for c in range(8):
 row=0
 for j in range(8):
  e=[0]*8;e[j]=1
  if trip_mod(e,2)[c]:row|=1<<j
 lsb_rows.append(row)
# verify bit-0 relation on real bytes
rr=np.random.default_rng(3);X=rr.integers(0,256,(20000,128));Y=trips(X)
ok=all(np.all(((Y[:,f*8+c]&1))==np.bitwise_xor.reduce(X[:,[f*8+j for j in range(8) if lsb_rows[c]>>j&1]]&1,axis=1)) for f in range(16) for c in range(8))
trip['bit0']=dict(exact=True,verified_on_20000_random_grids=bool(ok),corr=1.0,lsb_rows_in_masks=[f'{r:08b}'[::-1] for r in lsb_rows],
 note='bit 0 of each triplet output is the XOR of bit 0 of the inputs with odd coefficients; the whole 6-triplet staff layer is an exact GF(2)-linear map on the LSB plane.')
for k in (2,3):
 mod=1<<k;nb=8*k
 # enumerate all inputs mod 2^k on 8 cells: index bits: cell j uses bits [j*k,(j+1)*k)
 idx=np.arange(1<<nb);cells=[(idx>>(j*k))&(mod-1) for j in range(8)]
 x=list(cells)
 for _,(i,j,kk),M in N.TRIPLETS:
  u,v,w=x[i],x[j],x[kk];x[i],x[j],x[kk]=[(a*u+b*v+c*w)%mod for a,b,c in M]
 best=[]
 for c in range(8):
  f=1-2*((x[c]>>(k-1))&1);w=np.abs(wht(f))/f.size;w[0]=0;am=int(np.argmax(w))
  best.append(dict(output=f'cell {c} bit {k-1}',best_abs_corr=float(w.max()),log2=float(np.log2(w.max())),num_masks_at_best=int((w==w.max()).sum())))
 trip[f'bit{k-1}_exhaustive_mod_{mod}']=best
 del x,cells,idx
print('triplets done',flush=True)
# bow: empirical single-bit -> single-bit correlations of bow_pressure on one staff (64x64), N=2^20, plus LSB parity relations
def corrmat(X,Y):
 A=(1-2*X).astype(np.float32);Bm=(1-2*Y).astype(np.float32);return A.T@Bm
def tobits(x):  # (n,c) bytes -> (n,8c) bits, bit index = cell*8+bit
 return ((x[:,:,None]>>np.arange(8))&1).reshape(x.shape[0],-1)
Nb=1<<20;C=np.zeros((64,64),np.float64)
for ch in range(16):
 X=rr.integers(0,256,(Nb//16,128));Y=bow(X)
 C+=corrmat(tobits(X[:,:8]),tobits(Y[:,:8]))
C/=Nb;top=np.dstack(np.unravel_index(np.argsort(-np.abs(C).ravel())[:8],C.shape))[0]
bowres=dict(samples=Nb,noise_floor_1_over_sqrtN=1/math.sqrt(Nb),top_single_bit_relations=[dict(in_cell=int(i//8),in_bit=int(i%8),out_cell=int(j//8),out_bit=int(j%8),corr=float(C[i,j])) for i,j in top],
 count_abs_corr_ge_0_1=int((np.abs(C)>=0.1).sum()),count_abs_corr_ge_0_01=int((np.abs(C)>=0.01).sum()))
# exact LSB check: bit 0 of u'=u+rotl(v,r1) is u0 ^ v_{8-r1}; with data-dependent r1 there is no fixed exact bit-0 relation
trip_bow=None
res['layers']=dict(field_pairs=pairs,latin_pair=lat_pair,triplets_mod_2k=trip,bow_single_bit=bowres)
print('bow done',flush=True)
# ---------------- cross layer (16x16 over GF(2^8), per beat) and butterfly branch numbers
def gf_matrix(fn,n):
 Mx=np.zeros((n,n),np.int64)
 for j in range(n):
  e=[0]*n;e[j]=1;Mx[:,j]=fn(e)
 return Mx
def cross_vec(e):
 g=[[0]*8 for _ in range(16)]
 for f in range(16):g[f][0]=e[f]
 return [row[0] for row in N.cross_staff_mix(g)]
CX=gf_matrix(cross_vec,16)
def gf_matvec_batch(Mx,X):   # X (n,cols) -> (n,rows)
 out=np.zeros((X.shape[0],Mx.shape[0]),np.int64)
 for j in range(Mx.shape[1]):
  out^=GF[Mx[:,j][None,:],X[:,j][:,None]]
 return out
def gf_inv_matrix(Mx):
 n=Mx.shape[0];A=[list(map(int,r))+[1 if i==j else 0 for j in range(n)] for i,r in enumerate(Mx)]
 for c in range(n):
  p=next(i for i in range(c,n) if A[i][c]);A[c],A[p]=A[p],A[c];iv=N.gf_inv(A[c][c]);A[c]=[N.gf_mul(iv,x) for x in A[c]]
  for i in range(n):
   if i!=c and A[i][c]:f=A[i][c];A[i]=[x^N.gf_mul(f,y) for x,y in zip(A[i],A[c])]
 return np.array([r[n:] for r in A],np.int64)
from itertools import combinations
def branch_search(Mx,maxw=3):
 """min wt(x)+wt(Mx x) over x with wt(x)<=maxw, x projectively normalised (first nonzero coord = 1)."""
 n=Mx.shape[1];best=(99,None)
 for w in range(1,maxw+1):
  vals=np.array(np.meshgrid(*([np.array([1])]+[np.arange(1,256)]*(w-1)),indexing='ij')).reshape(w,-1).T
  for sup in combinations(range(n),w):
   X=np.zeros((vals.shape[0],n),np.int64);X[:,list(sup)]=vals
   for s in range(0,X.shape[0],1<<16):
    Y=gf_matvec_batch(Mx,X[s:s+(1<<16)]);tw=w+(Y!=0).sum(1);m=int(tw.min())
    if m<best[0]:i=int(np.argmin(tw));best=(m,dict(support=sup,x=list(map(int,X[s+i])),y=list(map(int,Y[i]))))
 return best
# Linear masks through a GF(2^8)-linear map: Tr(b.(Mx)) = Tr((M^T b).x) -> mask matrix is M^T (same field), supports exact.
t0=time.time()
CXi=gf_inv_matrix(CX);assert np.array_equal(gf_matvec_batch(CX,gf_matvec_batch(CXi,np.eye(16,dtype=np.int64))),np.eye(16,dtype=np.int64))
crossres={}
for label,Mx in (('differential C',CX),('differential C^-1',CXi),('linear C^T',CX.T.copy()),('linear (C^T)^-1',CXi.T.copy())):
 b,w=branch_search(Mx,3);crossres[label]=dict(min_total_weight_found=b,witness=w)
dbr=min(crossres['differential C']['min_total_weight_found'],crossres['differential C^-1']['min_total_weight_found'])
lbr=min(crossres['linear C^T']['min_total_weight_found'],crossres['linear (C^T)^-1']['min_total_weight_found'])
crossres['diff_branch_number']=dbr;crossres['linear_branch_number']=lbr
crossres['exact']=bool(dbr<=7 and lbr<=7)
crossres['note']='Searched every input of weight <=3 in both directions, so any codeword of total weight <=7 is found; a minimum <=7 is therefore exact.'
crossres['matrix_beat_t']=CX.tolist();crossres['seconds']=round(time.time()-t0,1)
res['cross_layer']=crossres
print('cross done',dbr,lbr,flush=True)
# ---------------- 3. trail bound (relaxed model)
Bx=lbr
def bound(R):return (2*R-1)*Bx+2
trail=dict(model=('Relaxed (sound lower bound for single trails): S-box layers S, S2 and both rehair Latin layers counted exactly '
 '(rehair active S-boxes = masked rehair output cells); triplets+bow treated as an ARBITRARY staff-local bijection (any mask pattern, correlation up to 1); '
 'B0 Latin S-boxes, weave/butterfly/shell/field bars counted as free (0 active). Each cross layer acts per beat as a 16x16 GF(2^8) map with linear branch number Bx, '
 'so (masked rehair-out cells)+(masked S2 cells) >= Bx and (masked rehair2-out cells)+(masked next-round S cells) >= Bx.'),
 Bx_linear=Bx,max_sbox_corr_log2=-3,
 rounds={R:dict(min_active_sboxes_lower_bound=bound(R),trail_corr_upper_bound_log2=-3*bound(R),data_needed_log2_approx=6*bound(R)) for R in (1,2,3,4,8,16)},
 caveats=['Single-trail bound only; linear hulls can add many trails (typically a modest gain, not hundreds of bits, but not proven here).',
  'Relaxation is loose: real triplets/bow cannot realise every pattern, so real trails are at least this weak.',
  'Bound assumes each active S-box costs at most 2^-3 (true: every keyed table has max |LAT| 32/256).'])
# tightest 1-round concrete instance in the relaxed model
res['trail_bound']=trail
print('trail bound',trail['rounds'],flush=True)
# ---------------- 4. empirical correlation matrices (single-bit in -> single-bit out), white-box fixed schedule
emp={}
for R,Ntot in ((1,1<<18),(2,1<<17)):
 C=np.zeros((1024,1024),np.float64);rng=np.random.default_rng(100+R);t0=time.time()
 lsb_par=0.0;allpar=0.0
 for s in range(Ntot//16384):
  X=rng.integers(0,256,(16384,128));Y=B.enc(X,R)
  bx=tobits(X);by=tobits(Y);C+=corrmat(bx,by)
  lsb_par+=float(np.sum(1-2*((np.bitwise_xor.reduce(X&1,axis=1))^(np.bitwise_xor.reduce(Y&1,axis=1)))))
 C/=Ntot;a=np.abs(C);i,j=np.unravel_index(np.argmax(a),a.shape)
 nf=1/math.sqrt(Ntot);exp_max=math.sqrt(2*math.log(2*1024*1024))*nf
 emp[f'{R}_round']=dict(samples=Ntot,noise_floor=nf,expected_max_of_2pow20_null=exp_max,observed_max_abs=float(a.max()),max_over_noise=float(a.max()/nf),
  argmax=dict(in_cell=int(i//8),in_bit=int(i%8),out_cell=int(j//8),out_bit=int(j%8),corr=float(C[i,j])),
  count_over_5sigma=int((a>5*nf).sum()),expected_over_5sigma=1024*1024*5.7e-7,
  mean_abs=float(a.mean()),expected_mean_abs=math.sqrt(2/math.pi)*nf,
  lsb_plane_all_parity_corr=lsb_par/Ntot,seconds=round(time.time()-t0,1))
 print('empirical',R,emp[f'{R}_round'],flush=True)
# targeted: bit-0 / LSB-plane masks through one round predicted by the exact triplet LSB map are destroyed by S-boxes; test the best partial-round control
# positive control: S-layer only (keyed S), best LAT mask pair should show corr ~2^-3
k=SCH.rounds[0];Ls=lat(k['S']);a_,b_=np.unravel_index(np.argmax(np.abs(Ls[1:,1:])),(255,255));a_+=1;b_+=1
X=np.random.default_rng(9).integers(0,256,(1<<18,));Y=np.array(k['S'])[X^int(B.rk[0][0])]
pc=float(np.mean(1-2*(PAR[X&a_]^PAR[Y&b_])))
emp['positive_control_single_sbox']=dict(in_mask=int(a_),out_mask=int(b_),predicted_abs=float(abs(Ls[a_,b_])/256),measured=pc,samples=1<<18)
res['empirical']=emp
# ---------------- 5. reach estimate
reach=dict(white_box_fixed_schedule=('Relaxed single-trail bound: <=2^%d after 1 round, 2^%d after 2, 2^%d after 3 (data ~2^%d, 2^%d, 2^%d). '
 'Rounds whose bound still needs <=2^1024 data (full codebook): %d; rounds within a 2^80 data budget: %d. Real trails are weaker than this relaxed bound.')%(
 -3*bound(1),-3*bound(2),-3*bound(3),6*bound(1),6*bound(2),6*bound(3),max([R for R in range(1,17) if 6*bound(R)<=1024],default=0),max([R for R in range(1,17) if 6*bound(R)<=80],default=0)),
 real_api='Every message gets a fresh schedule (synthetic nonce from SHA-256 over clef||pickup||block), so an outside attacker gets ONE block per schedule; statistical linear attacks need many blocks under one schedule and do not apply to the API as written. The white-box fixed-schedule numbers are a pessimistic lab model.')
res['reach']=reach;res['finished']=now();save('attack_linear',res)
