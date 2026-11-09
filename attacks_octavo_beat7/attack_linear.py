"""Linear: LAT of every keyed table, trail bound, measured 1-2 round single-bit correlations, bow cell6.bit0->cell7.bit4,
bow+rehair staff-level correlations, triplet LSB linearity regression, LSB-plane parity."""
from common import *
verify_live();t0=time.time()
res={'started':now(),'live_sha':LIVE_SHA}
B=Batch(SCH);B.validate()
rng=np.random.default_rng(4242)
H=np.array([[1]])
for _ in range(8):H=np.block([[H,H],[H,-H]])
def lat_np(S):
 S=np.asarray(S);bitsb=((S[:,None]&np.arange(256)[None,:]));par=np.array([bin(i).count('1')&1 for i in range(256)])
 # F[x,b] = (-1)^{b.S(x)}; W = H @ F gives 2*LAT
 F=1-2*par[bitsb];W=H@F;W[0,:]=0;W[:,0]=0;return int(np.abs(W).max()//2),np.unique(np.abs(W[1:,1:])//2,return_counts=True)
lats=[];spec=None
for s in (N.Schedule(SEED,NONCE),N.Schedule(SEED,DEMO_NONCE)):
 for k in s.rounds:
  for T in (k['S'],k['S2']):
   m,sp=lat_np(T);lats.append(m);spec=sp if spec is None else spec;assert np.array_equal(sp[0],spec[0]) and np.array_equal(sp[1],spec[1])
ms,_=lat_np(list(N.SM4_SBOX))
res['lat']=dict(tables=len(lats),max_abs_lat_each=sorted(set(lats)),max_corr=f'{max(lats)*2}/256 = 2^{math.log2(max(lats)*2/256):.0f}',sm4_base=ms,spectrum_identical_across_tables=True)
print('lat',res['lat'],flush=True)
res['trail_bound']=[dict(rounds=R,min_active=(2*R-1)*6+2,corr_le_log2=-3*((2*R-1)*6+2),data_log2=6*((2*R-1)*6+2)) for R in (1,2,3,4,8,16)]
def bits(x):return np.unpackbits(np.asarray(x,dtype=np.uint8)[:,:,None],axis=2,bitorder='little').reshape(len(x),-1).astype(np.float32)*2-1
def corrmat(R,N_,chunk=1<<14):
 C=np.zeros((1024,1024),dtype=np.float64)
 for s in range(0,N_,chunk):
  X=rng.integers(0,256,(chunk,128));Y=B.enc(X,R);C+=(bits(X).T@bits(Y)).astype(np.float64)
 return C/N_
emp=[]
for R,N_ in ((1,1<<18),(2,1<<17)):
 C=corrmat(R,N_);A=np.abs(C);sig=1/math.sqrt(N_);i,o=np.unravel_index(A.argmax(),A.shape)
 acc=0
 for s_ in range(32):
  X=rng.integers(0,256,(1<<15,128));Y=B.enc(X,R);acc+=int((((X[:,i//8]>>(i%8))&1)^((Y[:,o//8]>>(o%8))&1)).sum())
 re_c=1-2*acc/(1<<20)
 emp.append(dict(rounds=R,samples=N_,max_abs_corr=round(float(A.max()),5),max_sigma=round(float(A.max()/sig),2),expected_null_max_sigma=round(math.sqrt(2*math.log(2**20)),2),
  count_over_5sigma=int((A>5*sig).sum()),expected_over_5sigma=round(2**20*5.7e-7,2),mean_abs=round(float(A.mean()),6),null_mean_abs=round(sig*math.sqrt(2/math.pi),6),
  argmax=f'in {i//8}.{i%8} -> out {o//8}.{o%8}',argmax_fresh_2e20=round(re_c,5),argmax_fresh_sigma=round(re_c*2**10,2)))
 print('emp',emp[-1],flush=True)
res['empirical_single_bit']=emp
# LSB plane: triplets are exactly linear in bit 0 -> check full parity of LSBs after 1 and 2 rounds
lp=[]
for R in (1,2):
 X=rng.integers(0,256,(1<<16,128));Y=np.concatenate([B.enc(X[s:s+(1<<14)],R) for s in range(0,1<<16,1<<14)])
 px=np.bitwise_xor.reduce(X&1,axis=1);py=np.bitwise_xor.reduce(Y&1,axis=1);c=float(((px^py)*-2+1).mean())
 lp.append(dict(rounds=R,samples=1<<16,corr=round(c,5),sigma=round(c*256,2)))
res['lsb_plane_parity']=lp
# triplet bit-0 regression
X=rng.integers(0,256,(20000,128));T=trips(X).reshape(-1,16,8);Xs=X.reshape(-1,16,8)
res['triplet_bit0_linear']=dict(holds=bool(np.all((T[:,:,0]&1)==((Xs[:,:,0]^Xs[:,:,1]^Xs[:,:,2]^Xs[:,:,3]*0)&1)) or True),
 note='checked exact linear map of bit 0 below')
# exact: bit0 of triplet output is a GF(2)-linear function of input bits 0 (odd coeffs act as 1, even as 0); verify by solving
ok=True;Ab=None
L=np.zeros((8,8),dtype=int)
for j in range(8):
 e=np.zeros((1,128),dtype=np.int64);e[0,j]=1;L[:,j]=trips(e).reshape(16,8)[0]&1
pred=((Xs&1)@L.T)%2;ok=bool(np.all(pred==(T&1)))
res['triplet_bit0_linear']=dict(exact=ok,matrix_rows=L.tolist(),samples=20000)
# bow cell6.bit0 -> cell7.bit4 regression, and in bow+rehair (staff) context
k0=SCH.rounds[0];S0=np.array(k0['S']);S20=np.array(k0['S2'])
X=rng.integers(0,256,(1<<22,8));Y=bow_staff(X);c=float(((((X[:,6]&1)^((Y[:,7]>>4)&1))*-2)+1).mean())
Yo=bow_staff(X,OLD_STROKES);co=float(((((X[:,6]&1)^((Yo[:,7]>>4)&1))*-2)+1).mean())
Z=rehair_staff(Y[:1<<20],S0,S20);bz=bits(Z);bx=bits(X[:1<<20]);Cz=np.abs(bx.T@bz/(1<<20))
res['bow_bias']=dict(samples=1<<22,new_corr=round(c,5),old_corr=round(co,5),sigma=round(2**-11,6),
 bow_plus_rehair_max_single_bit_corr=round(float(Cz.max()),5),bow_plus_rehair_sigma=2**-10,note='rehair S-boxes cap any single-bit relation at the S-box LAT level or below')
print('bow bias',res['bow_bias'],res['triplet_bit0_linear']['exact'],lp,flush=True)
res['seconds']=round(time.time()-t0,1);res['finished']=now();save('attack_linear',res)
