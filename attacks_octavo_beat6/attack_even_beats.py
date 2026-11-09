"""Focus 1: even beats 0,2,4 (and all beats) -> bow+rehair single-byte leaks on the live (4,5,0) layout.
A rehair singleton needs the bow delta confined to ONE pair (i,i+1), both cells changed, with du==dv or du==2*dv
(the Latin pair's field kernel). That is table-independent, so only the bow is evaluated (fast), and every hit is
re-confirmed on the live odd_restack under all 16 round tables. Also: written-argument checks (forced-change beats)."""
from common import *
from multiprocessing import Pool
verify_live();t0=time.time()
LIVE=tuple(N.BOW_STROKES)
def u8bow(x,st):
 x=x.astype(np.int32).copy()
 for i,j,p in st:
  pp=x[:,p];r1=1+pp%7;r2=1+(pp>>3)%7
  v=x[:,j];u=(x[:,i]+(((v<<r1)|(v>>(8-r1)))&255))&255;x[:,i]=u;x[:,j]=v^(((u<<r2)|(u>>(8-r2)))&255)
 return x
assert N.BOW_ROT_BASE==1 and N.BOW_ROT_MOD==7 and N.BOW_R2_SHIFT==3
G2=GF[2].astype(np.int32)
def scan_chunk(args):
 B,beats,st,deltas=args;a=u8bow(B,st);out={t:{'cases':0,'hits':0,'wit':[],'one_pair_both':0,'pairs_hist':[0]*5} for t in beats}
 for t in beats:
  o=out[t]
  for d in deltas:
   H=B.copy();H[:,t]^=d;z=a^u8bow(H,st);act=z!=0
   pa=act.reshape(-1,4,2).any(2);np_=pa.sum(1);o['pairs_hist']=[x+int(y) for x,y in zip(o['pairs_hist'],np.bincount(np_,minlength=5))]
   o['cases']+=len(B)
   one=(np_==1)
   if one.any():
    for i in (0,2,4,6):
     m=one&act[:,i]&act[:,i+1]
     if m.any():
      o['one_pair_both']+=int(m.sum());k=m&((z[:,i]==z[:,i+1])|(z[:,i]==G2[z[:,i+1]]))
      if k.any():
       o['hits']+=int(k.sum())
       for q in np.nonzero(k)[0][:5]:o['wit'].append({'base':B[q].tolist(),'beat':t,'delta':int(d),'bow_delta':z[q].tolist()})
 return out
def merge(parts,beats):
 R={t:{'cases':0,'hits':0,'one_pair_both':0,'pairs_hist':[0]*5,'witnesses':[]} for t in beats}
 for p in parts:
  for t in beats:
   for k in ('cases','hits','one_pair_both'):R[t][k]+=p[t][k]
   R[t]['pairs_hist']=[x+y for x,y in zip(R[t]['pairs_hist'],p[t]['pairs_hist'])];R[t]['witnesses']+=p[t]['wit'][:20-len(R[t]['witnesses'])]
 return R
def run(B,beats,st=LIVE,deltas=range(1,256),chunk=1<<15):
 jobs=[(B[s:s+chunk],beats,st,list(deltas)) for s in range(0,len(B),chunk)]
 with Pool(6) as P:parts=P.map(scan_chunk,jobs)
 return merge(parts,beats)
res={'started':now(),'live_sha':LIVE_SHA,'strokes':LIVE}
if __name__=='__main__':
 rng=np.random.default_rng(66060)
 # A. large random scan, even beats, 2^21 bases x 255 deltas per beat
 B=rng.integers(0,256,(1<<21,8)).astype(np.int32)
 A=run(B,(0,2,4));res['A_random_even_2^21']={t:{k:v for k,v in A[t].items()} for t in A};print('A',{t:(A[t]['hits'],A[t]['one_pair_both'],A[t]['pairs_hist']) for t in A},round(time.time()-t0),flush=True)
 # B. all 8 beats, 2^18 fresh bases (sanity incl. odd beats and beat 6)
 B=rng.integers(0,256,(1<<18,8)).astype(np.int32)
 Bb=run(B,tuple(range(8)));res['B_random_all_beats_2^18']=Bb;print('B',{t:Bb[t]['hits'] for t in Bb},round(time.time()-t0),flush=True)
 # C. structured bases: every byte from the 16 rotation-symmetric values (rotl(x,4)==x) -- rotation changes are often invisible
 RS=np.array([x for x in range(256) if ((x<<4|x>>4)&255)==x]);B=RS[rng.integers(0,16,(1<<18,8))].astype(np.int32)
 C=run(B,tuple(range(8)));res['C_rotation_symmetric_bases_2^18']=C;print('C',{t:C[t]['hits'] for t in C},round(time.time()-t0),flush=True)
 # D. low-weight bases: all bases of Hamming weight <=2 over 64 bits (2081) + all [v]*8 + [v,0,..]/[0..v..] one-hot bytes
 lw=[np.zeros(8,np.int32)]
 for a in range(64):
  for b in range(a,64):
   x=np.zeros(64,np.int32);x[a]=1;x[b]=1;lw.append(np.packbits(x.astype(np.uint8),bitorder='little').astype(np.int32))
 for v in range(256):
  lw.append(np.full(8,v,np.int32))
  for c in range(8):x=np.zeros(8,np.int32);x[c]=v;lw.append(x);y=np.full(8,255,np.int32);y[c]=v;lw.append(y)
 B=np.unique(np.array(lw),axis=0);Dd=run(B,tuple(range(8)),chunk=1024);res['D_low_weight_bases']={'bases':len(B),'scan':Dd};print('D',len(B),{t:Dd[t]['hits'] for t in Dd},round(time.time()-t0),flush=True)
 # E. structured deltas: additive deltas (+k mod 256) on even beats (not XOR), 2^19 bases x 255
 def add_chunk(args):pass
 B=rng.integers(0,256,(1<<19,8)).astype(np.int32);a=u8bow(B,LIVE);E={}
 for t in (0,2,4):
  h=0;one=0
  for k in range(1,256):
   H=B.copy();H[:,t]=(H[:,t]+k)&255;z=a^u8bow(H,LIVE);act=z!=0;pa=act.reshape(-1,4,2).any(2);o1=pa.sum(1)==1
   for i in (0,2,4,6):
    m=o1&act[:,i]&act[:,i+1];one+=int(m.sum());h+=int((m&((z[:,i]==z[:,i+1])|(z[:,i]==G2[z[:,i+1]]))).sum())
  E[t]={'cases':len(B)*255,'hits':h,'one_pair_both':one}
 res['E_additive_deltas_2^19']=E;print('E',E,round(time.time()-t0),flush=True)
 # F. written argument checks: which beats ALWAYS change for an input change on beat t (random 2^20 x all deltas sample)
 B=rng.integers(0,256,(1<<16,8)).astype(np.int32);a=u8bow(B,LIVE);F={}
 for t in range(8):
  always=np.ones(8,bool);
  for d in range(1,256):
   H=B.copy();H[:,t]^=d;always&=(a!=u8bow(H,LIVE)).all(0)
  F[t]=[int(c) for c in np.nonzero(always)[0]]
 # beat 2: conditional on final beat 0 unchanged, do beats 3 and 4 always change?
 cnt=dict(b0_unchanged=0,b0_unch_and_3_4_both=0,b0_changed=0,b0_changed_pairs_hist=[0]*5)
 for d in range(1,256):
  H=B.copy();H[:,2]^=d;z=a^u8bow(H,LIVE);act=z!=0;u=~act[:,0]
  cnt['b0_unchanged']+=int(u.sum());cnt['b0_unch_and_3_4_both']+=int((u&act[:,3]&act[:,4]).sum());cnt['b0_changed']+=int((~u).sum())
  cnt['b0_changed_pairs_hist']=[x+int(y) for x,y in zip(cnt['b0_changed_pairs_hist'],np.bincount(act[~u].reshape(-1,4,2).any(2).sum(1),minlength=5))]
 res['F_forced_changes']={'always_changed_bow_outputs_by_input_beat':F,'beat2_case_split':cnt,'cases_per_beat':len(B)*255};print('F',F,cnt,flush=True)
 # live confirmation of any witnesses
 conf=[]
 for key in ('A_random_even_2^21','B_random_all_beats_2^18','C_rotation_symmetric_bases_2^18'):
  for t,row in res[key].items():
   for w in row['witnesses'][:3]:
    s,tt,d=w['base'],w['beat'],w['delta'];h=s[:];h[tt]^=d
    conf.append({'scan':key,**w,'live_weights_16_rounds':[sum(x!=y for x,y in zip(N.odd_restack(N.bow_pressure(s),k['S'],k['S2']),N.odd_restack(N.bow_pressure(h),k['S'],k['S2']))) for k in SCH.rounds]})
 res['live_confirmation']=conf;print('conf',conf[:6],flush=True)
 # validate the fast bow against the live bow_pressure
 X=rng.integers(0,256,(2000,8)).astype(np.int32);Y=u8bow(X,LIVE);assert all(list(Y[i])==N.bow_pressure(list(map(int,X[i]))) for i in range(2000))
 res['fast_bow_validated_vs_live_bow_pressure']=2000
 res['seconds']=round(time.time()-t0,1);res['finished']=now();save('attack_even_beats',res)
