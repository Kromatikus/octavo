"""Bow-pressure focus: live (4,5,0) layout vs previous (4,5,6) layout. Singletons, best differentials, linear biases, shared rotation."""
from common import *
verify_live();t0=time.time()
res={'started':now(),'live_sha':LIVE_SHA,'strokes_new':N.BOW_STROKES,'strokes_old':OLD_STROKES}
k0=SCH.rounds[0];S0=np.array(k0['S']);S20=np.array(k0['S2'])
# --- 1. exact replica of the test-suite 522,240 odd-beat scan (same RNG stream as test_sneak_n2.py)
rr4=random.Random(4419)
for _ in range(20000): rr4.randrange(256),rr4.randrange(256),rr4.randrange(1,256)
bases=[[v]*8 for v in range(256)]+[[rr4.randrange(256) for _ in range(8)] for _ in range(256)]
TS=(N.Schedule(SEED,DEMO_NONCE).rounds[0]['S'],N.Schedule(SEED,DEMO_NONCE).rounds[0]['S2'])
def scan(bases,beats,strokes,S,S2,keep=0):
 B=np.array(bases,dtype=np.int64);n=len(B);out={'cases':0,'bow_single':0,'bow_rehair_single':0,'min_after':8,'by_in_out':{},'kernel_pairs_after_bow':0,'weights_after':[0]*9,'witnesses':[],'rehair_singleton_witnesses':[],'rehair_single_by_beat':[0]*8}
 a=bow_staff(B,strokes);ar=rehair_staff(a,S,S2)
 for t in beats:
  for d in range(1,256):
   H=B.copy();H[:,t]^=d;b=bow_staff(H,strokes);br=rehair_staff(b,S,S2)
   db=(a!=b);w=db.sum(1);wr=(ar!=br).sum(1)
   out['cases']+=n;s1=(w==1);out['bow_single']+=int(s1.sum());out['bow_rehair_single']+=int((wr==1).sum());out['min_after']=min(out['min_after'],int(wr.min()))
   r1m=(wr==1);out['rehair_single_by_beat'][t]+=int(r1m.sum())
   for i in np.nonzero(r1m)[0][:20]:out['rehair_singleton_witnesses'].append({'base':B[i].tolist(),'beat':t,'delta':d,'bow_delta':(a[i]^b[i]).tolist(),'out_delta':(ar[i]^br[i]).tolist()})
   for k,c in zip(*np.unique(wr,return_counts=True)):out['weights_after'][int(k)]+=int(c)
   if s1.any():
    ob=db[s1].argmax(1)
    for o,c in zip(*np.unique(ob,return_counts=True)):
     key=f'{t}->{int(o)}';out['by_in_out'][key]=out['by_in_out'].get(key,0)+int(c)
    if len(out['witnesses'])<keep:
     for i in np.nonzero(s1)[0][:keep-len(out['witnesses'])]:out['witnesses'].append((B[i].tolist(),t,d,int(db[i].argmax())))
   # two-byte bow deltas inside one rehair pair (i,i+1), i even, in the field kernel du==dv or du==2dv
   dd=a^b;two=(w==2)
   for i in (0,2,4,6):
    m=two&db[:,i]&db[:,i+1]
    if m.any():
     du,dv=dd[m,i],dd[m,i+1];out['kernel_pairs_after_bow']+=int(((du==dv)|(du==GF[2,dv])).sum())
 return out
rep_new=scan(bases,(1,3,5,7),N.BOW_STROKES,np.array(TS[0]),np.array(TS[1]),keep=6)
rep_old=scan(bases,(1,3,5,7),OLD_STROKES,np.array(TS[0]),np.array(TS[1]),keep=6)
res['test_replica_odd_beats']={'new':rep_new,'old':rep_old}
print('replica new bow',rep_new['bow_single'],'rehair',rep_new['bow_rehair_single'],'| old bow',rep_old['bow_single'],'rehair',rep_old['bow_rehair_single'],flush=True)
assert rep_new['cases']==522240 and rep_new['bow_rehair_single']==0
# --- 2. extended: ALL 8 beats, 255 deltas, 4096 random bases, hello-schedule round-0 tables (8.36M cases per layout)
rng=np.random.default_rng(20261109);RB=rng.integers(0,256,(4096,8)).tolist()
ext_new=scan(RB,range(8),N.BOW_STROKES,S0,S20,keep=4);ext_old=scan(RB,range(8),OLD_STROKES,S0,S20,keep=4)
res['extended_all_beats']={'bases':4096,'new':ext_new,'old':ext_old}
print('extended new bow',ext_new['bow_single'],'rehair',ext_new['bow_rehair_single'],'min',ext_new['min_after'],'| old',ext_old['bow_single'],ext_old['bow_rehair_single'],ext_old['min_after'],flush=True)
# --- 3. two-input (truncated) deltas into bow+rehair: any adjacent / any pair of beats, does a singleton appear?
tw={'new':{},'old':{}}
B=np.array(RB[:1024],dtype=np.int64)
for lab,st in (('new',N.BOW_STROKES),('old',OLD_STROKES)):
 a=rehair_staff(bow_staff(B,st),S0,S20)
 for i in range(8):
  for j in range(i+1,8):
   cnt=0;tot=0
   for _ in range(64):
    d1=rng.integers(1,256,len(B));d2=rng.integers(1,256,len(B));H=B.copy();H[:,i]^=d1;H[:,j]^=d2
    w=(rehair_staff(bow_staff(H,st),S0,S20)!=a).sum(1);cnt+=int((w==1).sum());tot+=len(B)
   tw[lab][f'{i},{j}']=cnt/tot
res['two_beat_input_singleton_rate']={'note':'random two-beat input deltas, 65,536 per beat pair; random 8-byte map would give 8*255/256^7 ~ 1e-14','rates':tw}
print('two-beat singleton max rate new',max(tw['new'].values()),'old',max(tw['old'].values()),flush=True)
# --- 4. best single-beat differential through bow alone (most frequent full 8-byte output XOR), 2^14 bases per delta
def best_diff(strokes,nb=1<<14,deltas=range(1,256)):
 B=rng.integers(0,256,(nb,8));a=bow_staff(B,strokes);best=[]
 pack=lambda z:(z*(256**np.arange(8, dtype=np.int64))).sum(1)
 for t in range(8):
  bt=(0,0,None)
  for d in deltas:
   H=B.copy();H[:,t]^=d;z=pack(a^bow_staff(H,strokes));u,c=np.unique(z,return_counts=True);k=c.argmax()
   if c[k]>bt[0]:bt=(int(c[k]),d,[(int(u[k])>>(8*i))&255 for i in range(8)])
  best.append({'beat':t,'count':bt[0],'of':nb,'prob_log2':round(math.log2(bt[0]/nb),2),'delta':bt[1],'out_diff':bt[2]})
 return best
res['bow_best_single_beat_differential']={'new':best_diff(N.BOW_STROKES),'old':best_diff(OLD_STROKES)}
for lab in ('new','old'):print('bestdiff',lab,[(b['beat'],b['prob_log2']) for b in res['bow_best_single_beat_differential'][lab]],flush=True)
# --- 5. bow linear: all 64x64 single-bit correlations, 2^22 random staffs, new vs old; plus 2-bit input masks for the top output bits
def bits(x):return ((x[:,:,None]>>np.arange(8))&1).reshape(len(x),64).astype(np.float32)*2-1
def corr(strokes,N_=1<<22,chunk=1<<19):
 C=np.zeros((64,64));
 for s in range(0,N_,chunk):
  X=rng.integers(0,256,(chunk,8));Y=bow_staff(X,strokes);C+=bits(X).T@bits(Y)
 return C/N_
lin={}
for lab,st in (('new',N.BOW_STROKES),('old',OLD_STROKES)):
 C=corr(st);A=np.abs(C);idx=np.dstack(np.unravel_index(np.argsort(-A,axis=None)[:12],A.shape))[0]
 lin[lab]={'samples':1<<22,'sigma':1/math.sqrt(1<<22),'max_abs':float(A.max()),'count_ge_0.01':int((A>=0.01).sum()),'count_ge_0.03':int((A>=0.03).sum()),'count_ge_0.1':int((A>=0.1).sum()),
  'top':[{'in':f'cell{i//8}.bit{i%8}','out':f'cell{o//8}.bit{o%8}','corr':round(float(C[i,o]),5)} for i,o in idx],
  'cell6bit0_to_cell7bit4':round(float(C[6*8+0,7*8+4]),5),
  'by_out_cell_max':[round(float(A[:,c*8:(c+1)*8].max()),5) for c in range(8)]}
 print('lin',lab,lin[lab]['max_abs'],lin[lab]['count_ge_0.01'],lin[lab]['top'][:3],flush=True)
res['bow_linear_single_bit']=lin
# 2-bit input masks (all 2016 pairs) x 64 single output bits, 2^20 samples, new layout only + old for comparison
def corr2(strokes,N_=1<<20):
 X=rng.integers(0,256,(N_,8));Y=bow_staff(X,strokes);bx=bits(X);by=bits(Y);best=(0,None)
 iu=np.triu_indices(64,1);top=[]
 for i in range(63):
  P=bx[:,i:i+1]*bx[:,i+1:];C=P.T@by/N_;A=np.abs(C);k=np.unravel_index(A.argmax(),A.shape)
  top.append((float(A[k]),i,i+1+k[0],k[1],float(C[k])))
 top.sort(reverse=True);return [{'in':f'c{a//8}b{a%8}^c{b//8}b{b%8}','out':f'c{o//8}b{o%8}','corr':round(c,5)} for _,a,b,o,c in top[:8]]
res['bow_linear_two_bit_inputs']={'samples':1<<20,'sigma':2**-10,'new':corr2(N.BOW_STROKES),'old':corr2(OLD_STROKES)}
print('2bit new',res['bow_linear_two_bit_inputs']['new'][:3],'old',res['bow_linear_two_bit_inputs']['old'][:3],flush=True)
# --- 6. shared rotation structure: strokes (4,5,0), (6,7,0), (5,6,0) all read beat 0 (never written after stroke (0,1,2))
p=np.arange(256);r1=1+p%7;r2=1+(p>>3)%7
res['shared_rotation']={'fact':'strokes (4,5,0), (6,7,0) and (5,6,0) read the same byte s[0] after stroke 1, so all three use identical (r1,r2)',
 'readers_of_beat0_after_stroke1':[st for st in N.BOW_STROKES[1:] if st[2]==0],
 'beat0_written_after_stroke1':any(0 in st[:2] for st in N.BOW_STROKES[1:]),
 'r1_hist':np.bincount(r1,minlength=8)[1:].tolist(),'r2_hist':np.bincount(r2,minlength=8)[1:].tolist(),
 'complementary_r1_plus_r2_eq_8_prob':float(np.mean(r1+r2==8)),'r1_eq_r2_prob':float(np.mean(r1==r2))}
print('shared',res['shared_rotation'],flush=True)
# --- 7. conditional differential: delta confined to beats 5,6,7 (beat 0 untouched => fixed rotations in last two strokes)
cond={}
for lab,st in (('new',N.BOW_STROKES),('old',OLD_STROKES)):
 B=rng.integers(0,256,(1<<16,8));a=bow_staff(B,st);row={}
 for d in (0x01,0x80,0x40):
  H=B.copy();H[:,7]^=d;z=a^bow_staff(H,st);act=(z!=0)
  row[f'beat7^{d:#04x}']={'active_cells_hist':np.bincount(act.sum(1),minlength=9).tolist(),'beats_0_4_unchanged_frac':float((~act[:,:5]).all(1).mean()),
   'most_common_out_diff_prob':float(np.unique((z*(256**np.arange(8, dtype=np.int64))).sum(1),return_counts=True)[1].max()/len(B))}
 cond[lab]=row
res['beat7_conditional']=cond;print('beat7 cond',json.dumps(cond)[:400],flush=True)
res['seconds']=round(time.time()-t0,1);res['finished']=now();save('attack_bow',res)
