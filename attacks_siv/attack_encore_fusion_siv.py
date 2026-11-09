from common import *
import collections
log=Log('attack_encore_fusion');rng=np.random.default_rng(8801);res={}
log('Live round_enc ends: S2 -> bar_mix (encore). Boundary map per staff: y=S2(x) -> z=Bars(y) -> S_{r+1}(z ^ rk).')
# A. Exact Z/256 matrix of bar_mix on one staff (all 16 staves identical; bars are unkeyed)
M=np.zeros((8,8),dtype=int)
for i in range(8):
 g=[[0]*8 for _ in range(16)];g[0][i]=1;M[:,i]=N.bar_mix(g)[0]
for f in range(1,16):
 g=[[0]*8 for _ in range(16)]
 for i in range(8):g[f][i]=1+i
 assert N.bar_mix(g)[f]==N.bar_mix([[1+i for i in range(8)]]+[[0]*8]*15)[0]
log('Encore bar_mix matrix (row=output beat, col=input beat, mod 256):');[log('  ',list(map(int,r))) for r in M]
rows=[int((r!=0).sum()) for r in M];cols=[int((M[:,i]!=0).sum()) for i in range(8)]
log('Nonzero inputs per output beat',rows,'| outputs fed per input beat',cols,'| min row support',min(rows),'(1 would mean a per-cell fused table)')
# connected blocks
adj=(M!=0);blk=[];seen=set()
for i in range(8):
 if i in seen:continue
 comp={i};ch=True
 while ch:
  ch=False
  for a in list(comp):
   for b in range(8):
    if (adj[a,b] or adj[b,a]) and b not in comp:comp.add(b);ch=True
 seen|=comp;blk.append(sorted(comp))
log('Bar mix connected blocks within a staff',blk,'-> beat pairs (2,3) and (4,5) are never joined by any bar line')
v2=lambda c:8 if c%256==0 else (c & -c).bit_length()-1
low=[[v2(int(M[j,i])) if M[j,i] else 8 for i in range(8)] for j in range(8)]
lsb_single=[j for j in range(8) if sum(1 for i in range(8) if M[j,i]%2==1)==1]
detail={j:dict(inputs=[i for i in range(8) if M[j,i]],low_bits_blind_to={i:low[j][i] for i in range(8) if M[j,i] and low[j][i]>0}) for j in range(8)}
log('Output beats whose LSB depends on exactly ONE input cell',lsb_single)
log('2-adic blindness: output j low k bits ignore input i when coef has 2^k factor',detail)
res['matrix']=M.tolist();res['row_support']=rows;res['col_support']=cols;res['blocks']=blk;res['lsb_single_input_outputs']=lsb_single;res['two_adic']=detail
# B. Empirical: one S2-output cell change -> how many next-S inputs change (all 15 boundaries, 32 contexts, all 128 cells)
B=Batch(SCH);mins=[];hist=collections.Counter()
for r in range(15):
 for t in range(32):
  y=rng.integers(0,256,(129,128),dtype=np.uint16);y[1:]=y[0]
  for c in range(128):y[1+c,c]^=int(rng.integers(1,256))
  z=bars_np(y.copy())^np.frombuffer(flat(SCH.rounds[r+1]['rk']),dtype=np.uint8)
  d=(z[1:]!=z[0]).sum(axis=1);hist.update(map(int,d))
log('Single S2-output cell change (random nonzero XOR) -> number of next-round S inputs changed, histogram over 15x32x128',dict(sorted(hist.items())))
res['single_cell_change_hist']=dict(hist)
# Explicit no-fusion witness: next-S output at beat j changes when only a PARTNER cell changes, x_j held fixed
witness={}
for j in range(8):
 partners=[i for i in range(8) if i!=j and M[j,i]]
 k=SCH.rounds[1];S2=np.array(SCH.rounds[0]['S2']);S=np.array(k['S']);key=flat(k['rk'])[j]
 xs=rng.integers(0,256,(4096,8));ys=S2[xs];zj=lambda yy:S[(yy@M[j])%256 ^ key]
 xs2=xs.copy();i=partners[0];xs2[:,i]=rng.integers(0,256,4096);changed=float((zj(S2[xs2])!=zj(ys)).mean())
 witness[j]=dict(partner=i,fraction_changed=round(changed,4))
log('Boundary r=1->2 face 0: next-S output at beat j with x_j fixed and one partner varied (fraction changed)',witness,'=> no per-cell boundary table exists')
res['no_fusion_witness']=witness
# C. Single-cell XOR differences that stay single-cell through the encore (probability over value + random context)
surv={}
for i in range(8):
 for d in range(1,256):
  y=rng.integers(0,256,(4096,128),dtype=np.uint16);y2=y.copy();y2[:,i]^=d
  a=(bars_np(y.copy())[:,:8]!=bars_np(y2)[:,:8]).sum(axis=1);p=float((a==1).mean())
  if p>0:surv[(i,d)]=p
det=[k for k,v in surv.items() if v==1.0]
log('Single-cell XOR differences through the encore that stay ONE cell: count with p>0',len(surv),'| deterministic (p=1)',[(i,hex(d)) for i,d in det])
top=sorted(surv.items(),key=lambda kv:-kv[1])[:10];log('Top survival probabilities',[(i,hex(d),round(p,3)) for (i,d),p in top])
res['single_cell_survivors']={f'{i}:{d:#04x}':p for (i,d),p in surv.items()};res['deterministic_single_cell']=[f'{i}:{d:#04x}' for i,d in det]
# D. 16-bit super-box for block {3,4}: (x3,x4) -> S2 -> (y3+3y4, y3+4y4) -> ^k -> S_{r+1}; single-cell input differences, all 65536 inputs
def superbox(r,f,pair=(3,4)):
 S2=np.array(SCH.rounds[r]['S2'],dtype=np.int64);S=np.array(SCH.rounds[r+1]['S'],dtype=np.int64);k=flat(SCH.rounds[r+1]['rk'])
 a,b=pair;x=np.arange(65536);x3,x4=x>>8,x&255
 def F(x3,x4):
  y3,y4=S2[x3],S2[x4];return (S[((y3+3*y4)&255)^k[f*8+a]]<<8)|S[((y3+4*y4)&255)^k[f*8+b]]
 out=F(x3,x4);best=0;bestd=None;single=0;tot=0;rows=[]
 for side in (0,1):
  for d in range(1,256):
   o2=F(x3^d,x4) if side==0 else F(x3,x4^d);dd=out^o2;c=np.bincount(dd,minlength=65536);m=int(c.max())
   if m>best:best,bestd=m,(('x3','x4')[side],d,int(c.argmax()))
   s=int((((dd>>8)==0)|((dd&255)==0)).sum());single+=s;tot+=65536;rows.append(s)
 return best,bestd,single/tot,max(rows)/65536
def randperm_baseline(seed):
 P=np.random.default_rng(seed).permutation(65536);x=np.arange(65536);best=0
 for side in (0,1):
  for d in range(1,256):
   dd=P[x]^P[x^(d<<8 if side==0 else d)];best=max(best,int(np.bincount(dd,minlength=65536).max()))
 return best
sb=[]
for r in range(15):
 for f in (0,9):
  best,bd,sf,smax=superbox(r,f);sb.append(dict(boundary=r+1,face=f,ddt_max_single_cell_inputs=best,at=bd,mean_single_cell_out_frac=round(sf,6),max_single_cell_out_frac=round(smax,6)))
  log('Super-box {3,4}',sb[-1])
base=[randperm_baseline(s) for s in range(4)]
log('Matched random 16-bit permutation baseline (same 510 single-cell input diffs) DDT max',base,'| uniform 1-active output fraction ~',round(2*255/65535,6))
log('Super-box single-cell-input DDT max range',min(s['ddt_max_single_cell_inputs'] for s in sb),max(s['ddt_max_single_cell_inputs'] for s in sb),'/65536')
res['superbox34']=sb;res['superbox_random_baseline']=base
# E. Fusion check as in the previous report but with the live encore: S_{r+1}(S2_r(x)^k) is no longer what the cipher computes
ok=0
for r in range(15):
 x=rng.integers(0,256,(1,128),dtype=np.uint16);g=N.bytes_to_grid(bytes(x[0].astype(np.uint8)))
 # apply S2 of round r then encore then key r+1 then S r+1 via live functions vs naive fused per-cell table
 y=[[SCH.rounds[r]['S2'][v] for v in row] for row in g];live=[[SCH.rounds[r+1]['S'][v] for v in row] for row in N.xor_grid(N.bar_mix(y),SCH.rounds[r+1]['rk'])]
 naive=[[SCH.rounds[r+1]['S'][v] for v in row] for row in N.xor_grid(y,SCH.rounds[r+1]['rk'])]
 ok+=sum(a!=b for ra,rb in zip(live,naive) for a,b in zip(ra,rb))
log('Cells where the old per-cell fused table S_{r+1}(S2_r(x)^k) disagrees with the live boundary (15 boundaries x 128 cells)',ok,'/1920')
res['naive_fused_disagree']=ok
log('Verdict: no single-cell fused S-box remains (min row support 2). Fusion moved up to per-staff super-boxes on blocks',blk,'with no bar joining beats 2-3 or 4-5; low bits and some 0x40/0x80/0xC0 differences still pass the encore as one cell.')
log.save(res)
