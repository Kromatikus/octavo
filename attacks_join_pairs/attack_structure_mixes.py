"""Encore / super-box / beat-connectivity after the joins, per-matrix even-coefficient leakage, and 0x80 high-bit trails.
White-box structural analysis on the LIVE library (linear layers are Z/256-linear, so their matrices are exact)."""
from common import *
log=Log('attack_structure_mixes');res={}
PJ=load_old('pj','/tmp/sneak_n2_pre_join_pairs/sneak_n2.py')
def v2(x):
 x&=255
 return 8 if x==0 else (x&-x).bit_length()-1
def staff_matrix(bars):
 M=np.zeros((8,8),dtype=np.int64)
 for j in range(8):
  row=[0]*8;row[j]=1
  for _,_,(a,b),A in bars:row[a],row[b]=(A[0][0]*row[a]+A[0][1]*row[b])&255,(A[1][0]*row[a]+A[1][1]*row[b])&255
  M[:,j]=row
 return M
def comps(M):
 # connected components of bipartite in/out graph of nonzero entries
 par=list(range(16))
 def f(x):
  while par[x]!=x:par[x]=par[par[x]];x=par[x]
  return x
 for k in range(8):
  for j in range(8):
   if M[k,j]%256:par[f(k)]=f(8+j)
 g={}
 for j in range(8):g.setdefault(f(8+j),[]).append(j)
 return sorted(g.values())
for name,bars in [('live_post_join',N.BARS),('pre_join',PJ.BARS)]:
 M=staff_matrix(bars)
 # cross-check with library bar_mix
 lib=N if name=='live_post_join' else PJ
 for j in range(8):
  g=[[0]*8 for _ in range(16)];g[0][j]=1;assert lib.bar_mix(g)[0]==list(M[:,j])
 sup={f'out{k}':[j for j in range(8) if M[k,j]] for k in range(8)}
 fwd={f'in{j}':[k for k in range(8) if M[k,j]] for j in range(8)}
 odd={f'out{k}':[j for j in range(8) if M[k,j]%2] for k in range(8)}
 r=dict(matrix=M.tolist(),v2=[[v2(x) for x in row] for row in M.tolist()],out_support=sup,in_reach=fwd,odd_coeff_support=odd,
  superbox_components=comps(M),min_row_support=min(len(s) for s in sup.values()),beat0_from_beat7=bool(M[0,7]),beat7_to_beat0=bool(M[0,7]))
 res['encore_'+name]=r
 log(f'[{name}] encore 8x8 per-staff matrix mod 256 (rows=out beat, cols=in beat):');[log('   ',row) for row in M.tolist()]
 log(f'[{name}] super-box components across S2 -> encore -> XOR rk -> S:',r['superbox_components'])
 log(f'[{name}] next-round S input depends on #S2 outputs: min {r["min_row_support"]}; supports',sup)
 log(f'[{name}] odd-coefficient (full 8-bit) supports',odd)
 log(f'[{name}] input beat reach',fwd)
# ---- per 2x2 matrix exhaustive XOR-difference single-cell crossing
U=np.arange(65536)//256;V=np.arange(65536)%256
mixres={}
for name,_,(i,j),A in N.BARS+(( 'mix2 butterfly/shell',None,(0,1),((1,1),(1,2))),):
 a,b,c,d=A[0][0],A[0][1],A[1][0],A[1][1];det=(a*d-b*c)&255
 o1=(a*U+b*V)&255;o2=(c*U+d*V)&255;tot=0;one=0;certain=[];best=[]
 for pos in (0,1):
  for dl in range(1,256):
   U2,V2=(U^dl,V) if pos==0 else (U,V^dl)
   p1=((a*U2+b*V2)&255)!=o1;p2=((c*U2+d*V2)&255)!=o2
   single=np.count_nonzero(p1^p2);tot+=65536;one+=single
   pr=single/65536
   if pr==1.0:certain.append(dict(input=('u','v')[pos],delta=hex(dl),only_output=('first' if np.all(p1) else 'second')))
   elif pr>0:best.append((pr,('u','v')[pos],hex(dl)))
 best.sort(reverse=True)
 mixres[name]=dict(pair=(i,j),matrix=A,det=det,all_odd=all(x%2 for x in (a,b,c,d)),even_coeffs=[x for x in (a,b,c,d) if x%2==0],
  frac_single_cell=round(one/tot,5),prob1_single_cell=certain,top_partial=best[:4])
 log(f'{name:22s} {A} det={det} even={mixres[name]["even_coeffs"]}: single-cell output with prob 1 for',[(x["input"],x["delta"],x["only_output"]) for x in certain],
     '| overall frac(single-cell | 1-cell XOR input)=',mixres[name]['frac_single_cell'],'| best partial',best[:2])
res['per_mix_2x2']=mixres
res['all_odd_impossible']='a,b,c,d all odd => ad and bc odd => det=ad-bc even => not invertible mod 256'
# ---- full staff encore: single-beat XOR deltas, exact over the 256 values of the active cell
M=np.array(res['encore_live_post_join']['matrix'])
X=np.arange(256);rows=[]
for j in range(8):
 for dl in (0x80,0x40,0xC0,0x20,0x01):
  dadd=((X^dl)-X)&255
  act=[int(np.count_nonzero((M[:,j][:,None]*dadd[None,:])&255,axis=0).min()),int(np.count_nonzero((M[:,j][:,None]*dadd[None,:])&255,axis=0).max())]
  rows.append(dict(in_beat=j,delta=hex(dl),active_out_min_max=act,out_with_0x80=[k for k in range(8) if (M[k,j]*0x80)&255] if dl==0x80 else None))
res['encore_single_beat_deltas']=rows
log('Encore, single input beat with XOR 0x80 -> output beats carrying 0x80 (prob 1):',{r['in_beat']:r['out_with_0x80'] for r in rows if r['delta']=='0x80'})
log('Encore, single input beat XOR delta -> #active output beats [min,max over cell value]:',[(r['in_beat'],r['delta'],r['active_out_min_max']) for r in rows])
# ---- round-level matrices (exact) for weave+butterfly+shell+bars (L_mid) and the encore (E)
def lin_matrix(fn):
 L=np.zeros((128,128),dtype=np.int64)
 for c in range(128):
  g=[[0]*8 for _ in range(16)];g[c//8][c%8]=1;L[:,c]=np.array(flat(fn(g)) if False else sum(fn(g),[]))
 return L
E=lin_matrix(N.bar_mix)
Lm=[lin_matrix(lambda g,k=k,r=r:N.bar_mix(N.shell_mix(N.staff_mix(N.weave(g,k['SH'],k['SV']),k['sigma']),k['bridge'],r))) for r,k in enumerate(SCH.rounds[:4])]
def boolmul(A,B):return ((A.astype(np.int64)@B.astype(np.int64))>0)
SE=(E%256)!=0;SL=[(L%256)!=0 for L in Lm]
conn={}
cur=np.eye(128,dtype=bool)
for r in range(4):
 cur=boolmul(SE,boolmul(SL[r],cur))   # S cellwise full; one round = E . Lmid (S layers do not change cell support)
 conn[r+1]=dict(pairs_dependent=int(cur.sum()),of=128*128,min_inputs_per_output=int(cur.sum(1).min()),min_outputs_per_input=int(cur.sum(0).min()))
 log(f'Cell-support after {r+1} round(s) (white-box, S treated as full per cell): {conn[r+1]}')
res['round_cell_support']=conn
mid=SL[0];res['Lmid_r0']=dict(min_outputs_per_input=int(mid.sum(0).min()),max=int(mid.sum(0).max()),min_inputs_per_output=int(mid.sum(1).min()))
log('L_mid round 0 (weave+butterfly+shell+7 bars): S-output cell reaches S2 cells min/max',res['Lmid_r0'])
# ---- 0x80 high-bit trails: all diffs 0x80, deterministic through Z/256 linear layers; each S/S2 must map 0x80->0x80
def prop80(L,A):
 v=np.zeros(128,dtype=np.int64);v[list(A)]=1
 return set(np.nonzero((L@v)%2)[0].tolist())
def ddt(S,a,b):return sum(1 for x in range(256) if S[x]^S[x^a]==b)
D=[dict(S=ddt(k['S'],0x80,0x80),S2=ddt(k['S2'],0x80,0x80),Sbest=max(ddt(k['S'],a,0x80) for a in range(1,256))) for k in SCH.rounds[:3]]
log('DDT entries (out of 256) for 0x80->0x80, rounds 0-2:',D)
mins=[len(prop80(Lm[0],{c})) for c in range(128)]
res['Lmid_0x80_r0']=dict(min_S2_active_from_one_S_output_cell=min(mins),cells_hitting_exactly_one=[c for c in range(128) if mins[c]==1])
log('0x80 at ONE round-0 S output -> S2 inputs carrying 0x80 (prob 1): min',min(mins),'; S-output cells that hit exactly one S2 cell:',res['Lmid_0x80_r0']['cells_hitting_exactly_one'],'(see attack_highbit_trail.py)')
log('Note: all-0x80 trails need DDT[0x80->0x80]>0 at every active S/S2; above it is 0 for S,S2 in rounds 0-1, so the exact all-0x80 trail dies; the truncated version in attack_highbit_trail.py does not need it.')
# Encore alone: S2 output 0x80 in one cell -> # next-round S boxes hit (prob 1)
hit=[len(prop80(E,{c})) for c in range(128)]
res['encore_0x80_hits']=dict(min=min(hit),max=max(hit),per_beat=[len(prop80(E,{b})) for b in range(8)])
log('S2 output 0x80 in one cell -> next-round S inputs carrying 0x80 (prob 1): per beat',res['encore_0x80_hits']['per_beat'])
np.save(HERE/'Lmid_r0.npy',Lm[0])
log.save(res)
