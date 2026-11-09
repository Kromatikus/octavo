from common import *
log=Log('attack_schedule');R=random.Random(6122);rb=R.randbytes
def material(s):
 b=bytearray()
 for k in s.rounds:
  b.extend(flat(k['rk']))
  for name in ['A1','A2','A3','A4']:b.extend(k[name])
  b.extend(k[n] for n in ['b1','b2','b3','b4']);b.extend(k['SH']);b.extend(k['SV'])
  for row in k['sigma']:b.extend(row)
  b.extend(k['bridge'])
 b.extend(flat(s.white));return bytes(b)
def full(seed,nonce):
 s=N.Schedule(seed,nonce);return material(s)+s.mac_key+N.staff_clef(seed)
def parts(seed,nonce):
 s=N.Schedule(seed,nonce);return dict(keys_white=s.material(),S_tables=bytes(v for k in s.rounds for v in k['S']),S2_tables=bytes(v for k in s.rounds for v in k['S2']),
  mac_key=s.mac_key,clef=N.staff_clef(seed),siv_nonce_hello=N.siv_nonce(b'hello world',seed))
def xor(*xs):return bytes(a^b^c^d for a,b,c,d in zip(*xs))
res={}
for typ in ['seed','nonce']:
 vals=[];cl=[]
 for _ in range(8):
  w=128 if typ=='seed' else 16;a,b,c=(rb(w) for _ in range(3));d=bytes(x^y^z for x,y,z in zip(a,b,c))
  ms=[full(q,NONCE) if typ=='seed' else full(SEED,q) for q in [a,b,c,d]]
  vals.append(sum(x.bit_count() for x in xor(*ms))/(8*len(ms[0])))
  if typ=='seed':cl.append(sum(x.bit_count() for x in xor(*[N.staff_clef(q) for q in [a,b,c,d]])))
 res['affine_'+typ]=vals;log('GF2 affine parallelogram over full material(+mac_key+clef)',typ,'violation fractions',[round(v,4) for v in vals],'(affine => 0)')
 if cl:res['clef_affine_violation_bits']=cl;log('C-domain clef alone: parallelogram violating bits of 128, 8 trials',cl)
# N1-style affine basis predictor over the C-domain clef and full material
zero=bytes(128);base=full(zero,NONCE);pred=bytearray(base);target=rb(128)
for i in range(1024):
 if target[i//8]>>(i%8)&1:
  e=bytearray(128);e[i//8]=1<<(i%8);m=full(bytes(e),NONCE)
  for j,(a,b) in enumerate(zip(m,base)):pred[j]^=a^b
act=full(target,NONCE);res['n1_predictor_wrong_bits']=[hw(pred,act),len(act)*8]
res['n1_predictor_clef_wrong_bits']=hw(pred[-16:],act[-16:])
log('N1 affine basis predictor, fresh seed: wrong bits',hw(pred,act),'/',len(act)*8,'| clef part wrong',hw(pred[-16:],act[-16:]),'/128')
# Avalanche: one seed bit flip (nonce fixed) and one nonce bit flip
bp=parts(SEED,NONCE);res['avalanche']={}
for typ,w in [('seed',128),('nonce',16)]:
 d={k:[] for k in bp}
 for bit in range(w*8):
  a=bytearray(SEED if typ=='seed' else NONCE);a[bit//8]^=1<<(bit%8)
  p=parts(bytes(a),NONCE) if typ=='seed' else parts(SEED,bytes(a))
  for k in bp:d[k].append(hw(bp[k],p[k])/(8*len(bp[k])))
 res['avalanche'][typ]={}
 for k,v in d.items():
  row=dict(mean=round(statistics.mean(v),5),min=round(min(v),5),max=round(max(v),5),n=len(v));res['avalanche'][typ][k]=row;log('avalanche',typ,'->',k,row)
# Domain separation M/K/C: same seed, nonce = 0^16 (the C-domain uses a zero nonce)
z=bytes(16);K=N.StaffSponge(b'K',SEED,z).take(4096);M=N.StaffSponge(b'M',SEED,z).take(4096);C=N.StaffSponge(b'C',SEED,z).take(4096)
clef=N.staff_clef(SEED)
row=dict(KM_equal_positions=sum(a==b for a,b in zip(K,M)),KC_equal_positions=sum(a==b for a,b in zip(K,C)),MC_equal_positions=sum(a==b for a,b in zip(M,C)),expected=16,
 clef_in_K_stream=clef in K,clef_in_M_stream=clef in M,clef_equals_mac_key_prefix_any_nonce0=clef==N.Schedule(SEED,z).mac_key[:16],
 clef_in_demo_schedule_material=clef in material(SCH),mac_key_in_material=SCH.mac_key in material(SCH))
res['domains']=row;log('Domain separation (nonce=0^16 for all three, the only place C could collide)',row)
log('clef == C-stream(seed, 0^16)[:16]:',N.staff_clef(SEED)==N.StaffSponge(b'C',SEED,z).take(16),'-> seed-only; one clef for every message (nonce flips change 0 clef bits, above)')
log('Preimage framing: SN2/ || 1-byte domain || ctr32 || 128-byte seed || 16-byte nonce: fixed lengths, no ambiguity across domains.')
log('No seed or clef recovery demonstrated. Failure of the affine model is not a proof of security; seed entropy still matters.')
log.save(res)
