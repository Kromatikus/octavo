from common import *
log=Log('attack_schedule');R=random.Random(122);rb=R.randbytes
# Include ALL serialized forward material; SI/SI2 are determined by S/S2 parameters.
def material(s):
 b=bytearray()
 for k in s.rounds:
  b.extend(flat(k['rk']))
  for name in ['A1','A2','A3','A4']:b.extend(k[name])
  b.extend(k[n] for n in ['b1','b2','b3','b4']);b.extend(k['SH']);b.extend(k['SV'])
  for row in k['sigma']:b.extend(row)
  b.extend(k['bridge'])
 b.extend(flat(s.white));return bytes(b)
def parts(s):return [s.material(),bytes(v for k in s.rounds for v in k['S']),bytes(v for k in s.rounds for v in k['S2']),material(s)]
def xor(*xs):return bytes(a^b^c^d for a,b,c,d in zip(*xs))
results={}
for typ in ['seed','nonce']:
 vals=[]
 for _ in range(8):
  w=128 if typ=='seed' else 16;a,b,c=(rb(w) for _ in range(3));d=bytes(x^y^z for x,y,z in zip(a,b,c))
  ms=[material(N.Schedule(q,NONCE) if typ=='seed' else N.Schedule(SEED,q)) for q in [a,b,c,d]]
  vals.append(sum(x.bit_count() for x in xor(*ms))/(8*len(ms[0])))
 results['affine_'+typ]=vals;log('GF2 affine parallelogram',typ,'8 trials violations fraction',vals,'linear would be 0')
zero=bytes(128);base=material(N.Schedule(zero,NONCE));pred=bytearray(base);target=rb(128)
for i in range(1024):
 if target[i//8]>>(i%8)&1:
  e=bytearray(128);e[i//8]=1<<(i%8);m=material(N.Schedule(bytes(e),NONCE))
  for j,(a,b) in enumerate(zip(m,base)):pred[j]^=a^b
actual=material(N.Schedule(target,NONCE));results['linear_prediction_wrong_bits']=hw(pred,actual);results['material_bits']=len(actual)*8
log('N1 affine basis inversion attempt: fresh random seed prediction wrong bits',hw(pred,actual),'/',len(actual)*8,'(all set-bit columns of full 1024-dimensional model used)')
baseparts=parts(SCH)
for typ,w in [('seed',128),('nonce',16)]:
 dist=[[] for _ in range(4)]
 for bit in range(w*8):
  a=bytearray(SEED if typ=='seed' else NONCE);a[bit//8]^=1<<(bit%8)
  s=N.Schedule(bytes(a),NONCE) if typ=='seed' else N.Schedule(SEED,bytes(a))
  for j,(u,v) in enumerate(zip(baseparts,parts(s))):dist[j].append(hw(u,v)/(8*len(u)))
 results['avalanche_'+typ]={}
 for name,ds in zip(['keys_white','S_tables','S2_tables','full_material'],dist):
  data=dict(mean=statistics.mean(ds),min=min(ds),max=max(ds),n=len(ds));results['avalanche_'+typ][name]=data;log('avalanche',typ,name,data)
k=N.StaffSponge(b'K',SEED,NONCE).take(4096);m=N.StaffSponge(b'M',SEED,NONCE).take(4096)
log('domain K/M same byte positions',sum(a==b for a,b in zip(k,m)),'/4096 expected 16; identical streams',k==m)
log('MAC key substring in full serialized schedule',SCH.mac_key in material(SCH))
log('Seed 8-byte chunks copied verbatim into K stream',sum(SEED[i:i+8] in k for i in range(121)))
# Direct xor leakage / related-input superposition already tested on the raw stream, separately from resampling.
a,b,c=rb(128),rb(128),rb(128);d=bytes(x^y^z for x,y,z in zip(a,b,c));streams=[N.StaffSponge(b'K',s,NONCE).take(4096) for s in [a,b,c,d]]
log('Raw K stream GF2-superposition violation bits',sum(v.bit_count() for v in xor(*streams)),'/32768')
log('distinct counter blocks',len(set(k[i:i+32] for i in range(0,4096,32))),'/128')
log('integer seed same material',material(N.Schedule(int.from_bytes(SEED,'big'),NONCE))==material(SCH))
log('No seed recovery demonstrated. Failure of this affine model is not a proof against all attacks or a 1024-bit security claim.')
log.save(results)
