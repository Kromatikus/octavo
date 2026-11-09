from common import *
import ast
res={'started':now()};base=SCH;mb=base.material();clef=N.staff_clef(SEED);rng=random.Random(77)
def flip(b,i):a=bytearray(b);a[i//8]^=1<<(i%8);return bytes(a)
rows=[]
for kind in ('nonce','seed'):
 for i in rng.sample(range(128 if kind=='nonce' else 1024),32):
  seed=flip(SEED,i) if kind=='seed' else SEED;nonce=flip(NONCE,i) if kind=='nonce' else NONCE;s=N.Schedule(seed,nonce)
  rows.append({'kind':kind,'bit':i,'material_changed':hw(mb,s.material()),'material_total':len(mb)*8,'mac_key_changed':hw(base.mac_key,s.mac_key),'clef_changed':hw(clef,N.staff_clef(seed)),'S0_equal':s.rounds[0]['S']==base.rounds[0]['S']})
res['flips']=rows
res['summary']={}
for kind in ('nonce','seed'):
 rr=[x for x in rows if x['kind']==kind];res['summary'][kind]={'samples':len(rr),'material_fraction_range':[min(x['material_changed']/x['material_total'] for x in rr),max(x['material_changed']/x['material_total'] for x in rr)],'mac_key_bit_range':[min(x['mac_key_changed'] for x in rr),max(x['mac_key_changed'] for x in rr)],'clef_bit_range':[min(x['clef_changed'] for x in rr),max(x['clef_changed'] for x in rr)]}
res['domains_distinct']=len({N.StaffSponge(b'M',SEED,NONCE).take(32),N.StaffSponge(b'K',SEED,NONCE).take(32),N.StaffSponge(b'C',SEED,bytes(16)).take(32)})==3
src=Path(N.__file__).read_text();tree=ast.parse(src);imports=[]
for node in ast.walk(tree):
 if isinstance(node,ast.Import):imports.extend(x.name for x in node.names)
 if isinstance(node,ast.ImportFrom):imports.append(node.module)
res['source_imports']=imports;res['sm4_head']=N.SM4_SBOX[:16].hex();res['not_aes_head']=N.SM4_SBOX[:16]!=bytes.fromhex('637c777bf26b6fc53001672bfed7ab76');res['field_polynomial']=hex(0x1f5)
res['measured_spectra']={'base_ddt_max':N.ddt_max(N.SM4_SBOX),'keyed_S_ddt':N.ddt_max(base.rounds[0]['S']),'keyed_S_LAT_abs_bias_count':N.lat_max(base.rounds[0]['S']),'keyed_S2_ddt':N.ddt_max(base.rounds[0]['S2'])}
res['family_disclosure']='SM4 and AES S-boxes are both affine-equivalent to inversion over GF(2^8). No AES S-box or AES MixColumns in this source; shared algebraic family is not a novel primitive or security proof.'
res['finished']=now();save('attack_schedule',res)
