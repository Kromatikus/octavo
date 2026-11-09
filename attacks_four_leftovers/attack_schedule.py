from common import *
verify_live()
import ast
res={'started':now()};base=SCH;mb=base.material();clef=N.staff_clef(SEED);ks=N.key_signature(SEED);rng=random.Random(78)
def flip(b,i):a=bytearray(b);a[i//8]^=1<<(i%8);return bytes(a)
rows=[]
for kind in ('nonce','seed'):
 for i in rng.sample(range(128 if kind=='nonce' else 1024),32):
  seed=flip(SEED,i) if kind=='seed' else SEED;nonce=flip(NONCE,i) if kind=='nonce' else NONCE;s=N.Schedule(seed,nonce)
  rows.append({'kind':kind,'bit':i,'material_changed':hw(mb,s.material()),'material_total':len(mb)*8,'mac_key_changed':hw(base.mac_key,s.mac_key),'clef_changed':hw(clef,N.staff_clef(seed)),'key_sig_changed':hw(ks,N.key_signature(seed)),'S0_equal':s.rounds[0]['S']==base.rounds[0]['S']})
res['flips']=rows;res['summary']={}
for kind in ('nonce','seed'):
 rr=[x for x in rows if x['kind']==kind]
 res['summary'][kind]={'samples':len(rr),'material_fraction_range':[round(min(x['material_changed']/x['material_total'] for x in rr),4),round(max(x['material_changed']/x['material_total'] for x in rr),4)],
  'mac_key_bits_changed_range_of_256':[min(x['mac_key_changed'] for x in rr),max(x['mac_key_changed'] for x in rr)],'clef_bits_changed_range_of_128':[min(x['clef_changed'] for x in rr),max(x['clef_changed'] for x in rr)],'key_sig_bits_changed_range_of_128':[min(x['key_sig_changed'] for x in rr),max(x['key_sig_changed'] for x in rr)],'S0_equal_count':sum(x['S0_equal'] for x in rr)}
res['domains_distinct']=len({N.StaffSponge(d,SEED,NONCE).take(32) for d in (b'M',b'K')}|{N.StaffSponge(b'C',SEED,bytes(16)).take(32),N.StaffSponge(b'G',SEED,N.mix_description()).take(32)})==4
res['key_sig']=ks.hex();res['key_sig_in_blob']=ks in HB;res['mix_description_sha256']=hashlib.sha256(N.mix_description()).hexdigest()
tree=ast.parse(Path(N.__file__).read_text());imports=[]
for node in ast.walk(tree):
 if isinstance(node,ast.Import):imports.extend(x.name for x in node.names)
 if isinstance(node,ast.ImportFrom):imports.append(node.module)
res['source_imports']=imports;res['sm4_head']=N.SM4_SBOX[:16].hex();res['starts_d690e9fe']=N.SM4_SBOX[:4].hex()=='d690e9fe';res['not_aes_head']=N.SM4_SBOX[:4]!=bytes.fromhex('637c777b')
spec=importlib.util.spec_from_file_location('sm4_readonly_check','/workspace/sneak_n2/sm4_vector_check.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
res['SM4_reference_vectors_pass']=mod.sm4_table_ok(N.SM4_SBOX)
sp={}
for r in (0,1,15):
 k=base.rounds[r];sp[f'round{r}']={'S_ddt_max':N.ddt_max(k['S']),'S_lat_max':N.lat_max(k['S']),'S2_ddt_max':N.ddt_max(k['S2']),'S2_lat_max':N.lat_max(k['S2'])}
res['spectra']={'base_SM4_ddt_max':N.ddt_max(N.SM4_SBOX),'base_SM4_lat_max':N.lat_max(N.SM4_SBOX),**sp}
res['family_disclosure']='SM4 and AES S-boxes are both affine-equivalent to inversion over GF(2^8). "Not AES" does not mean an unrelated algebraic family; keyed affine wrapping preserves DDT/LAT spectra exactly.'
res['finished']=now();save('attack_schedule',res);print(json.dumps({k:v for k,v in res.items() if k!='flips'},indent=1))
