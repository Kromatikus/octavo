"""Spot-check key schedule domain separation / 1-bit avalanche and confirm no AES in the LIVE library."""
from common import *
import re
log=Log('attack_schedule_noaes');res={};R=random.Random(77)
base=N.Schedule(SEED,NONCE);mb=base.material();clef=N.staff_clef(SEED)
def flipb(b,i):b=bytearray(b);b[i//8]^=1<<(i%8);return bytes(b)
rows=[]
for kind in ('nonce','seed'):
 for _ in range(12):
  i=R.randrange(128 if kind=='nonce' else 1024)
  s=N.Schedule(flipb(SEED,i) if kind=='seed' else SEED,flipb(NONCE,i) if kind=='nonce' else NONCE)
  m=s.material();rows.append(dict(kind=kind,bit=i,material_bits_changed=hw(mb,m),of=len(mb)*8,mac_key_bits_changed=hw(base.mac_key,s.mac_key),
   sbox_same_r0=s.rounds[0]['S']==base.rounds[0]['S'],clef_bits_changed=hw(clef,N.staff_clef(flipb(SEED,i))) if kind=='seed' else 0))
res['flips']=rows
for kind in ('nonce','seed'):
 rr=[r for r in rows if r['kind']==kind]
 log(kind,'1-bit flips: material frac changed',[round(r['material_bits_changed']/r['of'],3) for r in rr],'| mac_key bits',[r['mac_key_bits_changed'] for r in rr],'| clef bits',[r['clef_bits_changed'] for r in rr])
M=N.StaffSponge(b'M',SEED,NONCE).take(32);K=N.StaffSponge(b'K',SEED,NONCE).take(32);C=N.StaffSponge(b'C',SEED,bytes(16)).take(32)
res['domains_distinct']=len({M,K,C})==3;res['clef_equals_K_or_M_for_zero_nonce']=clef in (N.StaffSponge(b'K',SEED,bytes(16)).take(16),N.StaffSponge(b'M',SEED,bytes(16)).take(16))
log('M/K/C domain outputs distinct:',res['domains_distinct'],'| clef collides with K/M for zero nonce:',res['clef_equals_K_or_M_for_zero_nonce'])
src=Path('/workspace/sneak_n2/sneak_n2.py').read_text()
AES_HEAD=bytes.fromhex('637c777bf26b6fc53001672bfed7ab76')
res['aes_sbox_bytes_in_source']=AES_HEAD.hex() in src.lower().replace('" "','').replace('"\n    "','')
res['sm4_table_head']=N.SM4_SBOX[:8].hex();res['sm4_is_aes']=N.SM4_SBOX==bytes(range(256)) or N.SM4_SBOX[:16]==AES_HEAD
res['aes_imports']=bool(re.search(r'\b(Crypto|cryptography|AES|aes)\b.*import|import .*\b(Crypto|cryptography)\b',src))
k=SCH.rounds[0];res['keyed_S_ddt_lat']=dict(ddt=N.ddt_max(k['S']),lat=N.lat_max(k['S']),S2_ddt=N.ddt_max(k['S2']))
res['inversion_family_note']='SM4 and AES S-boxes are both affine-equivalent to inversion in GF(2^8); same DDT 4 / LAT 16 class. Not AES, but same family.'
log('AES S-box head in source:',res['aes_sbox_bytes_in_source'],'| SM4 head',res['sm4_table_head'],'| AES/crypto imports:',res['aes_imports'],'| keyed S DDT/LAT',res['keyed_S_ddt_lat'])
log(res['inversion_family_note'])
log.save(res)
