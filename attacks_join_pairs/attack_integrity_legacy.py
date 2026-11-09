"""Integrity of the LIVE post-join N2 blob + replay of every older generation's blobs. Read-only on the live lib and old trees."""
from common import *
import collections,re,time,hmac
log=Log('attack_integrity_legacy');R=random.Random(20261108);res={}
def classify(b):
 try:return 'accepted',N.decrypt(b,SEED)
 except N.AuthError as e:return 'AuthError:'+str(e),None
 except N.DecodeError as e:return 'DecodeError:'+str(e),None
txt=Path('/workspace/sneak_n2/hello-world.txt').read_text()
HB=bytes.fromhex(re.search(r"blob \(179.*?: ([0-9a-f]+)",txt).group(1))
v,n,c,t=N.split_blob(HB)
res['hello']=dict(nonce=n.hex(),ct=c.hex(),tag=t.hex(),decrypts=N.decrypt(HB,SEED).decode(),reencrypt_identical=N.encrypt(b'hello world',SEED)==HB,
 siv_ok=n==N.siv_nonce(b'hello world',SEED))
log('Live hello-world:',res['hello'])
# 1. every single-bit flip of the 179-byte blob
cnt=collections.Counter();acc=[]
for i in range(len(HB)*8):
 b=bytearray(HB);b[i//8]^=1<<(i%8);k,m=classify(bytes(b));cnt[k]+=1
 if m is not None:acc.append(i)
res['bitflips']=dict(total=len(HB)*8,counts=dict(cnt),accepted=acc);log('All 1432 single-bit flips:',dict(cnt))
# 2. multi-byte random corruption of ct only
cnt=collections.Counter()
for _ in range(500):
 b=bytearray(HB);
 for _ in range(R.randrange(1,9)):b[R.randrange(19,147)]^=R.randrange(1,256)
 cnt[classify(bytes(b))[0]]+=1
res['ct_corrupt_500']=dict(cnt);log('500 random ct corruptions:',dict(cnt))
# 3. splicing between valid live blobs
blobs=[N.encrypt(R.randbytes(R.randrange(0,128)),SEED) for _ in range(40)]
cnt=collections.Counter()
for i in range(40):
 a=blobs[i];b=blobs[(i+1)%40]
 for mix in [a[:19]+b[19:],a[:19]+b[19:147]+a[147:],a[:147]+b[147:],a[:83]+b[83:147]+a[147:],a[:19]+a[83:147]+a[19:83]+a[147:]]:
  cnt[classify(mix)[0]]+=1
res['splices_200']=dict(cnt);log('200 splices (nonce/ct/tag/half-ct swaps):',dict(cnt))
# 4. random blobs, with and without correct prefix; truncation / extension
cnt=collections.Counter()
for _ in range(1000):cnt[classify(b'SN2'+R.randbytes(176))[0]]+=1
for _ in range(200):cnt[classify(R.randbytes(179))[0]]+=1
for L in (0,1,178,180,300):cnt[classify(HB[:L] if L<179 else HB+bytes(L-179))[0]]+=1
res['random_1205']=dict(cnt);log('1000 random SN2 blobs + 200 fully random + 5 bad lengths:',dict(cnt))
# 5. Old generations
gens=[('4bit_unlooped','/tmp/sneak_n2_4bit_unlooped'),('8bit_prebar','/tmp/sneak_n2_8bit_prebar'),('8bit_precolor2','/tmp/sneak_n2_8bit_precolor2'),
 ('pre_clef_encore_siv','/tmp/sneak_n2_pre_clef_encore_siv'),('pre_join_pairs_tmp','/tmp/sneak_n2_pre_join_pairs'),('testn3','/workspace/testn3')]
clef=N.staff_clef(SEED)
for tag,path in gens:
 m=load_old('old_'+tag,path+'/sneak_n2.py')
 demo=bytes.fromhex(re.search(r"blob \(\d+ bytes.*?: ([0-9a-f]+)",Path(path,'hello-world.txt').read_text()).group(1))
 row=dict(archived_len=len(demo),old_lib_decrypts=m.decrypt(demo,SEED).decode(),live_result=classify(demo)[0])
 if len(demo)==179:
  _,on,oc,ot=N.split_blob(demo);row['tag_valid_under_live_mac']=hmac.compare_digest(ot,N._tag(N.Schedule(SEED,on).mac_key,on,oc,clef))
 n_samp=2000 if tag in('pre_join_pairs_tmp',) else 300
 cnt=collections.Counter();wrong=[];t0=time.time();rt=0
 for i in range(n_samp):
  msg=R.randbytes(R.randrange(0,m.MAX_MSG+1));b=m.encrypt(msg,SEED)
  if i<20:rt+=m.decrypt(b,SEED)==msg
  k,p=classify(b);cnt[k]+=1
  if p is not None:wrong.append(dict(blob=b.hex(),msg=msg.hex(),got=p.hex()))
 row.update(sample=n_samp,old_roundtrip=f'{rt}/20',live_counts=dict(cnt),plaintexts_returned=len(wrong),wrong_plaintexts=wrong[:3],secs=round(time.time()-t0,1))
 res['legacy_'+tag]=row;log('Legacy',tag,row)
# expected arithmetic for the pre-join leftover
res['prejoin_expectation']=('A pre-join blob passes the live tag, decrypts under the post-join permutation to a ~random block. '
 'DecodeError unless b[0]<=127 and all bytes after 1+L are zero; the only realistic pass is b[0]==127 (prob 1/256), '
 'which then hits the SIV-nonce recheck (AuthError: SIV nonce mismatch) unless SHA-256 truncation matches (2^-128).')
log(res['prejoin_expectation'])
import hashlib
res['mac_key_unchanged_vs_prejoin']=load_old('pj','/tmp/sneak_n2_pre_join_pairs/sneak_n2.py').Schedule(SEED,n).mac_key==N.Schedule(SEED,n).mac_key
log('MAC key identical pre-join vs live (same nonce):',res['mac_key_unchanged_vs_prejoin'])
log.save(res)
