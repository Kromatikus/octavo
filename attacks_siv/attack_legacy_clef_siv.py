from common import *
import collections,re,time
log=Log('attack_legacy_clef');R=random.Random(5501);res={}
def classify(b):
 try:return 'accepted',N.decrypt(b,SEED)
 except N.AuthError as e:return 'AuthError:'+str(e),None
 except N.DecodeError:return 'DecodeError',None
log('Current tag transcript: HMAC(mac_key, clef || SN2 || nonce || ct); clef = StaffSponge(C, seed, 0^16).take(16), not in blob')
olds={}
for tag,path in [('precolor2','/tmp/sneak_n2_8bit_precolor2'),('pre_clef_encore_siv','/tmp/sneak_n2_pre_clef_encore_siv')]:
 m=load_old('old_'+tag,path+'/sneak_n2.py');olds[tag]=m
 txt=Path(path,'hello-world.txt').read_text();demo=bytes.fromhex(re.search(r"blob .*?: ([0-9a-f]+)",txt).group(1))
 v,n,c,t=N.split_blob(demo);osch=m.Schedule(SEED,n);sch=N.Schedule(SEED,n)
 row=dict(archived_blob_len=len(demo),old_decrypts_to=m.decrypt(demo,SEED).decode(),same_mac_key=osch.mac_key==sch.mac_key,
  old_tag_equals_current_tag=t==N._tag(sch.mac_key,n,c,N.staff_clef(SEED)),current_result=classify(demo)[0])
 res[tag+'_archived_hello']=row;log('Archived old hello-world from',path,row)
 # Corpus A: 2048 valid old blobs under ONE fixed old nonce (as in the 8-bit report), random 127-byte messages.
 cnt=collections.Counter();oldvalid=0;t0=time.time()
 _S=N.Schedule;N.Schedule=lambda s,nn,_n=n,_sch=sch:_sch if nn==_n else _S(s,nn)
 try:
  for i in range(2048):
   msg=R.randbytes(127);ct=m.grid_to_bytes(m.encrypt_grid(m.bytes_to_grid(m.encode_block(msg)),osch));blob=b'SN2'+n+ct+m._tag(osch.mac_key,n,ct)
   if i<64:oldvalid+=m.decrypt(blob,SEED)==msg
   cnt[classify(blob)[0]]+=1
 finally:N.Schedule=_S
 res[tag+'_fixed_nonce_2048']=dict(counts=dict(cnt),old_lib_roundtrip_checked=f'{oldvalid}/64');log(tag,'2048 valid old blobs (fixed nonce)',dict(cnt),'old-lib roundtrip',oldvalid,'/64',round(time.time()-t0,1),'s')
 # Corpus B: 512 valid old blobs via the OLD PUBLIC encrypt() with fresh random nonces and short messages.
 cnt=collections.Counter()
 for i in range(512):
  blob=m.encrypt(R.randbytes(R.randrange(0,128)),SEED);cnt[classify(blob)[0]]+=1
 res[tag+'_random_nonce_512']=dict(counts=dict(cnt));log(tag,'512 valid old blobs from old public encrypt() (random nonces)',dict(cnt))
# The 7 wrong-plaintext witnesses saved by the previous report.
w=json.loads(Path('/workspace/sneak_n2/attacks_8bit/attack_second_coloring_results.json').read_text())['legacy']['witnesses']
c=collections.Counter(classify(bytes.fromhex(x['blob_hex']))[0] for x in w);res['previous_7_witnesses']=dict(n=len(w),counts=dict(c));log('Previous report wrong-plaintext witnesses replayed against current code',len(w),dict(c))
# Can an OLD transcript tag ever equal a NEW one? Different HMAC message prefix (clef||SN2 vs SN2) => would be a fresh HMAC collision/forgery.
clef=N.staff_clef(SEED);log('Clef (white-box, 16 bytes) starts with b"SN2"?',clef[:3]==b'SN2')
# Downgrade direction (informational): current blobs fed to old decrypt (if a stale decoder is still deployed).
cnt=collections.Counter()
for tag,m in olds.items():
 for i in range(256):
  b=N.encrypt(R.randbytes(R.randrange(0,128)),SEED)
  try:m.decrypt(b,SEED);cnt[tag+':accepted']+=1
  except m.AuthError:cnt[tag+':AuthError']+=1
  except m.DecodeError:cnt[tag+':DecodeError']+=1
res['current_blobs_into_old_decoders']=dict(cnt);log('Current blobs into old decoders (stale-decoder direction)',dict(cnt))
log('Conclusion: replaying authenticated legacy blobs now fails at the tag. This is NOT a fresh forgery test; it shows the clef changes the MAC transcript. Old and current MAC keys are still identical; separation rests only on the clef prefix.')
log.save(res)
