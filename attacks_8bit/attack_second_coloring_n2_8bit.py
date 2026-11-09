from common import *
import importlib.util,collections,re
log=Log('attack_second_coloring');R=random.Random(223);rng=np.random.default_rng(223);results={}
# Exhaustive DDT for byte maps, implemented locally as accelerator; crosschecked live helper.
xx=np.arange(256,dtype=np.uint16);aa=np.arange(1,256,dtype=np.uint16)
def ddt(s):
 s=np.array(s,dtype=np.uint16);diff=s[xx][None,:]^s[aa[:,None]^xx];keys=(np.arange(255)[:,None]*256+diff).ravel();return int(np.bincount(keys,minlength=255*256).max())
assert ddt(SCH.rounds[0]['S'])==N.ddt_max(SCH.rounds[0]['S'])
def affine(s):
 t=np.array(s,dtype=np.uint16)^s[0];pred=np.zeros(256,dtype=np.uint16)
 for b in range(8):pred^=((xx>>b)&1)*t[1<<b]
 return bool(np.array_equal(t,pred))
all_ddt=[];summ=[]
for r in range(15):
 k=SCH.rounds[r];nxt=SCH.rounds[r+1];keys=set(flat(nxt['rk']));ds=[];aff=0
 for key in keys:
  comp=[nxt['S'][k['S2'][x]^key] for x in range(256)];ds.append(ddt(comp));aff+=affine(comp)
  # This explicitly IS one byte permutation; a fused table reproduces boundary exactly.
  assert len(set(comp))==256
 rep=flat(nxt['rk'])[0];comp=[nxt['S'][k['S2'][x]^rep] for x in range(256)]
 row=dict(boundary=r+1,distinct_actual_key_bytes=len(keys),affine_compositions=aff,ddt_min=min(ds),ddt_max=max(ds),ddt_equal4=sum(v==4 for v in ds),representative_lat=N.lat_max(comp));summ.append(row);all_ddt+=ds;log('Boundary S_next(S2_current(x) xor key)',row)
results['boundaries']=summ
log('Total boundary maps',len(all_ddt),'DDT range',min(all_ddt),max(all_ddt),'base SM4 DDT4. DDT>4 proves not affine-equivalent to SM4. Every pair DOES fuse into one arbitrary 8-bit S-box; no extra diffusion separates these two layers.')
checks=0
for nonce in [NONCE]+[R.randbytes(16) for _ in range(16)]:
 s=SCH if nonce==NONCE else N.Schedule(SEED,nonce)
 for k in s.rounds:assert k['S2']!=k['S'];checks+=1
log('S2 distinct from S',checks,'/',checks,'17 schedules')
# Exhaustively verify low-bit and high-difference structure in each modular pair map.
trails=[]
for name,M in [('mix2',((1,1),(1,2)))]+[(n,M) for n,_,_,M in N.BARS]:
 good=0;lsb=0
 for u in range(256):
  for v in range(256):
   a,b=N.bar_apply(M,u,v);c,d=N.bar_apply(M,u^128,v)
   good+=((a^c,b^d)==((M[0][0]&1)*128,(M[1][0]&1)*128))
   lsb+=((a&1,b&1)==(((M[0][0]&1)*(u&1)^(M[0][1]&1)*(v&1)),((M[1][0]&1)*(u&1)^(M[1][1]&1)*(v&1))))
 row=dict(name=name,msb_trail=good,lsb_linear=lsb,total=65536);trails.append(row);log('Mod256 mix trail',row)
results['mix_trails']=trails
for label in ['S','S2']:
 counts=[];allmsb=0
 for k in SCH.rounds:
  s=k[label];hist=collections.Counter(s[x]^s[x^128] for x in range(256));counts.append(max(hist.values()));allmsb+=hist.get(128,0)
 log('Through',label,'fixed delta128 max exact output-difference count range',min(counts),max(counts),'/256; delta128->128 occurrences across16boxes',allmsb,'/4096. Deterministic high-bit trails do not persist through a coloring.')
# Legacy same-length same-version blobs authenticate under current M domain.
oldpath=Path('/tmp/sneak_n2_8bit_precolor2/sneak_n2.py')
if oldpath.exists():
 spec=importlib.util.spec_from_file_location('old_precolor2',str(oldpath));old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old);osch=old.Schedule(SEED,NONCE)
 log('Legacy snapshot loaded read-only',str(oldpath),'same MAC key',osch.mac_key==SCH.mac_key)
 txt=oldpath.with_name('hello-world.txt').read_text();demo=bytes.fromhex(re.search(r"blob .*?: ([0-9a-f]+)",txt).group(1))
 def classify(blob):
  try:return 'accepted',N.decrypt(blob,SEED)
  except N.AuthError:return 'AuthError',None
  except N.DecodeError:return 'DecodeError',None
 orig=N.Schedule
 N.Schedule=lambda seed,nonce:SCH if seed==SEED and nonce==NONCE else orig(seed,nonce)
 try:
  log('Archived old hello-world blob current result',classify(demo)[0]);cnt=collections.Counter();validtags=0;witness=[]
  for i in range(2048):
   msg=R.randbytes(127);ct=old.grid_to_bytes(old.encrypt_grid(old.bytes_to_grid(old.encode_block(msg)),osch));tag=old._tag(osch.mac_key,NONCE,ct);blob=b'SN2'+NONCE+ct+tag
   validtags+=N._tag(SCH.mac_key,NONCE,ct)==tag;kind,decoded=classify(blob);cnt[kind]+=1
   if kind=='accepted':
    witness.append(dict(index=i,old_message_hex=msg.hex(),current_decoded_hex=decoded.hex(),blob_hex=blob.hex()));assert decoded!=msg
  log('Legacy generated2048 valid old blobs',dict(cnt),'current HMAC verifies',validtags,'wrong plaintext accepts',len(witness))
  results['legacy']=dict(counts=dict(cnt),valid_tags=validtags,trials=2048,witnesses=witness)
 finally:N.Schedule=orig
else:log('Legacy snapshot absent; legacy test not run')
log('Not a fresh HMAC forgery: authenticated legacy ciphertext replay / unversioned-algorithm ambiguity. No full16round current plaintext/key recovery.')
log.save(results)
