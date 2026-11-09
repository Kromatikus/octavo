from common import *
import collections,time,hashlib
log=Log('attack_siv_nonce');R=random.Random(7701);res={}
# 1. Determinism: same (seed,msg) -> identical blob
msgs=[R.randbytes(R.randrange(0,128)) for _ in range(200)]
same=sum(N.encrypt(m,SEED)==N.encrypt(m,SEED) for m in msgs);res['deterministic_identical']=f'{same}/200';log('Same seed+message -> identical 179-byte blob',same,'/200 (passive equality leak: repeated messages are visible)')
# 2. Distinct messages -> distinct nonces
t=time.time();ns=set();cnt=0
for i in range(200000):
 m=i.to_bytes(4,'big')+R.randbytes(R.randrange(0,60));ns.add(N.siv_nonce(m,SEED));cnt+=1
res['distinct_nonce']=dict(messages=cnt,distinct=len(ns));log('SIV nonces for',cnt,'distinct messages: distinct',len(ns),'(collision expected only near 2^64)')
d=[];base=b'attack at dawn';b0=N.siv_nonce(base,SEED)
for i in range(len(base)*8):
 m=bytearray(base);m[i//8]^=1<<(i%8);d.append(hw(b0,N.siv_nonce(bytes(m),SEED)))
d2=[hw(N.siv_nonce(b'',SEED),N.siv_nonce(bytes(L),SEED)) for L in range(1,128)]
res['nonce_bitflip_hw']=dict(mean=statistics.mean(d),min=min(d),max=max(d));log('1-bit message flip -> SIV nonce bits changed mean/min/max',round(statistics.mean(d),2),min(d),max(d),'/128 | zero-message length change mean',round(statistics.mean(d2),2))
# 3. Caller nonce must equal SIV nonce
target=N.encrypt(b'PIN=731',SEED);tn=target[3:19];rej=0;acc=[]
for p in range(1000):
 g=b'PIN=%03d'%p
 try:N.encrypt(g,SEED,nonce=tn);acc.append(g)
 except ValueError:rej+=1
rnd=0
for _ in range(1000):
 try:N.encrypt(b'PIN=731',SEED,nonce=R.randbytes(16))
 except ValueError:rnd+=1
res['caller_nonce']=dict(rejected=rej,accepted=[a.decode() for a in acc],random_nonce_for_true_msg_rejected=rnd);log('encrypt(guess, nonce=target_nonce): rejected',rej,'/1000, accepted only',acc,'| random caller nonce for the true message rejected',rnd,'/1000')
log('NOTE: the ValueError itself is an oracle: if a caller can pass nonce=target_nonce, "no ValueError" confirms the guess (accepted list above) -- same power as comparing blobs.')
# 4. Dictionary / PIN via deterministic encryption oracle (EXPECTED to still work)
t=time.time();found=None;tries=0
for p in range(1000):
 tries+=1
 if N.encrypt(b'PIN=%03d'%p,SEED)==target:found=p;break
res['pin_blob_compare']=dict(found=found,guesses=tries,seconds=round(time.time()-t,2));log('Dictionary via encrypt(guess)==target_blob: found PIN',found,'after',tries,'guesses',round(time.time()-t,2),'s')
# Nonce-only comparison is enough (cheaper; still needs the secret clef via an oracle)
tries=0;found2=None
for p in range(1000):
 tries+=1
 if N.siv_nonce(b'PIN=%03d'%p,SEED)==tn:found2=p;break
res['pin_nonce_compare']=dict(found=found2,guesses=tries);log('Same with only the public nonce field: PIN',found2,'after',tries,'(needs clef = seed-holder/oracle access)')
# Offline (no oracle): try nonce = SHA-256(guess_clef || block) with seedless clef guesses
off=0
for _ in range(2000):
 c=R.randbytes(16)
 for p in (731,):off+=hashlib.sha256(c+N.encode_block(b'PIN=%03d'%p)).digest()[:16]==tn
for c in [bytes(16),b'SN2'+bytes(13),hashlib.sha256(b'SN2').digest()[:16]]:off+=hashlib.sha256(c+N.encode_block(b'PIN=731')).digest()[:16]==tn
res['offline_without_clef']=off;log('Offline guess check WITHOUT the clef (2003 clef guesses, true PIN):',off,'matches -> no offline dictionary without the seed-derived clef')
# 5. Not keystream reuse
xs=0;wts=[]
for _ in range(300):
 a,b=R.randbytes(R.randrange(0,128)),R.randbytes(R.randrange(0,128));ca,cb=N.encrypt(a,SEED)[19:147],N.encrypt(b,SEED)[19:147]
 xs+=bytes(x^y for x,y in zip(ca,cb))==bytes(x^y for x,y in zip(N.encode_block(a),N.encode_block(b)));wts.append(hw(ca,cb))
res['xor_keystream']=dict(holds=xs,pairs=300,mean_ct_xor_weight=statistics.mean(wts));log('ct1^ct2 == pt1^pt2 holds',xs,'/300; mean ct XOR weight',round(statistics.mean(wts),2),'/1024')
# 6. Wrong nonce stuffed into a blob
hello=N.encrypt(b'hello world',SEED);other=N.encrypt(b'attack at dawn',SEED);_,n1,c1,t1=N.split_blob(hello);_,n2,c2,t2=N.split_blob(other)
def classify(b):
 try:N.decrypt(b,SEED);return 'accepted'
 except N.AuthError as e:return 'AuthError:'+str(e)
 except N.DecodeError:return 'DecodeError'
c=collections.Counter();c[classify(b'SN2'+n2+c1+t1)]+=1;c[classify(b'SN2'+R.randbytes(16)+c1+t1)]+=1
for _ in range(200):c[classify(b'SN2'+R.randbytes(16)+c1+t1)]+=1
res['wrong_nonce_old_tag']=dict(c);log('Wrong nonce + original tag (seedless):',dict(c))
# Key-holder constructions (NOT attacks): recomputed valid tag with a non-SIV nonce
clef=N.staff_clef(SEED);c=collections.Counter()
for i in range(256):
 n=R.randbytes(16);s=N.Schedule(SEED,n);ct=flat(N.encrypt_grid(N.bytes_to_grid(N.encode_block(b'hello world')),s))
 c[classify(b'SN2'+n+ct+N._tag(s.mac_key,n,ct,clef))]+=1
res['keyholder_nonSIV_nonce_valid_tag']=dict(c);log('KEY-HOLDER: well-formed hello world under random non-SIV nonce + recomputed valid tag ->',dict(c))
c=collections.Counter()
for i in range(256):
 n=R.randbytes(16);s=N.Schedule(SEED,n);c[classify(b'SN2'+n+c1+N._tag(s.mac_key,n,c1,clef))]+=1
res['keyholder_swapped_nonce_valid_tag']=dict(c);log('KEY-HOLDER: hello ct under random nonce + recomputed tag ->',dict(c))
log('Summary: SIV binds nonce to message; reuse with different messages is impossible through encrypt(); equality of identical messages and oracle dictionary attacks remain (expected for deterministic AE).')
log.save(res)
