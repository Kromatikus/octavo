from common import *
import collections,inspect,time
log=Log('attack_integrity');R=random.Random(4401);res={}
src=inspect.getsource(N.decrypt)
log('Source order check: tag compare line precedes decrypt_grid line:',src.index('compare_digest(tag')<src.index('decrypt_grid('),'| SIV check after decode:',src.index('SIV nonce mismatch')>src.index('decrypt_grid('))
# In-process instrumentation only (file untouched): count decrypt_grid entries; memoize the demo-nonce schedule.
calls=[0];_dg=N.decrypt_grid
def dg(*a,**k):calls[0]+=1;return _dg(*a,**k)
N.decrypt_grid=dg
_S=N.Schedule
def S(seed,nonce):return SCH if (bytes(seed) if not isinstance(seed,int) else seed.to_bytes(128,'big'))==SEED and nonce==NONCE else _S(seed,nonce)
N.Schedule=S
def classify(b):
 try:return 'accepted:'+N.decrypt(b,SEED).hex()
 except N.AuthError as e:return 'AuthError:'+str(e)
 except N.DecodeError:return 'DecodeError'
valid=N.encrypt(b'hello world',SEED);assert valid==bytes.fromhex(open('/workspace/sneak_n2/hello-world.txt').read().split('blob (179 bytes')[1].split(': ')[1].split()[0])
log('Demo blob reproduces hello-world.txt; decrypts to',N.decrypt(valid,SEED))
other=N.encrypt(b'attack at dawn',SEED)
def run(name,blobs):
 c0=calls[0];cnt=collections.Counter(classify(b).split(':')[0] for b in blobs);reasons=None
 row=dict(test=name,n=len(blobs),counts=dict(cnt),decrypt_grid_calls=calls[0]-c0);res[name]=row;log(row);return row
t=time.time()
run('random 179-byte',[R.randbytes(179) for _ in range(200000)])
run('SN2 + random nonce/ct/tag',[b'SN2'+R.randbytes(176) for _ in range(1000)])
run('SN2 + real nonce + random ct/tag',[b'SN2'+NONCE+R.randbytes(160) for _ in range(10000)])
flips=[]
for i in range(179*8):
 b=bytearray(valid);b[i//8]^=1<<(i%8);flips.append(bytes(b))
r=run('all single-bit flips',flips)
byregion=collections.Counter();
for i,b in enumerate(flips):
 k=classify(b);reg='version' if i<24 else 'nonce' if i<152 else 'ct' if i<1176 else 'tag';byregion[(reg,k.split(':')[0])]+=1
log('bit flips by region',{f'{a}/{b}':v for (a,b),v in sorted(byregion.items())})
res['bitflip_regions']={f'{a}/{b}':v for (a,b),v in byregion.items()}
for reg,(lo,hi) in {'nonce':(3,19),'ct':(19,147),'tag':(147,179)}.items():
 bl=[]
 for _ in range(3000):
  b=bytearray(valid);p=R.randrange(lo,hi);b[p]^=R.randrange(1,256);bl.append(bytes(b))
 run(f'random byte change in {reg}',bl)
v1,n1,c1,t1=N.split_blob(valid);v2,n2,c2,t2=N.split_blob(other)
run('splices (nonce/ct/tag mixed between two valid blobs)',[v1+n1+c2+t1,v1+n1+c1+t2,v1+n2+c1+t1,v1+n2+c2+t1,v1+n1+c2+t2,v1+n2+c1+t2])
run('truncations 0..178',[valid[:i] for i in range(179)])
run('extensions +1..32',[valid+R.randbytes(i) for i in range(1,33)])
run('seedless random tags on real nonce+ct',[v1+n1+c1+R.randbytes(32) for _ in range(20000)])
# Seedless "structured" tag guesses: wrong-seed tags, old transcript without clef under a wrong seed, zero clef.
ws=[R.randbytes(128) for _ in range(64)];g=[]
for w in ws:
 mk=N.StaffSponge(b'M',w,n1).take(32);g+= [v1+n1+c1+N._tag(mk,n1,c1,N.staff_clef(w)),v1+n1+c1+N._tag(mk,n1,c1,bytes(16))]
run('wrong-seed / zero-clef tag guesses',g)
# Key-holder sanity (NOT an attack): valid MAC over a malformed block -> DecodeError; reached decrypt_grid by design.
mk=SCH.mac_key;clef=N.staff_clef(SEED);bad=flat(N.encrypt_grid(N.bytes_to_grid(bytes([200])+bytes(127)),SCH))
run('KEY-HOLDER: valid tag, malformed block (expect DecodeError)',[b'SN2'+NONCE+bad+N._tag(mk,NONCE,bad,clef)])
fresh=sum(r['n'] for k,r in res.items() if isinstance(r,dict) and 'n' in r and not k.startswith('KEY-HOLDER'))
fa=sum(v for k,r in res.items() if isinstance(r,dict) and 'counts' in r and not k.startswith('KEY-HOLDER') for kk,v in r['counts'].items() if kk!='AuthError')
fc=sum(r['decrypt_grid_calls'] for k,r in res.items() if isinstance(r,dict) and 'decrypt_grid_calls' in r and not k.startswith('KEY-HOLDER'))
log('TOTAL fresh invalid inputs',fresh,'non-AuthError outcomes',fa,'decrypt_grid calls',fc,'elapsed s',round(time.time()-t,1))
res['total']=dict(fresh=fresh,non_auth=fa,decrypt_grid_calls=fc)
N.decrypt_grid=_dg;N.Schedule=_S
log('No fresh tag forgery found. Random-tag tests are sanity checks, not a proof of HMAC security.')
log.save(res)
