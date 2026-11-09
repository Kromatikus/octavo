from common import *
import collections,inspect
log=Log('attack_integrity');R=random.Random(1108);rb=R.randbytes
# Cache only exact fixed-nonce schedules; unchanged decrypt still performs all checks.
orig=N.Schedule;cache={NONCE:SCH};counts=collections.Counter();decrypt_calls=[0]
def cached(seed,nonce):
 if nonce in cache and seed==SEED:return cache[nonce]
 return orig(seed,nonce)
N.Schedule=cached
orig_dec=N.decrypt_grid
def traced(*a,**kw):decrypt_calls[0]+=1;return orig_dec(*a,**kw)
N.decrypt_grid=traced
def err(blob):
 try:N.decrypt(blob,SEED);return 'accepted'
 except N.AuthError:return 'AuthError'
 except N.DecodeError:return 'DecodeError'
def test(name,blobs):
 c=collections.Counter(err(b) for b in blobs);counts[name]=dict(c);log(name,dict(c),'decrypt_grid calls cumulative',decrypt_calls[0])
def change(b,k):z=bytearray(b);z[k]^=R.randrange(1,256);return bytes(z)
demo=N.encrypt(b'hello world',SEED,NONCE)
log('Live 8-bit, five bars, second coloring; blob length',len(demo),'demo roundtrip',N.decrypt(demo,SEED)==b'hello world')
decrypt_calls[0]=0
log('Fixed public-nonce Schedule memoized in memory only; original decrypt and tag comparison unchanged. Random nonces use original full Schedule.')
test('random_179_200000',(rb(179) for _ in range(200000)))
test('SN2_random_nonce_1000',(b'SN2'+rb(176) for _ in range(1000)))
test('SN2_real_nonce_10000',(b'SN2'+NONCE+rb(160) for _ in range(10000)))
for name,lo,hi in [('version',0,3),('nonce',3,19),('ct',19,147),('tag',147,179)]:
 test('bitflip_'+name,(bytes(v^(1<<(k%8)) if i==k//8 else v for i,v in enumerate(demo)) for k in range(lo*8,hi*8)))
for name,lo,hi in [('nonce',3,19),('ct',19,147),('tag',147,179)]:test('bytechange_'+name,(change(demo,R.randrange(lo,hi)) for _ in range(3000)))
n2=rb(16);cache[n2]=orig(SEED,n2);other=N.encrypt(b'retreat at dusk',SEED,n2)
test('splice',[demo[:19]+other[19:147]+demo[147:],other[:19]+demo[19:],demo[:147]+other[147:],demo[:19]+other[19:]])
test('truncate',(demo[:k] for k in range(179)));test('extend',(demo+rb(k) for k in range(1,33)))
test('seedless_random_tags_20000',(demo[:147]+rb(32) for _ in range(20000)))
log('Outsider tests total',sum(sum(c.values()) for c in counts.values()),'decrypt_grid calls',decrypt_calls[0])
assert decrypt_calls[0]==0
bad=bytes([200])+bytes(127);ct=flat(N.encrypt_grid(N.bytes_to_grid(bad),SCH));log('Key-holder malformed block',err(b'SN2'+NONCE+ct+N._tag(SCH.mac_key,NONCE,ct)))
log('Source verifies compare_digest tag before decrypt_grid:',inspect.getsource(N.decrypt).index('compare_digest(tag')<inspect.getsource(N.decrypt).index('decrypt_grid'))
N.Schedule=orig;N.decrypt_grid=orig_dec
log.save(dict(tests=dict(counts),outsider_decrypt_calls=0))
