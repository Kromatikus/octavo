"""Regression of every prior API-level finding on the beat-6-fix code: integrity, tag, SIV/nonce misuse, pickup, related nonce, slide, key-signature tamper."""
from common import *
import itertools, types, builtins, importlib.util
from collections import Counter
from unittest.mock import patch
verify_live();t0=time.time()
res={'started':now(),'live_sha':LIVE_SHA}
def outcome(blob):
 try:return 'ACCEPTED:'+repr(N.decrypt(blob,SEED))
 except N.AuthError as e:return 'AuthError: '+str(e)
 except N.DecodeError as e:return 'DecodeError: '+str(e)
 except Exception as e:return type(e).__name__+': '+str(e)
assert N.decrypt(HB,SEED)==b'hello world'
# ---- 1. integrity
flips=Counter()
for i in range(len(HB)*8):
 b=bytearray(HB);b[i//8]^=1<<(i%8);flips[outcome(bytes(b))]+=1
old={}
for d in ('/tmp/sneak_n2_pre_beat6','/tmp/sneak_n2_pre_beat7','/tmp/sneak_n2_pre_sig_gap','/tmp/sneak_n2_pre_latin_mix','/tmp/sneak_n2_pre_rotation_retune'):
 ob=bytes.fromhex(re.search(r'blob \(195 bytes.*?: ([0-9a-f]+)',Path(d+'/hello-world.txt').read_text()).group(1));old[ob[3:19].hex()]=outcome(ob)
fa,fb=N.split_blob(HB),N.split_blob(PREV_BLOB);spl=Counter()
for choice in itertools.product((0,1),repeat=4):
 if choice in ((0,0,0,0),(1,1,1,1)):continue
 spl[outcome(N.VERSION+b''.join((fa,fb)[c][i+1] for i,c in enumerate(choice)))]+=1
lens=Counter(outcome(HB[:n]) for n in range(len(HB)));lens.update(outcome(HB+x) for x in (b'\0',b'\0'*5,HB))
r=random.Random(21);rnd=Counter(outcome(N.VERSION+bytes(r.randrange(256) for _ in range(192))) for _ in range(200))
ctc=Counter()
for _ in range(500):
 b=bytearray(HB);b[N.CT0+r.randrange(128)]^=r.randrange(1,256);ctc[outcome(bytes(b))]+=1
tagt=Counter()
for _ in range(200):
 b=bytearray(HB);b[N.CT1+r.randrange(32)]^=r.randrange(1,256);tagt[outcome(bytes(b))]+=1
# seed-holder constructions (expected-access checks of the decrypt ordering, not attacks)
sch=N.Schedule(SEED,NONCE);clef=N.staff_clef(SEED);ks=N.key_signature(SEED)
blk=N.encode_block(b'hello worle');ct2=flat(N.encrypt_grid(N.bytes_to_grid(blk),sch))
siv_bad=N.VERSION+PICKUP+NONCE+ct2+N._tag(sch.mac_key,PICKUP,NONCE,ct2,clef,ks)
rct=bytes(r.randrange(256) for _ in range(128));dec_bad=N.VERSION+PICKUP+NONCE+rct+N._tag(sch.mac_key,PICKUP,NONCE,rct,clef,ks)
res['integrity']=dict(hello_pickup=PICKUP.hex(),hello_nonce=NONCE.hex(),single_bit_flips=dict(flips),older_samples=old,splices_with_previous=dict(spl),
 wrong_lengths=dict(lens),random_SN2_blobs=dict(rnd),ct_byte_corruptions_500=dict(ctc),tag_byte_corruptions_200=dict(tagt),
 seed_holder_valid_tag_wrong_siv=outcome(siv_bad),seed_holder_valid_tag_random_ct=outcome(dec_bad))
res['integrity']['any_accepted_or_decodeerror_without_seed']=any(k.startswith(('ACCEPTED','DecodeError')) for c in (flips,spl,lens,rnd,ctc,tagt) for k in c) or any(not v.startswith('AuthError') for v in old.values())
print('integrity',res['integrity']['any_accepted_or_decodeerror_without_seed'],dict(flips),old,flush=True)
# ---- 2. nonce / SIV misuse and pickup
mis={}
try:N.encrypt(b'hello world',SEED,nonce=NONCE);mis['caller_nonce_reuse']='accepted'
except ValueError as e:mis['caller_nonce_reuse']='ValueError: '+str(e)
try:N.encrypt(b'hello world',SEED,nonce=bytes(16));mis['caller_zero_nonce']='accepted'
except ValueError as e:mis['caller_zero_nonce']='ValueError: '+str(e)
pk=Counter();nn=set()
for _ in range(1000):
 b=N.encrypt(b'hello world',SEED);pk[b[3:19]]+=1;nn.add(b[19:35])
mis['1000_encryptions_same_msg']=dict(unique_pickups=len(pk),unique_nonces=len(nn))
# broken RNG model: fixed pickup -> deterministic (SIV) behaviour: equality leak only
with patch.object(N.os,'urandom',lambda n:bytes(n)):
 a1=N.encrypt(b'hello world',SEED);a2=N.encrypt(b'hello world',SEED);a3=N.encrypt(b'hello worle',SEED)
mis['fixed_pickup_model']=dict(same_msg_identical_blob=a1==a2,different_msg_same_nonce=a1[19:35]==a3[19:35],ct_byte_equal_count_between_two_msgs=sum(x==y for x,y in zip(a1[35:163],a3[35:163])),
 decrypts=[N.decrypt(a1,SEED),N.decrypt(a3,SEED)],note='If os.urandom were broken, equal messages give equal blobs (deterministic-AE equality leak); different messages still get different SIV nonces and unrelated ciphertexts.')
mis['decrypt_rejects_valid_tag_with_non_synthetic_nonce']=res['integrity']['seed_holder_valid_tag_wrong_siv']
res['nonce_pickup']=mis;print('nonce',mis['1000_encryptions_same_msg'],mis['fixed_pickup_model']['same_msg_identical_blob'],mis['fixed_pickup_model']['different_msg_same_nonce'],flush=True)
# ---- 3. related nonce and slide
def hd(a,b):return sum(bin(x^y).count('1') for x,y in zip(a,b))
rel=[];rngp=random.Random(5)
for _ in range(48):
 n1=bytes(rngp.randrange(256) for _ in range(16));bi=rngp.randrange(128);n2=bytearray(n1);n2[bi//8]^=1<<(bi%8)
 s1,s2=N.Schedule(SEED,n1),N.Schedule(SEED,bytes(n2))
 rel.append(dict(rk_hd=np.mean([hd(flat(a['rk']),flat(b['rk'])) for a,b in zip(s1.rounds,s2.rounds)]),S_agree=np.mean([sum(x==y for x,y in zip(a['S'],b['S'])) for a,b in zip(s1.rounds,s2.rounds)]),
  mac_hd=hd(s1.mac_key,s2.mac_key),white_hd=hd(flat(s1.white),flat(s2.white))))
res['related_nonce']={k:[round(float(np.mean([x[k] for x in rel])),3),round(float(np.std([x[k] for x in rel])),3)] for k in rel[0]}
res['related_nonce']['pairs']=48;res['related_nonce']['ideal']={'rk_hd':512,'S_agree':1,'mac_hd':128,'white_hd':512}
eq=Counter()
for _ in range(100):
 s=N.Schedule(SEED,bytes(rngp.randrange(256) for _ in range(16)))
 for a,b in itertools.combinations(range(16),2):
  A,Bk=s.rounds[a],s.rounds[b]
  for k in ('rk','S','S2','sigma','bridge','SH','SV'):eq[k]+=A[k]==Bk[k]
 eq['S_eq_S2_same_round']+=sum(k['S']==k['S2'] for k in s.rounds)
res['slide']=dict(schedules=100,round_pairs=12000,equal_counts=dict(eq),total_equal_full_rounds=0)
print('related',res['related_nonce'],'slide',dict(eq),flush=True)
# ---- 4. key signature tamper
live_sig=N.key_signature(SEED);desc0=N.mix_description()
orig={k:getattr(N,k) for k in dir(N) if not k.startswith('__')}
def restore():
 for k in list(vars(N)):
  if not k.startswith('__') and k not in orig:delattr(N,k)
 for k,v in orig.items():setattr(N,k,v)
tam=[]
def tamper(label,fn,undo=None):
 fn()
 try:
  try:sig=N.key_signature(SEED);sigerr=None
  except Exception as e:sig=None;sigerr=type(e).__name__+': '+str(e)
  try:blob=N.encrypt(b'hello world',SEED);encerr=None
  except Exception as e:blob=None;encerr=type(e).__name__+': '+str(e)
  # does tampering change cipher behaviour? compare raw block encryption under the hello schedule
  try:beh=flat(N.encrypt_grid(N.bytes_to_grid(N.encode_block(b'hello world')),N.Schedule(SEED,NONCE)))!=CT;behe=None
  except Exception as e:beh=None;behe=type(e).__name__
 finally:
  if undo:undo()
  restore()
 assert N.key_signature(SEED)==live_sig
 row=dict(change=label,key_sig_changed=(None if sig is None else sig!=live_sig),key_sig_error=sigerr,cipher_behaviour_changed=beh,behaviour_error=behe,
  live_decrypt_of_tampered_blob=(outcome(blob) if blob else encerr))
 row['signature_blind_spot']=bool(beh) and row['key_sig_changed'] is False
 tam.append(row);print('tamper',label,row['key_sig_changed'],row['cipher_behaviour_changed'],row['live_decrypt_of_tampered_blob'][:40],flush=True)
tamper('revert BOW_STROKES to previous (4,5,6) layout',lambda:setattr(N,'BOW_STROKES',OLD_STROKES))
tamper('identity staff_mix (prior blind-spot demo)',lambda:setattr(N,'staff_mix',lambda g,sigma:[row[:] for row in g]))
def no_restack(staff,Sa,Sb):return list(staff)
tamper('odd_restack replaced by identity function',lambda:setattr(N,'odd_restack',no_restack))
tamper('BARS drop B0',lambda:setattr(N,'BARS',orig['BARS'][1:]))
tamper('MIX2_MATRIX -> ((1,1),(1,3))',lambda:setattr(N,'MIX2_MATRIX',((1,1),(1,3))))
tamper('NR 16 -> 8',lambda:setattr(N,'NR',8))
tamper('default arg: encrypt_grid rounds default 16 -> 4',lambda:setattr(N.encrypt_grid,'__defaults__',(4,True)),lambda:setattr(N.encrypt_grid,'__defaults__',(16,True)))
tamper('new module global shadowing builtin sum (builtin object)',lambda:setattr(N,'sum',max))
# NEW blind spots: same source text, different behaviour
evil=dict(vars(N));evil['BOW_ROT_MOD']=5
tamper('bow_stroke rebuilt from its own __code__ with foreign globals (BOW_ROT_MOD=5 seen only by bow_stroke)',
 lambda:setattr(N,'bow_stroke',types.FunctionType(orig['bow_stroke'].__code__,evil,'bow_stroke')))
c=orig['bow_stroke'].__code__
tamper('bow_stroke __code__ edited in memory (co_names swap BOW_R2_SHIFT->BOW_ROT_BASE)',
 lambda:setattr(N.bow_stroke,'__code__',c.replace(co_names=tuple('BOW_ROT_BASE' if n=='BOW_R2_SHIFT' else n for n in c.co_names))),
 lambda:setattr(orig['bow_stroke'],'__code__',c))
od=builtins.divmod
tamper('builtins.divmod patched (used by shell_mix); interpreter-level',lambda:setattr(builtins,'divmod',lambda a,b:(a//b,(a%b)^1) if b==8 else od(a,b)),lambda:setattr(builtins,'divmod',od))
res['key_signature_tamper']=dict(live_key_sig=live_sig.hex(),closure_code_names=len(N.mix_code_closure()[0]),closure_data_names=len(N.mix_code_closure()[1]),
 MIX_CODE_FUNCS=len(N.MIX_CODE_FUNCS),cases=tam,blind_spots=[t['change'] for t in tam if t['signature_blind_spot']])
assert N.decrypt(HB,SEED)==b'hello world' and N.mix_description()==desc0
res['seconds']=round(time.time()-t0,1);res['finished']=now();save('attack_regression',res)
