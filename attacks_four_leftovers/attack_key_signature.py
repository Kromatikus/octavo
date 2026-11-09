from common import *
verify_live()
res={'started':now()}
def classify(b):
 try:return 'ACCEPTED:'+N.decrypt(b,SEED).hex()
 except Exception as e:return type(e).__name__+': '+str(e)
orig={k:getattr(N,k) for k in ('BARS','TRIPLETS','MIX2_MATRIX','BOW_ROT_BASE','BOW_STROKES','bar_mix','FIELD_POLY','B0_ROT_R1','B0_ROT_R2','ODD_RESTACK_R1','ODD_RESTACK_R2','CROSS_BRIDGE','CROSS_LAYERS','odd_restack','b0_apply','staff_mix')}
live_sig=N.key_signature(SEED)
def restore():
 for k,v in orig.items():setattr(N,k,v)
def with_change(label,fn,msg=b'hello world'):
 fn()
 try:
  alt_sig=N.key_signature(SEED);blob=N.encrypt(msg,SEED);desc=N.mix_description()
 finally:restore()
 assert N.key_signature(SEED)==live_sig and N.BARS is orig['BARS']
 r={'change':label,'alt_key_sig':alt_sig.hex(),'key_sig_changed':alt_sig!=live_sig,'live_result':classify(blob),'blob':blob.hex()}
 # Would it have DecodeError'd without the key signature? Recompute pickup-era style tag (no key_sig) and check the ct body
 v,pk,n,ct,tag=N.split_blob(blob);sch=N.Schedule(SEED,n);clef=N.staff_clef(SEED)
 b=flat(N.decrypt_grid(N.bytes_to_grid(ct),sch));L=b[0]
 r['live_tables_decrypt_body_well_formed']=not(L>N.MAX_MSG or any(b[1+L:]))
 # replace tag with a tag computed under LIVE key_sig (seed-holder only) to show the body would be malformed
 good=N.VERSION+pk+n+ct+N._tag(sch.mac_key,pk,n,ct,clef,live_sig)
 r['if_retagged_by_seed_holder_under_live_sig']=classify(good)
 res.setdefault('changes',[]).append(r);print(label,r['key_sig_changed'],r['live_result'],r['if_retagged_by_seed_holder_under_live_sig'],flush=True)
B=orig['BARS'];T=orig['TRIPLETS']
with_change('B0 r2 5->4',lambda:setattr(N,'B0_ROT_R2',4))
with_change('skip B0 via BARS[1:]',lambda:setattr(N,'BARS',B[1:]))
with_change('T0 row0 (5,1,1)->(5,1,3)',lambda:setattr(N,'TRIPLETS',((T[0][0],T[0][1],((5,1,3),)+T[0][2][1:]),)+T[1:]))
with_change('skip T0',lambda:setattr(N,'TRIPLETS',T[1:]))
with_change('mix2 matrix ((1,1),(1,2))->((1,1),(1,3))',lambda:setattr(N,'MIX2_MATRIX',((1,1),(1,3))))
with_change('bow base 1->2',lambda:setattr(N,'BOW_ROT_BASE',2))
with_change('skip bow via empty strokes',lambda:setattr(N,'BOW_STROKES',()))
with_change('skip CROSS_BRIDGE and fourth CROSS_LAYERS',lambda:(setattr(N,'CROSS_BRIDGE',()),setattr(N,'CROSS_LAYERS',N.CROSS_LAYERS[:3])))
with_change('odd_restack r2 6->5',lambda:setattr(N,'ODD_RESTACK_R2',5))
def no_restack(staff):return list(staff)
with_change('skip odd_restack via listed function source replacement',lambda:setattr(N,'odd_restack',no_restack))
# Isolated module copy (exactly the pickup-era style), alt constants; tag computed with alt module's own key signature
spec=importlib.util.spec_from_file_location('isolated_three_fixes',N.__file__);alt=importlib.util.module_from_spec(spec);spec.loader.exec_module(alt)
alt.BARS=alt.BARS[1:];alt.TRIPLETS=alt.TRIPLETS[1:]
ab=alt.encrypt(b'hello world',SEED)
res['isolated_module_skip_B0_T0']={'alt_key_sig':alt.key_signature(SEED).hex(),'live_result':classify(ab),'blob':ab.hex()}
print('isolated',res['isolated_module_skip_B0_T0']['live_result'])
# Honest limit: code change that leaves serialized constants identical (monkeypatch bar_mix to skip B0 in the CODE path only)
def bar_mix_skip_b0(g):
 g=[row[:] for row in g]
 for row in g:
  for _,_,(i,j),M in orig['BARS'][1:]:row[i],row[j]=N.bar_apply(M,row[i],row[j])
 return g
N.bar_mix=bar_mix_skip_b0
try:
 sig2=N.key_signature(SEED);blob=N.encrypt(b'hello world',SEED)
finally:restore()
res['listed_bar_mix_source_patch']={'change':'bar_mix() body patched to skip B0; BARS constant untouched','key_sig_same_as_live':sig2==live_sig,'live_result':classify(blob),'blob':blob.hex(),
 'note':'Listed bar_mix source replacement is now committed: expected tag mismatch; constructing alternate blob requires seed.'}
print('code-only',res['listed_bar_mix_source_patch']['live_result'])
# Omitted helper: behavior changes without changing listed function source.
def skipped_staff_mix(g,sigma):return [row[:] for row in g]
N.staff_mix=skipped_staff_mix
try:
 sig3=N.key_signature(SEED);desc3=N.mix_description();blob3=N.encrypt(b'hello world',SEED)
finally:restore()
res['omitted_helper_staff_mix']={'key_sig_same_as_live':sig3==live_sig,'listed_mix_code_unchanged':json.loads(desc3)['mix_code']==json.loads(N.mix_description())['mix_code'],'live_result':classify(blob3),'blob':blob3.hex(),'needs_seed_to_build':True,'note':'staff_mix is absent from MIX_CODE_FUNCS; live tag validates, then altered arithmetic body is malformed. Not a seed-free forgery.'}
print('omitted helper',res['omitted_helper_staff_mix'],flush=True)
assert N.key_signature(SEED)==live_sig and N.decrypt(HB,SEED)==b'hello world'
res['live_key_sig_restored_and_hello_ok']=True
res['finished']=now();save('attack_key_signature',res)
