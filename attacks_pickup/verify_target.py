from common import *
import inspect, ast
expected='86582773a55807708112e7ad5b3fa7080c48196c6abdd95158fc9c750b3a0430';source=Path(N.__file__).read_bytes();sha=hashlib.sha256(source).hexdigest();assert sha==expected
res={'timestamp':now(),'sha256':sha,'expected_sha256_matches':True,'blob_len':N.BLOB_LEN,'parts_lengths':list(map(len,N.split_blob(HB))),'recorded_hello_decrypt':N.decrypt(HB,SEED).decode(),'nonce_formula_matches':N.siv_nonce(b'hello world',PICKUP,SEED)==NONCE,'encrypt_has_pickup_argument':'pickup' in inspect.signature(N.encrypt).parameters,'BARS':N.BARS,'TRIPLETS':N.TRIPLETS,'round_order':['XOR rk','S','weave','staff_mix Z/256','shell_mix Z/256','bar_mix GF(2^8) 0x1f5','triplet_mix Z/256','S2','bar_mix GF','triplet_mix Z/256'],'source_verification':'Read live source in full: decrypt checks length, version, HMAC with compare_digest before decrypt_grid; decode then SIV check. os.urandom(16) is called by encrypt; no end-to-end beat wrap.'}
# Correctly authenticated and well-encoded, but nonce copied from hello does not match message+pickup.
m=b'nonce substitution test';sch=N.Schedule(SEED,NONCE);ct=flat(N.encrypt_grid(N.bytes_to_grid(N.encode_block(m)),sch));tag=N._tag(sch.mac_key,PICKUP,NONCE,ct,N.staff_clef(SEED));blob=N.VERSION+PICKUP+NONCE+ct+tag
try:N.decrypt(blob,SEED);out='ACCEPTED'
except Exception as e:out=type(e).__name__+': '+str(e)
res['valid_tag_wrong_siv']=out;assert out=='AuthError: SIV nonce mismatch'
try:N.encrypt(b'hello world',SEED,nonce=NONCE);out='ACCEPTED'
except Exception as e:out=type(e).__name__+': '+str(e)
res['forced_old_nonce_encrypt']=out;assert out.startswith('ValueError:')
# Old same-nonce key material independent of tables, confirmed across actual pre-pickup code.
spec=importlib.util.spec_from_file_location('readonly_pre_pickup','/tmp/sneak_n2_pre_pickup/sneak_n2.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old);osch=old.Schedule(SEED,NONCE)
res['actual_pre_pickup_same_nonce_mac_key_equal']=sch.mac_key==osch.mac_key;res['actual_pre_pickup_same_nonce_schedule_material_equal']=sch.material()==osch.material()
save('verify_target',res)
