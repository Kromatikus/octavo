"""Follow-up: the 1-round (cell, output-delta) bias max hit 108 (null max ~100). Re-locate the top cells and re-measure on fresh data."""
from common import *
verify_live();t0=time.time();B=Batch(SCH);B.validate();rng=np.random.default_rng(31337)
X=rng.integers(0,256,(1<<14,128));Y0=B.enc(X,1);top=[]
for c in range(0,128,8):
 d=int(rng.integers(1,256));Y=X.copy();Y[:,c]^=d;D=Y0^B.enc(Y,1)
 for o in range(128):
  bc=np.bincount(D[:,o],minlength=256);v=int(bc.argmax());top.append((int(bc[v]),c,d,o,v))
top.sort(reverse=True);res={'started':now(),'first_pass_top5':top[:5],'null_note':'Binomial(16384,1/256): mean 64, sd 8; max over 32768 tests ~96-100'}
fresh=[]
for cnt,c,d,o,v in top[:5]:
 X2=rng.integers(0,256,(1<<16,128));D=B.enc(X2,1)^B.enc(np.where(np.arange(128)==c,X2^d,X2),1)
 k=int((D[:,o]==v).sum());fresh.append({'in_cell':c,'delta':d,'out_cell':o,'value':v,'first':cnt,'fresh_count_2^16':k,'fresh_expected':256,'fresh_sigma':round((k-256)/16,2)})
res['fresh_remeasure']=fresh;print(json.dumps(res),flush=True)
res['seconds']=round(time.time()-t0,1);res['finished']=now();save('attack_bias_followup',res)
