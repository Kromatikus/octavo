"""Even-beat inputs into bow+rehair: the SPEC's no-singleton argument covers odd beats only. Large table-independent scan."""
from common import *
verify_live();t0=time.time()
res={'started':now(),'note':'A rehair singleton needs a bow delta inside one pair (i,i+1) with du==dv or du==2dv (field kernel); this is table-independent, so only the bow is evaluated.'}
rng=np.random.default_rng(6060);NB_=1<<16
B=rng.integers(0,256,(NB_,8))
out={}
for lab,st in (('new',N.BOW_STROKES),('old',OLD_STROKES)):
 a=bow_staff(B,st);row={}
 for t in range(8):
  hits=0;wit=[]
  for d in range(1,256):
   H=B.copy();H[:,t]^=d;z=a^bow_staff(H,st);act=z!=0;w=act.sum(1)
   m=np.zeros(len(B),bool)
   for i in (0,2,4,6):
    mm=(w==2)&act[:,i]&act[:,i+1];m|=mm&((z[:,i]==z[:,i+1])|(z[:,i]==GF[2,z[:,i+1]]))
   hits+=int(m.sum())
   for k in np.nonzero(m)[0][:max(0,3-len(wit))]:wit.append({'base':B[k].tolist(),'beat':t,'delta':d,'bow_delta':z[k].tolist()})
  row[t]={'cases':NB_*255,'rehair_singletons':hits,'rate':hits/(NB_*255),'witnesses':wit}
 out[lab]=row;print(lab,{t:row[t]['rehair_singletons'] for t in row},flush=True)
res['scan']=out;res['cases_per_beat']=NB_*255
conf=[]
for w in out['new'][6]['witnesses']:
 s,t,d=w['base'],w['beat'],w['delta'];h=s[:];h[t]^=d
 ws=[sum(x!=y for x,y in zip(N.odd_restack(N.bow_pressure(s),k['S'],k['S2']),N.odd_restack(N.bow_pressure(h),k['S'],k['S2']))) for k in SCH.rounds]
 conf.append({'base':s,'beat':t,'delta':d,'bow_rehair_weights_all_16_rounds':ws})
res['live_confirmation']=conf;print(conf,flush=True)
res['cross_after_single_cell_active_cells']=[sum(1 for row in N.cross_staff_mix([[ (1 if (f2==ff and t==6) else 0) for t in range(8)] for f2 in range(16)]) for x in row if x) for ff in range(16)]
print(res['cross_after_single_cell_active_cells'])
res['seconds']=round(time.time()-t0,1);res['finished']=now();save('attack_even_beats',res)
