from common import *
verify_live()
# Layer-local linear diagnostics: connected static graph need not imply one-pass temporal reach.
M=[]
for c in range(16):
 g=[[0]*8 for _ in range(16)];g[c][0]=1;y=N.cross_staff_mix(g);M.append([row[0] for row in y])
res={'started':now(),'field_poly':hex(N.FIELD_POLY),'cross_column_active_staff_counts':[sum(z!=0 for z in col) for col in M],'cross_columns':M}
# Exhaustive two-active-staff deltas up to scalar normalization (linearity), beat 0.
best=17;witness=None;hist={}
for i in range(16):
 for j in range(i+1,16):
  for d in range(1,256):
   y=[x^N.gf_mul(d,z) for x,z in zip(M[i],M[j])];w=sum(z!=0 for z in y);hist[w]=hist.get(w,0)+1
   if w<best:best=w;witness={'input_staffs':[i,j],'input_deltas':[1,d],'output_delta':y}
res['normalized_two_input_scan']={'cases':120*255,'min_active_staffs':best,'histogram':hist,'witness':witness,'note':'Cross layer only, not a whole round; single shared beat. Normalization by nonzero field scalar covers all two-input delta ratios.'}
# Small copy-pasteable live witnesses checked against actual helper functions.
res['simple_rehair_witnesses']=[]
for t in (3,5,7):
 x=[0]*8;y=x.copy();y[t]=85;a=N.odd_restack(N.bow_pressure(x));b=N.odd_restack(N.bow_pressure(y))
 res['simple_rehair_witnesses'].append({'base':x,'beat':t,'delta':85,'output_delta':[u^v for u,v in zip(a,b)]})
res['finished']=now();save('attack_cross_local',res)
