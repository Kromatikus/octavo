from common import *
verify_live()
# Exact local bit relations, not whole-round linear cryptanalysis.
u=np.repeat(np.arange(256,dtype=np.uint16),256);v=np.tile(np.arange(256,dtype=np.uint16),256)
def analyze(r1,r2):
 a=(u+rotl(v,r1))&255;b=v^rotl(a,r2)
 rel=[]
 for col,out in enumerate((a,b)):
  for bit in range(8):
   # Infer an affine relation from zero and basis vectors, then test all 2^16 inputs.
   def output(uu,vv):
    aa=(uu+N.rotl8(vv,r1))&255;bb=vv^N.rotl8(aa,r2);return ((aa,bb)[col]>>bit)&1
   const=output(0,0);um=sum((output(1<<j,0)^const)<<j for j in range(8));vm=sum((output(0,1<<j)^const)<<j for j in range(8))
   pred=np.full(65536,const,dtype=np.uint16)
   for j in range(8):
    if um>>j&1:pred^=(u>>j)&1
    if vm>>j&1:pred^=(v>>j)&1
   if np.array_equal(pred,(out>>bit)&1):rel.append({'output_column':col,'output_bit':bit,'u_mask':um,'v_mask':vm,'constant':const,'holds':65536,'of':65536})
 fixed=[]
 for uu in (0,128):
  vals=np.unique(b[u==uu]);fixed.append({'u':uu,'second_output_values_all_256_v':vals.tolist()})
 return {'rotations':[r1,r2],'affine_output_bits':rel,'fixed_rows':fixed}
r={'started':now(),'B0':analyze(3,5),'rehair_pair':analyze(2,6),'scope':'Local 2-byte layers only. S/S2 and other mixing intervene in complete rounds; no full-round or seed-free attack is implied.'}
# Validate algebra against live functions on all 65536 pairs, not just vector formulas.
r['B0']['live_vout_bit5_equals_u_bit0_failures']=sum(((N.b0_apply(uu,vv)[1]>>5)&1)!=(uu&1) for uu in range(256) for vv in range(256))
r['rehair_pair']['live_vout_bit6_equals_u_bit0_failures']=sum(((N.odd_restack([uu,vv,0,0,0,0,0,0])[1]>>6)&1)!=(uu&1) for uu in range(256) for vv in range(256))
r['finished']=now();save('attack_arx_relations',r)
