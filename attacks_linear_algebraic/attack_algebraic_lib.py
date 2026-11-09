"""S-box algebra helpers copied from attack_algebraic.py (no side effects)."""
import numpy as np
def moebius(f):  # f: array of 0/1 length 256 -> ANF coefficients
 a=np.array(f,dtype=np.int64).copy();h=1
 while h<256:
  a=a.reshape(-1,2,h);a[:,1,:]^=a[:,0,:];a=a.reshape(256);h*=2
 return a
WT=np.array([bin(i).count('1') for i in range(256)])
def degrees(S):
 S=np.array(list(S));comp=[]
 for b in range(1,256):
  f=np.array([bin(b&y).count('1')&1 for y in S]);an=moebius(f);comp.append(int(WT[an!=0].max()))
 return min(comp),max(comp),[int(WT[moebius((S>>i)&1)!=0].max()) for i in range(8)]
def gf2_rank(rows):
 rows=[int(r) for r in rows];rank=0;piv=[]
 basis=[]
 for r in rows:
  for b in basis:r=min(r,r^b)
  if r:basis.append(r);rank+=1
 return rank
def quad_counts(S):
 S=list(S);x=[[a>>i&1 for i in range(8)] for a in range(256)];y=[[S[a]>>i&1 for i in range(8)] for a in range(256)]
 def count(monos):
  # columns are monomials; rank over the 256 evaluation points; equations = #monos - rank
  cols=[]
  for m in monos:
   v=0
   for a in range(256):
    if m(x[a],y[a]):v|=1<<a
   cols.append(v)
  return len(monos)-gf2_rank(cols)
 lin=[lambda X,Y:1]+[lambda X,Y,i=i:X[i] for i in range(8)]+[lambda X,Y,i=i:Y[i] for i in range(8)]
 bi=[lambda X,Y,i=i,j=j:X[i]&Y[j] for i in range(8) for j in range(8)]
 xx=[lambda X,Y,i=i,j=j:X[i]&X[j] for i in range(8) for j in range(i+1,8)]
 yy=[lambda X,Y,i=i,j=j:Y[i]&Y[j] for i in range(8) for j in range(i+1,8)]
 return dict(bi_affine=count(lin+bi),full_quadratic=count(lin+bi+xx+yy),monomials_bi_affine=len(lin+bi),monomials_full=len(lin+bi+xx+yy))
