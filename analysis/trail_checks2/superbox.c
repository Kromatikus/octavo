/* OCT-4 Stage 3: exact clustering on Octavo's smallest two-S-layer piece, with real keyed S-boxes.
   F(x0,x1) = Latin(S[x0^k0], S[x1^k1]) where Latin(u,v) = (S[u^v], S2[u ^ 2v])  (2v in SM4 field, as octavo_np.mix2/latin)
   Key bytes do not change DP/|corr| of a fixed function up to relabelling, so k = 0.
   Computes MEDP = max_{a!=0,b} DP_F(a->b) exactly (2^32 work) and the best single characteristic
   max_{a,c,b} DP_S(a0->c0) DP_S(a1->c1) DP_S(m0->b0) DP_S2(m1->b1) with m = mix2(c); same for linear (ELP, exact via WHT).
   usage: superbox sboxfile  (file: 512 bytes S then S2, plus 256 bytes MUL2 table) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
static unsigned char S[256], S2[256], M2[256];
static unsigned short F[65536];
static int DS[256][256], DS2[256][256];
int main(int argc, char **argv){
  FILE *fp=fopen(argv[1],"rb"); if(fread(S,1,256,fp)!=256||fread(S2,1,256,fp)!=256||fread(M2,1,256,fp)!=256) return 1; fclose(fp);
  for(int x=0;x<65536;x++){ int u=S[x>>8], v=S[x&255]; F[x]=(S[u^v]<<8)|S2[u^M2[v]]; }
  for(int a=0;a<256;a++) for(int x=0;x<256;x++){ DS[a][S[x]^S[x^a]]++; DS2[a][S2[x]^S2[x^a]]++; }
  int maxds=0,maxds2=0; for(int a=1;a<256;a++) for(int b=0;b<256;b++){ if(DS[a][b]>maxds)maxds=DS[a][b]; if(DS2[a][b]>maxds2)maxds2=DS2[a][b]; }
  /* exact MEDP */
  long best=0; int ba=0,bb=0; double sumrowmax=0;
  #pragma omp parallel
  { static __thread int h[65536]; long lb=0; int la=0,lbb=0; double ls=0;
    #pragma omp for schedule(dynamic,256)
    for(int a=1;a<65536;a++){ memset(h,0,sizeof h); for(int x=0;x<65536;x++) h[F[x]^F[x^a]]++;
      int rm=0,rb=0; for(int b=0;b<65536;b++) if(h[b]>rm){rm=h[b];rb=b;}
      ls+=rm; if(rm>lb){lb=rm;la=a;lbb=rb;} }
    #pragma omp critical
    { if(lb>best){best=lb;ba=la;bb=lbb;} sumrowmax+=ls; } }
  /* best single characteristic (differential), exact max over a, c */
  double bestch=0; double sum_at_best=0; int RM[256], RM2[256];
  for(int m=0;m<256;m++){ RM[m]=0; RM2[m]=0; for(int b=0;b<256;b++){ if(DS[m][b]>RM[m])RM[m]=DS[m][b]; if(DS2[m][b]>RM2[m])RM2[m]=DS2[m][b]; } }
  for(int a=1;a<65536;a++){ int a0=a>>8,a1=a&255;
    for(int c0=0;c0<256;c0++){ if(!DS[a0][c0]) continue; for(int c1=0;c1<256;c1++){ if(!DS[a1][c1]) continue;
      int m0=c0^c1, m1=c0^M2[c1]; double p=DS[a0][c0]*DS[a1][c1]/65536.0;
      int mx0=RM[m0], mx1=RM2[m1];
      double q=p*mx0*mx1/65536.0; if(q>bestch) bestch=q; } } }
  /* number of characteristics behind the best differential (ba->bb) and their summed probability */
  int nch=0; { int a0=ba>>8,a1=ba&255,b0=bb>>8,b1=bb&255;
    for(int c0=0;c0<256;c0++) for(int c1=0;c1<256;c1++){ int m0=c0^c1, m1=c0^M2[c1];
      double q=(double)DS[a0][c0]*DS[a1][c1]*DS[m0][b0]*DS2[m1][b1]/4294967296.0; if(q>0){nch++; sum_at_best+=q;} } }
  /* linear: exact max |corr| of F over all nonzero masks (WHT per output mask) */
  double bestc=0; int la_=0, lb_=0;
  #pragma omp parallel
  { static __thread float f[65536]; double lbc=0; int a_=0,b_=0;
    #pragma omp for schedule(dynamic,256)
    for(int b=1;b<65536;b++){ for(int x=0;x<65536;x++) f[x]=(__builtin_popcount(b&F[x])&1)?-1.f:1.f;
      for(int h=1;h<65536;h<<=1) for(int i=0;i<65536;i+=2*h) for(int j=i;j<i+h;j++){ float A=f[j],B=f[j+h]; f[j]=A+B; f[j+h]=A-B; }
      for(int a=1;a<65536;a++){ double c=fabs(f[a]); if(c>lbc){lbc=c;a_=a;b_=b;} } }
    #pragma omp critical
    { if(lbc>bestc){bestc=lbc;la_=a_;lb_=b_;} } }
  bestc/=65536.0;
  /* best single linear characteristic: LAT of S, S2; mix2 masks: (b0,b1) on outputs of mix2 -> input mask (b0 ^ b1, mixT) ;
     approximate by exhaustive: for each S-layer-1 output mask pair (g0,g1) the mix2 output mask is unique (transpose-inverse). */
  static int LS[256][256], LS2[256][256];
  for(int a=0;a<256;a++) for(int b=0;b<256;b++){ int s=0,s2=0; for(int x=0;x<256;x++){ s+=(__builtin_popcount((a&x)^(b&S[x]))&1)?-1:1; s2+=(__builtin_popcount((a&x)^(b&S2[x]))&1)?-1:1; } LS[a][b]=s; LS2[a][b]=s2; }
  /* mask through mix2 (u,v)->(u^v, u^2v): input masks (g0,g1) = (m0 ^ m1, m0 ^ 2^T m1) where 2^T is the transpose of the GF mul-by-2 matrix */
  int T2[256]; for(int m=0;m<256;m++){ int r=0; for(int bit=0;bit<8;bit++){ int x=1<<bit; if(__builtin_popcount(m&M2[x])&1) r|=x; } T2[m]=r; }
  double bestlc=0; int maxl0[256], maxl1[256], maxlin0[256];
  for(int m=0;m<256;m++){ maxl0[m]=0; maxl1[m]=0; maxlin0[m]=0; for(int b=1;b<256;b++){ if(abs(LS[m][b])>maxl0[m])maxl0[m]=abs(LS[m][b]); if(abs(LS2[m][b])>maxl1[m])maxl1[m]=abs(LS2[m][b]); } }
  for(int a=0;a<256;a++){ for(int g=1;g<256;g++) if(abs(LS[a][g])>maxlin0[a]) maxlin0[a]=abs(LS[a][g]); }
  for(int m0=0;m0<256;m0++) for(int m1=0;m1<256;m1++){ if(!m0&&!m1) continue; int g0=m0^m1, g1=m0^T2[m1];
    double c=1; c*= m0? maxl0[m0]/256.0 : 1; c*= m1? maxl1[m1]/256.0 : 1;
    int best0=0,best1=0; for(int a=0;a<256;a++){ if(g0&&abs(LS[a][g0])>best0)best0=abs(LS[a][g0]); if(g1&&abs(LS[a][g1])>best1)best1=abs(LS[a][g1]); }
    c*= g0? best0/256.0:1; c*= g1? best1/256.0:1; if(c>bestlc) bestlc=c; }
  printf("{\"max_dp_S\": %g, \"max_dp_S2\": %g, \"MEDP\": %g, \"MEDP_log2\": %.3f, \"argmax_a\": \"%04x\", \"argmax_b\": \"%04x\","
         " \"best_characteristic_dp\": %g, \"best_char_log2\": %.3f, \"chars_behind_MEDP\": %d, \"sum_chars_at_MEDP\": %g,"
         " \"mean_rowmax_dp_log2\": %.3f, \"max_abs_corr\": %g, \"max_corr_log2\": %.3f, \"best_linear_char_corr\": %g, \"best_lin_char_log2\": %.3f}\n",
    maxds/256.0, maxds2/256.0, best/65536.0, log2(best/65536.0), ba, bb, bestch, log2(bestch), nch, sum_at_best,
    log2(sumrowmax/65535/65536.0), bestc, log2(bestc), bestlc, log2(bestlc));
  return 0;
}
