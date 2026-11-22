/* OCT-4 Stage 4: exact differential / linear tables of one bow ARX stroke, averaged over the pressure byte.
   Stroke (octavo_np._bow): pr = rotl8(x_p, k); r1 = 1 + pr%7; r2 = 1 + (pr>>3)%7;
   u' = (u + rotl8(v, r1)) mod 256; v' = v ^ rotl8(u', r2).  p is unchanged. pr is uniform when x_p is uniform (any k).
   With p's difference / mask zero, and p uniform and independent of (u,v) (Markov assumption):
   DP(du,dv->du',dv') = sum_{r1,r2} w * DPadd(du, rotl(dv,r1) -> du') * [dv' == dv ^ rotl(du',r2)]
   C (du..) = sum w * Cadd(a=au, b=rotl(av^bv, r1); g = bu ^ rotr(bv, r2))     (exact identities, no sampling)
   Output: per support pattern (in in {u,v,uv}) x (out in {u',v',u'v'}) the max DP and max |corr|, plus typical stats. */
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
static inline unsigned rl(unsigned x, int r){ r&=7; return ((x<<r)|(x>>((8-r)&7)))&255; }
static inline unsigned rr(unsigned x, int r){ return rl(x, 8-(r&7)); }
static float DPA[256][256][256];   /* DPA[a][b][c] */
static float CA[256][256][256];    /* CA[g][a][b]  */
int main(void){
  double w[8][8]; memset(w,0,sizeof w);
  for(int pr=0;pr<256;pr++) w[1+pr%7][1+(pr>>3)%7] += 1.0/256;
  /* DP of modular addition, exhaustive */
  static unsigned cnt[256];
  for(int a=0;a<256;a++) for(int b=0;b<256;b++){
    memset(cnt,0,sizeof cnt);
    for(int x=0;x<256;x++){ int xa=x^a; for(int y=0;y<256;y++) cnt[((xa+(y^b))^(x+y))&255]++; }
    for(int c=0;c<256;c++) DPA[a][b][c]=cnt[c]/65536.0f;
  }
  /* correlation of modular addition via WHT */
  static float f[65536];
  for(int g=0;g<256;g++){
    for(int x=0;x<256;x++) for(int y=0;y<256;y++) f[x*256+y] = (__builtin_popcount(g&((x+y)&255))&1)? -1.f: 1.f;
    for(int h=1;h<65536;h<<=1) for(int i=0;i<65536;i+=2*h) for(int j=i;j<i+h;j++){ float A=f[j],B=f[j+h]; f[j]=A+B; f[j+h]=A-B; }
    for(int a=0;a<256;a++) for(int b=0;b<256;b++) CA[g][a][b]=f[a*256+b]/65536.0f;
  }
  /* sanity: brute-force one random stroke DP and correlation entry */
  double maxdp[3][3]={{0}}, maxc[3][3]={{0}}; int argdp[3][3]={{0}}, argc[3][3]={{0}};
  double sum_rowmax=0; long nrow=0; double hist_dp[20]={0};
  static double acc[65536];
  for(int du=0;du<256;du++) for(int dv=0;dv<256;dv++){
    if(!du && !dv) continue;
    memset(acc,0,sizeof acc);
    for(int r1=1;r1<8;r1++) for(int r2=1;r2<8;r2++){ double ww=w[r1][r2]; if(ww==0) continue;
      unsigned b=rl(dv,r1);
      for(int c=0;c<256;c++){ float d=DPA[du][b][c]; if(d==0) continue; unsigned dv2=dv^rl(c,r2); acc[c*256+dv2]+=ww*d; } }
    int pin = (du&&dv)?2:(du?0:1); double rowmax=0;
    for(int o=1;o<65536;o++){ double d=acc[o]; if(d==0) continue; int c=o>>8, e=o&255; int pout=(c&&e)?2:(c?0:1);
      if(d>maxdp[pin][pout]){ maxdp[pin][pout]=d; argdp[pin][pout]=(du<<24)|(dv<<16)|o; } if(d>rowmax) rowmax=d; }
    sum_rowmax+=rowmax; nrow++; int k=(int)floor(-log2(rowmax)); if(k>19)k=19; hist_dp[k]++;
  }
  /* linear: for each output mask (bu,bv) accumulate over (au,av) */
  double hist_c[20]={0}; double sum_colmax=0; long ncol=0;
  #pragma omp parallel
  {
    static __thread double ac[65536];
    double lmax[3][3]={{0}}; int larg[3][3]={{0}}; double lhist[20]={0}; double lsum=0; long lcnt=0;
    #pragma omp for schedule(dynamic,64)
    for(int bo=1;bo<65536;bo++){
      int bu=bo>>8, bv=bo&255; memset(ac,0,sizeof ac);
      for(int r1=1;r1<8;r1++) for(int r2=1;r2<8;r2++){ double ww=w[r1][r2]; if(ww==0) continue;
        unsigned g=bu^rr(bv,r2);
        for(int au=0;au<256;au++){ float *row=CA[g][au]; double *dst=ac+au*256;
          for(int av=0;av<256;av++) dst[av]+=ww*row[rl(av^bv,r1)]; } }
      int pout=(bu&&bv)?2:(bu?0:1); double cmax=0;
      for(int i=1;i<65536;i++){ double c=fabs(ac[i]); if(c<1e-12) continue; int au=i>>8, av=i&255; int pin=(au&&av)?2:(au?0:1);
        if(c>lmax[pin][pout]){ lmax[pin][pout]=c; larg[pin][pout]=(i<<16)|bo; } if(c>cmax) cmax=c; }
      if(ac[0]!=0 && fabs(ac[0])>1e-9) { /* input mask zero with nonzero output mask: must be 0 for a bijection */ }
      lsum+=cmax; lcnt++; int k=(int)floor(-log2(cmax)); if(k>19)k=19; lhist[k]++;
    }
    #pragma omp critical
    { for(int a=0;a<3;a++) for(int b=0;b<3;b++) if(lmax[a][b]>maxc[a][b]){ maxc[a][b]=lmax[a][b]; argc[a][b]=larg[a][b]; }
      for(int k=0;k<20;k++) hist_c[k]+=lhist[k]; sum_colmax+=lsum; ncol+=lcnt; }
  }
  const char *nm[3]={"u","v","uv"};
  printf("{\n \"rot_pair_weights_nonzero\": %d,\n \"diff_max_dp\": {", 0);
  for(int a=0;a<3;a++) for(int b=0;b<3;b++) printf("%s\"%s->%s'\": %.6g", (a||b)?", ":"", nm[a], nm[b], maxdp[a][b]);
  printf("},\n \"lin_max_abs_corr\": {");
  for(int a=0;a<3;a++) for(int b=0;b<3;b++) printf("%s\"%s->%s'\": %.6g", (a||b)?", ":"", nm[a], nm[b], maxc[a][b]);
  printf("},\n \"diff_mean_rowmax_dp\": %.6g, \"diff_hist_floor_neglog2_rowmax\": [", sum_rowmax/nrow);
  for(int k=0;k<20;k++) printf("%s%.0f", k?",":"", hist_dp[k]);
  printf("],\n \"lin_mean_colmax_abs_corr\": %.6g, \"lin_hist_floor_neglog2_colmax\": [", sum_colmax/ncol);
  for(int k=0;k<20;k++) printf("%s%.0f", k?",":"", hist_c[k]);
  printf("],\n \"diff_argmax_hex_du_dv_du2_dv2\": {"); for(int a=0;a<3;a++) for(int b=0;b<3;b++) printf("%s\"%s->%s'\": \"%08x\"", (a||b)?", ":"", nm[a], nm[b], (unsigned)argdp[a][b]);
  printf("},\n \"lin_argmax_hex_au_av_bu_bv\": {"); for(int a=0;a<3;a++) for(int b=0;b<3;b++) printf("%s\"%s->%s'\": \"%08x\"", (a||b)?", ":"", nm[a], nm[b], (unsigned)argc[a][b]);
  printf("}\n}\n");
  /* dump weights for the brute-force check */
  FILE *F=fopen("runs/bow_rot_weights.txt","w"); for(int a=1;a<8;a++){ for(int b=1;b<8;b++) fprintf(F,"%.8f ",w[a][b]); fprintf(F,"\n"); } fclose(F);
  return 0;
}
