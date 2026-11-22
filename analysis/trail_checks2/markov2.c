/* OCT-4 Stage 3c: Markov (independent-key) clustering on the same 2-S-layer piece as superbox.c:
   EDP(a->b) = sum_c DP_S(a0->c0) DP_S(a1->c1) DP_S(m0->b0) DP_S2(m1->b1), m = mix2(c)  (all characteristics summed)
   ELP(a->b) = sum_g C_S(a0,g0)^2 C_S(a1,g1)^2 C_S(n0,b0)^2 C_S2(n1,b1)^2, n = mask of mix2 inputs->outputs (g = mix2^T n)
   Reports max EDP / max ELP over one-byte inputs (all 510) and 64 random two-byte inputs (linear: 4 of them), vs the best single characteristic. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
static unsigned char S[256], S2[256], M2[256];
static double D[256][256], D2[256][256], L[256][256], L2[256][256];
static double acc[65536];
int main(int argc, char **argv){
  FILE *fp=fopen(argv[1],"rb"); if(fread(S,1,256,fp)!=256||fread(S2,1,256,fp)!=256||fread(M2,1,256,fp)!=256) return 1; fclose(fp);
  for(int a=0;a<256;a++) for(int x=0;x<256;x++){ D[a][S[x]^S[x^a]]+=1/256.0; D2[a][S2[x]^S2[x^a]]+=1/256.0; }
  for(int a=0;a<256;a++) for(int b=0;b<256;b++){ int s=0,s2=0; for(int x=0;x<256;x++){ s+=(__builtin_popcount((a&x)^(b&S[x]))&1)?-1:1; s2+=(__builtin_popcount((a&x)^(b&S2[x]))&1)?-1:1; }
    L[a][b]=(s/256.0)*(s/256.0); L2[a][b]=(s2/256.0)*(s2/256.0); }
  /* transpose of mul-by-2 as a GF(2)-linear map on masks */
  int T2[256]; for(int mm=0;mm<256;mm++){ int r=0; for(int bit=0;bit<8;bit++) if(__builtin_popcount(mm&M2[1<<bit])&1) r|=1<<bit; T2[mm]=r; }
  /* inverse map n -> g:  g0 = n0 ^ n1, g1 = n0 ^ T2[n1]; build table g -> n */
  static int G2N[65536]; for(int n=0;n<65536;n++){ int n0=n>>8,n1=n&255; G2N[((n0^n1)<<8)|(n0^T2[n1])]=n; }
  srand(12345);
  int as[600], na=0; for(int v=1;v<256;v++){ as[na++]=v<<8; as[na++]=v; } for(int k=0;k<64;k++){ int a0=1+rand()%255,a1=1+rand()%255; as[na++]=(a0<<8)|a1; }
  double medp1=0, medp2=0, mbest1=0, mbest2=0, melp1=0, melp2=0, lbest1=0, lbest2=0;
  for(int t=0;t<na;t++){ int a=as[t], a0=a>>8, a1=a&255; int two=(a0&&a1);
    memset(acc,0,sizeof acc); double bc=0;
    for(int c0=0;c0<256;c0++){ double p0=D[a0][c0]; if(p0==0) continue; for(int c1=0;c1<256;c1++){ double p1=D[a1][c1]; if(p1==0) continue;
      int m0=c0^c1, m1=c0^M2[c1]; double p=p0*p1; double r0max=0,r1max=0;
      for(int b0=0;b0<256;b0++){ double q0=D[m0][b0]; if(q0==0) continue; if(q0>r0max)r0max=q0; double pq=p*q0; double *dst=acc+(b0<<8);
        for(int b1=0;b1<256;b1++){ double q1=D2[m1][b1]; if(q1!=0) dst[b1]+=pq*q1; } }
      for(int b1=0;b1<256;b1++) if(D2[m1][b1]>r1max) r1max=D2[m1][b1];
      if(p*r0max*r1max>bc) bc=p*r0max*r1max; } }
    double mx=0; for(int b=1;b<65536;b++) if(acc[b]>mx) mx=acc[b];
    if(two){ if(mx>medp2)medp2=mx; if(bc>mbest2)mbest2=bc; } else { if(mx>medp1)medp1=mx; if(bc>mbest1)mbest1=bc; }
    if(two && t >= 510 + 4) continue;   /* linear two-byte inputs: only 4 (each costs ~4e9 steps) */
    /* linear */
    memset(acc,0,sizeof acc); double lb=0;
    for(int g0=0;g0<256;g0++){ double p0=L[a0][g0]; if(p0==0) continue; for(int g1=0;g1<256;g1++){ double p1=L[a1][g1]; if(p1==0) continue;
      if(!g0&&!g1) continue; int n=G2N[(g0<<8)|g1], n0=n>>8, n1=n&255; double p=p0*p1, r0=0, r1=0;
      for(int b0=0;b0<256;b0++){ double q0=L[n0][b0]; if(q0==0) continue; if(q0>r0)r0=q0; double pq=p*q0; double *dst=acc+(b0<<8);
        for(int b1=0;b1<256;b1++){ double q1=L2[n1][b1]; if(q1!=0) dst[b1]+=pq*q1; } }
      for(int b1=0;b1<256;b1++) if(L2[n1][b1]>r1) r1=L2[n1][b1];
      if(p*r0*r1>lb) lb=p*r0*r1; } }
    mx=0; for(int b=1;b<65536;b++) if(acc[b]>mx) mx=acc[b];
    if(two){ if(mx>melp2)melp2=mx; if(lb>lbest2)lbest2=lb; } else { if(mx>melp1)melp1=mx; if(lb>lbest1)lbest1=lb; }
  }
  printf("{\"one_byte_in\": {\"max_markov_EDP_log2\": %.3f, \"best_char_log2\": %.3f, \"gain_bits\": %.3f, \"max_markov_ELP_log2\": %.3f, \"best_lin_char_ELP_log2\": %.3f, \"lin_gain_bits\": %.3f},"
         " \"two_byte_in_64_random\": {\"max_markov_EDP_log2\": %.3f, \"best_char_log2\": %.3f, \"gain_bits\": %.3f, \"max_markov_ELP_log2\": %.3f, \"best_lin_char_ELP_log2\": %.3f, \"lin_gain_bits\": %.3f}}\n",
    log2(medp1), log2(mbest1), log2(medp1/mbest1), log2(melp1), log2(lbest1), log2(melp1/lbest1),
    log2(medp2), log2(mbest2), log2(medp2/mbest2), log2(melp2), log2(lbest2), log2(melp2/lbest2));
  return 0;
}
