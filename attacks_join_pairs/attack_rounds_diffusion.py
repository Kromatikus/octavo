"""Reduced-round diffusion + simple statistical distinguishers on the LIVE post-join N2 at r = 1,2,3,4,16.
White-box keyed rounds on raw 128-byte blocks (chosen-plaintext; raw blocks need not be encodable). 'not detected' != 'absent'."""
from common import *
import math
log=Log('attack_rounds_diffusion');res={}
B=Batch(SCH);log('accelerator cross-check:',B.validate(16),'round evaluations OK')
rng=np.random.default_rng(20261108)
for R in (1,2,3,4,16):
 r={}
 # (a) byte dependence: every input byte, 32 random bases/deltas each
 K=32;x=rng.integers(0,256,(128*K,128),dtype=np.uint16);y=x.copy();idx=np.repeat(np.arange(128),K);y[np.arange(128*K),idx]^=rng.integers(1,256,128*K,dtype=np.uint16)
 dx=(B.enc(x,R)^B.enc(y,R))!=0;dep=np.zeros((128,128),bool)
 for i in range(128):dep[i]=dx[i*K:(i+1)*K].any(0)
 r['byte_dependence']=dict(pairs=int(dep.sum()),of=16384,full=bool(dep.all()))
 # (b) bit avalanche
 n=4096;x=rng.integers(0,256,(n,128),dtype=np.uint16);y=x.copy();bit=rng.integers(0,1024,n);y[np.arange(n),bit//8]^=(1<<(bit%8)).astype(np.uint16)
 d=(B.enc(x,R)^B.enc(y,R)).astype(np.uint8);bits=np.unpackbits(d,axis=1);hw=bits.sum(1);rate=bits.mean(0)
 r['bit_avalanche']=dict(pairs=n,mean=round(float(hw.mean()),2),sd=round(float(hw.std()),2),min=int(hw.min()),max=int(hw.max()),
  worst_bit_rate_dev=round(float(np.abs(rate-0.5).max()),4),expected_dev_4sigma=round(4*0.5/math.sqrt(n),4))
 # (c) zero-difference bytes after a single-byte input difference
 n=65536;x=rng.integers(0,256,(n,128),dtype=np.uint16);y=x.copy();pos=rng.integers(0,128,n);y[np.arange(n),pos]^=rng.integers(1,256,n,dtype=np.uint16)
 dz=(B.enc(x,R)^B.enc(y,R))==0;z=dz.sum(0);chi=float(((z-n/256)**2/(n/256)).sum())
 r['zero_diff_bytes']=dict(pairs=n,mean_zero_bytes_per_pair=round(float(dz.sum(1).mean()),4),expected=0.5,chi2_128pos=round(chi,1),chi2_df=127,
  max_pos=int(z.max()),min_pos=int(z.min()),expected_per_pos=n/256)
 # (d) fixed high-bit input difference 0x80 in cell 18 (the even-coefficient crossing cell): output-diff==0x80 rate, and full diff histogram on one byte
 x=rng.integers(0,256,(n,128),dtype=np.uint16);y=x.copy();y[:,18]^=0x80
 d=(B.enc(x,R)^B.enc(y,R));e80=(d==0x80).sum(0);h=np.bincount(d[:,38],minlength=256)
 chi38=float(((h-n/256)**2/(n/256)).sum())
 r['delta80_cell18']=dict(pairs=n,max_pos_count_of_0x80=int(e80.max()),expected_per_pos=n/256,zero_rate_mean=round(float((d==0).mean()),5),
  chi2_outbyte38_diff_hist=round(chi38,1),chi2_df=255)
 res[R]=r
 log(f'--- {R} round(s) ---');[log('   ',k,v) for k,v in r.items()]
res['interpretation']=('chi2 df=127: 99.9% critical ~181; df=255: 99.9% critical ~330. Bit avalanche random: mean 512, sd 16. '
 '1 round: incomplete dependence + the 3-byte truncated differential (attack_highbit_trail.py). Anything at r>=2 below is only what these tests see.')
log(res['interpretation'])
log.save(res)
