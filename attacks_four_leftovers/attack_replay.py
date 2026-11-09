from common import *
verify_live()
# Fast regression replay of concrete findings; does not alter the cipher.
def delta(fn,x,y):return [a^b for a,b in zip(fn(x),fn(y))]
assert N.decrypt(HB,SEED)==b'hello world'
assert N.b0_apply(0,1)==(8,0)
assert delta(lambda z:N.b0_apply(*z),[0,0],[5,1])==[13,160]
x=[192]*8;y=x.copy();y[3]^=128
assert delta(lambda z:N.odd_restack(N.bow_pressure(z)),x,y)==[8,0,0,0,0,0,0,0]
for t,p in [(3,0),(5,2),(7,4)]:
 x=[0]*8;y=x.copy();y[t]=85;want=[0]*8;want[p]=85
 assert delta(lambda z:N.odd_restack(N.bow_pressure(z)),x,y)==want
assert N.bar_apply(N.BARS[1][3],1,1)==(0,3)
assert N.mix2(0,128)==(128,245)
g=[[0]*8 for _ in range(16)];g[0][0]=1;g[1][0]=250
h=N.cross_staff_mix(g);assert [row[0] for row in h]==[251,0,0,0]*4
print('PASS: recorded hello, B0 wrap/old differential, four bow+rehair witnesses, field cancellation, mix2, cross-only 2-to-4 cancellation. Source:',LIVE_SHA)
