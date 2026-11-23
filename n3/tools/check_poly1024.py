#!/usr/bin/env python3
"""Rabin irreducibility test for the CMAC doubling polynomial x^1024+x^19+x^6+x+1."""
N=1024; F=(1<<N)|(1<<19)|(1<<6)|(1<<1)|1
def mod(a,f=F):
    df=f.bit_length()-1
    while a.bit_length()-1>=df: a^=f<<(a.bit_length()-1-df)
    return a
def sq(a):
    r=0;i=0
    while a:
        if a&1: r|=1<<(2*i)
        a>>=1;i+=1
    return r
def gcd(a,b):
    while b: a,b=b,mod(a,b)
    return a
x=2; t=x; half=None
for k in range(1,N+1):
    t=mod(sq(t))
    if k==N//2: half=t
print("x^(2^1024) == x mod f:", t==x)
print("gcd(x^(2^512)-x, f) == 1:", gcd(F, half^x)==1)
