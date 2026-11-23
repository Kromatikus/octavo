#!/usr/bin/env python3
"""Feed malformed lines to n3draft; it must exit 0/2 with a message, never panic (exit 101)."""
import random, subprocess, sys
BIN = sys.argv[1]
S = "ab" * 128; N = "cd" * 16; Bk = "ef" * 128
cases = [b"x\n", b"e\n", ("e %s %s %s\n" % (S, N, Bk[:-1])).encode(), ("e %s %s zz%s\n" % (S, N, Bk[2:])).encode(),
         ("e %s %s %s\n" % (S, N, "\u00e9" * 128)).encode(), b"\xff\xfe\n", ("q %s %s %s\n" % (S, N, Bk)).encode(),
         ("e %s %s %s\n" % (S[:-2], N, Bk)).encode(), ("e %s %s %s extra\n" % (S, N, Bk)).encode(),
         ("e %s %s \u00e9%s\n" % (S, N, Bk[1:])).encode(), ("e %s %s %s\n" % (S, N, Bk)).encode()]
r = random.Random(1)
for _ in range(300):
    good = bytearray(("e %s %s %s\n" % (S, N, Bk)).encode())
    for _ in range(r.randint(1, 5)): good[r.randrange(len(good))] = r.randrange(256)
    cases.append(bytes(good))
bad = 0; codes = {}
for c in cases:
    p = subprocess.run([BIN], input=c, capture_output=True)
    codes[p.returncode] = codes.get(p.returncode, 0) + 1
    if p.returncode not in (0, 2) or b"panicked" in p.stderr: bad += 1; print("BAD", c[:60], p.returncode, p.stderr[:200])
print("cases", len(cases), "exit codes", codes, "panics", bad)
