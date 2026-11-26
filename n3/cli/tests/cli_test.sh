#!/bin/bash
# CLI checks for n3file: keys, roundtrips, -j identity, and "no output file on any reject".
# Usage: cli_test.sh /abs/path/to/n3file /abs/path/to/demo-seed.txt
set -euo pipefail
B="$1"; DEMO="$2"
mkdir -p "$(cd "$(dirname "$0")/.." && pwd)/target"
T=$(mktemp -d "$(cd "$(dirname "$0")/.." && pwd)/target/cli_test.XXXXXX")
trap 'rm -rf -- "$T"' EXIT
pass=0; failn=0
ok() { pass=$((pass+1)); }
bad() { echo "FAIL: $*"; failn=$((failn+1)); }
expect() { # expect CODE cmd...
  local want=$1; shift
  set +e; "$@" >"$T/out.txt" 2>"$T/err.txt"; local got=$?; set -e
  if [ "$got" = "$want" ]; then ok; else bad "exit $got != $want: $* :: $(head -c 300 "$T/err.txt")"; fi
}
cd "$T"
# keys
expect 0 "$B" keygen -o "$T/k1"
[ "$(stat -c %a "$T/k1")" = 600 ] && ok || bad "key mode"
[ "$(tr -d '\n' < "$T/k1" | wc -c)" = 256 ] && ok || bad "key length"
expect 1 "$B" keygen -o "$T/k1"                       # refuses overwrite
expect 0 "$B" keygen -o "$T/k2"
expect 0 "$B" check-key -k "$T/k1"
python3 -c "print('00'*128)" > "$T/weak"; chmod 600 "$T/weak"
expect 1 "$B" check-key -k "$T/weak"
python3 -c "print(''.join('%02x'%(i*17+0xa5 & 255) for i in range(128)))" > "$T/ctr"; chmod 600 "$T/ctr"
expect 1 "$B" check-key -k "$T/ctr"                    # arithmetic sequence
cp "$DEMO" "$T/demo"; chmod 600 "$T/demo"
head -c 5000 /dev/urandom > "$T/p5k"
expect 1 "$B" seal -k "$T/demo" -o "$T/d.n3f" "$T/p5k"   # demo seed refused
[ ! -e "$T/d.n3f" ] && ok || bad "demo seal left a file"
expect 0 "$B" seal -k "$T/demo" --allow-demo-seed -o "$T/d.n3f" "$T/p5k"
expect 2 "$B" seal -k "$T/k1" --chunk-size 1000 -o "$T/x" "$T/p5k"   # usage
expect 2 "$B" seal -k "$T/k1" --ad a --ad-hex 00 -o "$T/x" "$T/p5k"
expect 2 "$B" seal -k "$T/k1" --ad-hex zz -o "$T/x" "$T/p5k"
# roundtrips (chunk 4096) at 0, 1, c-1, c, c+1, multi
for n in 0 1 4095 4096 4097 40000 1048576; do
  head -c $n /dev/urandom > "$T/p$n"
  expect 0 "$B" seal -k "$T/k1" --chunk-size 4096 --ad "hello" -o "$T/c$n" "$T/p$n"
  expect 0 "$B" open -k "$T/k1" --ad "hello" -o "$T/r$n" "$T/c$n"
  cmp -s "$T/p$n" "$T/r$n" && ok || bad "roundtrip $n"
done
# stdin/stdout seal, stdout open needs the explicit flag
"$B" seal -k "$T/k1" < "$T/p40000" > "$T/s.n3f" 2>/dev/null && ok || bad "stdin seal"
expect 2 "$B" open -k "$T/k1" "$T/s.n3f"
expect 2 "$B" open -k "$T/k1" -o - "$T/s.n3f"
"$B" open -k "$T/k1" -o - --stdout-unverified-tail "$T/s.n3f" > "$T/s.out" 2>"$T/s.err" && ok || bad "stdout open"
cmp -s "$T/s.out" "$T/p40000" && ok || bad "stdout open content"
grep -q "cannot be withheld" "$T/s.err" && ok || bad "stdout warning"
# -j byte identity with a fixed (test-only) nonce
head -c 3000000 /dev/urandom > "$T/pj"
for j in 1 2 3 8; do
  "$B" seal -k "$T/k1" -j $j --test-file-nonce 000102030405060708090a0b0c0d0e0f -o "$T/j$j" "$T/pj" 2>/dev/null
done
for j in 2 3 8; do cmp -s "$T/j1" "$T/j$j" && ok || bad "-j$j differs"; done
"$B" seal -k "$T/k1" -o "$T/rnd1" "$T/pj" && "$B" seal -k "$T/k1" -o "$T/rnd2" "$T/pj"
cmp -s "$T/rnd1" "$T/rnd2" && bad "two RNG seals equal" || ok
# existing output: refused without -f, replaced with -f
expect 1 "$B" open -k "$T/k1" --ad hello -o "$T/r40000" "$T/c40000"
expect 0 "$B" open -k "$T/k1" --ad hello -f -o "$T/r40000" "$T/c40000"
# tampering: every reject exits 1 and leaves NO output file and no temp files
C="$T/c40000"; L=$(stat -c %s "$C"); R=$((32+4096)); H=26
tam() { # name, then a python expression transforming bytes d
  python3 - "$C" "$T/tam" "$2" <<'PY'
import sys
d=bytearray(open(sys.argv[1],'rb').read()); H=26; R=32+4096
d=eval(sys.argv[3]); open(sys.argv[2],'wb').write(bytes(d))
PY
  mkdir -p "$T/o"; rm -f "$T/o/"* "$T/o/".??* 2>/dev/null || true
  expect 1 "$B" open -k "$T/k1" --ad hello -o "$T/o/out" "$T/tam"
  [ -z "$(ls -A "$T/o")" ] && ok || bad "$1 left output: $(ls -A "$T/o")"
}
tam "magic"        'd[:0]+bytearray([d[0]^1])+d[1:]'
tam "version"      'd[:5]+bytearray([2])+d[6:]'
tam "chunk size"   'd[:6]+(8192).to_bytes(4,"little")+d[10:]'
tam "file nonce"   'd[:12]+bytearray([d[12]^1])+d[13:]'
tam "tag byte"     'd[:H+R+5]+bytearray([d[H+R+5]^1])+d[H+R+6:]'
tam "chunk byte"   'd[:H+2*R+100]+bytearray([d[H+2*R+100]^1])+d[H+2*R+101:]'
tam "last byte"    'd[:-1]+bytearray([d[-1]^1])'
tam "swap 0/1"     'd[:H]+d[H+R:H+2*R]+d[H:H+R]+d[H+2*R:]'
tam "drop last"    'd[:H+(len(d)-H)//R*R] if (len(d)-H)%R else d[:-R]'
tam "drop chunk 3" 'd[:H+3*R]+d[H+4*R:]'
tam "dup chunk 2"  'd[:H+3*R]+d[H+2*R:H+3*R]+d[H+3*R:]'
tam "truncate 1"   'd[:-1]'
tam "truncate boundary" 'd[:H+5*R]'
tam "header only"  'd[:H]'
tam "empty"        'd[:0]'
tam "append 1"     'd+b"\x00"'
tam "append rec"   'd+d[H:H+R]'
mkdir -p "$T/o"; rm -f "$T/o/"* 2>/dev/null || true
expect 1 "$B" open -k "$T/k1" --ad hellO -o "$T/o/out" "$C"; [ -z "$(ls -A "$T/o")" ] && ok || bad "wrong AD left output"
expect 1 "$B" open -k "$T/k1" -o "$T/o/out" "$C"; [ -z "$(ls -A "$T/o")" ] && ok || bad "missing AD left output"
expect 1 "$B" open -k "$T/k2" --ad hello -o "$T/o/out" "$C"; [ -z "$(ls -A "$T/o")" ] && ok || bad "wrong key left output"
# an existing target is untouched by a failed open with -f
echo keep > "$T/o/out"
expect 1 "$B" open -k "$T/k2" --ad hello -f -o "$T/o/out" "$C"
[ "$(cat "$T/o/out")" = keep ] && [ "$(ls -A "$T/o")" = out ] && ok || bad "failed -f open touched target"
# keys never printed anywhere
K1=$(tr -d '\n' < "$T/k1")
for f in "$T"/out.txt "$T"/err.txt "$T"/s.err; do grep -qi "$K1" "$f" && bad "key printed in $f" || ok; done
"$B" --help 2>&1 | grep -q "AES-GCM-SIV" && ok || bad "help honesty"
echo "cli_test: $pass passed, $failn failed"
[ "$failn" = 0 ]
