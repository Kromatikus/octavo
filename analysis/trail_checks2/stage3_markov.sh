#!/bin/bash
cd "$(dirname "$0")"
for f in runs/sbox_seed20261121_s0_r0.bin runs/sbox_seed20261122_s2_r11.bin; do echo "$f $(nice -n 10 ./markov2 $f)"; done > runs/stage3_markov.txt
echo MARKOV_DONE >> runs/stage3_markov.txt
