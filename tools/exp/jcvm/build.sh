#!/bin/bash
# Build jch (the Java Card VM on the host, with the UI sim's fake libctru) next to this script.
set -e
D=$(cd "$(dirname "$0")" && pwd)
S="$D/../../../prox3ds"
gcc -m32 -g -O0 -Wall -Wno-unused-function -I"$S/sim/include" -I"$S/source" -o "$D/jch" "$D/jch.c" \
	"$S/source/jcvm.c" "$S/source/jcapi.c" "$S/source/jccard.c" "$S/source/jcapitab.c" "$S/source/zip.c" "$S/source/sha1.c" "$S/source/jccrypto.c" "$S/source/bn.c" "$S/source/ecc.c" "$S/source/dfcrypto.c" "$S/sim/fake.c" -pthread -lm
