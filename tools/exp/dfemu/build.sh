#!/bin/bash
# Build dfh (dfemu.c + the UI sim's fake libctru) next to this script.
set -e
D=$(cd "$(dirname "$0")" && pwd)
cd "$D/../../../nfcprobe/sim"
SRC=$(make -pn | sed -n "s/^SRC *:= //p" | head -1)
F="-m32 -D_FILE_OFFSET_BITS=64 -D_TIME_BITS=64 -g -O0 -w -Iinclude -I../source -I."
gcc $F -Dmain=sim_main -c scenes.c -o "$D/scenes.o"
gcc $F -o "$D/dfh" "$D/dfh.c" "$D/scenes.o" ${SRC/scenes.c/} -pthread -lm
rm "$D/scenes.o"
