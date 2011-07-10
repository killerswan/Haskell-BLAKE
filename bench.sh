#!/bin/bash


# DELETE OLD
[ -f blakesum.exe ] && rm blakesum.exe
[ -f blakesum.hp  ] && rm blakesum.hp
[ -f blakesum.ps  ] && rm blakesum.ps


# COMPILE
ghc -Wall -O2 -prof -auto-all -rtsopts -fforce-recomp -o blakesum --make Main
[ -x blakesum.exe ] || exit 1


# RUN AND PROFILE
date
./blakesum.exe --version

#FILE="testheap.data"  # about 840 megabytes
FILE="C:\Users\Kevin\Desktop\Next_700.pdf"

# +RTS -p -hd OR -hc OR -hy
# +RTS -M1G -hy
time ./blakesum.exe -a 512 "$FILE" +RTS -hc
[ -r blakesum.hp ] || exit 1


# DISPLAY PROFILE
hp2ps -e8in -d -c blakesum.hp
cygstart blakesum.ps


