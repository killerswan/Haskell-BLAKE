#!/bin/bash

EXEBASE=blakesum
EXE="$EXEBASE.exe"

# quiet rm
function qrm() {
    [ -f "$1" ] && rm "$1"
}

# COMPILE
qrm "$EXEBASE".exe
ghc -Wall -O2 -prof -auto-all -rtsopts -fforce-recomp -o blakesum --make Main
[ -x "$EXE" ] || exit 1

# VERSION
./"$EXE" --version

# FILE TO TEST
#FILE="testheap.data"  # about 840 megabytes
FILE="C:\Users\Kevin\Desktop\Next_700.pdf"

# PROFILE
# TODO: USE $@ instead of $1
# TODO: temporary files
function profileWithOption() {
    qrm "$EXEBASE"-"$1".hp
    qrm "$EXEBASE"-"$1".ps

    time ./"$EXE" -a 512 "$FILE" +RTS $1
    [ -r "$EXEBASE".hp ] || exit 1

    mv "$EXEBASE".hp "$EXEBASE"-"$1".hp
    hp2ps -e8in -d -c "$EXEBASE"-"$1".hp
    cygstart "$EXEBASE"-"$1".ps
}

# -p -hd OR -hc OR -hy
# -M1G -hy
profileWithOption -hc
profileWithOption -hy


