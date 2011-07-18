#!/bin/bash

EXEBASE=blakesum
EXE="$EXEBASE"

# quiet rm
function qrm() {
    [ -f "$1" ] && rm "$1"
}

# COMPILE
qrm "$EXE"

# FILE TO TEST
#FILE="testheap.data"  # about 840 megabytes
#FILE="C:\Users\Kevin\Desktop\Next_700.pdf"
FILE=Next_700.pdf

# PROFILE
# TODO: USE $@ instead of $1
# TODO: temporary files
function profileWithOption() {
    qrm "$EXEBASE"-"$1".hp
    qrm "$EXEBASE"-"$1".ps

    ghc -Wall -O2 -prof -auto-all -rtsopts -fforce-recomp -fspec-constr-count=15 -o blakesum --make Main
    [ -x "$EXE" ] || exit 1
    ./"$EXE" --version

    time ./"$EXE" -a 512 "$FILE" +RTS -sstderr -p $1 # -xt -K100M -H100M
    [ -r "$EXEBASE".hp ] || exit 1

    mv "$EXEBASE".hp "$EXEBASE"-"$1".hp
    hp2ps -e8in -d -c "$EXEBASE"-"$1".hp
#    cygstart "$EXEBASE"-"$1".ps
    evince "$EXEBASE"-"$1".ps &
}

function runThreadscope() {
   ghc -Wall -O2 -threaded -eventlog -auto-all -rtsopts -fforce-recomp -fspec-constr-count=15 -o blakesumTS --make Main
   time ./blakesumTS -a 512 "$FILE" +RTS -N -ls -sstderr # -K100M -H100M
   threadscope blakesumTS.eventlog &
}

function runVisualProf() {
   SRC=Data/Digest/SHA3/Candidate/BLAKE.hs
   RUN=Main
   ARGS=Next_700.pdf
   
   visual-prof -px "$SRC" "$RUN" "$ARGS"
   google-chrome "$SRC.html" &
}

# -p -hd OR -hc OR -hy
# -M1G -hy

runThreadscope

#runVisualProf

profileWithOption -hc
profileWithOption -hy


