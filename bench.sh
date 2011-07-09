rm blakesum.exe
ghc -Wall -O2 -prof -auto-all -rtsopts -fforce-recomp -o blakesum --make Main

./blakesum.exe --version
date

FILE="C:\Users\Kevin\Desktop\Next_700.pdf"
#FILE="testheap.data"

#time ./blakesum.exe "C:\Users\Kevin\Desktop\Next_700.pdf" +RTS -p -hd
#time ./blakesum.exe "C:\Users\Kevin\Desktop\Next_700.pdf" +RTS -p -hc
#time ./blakesum.exe "SHA3\BLAKE.hs" +RTS -p -hc
#time ./blakesum.exe "C:\Users\Kevin\Desktop\Next_700.pdf" +RTS -M1G -hy
#time ./blakesum.exe "$FILE" +RTS -M1G -hy
time ./blakesum.exe "$FILE" +RTS -M900M -hy

hp2ps -e8in -c blakesum.hp
cygstart blakesum.ps

## broken
#hp2pretty --uniform-scale=time blakesum.hp
#cygstart blakesum.svg
