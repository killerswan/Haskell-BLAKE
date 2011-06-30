rm blakesum.exe
ghc -Wall -O2 -rtsopts -prof -auto-all -caf-all -fforce-recomp -o blakesum --make Main

./blakesum.exe --version
date

#time ./blakesum.exe "C:\Users\Kevin\Desktop\Next_700.pdf" +RTS -p -hd
time ./blakesum.exe "C:\Users\Kevin\Desktop\Next_700.pdf" +RTS -p -hc

hp2ps -e8in -c blakesum.hp
cygstart blakesum.ps
