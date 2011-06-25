REM First, the BLAKE algorithms
tests.exe

REM Next, some writing
blakesum.exe        README Main.hs Tests.hs SHA3\BLAKE.hs > 256.tmp
blakesum.exe -a 512 README Main.hs Tests.hs SHA3\BLAKE.hs > 512.tmp

REM Then checking those writes
blakesum.exe -c        256.tmp
blakesum.exe -c -a 512 512.tmp

del 256.tmp 512.tmp

REM Together
blakesum.exe README Main.hs Tests.hs SHA3\BLAKE.hs | blakesum.exe -c

REM Again
blakesum.exe README Main.hs Tests.hs SHA3\BLAKE.hs | blakesum.exe -c -

REM Now summing from a pipe
echo "holy cow" | blakesum.exe -a 256
echo "holy cow" | blakesum.exe -a 256 -s 1,5,353453,23234
echo "holy cow" | blakesum.exe -a 512
echo "holy cow" | blakesum.exe -a 512 -s 23,14,5423,54

REM Needs more tests...
