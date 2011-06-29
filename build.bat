REM ghc -Wall -O2 -o blakesum --make Main
ghc -Wall -O2 -rtsopts -prof -auto-all -caf-all -fforce-recomp -o blakesum --make Main
REM profiling, then, via
REM +RTS -p [-hp | -hy | -hd]

ghc -Wall -O2 -o tests    --make Tests
