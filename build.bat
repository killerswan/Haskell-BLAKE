ghc -Wall -O2 -fspec-constr-count=15 -o blakesum --make Main
ghc -Wall -O2 -fspec-constr-count=15 -o tests    --make Tests
