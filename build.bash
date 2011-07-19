#!/bin/bash

cabal configure --enable-tests
echo ""
cabal haddock
echo ""
cabal build
echo ""
cabal test
echo ""
cabal install
echo ""
cabal sdist
