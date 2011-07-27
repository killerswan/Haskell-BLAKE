-- |
-- Module      : Tests.Bench
-- Copyright   : (c) 2011 Kevin Cantu
--
-- License     : BSD-style
-- Maintainer  : Kevin Cantu <me@kevincantu.org>
-- Stability   : experimental
--
-- Benchmarking...
--module Bench ( ) where


import Data.Digest.BLAKE
import qualified Data.ByteString.Lazy as B
import Data.Text.Lazy as T
import Criterion.Main



blake512of0s z = blake512 (B.take 32 $ B.repeat 0x00) (B.take z $ B.repeat 0x00)


main =
   defaultMain [ bench "simple blake512, 1.2 MB" $ whnf blake512of0s 1206396
               , bench "simple blake512, 2.4 MB" $ whnf blake512of0s (2*1206396)
               ]


