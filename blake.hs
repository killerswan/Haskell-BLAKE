-- Copyright (c) 2011 Kevin Cantu <me@kevincantu.org>
--
-- A naive implementation of the Blake cryptographic hash: 
-- use at your own risk.


import Data.Bits
import Data.Word
import qualified Data.ByteString as B


-- BLAKE-256 initial values
--iv :: [Word64]
iv = [ 0x6a09e667, 0xbb67ae85,
       0x3c6ef372, 0xa54ff53a,
       0x510e527f, 0x9b05688c,
       0x1f83d9ab, 0x5be0cd19 ]

-- BLAKE-256 constants
--c :: [Word64]
c = [ 0x243f6a88, 0x85a308d3,
      0x13198a2e, 0x03707344,
      0xa4093822, 0x299f31d0,
      0x082efa98, 0xec4e6c89,
      0x452821e6, 0x38d01377,
      0xbe5466cf, 0x34e90c6c,
      0xc0ac29b7, 0xc97cd0dd,
      0x3f84d5b5, 0xb5470917 ]

-- BLAKE-256 permutations of 0 to 15
--sigma :: [[Word64]]
sigma = [[ 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 ],
         [ 14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3 ],
         [ 11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4 ],
         [ 7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8 ],
         [ 9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13 ],
         [ 2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9 ],
         [ 12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11 ],
         [ 13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10 ],
         [ 6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5 ],
         [ 10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0 ]]


-- BLAKE-256 compression
-- h is a chain         0-7
-- m is a message block 0-15
-- s is a salt          0-3
-- t is a counter       0-1
-- return h'
compress :: [Word64] -> [Word64] -> [Word64] -> [Word64] -> [Char]
compress h m s t =


    -- initialization
    -- 16 word state
    --v :: [[WordX]]
    -- should probably be more verbose, not less
    let v = (++) h $ zipWith (.|.) (s ++ [t!!0, t!!0, t!!1, t!!1]) (take 8 c)
    in

    
    -- sequence changed in each round
    let g = [ (0,4,8,12), (1,5,9,13), (2,6,10,14), (3,7,11,15),  -- columns
              (0,5,10,15), (1,6,11,12), (2,7,8,13), (3,4,9,14) ] -- diagonals
    in

    let round (a,b,c,d) v = ""



    in





    ""
               

    
              
              








doStuff :: B.ByteString -> IO ()
doStuff x = B.putStrLn x


main :: IO ()
main = B.readFile "blake.hs" 
       >>= doStuff
