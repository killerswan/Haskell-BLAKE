-- Copyright (c) 2011 Kevin Cantu <me@kevincantu.org>
--
-- A naive implementation of the Blake cryptographic hash: 
-- use at your own risk.


import Data.Bits
import Data.Word
import Data.List -- needed for zipWith4
import Data.Maybe -- needed for isJust, fromJust
import qualified Data.ByteString as B


-- BLAKE-256 initial values
initialValues :: [Word32]
initialValues = [ 0x6a09e667, 0xbb67ae85,
                  0x3c6ef372, 0xa54ff53a,
                  0x510e527f, 0x9b05688c,
                  0x1f83d9ab, 0x5be0cd19 ]


-- BLAKE-256 constants
constants :: [Word32]
constants = [ 0x243f6a88, 0x85a308d3,
              0x13198a2e, 0x03707344,
              0xa4093822, 0x299f31d0,
              0x082efa98, 0xec4e6c89,
              0x452821e6, 0x38d01377,
              0xbe5466cf, 0x34e90c6c,
              0xc0ac29b7, 0xc97cd0dd,
              0x3f84d5b5, 0xb5470917 ]


-- BLAKE-256 permutations of 0 to 15
sigma :: [[ Int ]]
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


-- replace items in a list
replace :: [(Int, a)] -> [a] -> [a]
replace newWords words = 
    let f (i, word) =  
            let newWord = lookup i newWords
            in

            if isJust newWord then
                fromJust newWord
            else
                word
    in
    map f $ zip [0..] words


-- BLAKE-256 round function
-- apply multiple G computations for a single round
blakeRound messageblock stateV r = 

        -- define each Gi in a round as (i, cell numbers)
        -- TODO: when parallelizing, make this more complicated
        let g = zip [0..] [ [0,4,8,12],   -- 4 columns
                            [1,5,9,13], 
                            [2,6,10,14], 
                            [3,7,11,15], 
                            [0,5,10,15],  -- 4 diagonals
                            [1,6,11,12], 
                            [2,7,8,13], 
                            [3,4,9,14] ] 
        in

        -- perform a given Gi within the round function
        let fG stateV (i,cells) =
                -- a-d
                let [a,b,c,d] = map getCell cells
                     where getCell i = (stateV !! (cells !! i))
                in
            
                -- compute the round
                let a'  = a  + b  + (messageblock !! (sigma !! (r `mod` 10) !! (2*i)) `xor` 
                                       (constants !! (sigma !! (r `mod` 10) !! (2*i + 1))))
                    d'  = (d `xor` a') `rotate` (-16) 
                    c'  = c + d' 
                    b'  = (b `xor` c') `rotate` (-12) 
                    a'' = a' + b' + (messageblock !! (sigma !! (r `mod` 10) !! (2*i + 1)) `xor` 
                                       (constants !! (sigma !! (r `mod` 10) !! (2*i)))) 
                    d'' = (d' `xor` a'') `rotate` (-8) 
                    c'' = c' + d'' 
                    b'' = (b' `xor` c'') `rotate` (-7)
                in

                -- return a copy of the state list
                -- with each of the computed cells replaced 
                replace (zip cells [a'', b'', c'', d'']) stateV
        in

        foldl fG stateV g


-- BLAKE-256 compression
-- h is a chain         0-7
-- m is a message block 0-15
-- s is a salt          0-3
-- t is a counter       0-1
-- return h'
-- 
-- TODO: fix this type?
compress :: [Word32] -> [Word32] -> [Word32] -> [Word32] -> [Word32]
compress h s t m =

    -- initialize state, 16 words
    let v = (++) h $ zipWith xor (s ++ [t!!0, t!!0, t!!1, t!!1]) (take 8 constants)
    in

    -- do 14 rounds on this messageblock
    let v' = foldl (blakeRound m) v [0..13]
    in

    -- finalize
    zipWith4 xor4 h (s ++ s) (take 8 v') (drop 8 v')
                where xor4 a b c d = a `xor` b `xor` c `xor` d  -- can xor be folded?



-- group bytes into larger words
-- should be built-in?
-- requires caller to specify type, e.g., from8toN 8 data :: [Word64]
from8toN :: Bits a => Int -> [Word8] -> [a]
from8toN mode words = 
    -- make one word
    let getWord os = if length os /= mode then
                            error "sorry, would have to pad this list to make words"
                     else
                            foldl f 0 os

            where f acc octet = (acc `shift` 8) + (fromIntegral octet)
    in

    -- make list of words
    let loop acc []     = acc
        loop acc octets = accum ((getWord (take mode octets)) : acc) 
                                (drop mode octets)
    in

    -- fold into words
    loop [] words
    
{-
-- padding as necessary...
padded :: Word64 -> Word64
padded len = (len + adjust len + 1 + 64)
    where adjust len = (447 - len) `mod` 512
                    -- adjustment is by 1000000..
-}


-- group by blocks of 16 32-bit words / 512 bits
-- insert padding as necessary
blocks :: B.ByteString -> [Word32]
blocks s = 
    
    -- call compress
    -- sometimes with a null t
    -- padding when necessary
    -- etc.


-- temporary
doStuff :: B.ByteString -> IO ()
doStuff x = B.putStrLn x


-- temporary
main :: IO ()
main = B.readFile "blake.hs" 
       >>= doStuff
