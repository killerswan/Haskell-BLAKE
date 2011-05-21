-- Copyright (c) 2011 Kevin Cantu <me@kevincantu.org>
--
-- A naive implementation of the Blake cryptographic hash: 
-- use at your own risk.

module SHA3.BLAKE ( blake256,
                    blakeRound, 
                    initialValues, 
                    initialState, 
                    blocks ) 
where


import Data.Bits
import Data.Word
import Data.List -- needed for zipWith4
import Data.Maybe -- needed for isJust, fromJust


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
              0xc0ac29b7, 0xc97c50dd,
              0x3f84d5b5, 0xb5470917 ]


-- BLAKE-256 permutations of 0 to 15
sigmaTable :: [[ Int ]]
sigmaTable = [[  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ], 
              [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ], 
              [ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ], 
              [  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ], 
              [  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ], 
              [  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ], 
              [ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ], 
              [ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ], 
              [  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ], 
              [ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 ]]


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
-- PENDING: THERE IS AN ERROR IN THIS FUNCTION...
blakeRound shifts messageblock state round = 

        -- define each Gi in a round as (i, cell numbers)
        -- TODO: when parallelizing, make this more complicated
        let g = [ [0,4,8,12],   -- 4 columns
                  [1,5,9,13], 
                  [2,6,10,14], 
                  [3,7,11,15], 
                  [0,5,10,15],  -- 4 diagonals
                  [1,6,11,12], 
                  [2,7,8,13], 
                  [3,4,9,14] ] 
            (s0, s1, s2, s3) = shifts -- minus 16, 12, 8, 7 for 256-bit mode
        in

        -- perform a given Gi within the round function
        let fG state ii = 
                let 
                    [a,b,c,d] = map (state !!) (g !! ii)

                    -- get sigma
                    sigma n = sigmaTable !! (round `mod` 10) !! n

                    messageword n = messageblock !! sigma n
                    constant    n = constants    !! sigma n
            
                    -- compute the round
                    a'  = a  + b  + (messageword (2*ii) `xor` constant (2*ii + 1))
                    d'  = (d `xor` a') `rotate` s0
                    c'  = c + d' 
                    b'  = (b `xor` c') `rotate` s1
                    a'' = a' + b' + (messageword (2*ii + 1) `xor` constant (2*ii))
                    d'' = (d' `xor` a'') `rotate` s2
                    c'' = c' + d'' 
                    b'' = (b' `xor` c'') `rotate` s3
                in

                -- return a copy of the state list
                -- with each of the computed cells replaced 
                replace (zip (g !! ii) [a'', b'', c'', d'']) state
        in

        foldl' fG state [0..7]
        


-- initial 16 word state for compressing a block
-- here, my counter 't' contains [high,low] words 
-- rather than reverse it in `blocks` below, i changed the numbering here
initialState h s t = 
    h ++ 
    zipWith xor (s ++ [t!!1, t!!1, t!!0, t!!0]) (take 8 constants)


-- BLAKE-256 compression of one message block
-- h is a chain         0-7
-- m is a message block 0-15
-- s is a salt          0-3
-- t is a counter       0-1
-- return h'
--compress :: [Word32] -> [Word32] -> [Word32] -> [Word32] -> [Word32]
compress rounds shifts h m s t =

    -- do 14 rounds on this messageblock for 256-bit
    let v = foldl' (blakeRound shifts m) (initialState h s t) [0..rounds-1]
    in

    -- finalize
    zipWith4 xor4 h (s ++ s) (take 8 v) (drop 8 v)
                where xor4 a b c d = a `xor` b `xor` c `xor` d  -- can xor be folded?



-- group bytes into larger words
-- should be built-in?
from8toN :: Bits a => Int -> [Word8] -> [a]
from8toN mode words = 
    -- make one word
    let getWord os = if length os /= mode then
                            error "sorry, would have to pad this list to make words"
                     else
                            foldl' f 0 os

            where f acc octet = (acc `shift` 8) + (fromIntegral octet)
    in

    -- make list of words
    let loop acc []     = acc
        loop acc octets = loop (acc ++ [getWord (take mode octets)])  -- TODO ASAP: master HUnit?
                               (drop mode octets)
    in

    -- fold into words
    loop [] words

from8to32 :: [Word8] -> [Word32]
from8to32 = from8toN 4

from8to64 :: [Word8] -> [Word64]
from8to64 = from8toN 8


-- 16 words
type MessageBlock = [Word32]

-- 2 words
-- cumulative bit length
type Counter = [Word32]

-- IS THERE A WAY TO MAKE HASKELL DO LENGTH CHECKING BY TYPE?
-- how about with vectors or repa or something?


-- BLAKE-256 padding
-- blocks of 512 bits, padded, as 32 bit words 
-- (tupled with counter words)
blocks :: Word64 -> [Word8] -> [( [Word32], [Word32] )]
blocks counter message = 

    let 
        -- the next message block
        next = take 64 message

        -- block length
        len = length next

        -- cumulative block length in bits
        counter' = counter + 8 * fromIntegral len

        -- cumulative block length in bits as two 32 bit words
        counter32 :: [Word32]
        counter32 = fromIntegral (counter' `shift` (-32)) : fromIntegral counter' : []
    in

    -- all 512 bits?
    if len < 64
    then
        -- this is the last message block (empty or partial)
        let simplePadding = 
                let zerobits  = (446 - 8 * len) `mod` 512
                    zerobytes = (zerobits - 7 - 7) `div` 8
                in 
                case zerobits of 
                        -- as a practical matter, the adjustment must be one byte or more
                        -- though I'm not sure that this is conformant
                        z | (z + 2) `mod` 8 /= 0 -> error "padding needed is wrong: not 0 `mod` 8"
                        -- one byte
                        z | z == 6 -> [0x81]
                        -- more bytes
                        z | z > 6 -> [0x80] ++ take zerobytes (repeat 0) ++ [0x01]

            final = from8to32 (next ++ simplePadding) ++ counter32
        in
    
        case length final of
            16 -> [( final, counter32 )]
            32 -> [( take 16 final, counter32 ), ( drop 16 final, [0,0] )]
            otherwise -> error "we have created a monster! padding --> nonsense"
    
    else
        -- this is an ordinary message block, so recurse
        ( from8to32 next, counter32 ) : (blocks counter' (drop 64 message))
    

-- BLAKE-256
blake256 salt message =
    let compress' s h (m,t) = compress 14 (-16,-12,-8,-7) h m s t
    in foldl' (compress' salt) initialValues $ blocks 0 message




-- TODO: 512, other hash sizes; optimize

