-- Copyright (c) 2011 Kevin Cantu <me@kevincantu.org>
--
-- A naive implementation of the Blake cryptographic hash: 
-- use at your own risk.

module SHA3.BLAKE ( blake256,
                    --initialValues256,
                    --initialState,
                    --blocks,
                    --blakeRound,
                    blake512--,
                    --blake224,
                    --blake384
                    ) where


import Data.Bits
import Data.Word
import Data.List -- needed for zipWith4
import Data.Maybe -- needed for isJust, fromJust


-- BLAKE-256 initial values
initialValues256 :: [Word32]
initialValues256 = 
    [ 0x6a09e667, 0xbb67ae85,
      0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c,
      0x1f83d9ab, 0x5be0cd19 ]


-- BLAKE-256 constants
constants256 :: [Word32]
constants256 = 
    [ 0x243f6a88, 0x85a308d3,
      0x13198a2e, 0x03707344,
      0xa4093822, 0x299f31d0,
      0x082efa98, 0xec4e6c89,
      0x452821e6, 0x38d01377,
      0xbe5466cf, 0x34e90c6c,
      0xc0ac29b7, 0xc97c50dd,
      0x3f84d5b5, 0xb5470917 ]


-- BLAKE-512 initial values
initialValues512 :: [Word64]
initialValues512 = 
    [ 0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
      0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
      0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
      0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179 ]


-- BLAKE-512 constants
constants512 :: [Word64]
constants512 = 
    [ 0x243F6A8885A308D3, 0x13198A2E03707344,
      0xA4093822299F31D0, 0x082EFA98EC4E6C89,
      0x452821E638D01377, 0xBE5466CF34E90C6C,
      0xC0AC29B7C97C50DD, 0x3F84D5B5B5470917,
      0x9216D5D98979FB1B, 0xD1310BA698DFB5AC,
      0x2FFD72DBD01ADFB7, 0xB8E1AFED6A267E96,
      0xBA7C9045F12C7F99, 0x24A19947B3916CF7,
      0x0801F2E2858EFC16, 0x636920D871574E69 ]


-- BLAKE-256 permutations of {0..15}
sigmaTable :: [[ Int ]]
sigmaTable =
    [[  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ], 
     [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ], 
     [ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ], 
     [  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ], 
     [  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ], 
     [  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ], 
     [ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ], 
     [ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ], 
     [  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ], 
     [ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 ]]



-- bit shift
-- perform a given Gi within the round function
--
-- generic bit shifting
bitshiftX :: Bits a => [a] -> [Int] -> [a] -> [a] -> Int -> (Int, [Int]) -> [a]
bitshiftX constants [r0,r1,r2,r3] state messageblock round (ii, cells) = 
                let 
                    -- cells to handle
                    [a,b,c,d] = map (state !!) cells
                
                    -- get sigma
                    sigma n = sigmaTable !! (round `mod` 10) !! n

                    messageword n = messageblock !! sigma n
                    constant    n = constants !! sigma n
            
                    -- compute the round
                    a'  = a  + b  + (messageword (2*ii) `xor` constant (2*ii + 1))
                    d'  = (d `xor` a') `rotate` r0
                    c'  = c + d' 
                    b'  = (b `xor` c') `rotate` r1
                    a'' = a' + b' + (messageword (2*ii + 1) `xor` constant (2*ii))
                    d'' = (d' `xor` a'') `rotate` r2
                    c'' = c' + d'' 
                    b'' = (b' `xor` c'') `rotate` r3
                in

                -- out
                [a'', b'', c'', d'']
--
-- BLAKE-256 bit shifting
bitshift256 :: [Word32] -> [Word32] -> Int -> (Int, [Int]) -> [Word32]
bitshift256 = bitshiftX constants256 [-16, -12,  -8,  -7]
--
-- BLAKE-512 bit shifting
bitshift512 :: [Word64] -> [Word64] -> Int -> (Int, [Int]) -> [Word64]
bitshift512 = bitshiftX constants512 [-32, -25, -16, -11]


-- BLAKE-256 round function
-- apply multiple G computations for a single round
--
-- This is uglier than the fold I had before,
-- but this can be parallelized a teeny bit...
blakeRound mode messageblock state round = 

        let 
            -- perform one G
            g state = bitshift256 state messageblock round


            -- rotate a 2d list
            rotate4 m = 
                map (!! 0) m :
                map (!! 1) m : 
                map (!! 2) m : 
                map (!! 3) m : []


            -- apply G to columns
            -- then rotate result back into order
            applyColumns state = 
                let 
                    cols = map (g state)
                                -- i, cells for each Gi
                                [ (0, [0,4,8,12]),
                                  (1, [1,5,9,13]), 
                                  (2, [2,6,10,14]), 
                                  (3, [3,7,11,15]) ] 
                in
                concat $ rotate4 cols


            -- apply G to diagonals
            -- then rotate result back into order
            applyDiagonals state = 
                let 
                    diags = map (g state)
                                -- i, cells for each Gi
                                [ (4, [0,5,10,15]),
                                  (5, [1,6,11,12]), 
                                  (6, [2,7,8,13]), 
                                  (7, [3,4,9,14]) ] 

                    cols = rotate4 diags

                    shiftRowRight n row = drop j row ++ take j row
                                            where j = length row - n
                in
                concat [ shiftRowRight 0 (cols !! 0),
                         shiftRowRight 1 (cols !! 1),
                         shiftRowRight 2 (cols !! 2),
                         shiftRowRight 3 (cols !! 3)  ]
        in

        applyDiagonals $ applyColumns state


-- initial 16 word state for compressing a block
-- here, my counter 't' contains [high,low] words 
-- rather than reverse it in `blocks` below, i changed the numbering here
initialState h s t = 
    h ++ 
    zipWith xor (s ++ [t!!1, t!!1, t!!0, t!!0]) (take 8 constants256)


-- BLAKE-256 compression of one message block
-- h is a chain         0-7
-- m is a message block 0-15
-- s is a salt          0-3
-- t is a counter       0-1
-- return h'
--compress :: Int -> Hash -> MessageBlock -> Salt -> Counter -> Hash
compress mode h m s t =
    let 
        -- rounds to iterate
        rounds = case mode of
                    256 -> 14
                    512 -> 16

        -- do 14 rounds on this messageblock for 256-bit
        v = foldl' (blakeRound mode m) (initialState h s t) [0..rounds-1]
    in

    -- finalize
    zipWith4 xor4 h (s ++ s) (take 8 v) (drop 8 v)
                where xor4 a b c d = a `xor` b `xor` c `xor` d  -- can xor be folded?



-- group bytes into larger words
-- should be built-in?
from8toN :: Bits a => Int -> [Word8] -> [a]
from8toN size words = 
    let 
        octets = size `div` 8

        -- make one word
        getWord os = if length os /= octets then
                            error "sorry, would have to pad this list to make words"
                     else
                            foldl' f 0 os
            where f acc word = (acc `shift` 8) + (fromIntegral word)

        -- make list of words
        loop acc []     = acc
        loop acc words = loop (acc ++ [getWord (take octets words)]) (drop octets words)
    in

    -- fold into words
    loop [] words

{-
-}

-- 16 words
type MessageBlock = [Word32]

-- 4 words
type Salt = [Word32]

-- 16 words
type Hash = [Word32]

-- 2 words
-- cumulative bit length
type Counter = [Word32]

data BW a = BW32 [Word32] | BW64 [Word64]


-- IS THERE A WAY TO MAKE HASKELL DO LENGTH CHECKING BY TYPE?
-- how about with vectors or repa or something?


-- BLAKE-256 padding
-- blocks of twice the hash size, which is 8 words
-- with a counter per block
blocks mode message = 

    --let loop :: (Bits a, Bounded a, Enum a, Eq a, Integral a, Num a, Ord a, Read a, Real a, Show a) => Integer -> [Word8] -> [( [a], [a] )]
    let loop :: Integer -> [Word8] -> [( MessageBlock, Counter )]
        loop counter message =
            let 
                (paddingTerminator, wordSize) = case mode of 
                                                    256 -> (0x01, 32)
                                                    512 -> (0x01, 64)
                hashSize = 8 * wordSize -- i.e. 256
                blockSize = 16 * wordSize
                blockBytes = blockSize `div` 8
    
                -- the next message block
                next = take blockBytes message

                -- block length in bits
                len = 8 * length next

                -- cumulative block length in bits
                counter' = counter + fromIntegral len

                -- counter, in two words
                splitCounter = fromIntegral (counter' `shift` (-wordSize)) : fromIntegral counter' : []

            in


            -- needs padding?
            if len < blockSize
            then
                -- this is the last message block (empty or partial)
                let simplePadding = 
                        let target = 2 * hashSize - 2 - 2 * wordSize -- length zero padding will be used to build, 446 or 894
                            zerobits  = (target - len) `mod` blockSize -- where len is bytes in this data
                            zerobytes = (zerobits - 7 - 7) `div` 8
                        in 
                        case zerobits of 
                                -- as a practical matter, the adjustment must be one byte or more
                                -- though I'm not sure that this is conformant
                                z | (z + 2) `mod` 8 /= 0 -> error "padding needed is wrong: not 0 `mod` 8"
                                -- one byte
                                z | z == 6 -> [0x80 + paddingTerminator]
                                -- more bytes
                                z | z > 6 -> [0x80] ++ take zerobytes (repeat 0) ++ [paddingTerminator]

                    final = from8toN wordSize (next ++ simplePadding) ++ splitCounter
                in
            
                case length final of
                    -- each message block is padded to 16 words
                    16 -> [( final, splitCounter )]
                    32 -> [( take 16 final, splitCounter ), ( drop 16 final, [0,0] )]
                    otherwise -> error "we have created a monster! padding --> nonsense"
            
            else
                -- this is an ordinary message block, so recurse
                ( from8toN wordSize next, splitCounter ) : (loop counter' (drop blockBytes message))

    in
    loop 0 message
        

--blake :: Int -> Salt -> [Word8] -> Hash
blake mode salt message =
    let ivs = case mode of
                256 -> initialValues256
        
        compress' h (m,t) = compress mode h m salt t
    in
    foldl' compress' ivs $ blocks mode message
     

blake256 :: [Word32] -> [Word8] -> [Word32]
blake256 = blake 256

blake512 :: [Word64] -> [Word8] -> [Word64]
blake512 a b = []

{-
blake224 :: [Word32] -> [Word8] -> [Word32]
blake224 = blake 224

blake384 :: [Word64] -> [Word8] -> [Word64]
blake384 = blake 384
-}
