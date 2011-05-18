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
                  0x1f83d9ab, 0x5be0cd19 ] --ok


-- BLAKE-256 constants
constants :: [Word32]
constants = [ 0x243f6a88, 0x85a308d3,
              0x13198a2e, 0x03707344,
              0xa4093822, 0x299f31d0,
              0x082efa98, 0xec4e6c89,
              0x452821e6, 0x38d01377,
              0xbe5466cf, 0x34e90c6c,
              0xc0ac29b7, 0xc97cd0dd,
              0x3f84d5b5, 0xb5470917 ] --ok


-- BLAKE-256 permutations of 0 to 15
sigma :: [[ Int ]]
sigma = [[  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ], 
         [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ], 
         [ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ], 
         [  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ], 
         [  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ], 
         [  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ], 
         [ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ], 
         [ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ], 
         [  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ], 
         [ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 ]] --ok?


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
blakeRound messageblock stateV round = 

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
        in

        -- perform a given Gi within the round function
        let fG v ii = 
                let [a,b,c,d] = map (v !!) (g !! ii)
                in

                -- get sigma
                let sigmaf n = sigma !! (round `mod` 10) !! n
                in

                let messageword n = messageblock !! sigmaf n
                in
    
                let constant n = constants !! sigmaf n
                in
            
                -- compute the round
                let a'  = a  + b  + (messageword (2*ii) `xor` constant (2*ii + 1))
                    d'  = (d `xor` a') `rotate` (-16) 
                    c'  = c + d' 
                    b'  = (b `xor` c') `rotate` (-12) 
                    a'' = a' + b' + (messageword (2*ii + 1) `xor` constant (2*ii))
                    d'' = (d' `xor` a'') `rotate` (-8) 
                    c'' = c' + d'' 
                    b'' = (b' `xor` c'') `rotate` (-7)
                in

                -- return a copy of the state list
                -- with each of the computed cells replaced 
                replace (zip (g !! ii) [a'', b'', c'', d'']) v
                --replace (zip (g !! ii) [a, b, c, d]) v               -- turn this into identity
        in

        foldl' fG stateV [0..7]


-- BLAKE-256 compression of one message block
-- h is a chain         0-7
-- m is a message block 0-15
-- s is a salt          0-3
-- t is a counter       0-1
-- return h'
-- 
-- TODO: fix this type?
compress :: [Word32] -> [Word32] -> [Word32] -> [Word32] -> [Word32]
compress h m s t =

    -- initialize state, 16 words
    let v = h ++ (zipWith xor (s ++ [t!!0, t!!0, t!!1, t!!1]) (take 8 constants))
    in

    -- do 14 rounds on this messageblock
    let v' = foldl' (blakeRound m) v [0..13]
    in

    -- finalize
    zipWith4 xor4 h (s ++ s) (take 8 v') (drop 8 v')
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


-- BLAKE-256 padding
-- blocks of 512 bits, padded, as 32 bit words 
-- (tupled with counter words)
{- OK:
    *Main> blocks 0 [0]
    [([8388608,0,0,0,0,0,0,0,0,0,0,0,0,1,8,0],[8,0])]
-}
blocks :: Word64 -> [Word8] -> [( [Word32], [Word32] )]
blocks counter s = 

    -- do this before calling blocks?
    -- let s8 = B.unpack s

    -- the next message block
    let next = take 64 s
    in

    -- block length
    let len = length next
    in
    
    -- cumulative block length in bits
    let counter' = counter + 8 * fromIntegral len
    in

    -- cumulative block length in bits as two 32 bit words
    -- low:high:[]
    let counter32 :: [Word32]
        counter32 = fromIntegral counter' : fromIntegral (counter' `shift` (-32)) : []
    in

    -- all 512 bits?
    if len < 64
    then
        -- this is the last message block (empty or partial)
        let simplePadding = 
                let zerobits  = (446 - 8 * len) `mod` 512
                in
                let zerobytes = (zerobits - 7 - 7) `div` 8
                in 
                case zerobits of 
                        -- as a practical matter, the adjustment must be one byte or more
                        -- though I'm not sure that this is conformant
                        z | (z + 2) `mod` 8 /= 0 -> error "padding needed is wrong: not 0 `mod` 8"
                        -- one byte
                        z | z == 6 -> [0x81]
                        -- more bytes
                        z | z > 6 -> [0x80] ++ take zerobytes (repeat 0) ++ [0x01]
        in

        let final = from8to32 (next ++ simplePadding) ++ counter32
        in
    
        case length final of
            16 -> [( final, counter32 )]
            32 -> [( take 16 final, counter32 ), ( drop 16 final, [0,0] )]
            otherwise -> error "we have created a monster! padding --> nonsense"
    
    else
        -- this is an ordinary message block, so recurse
        ( from8to32 next, counter32 ) : (blocks counter' (drop 64 s))
    



blake256 message salt = 
        let compress' s h (m,t) = compress h m s t
        in
        --foldl' (compress' s) initialValues $ blocks 0 $ B.unpack message -- B.readFile "blake.hs"
        --OK? compress' [0..] [0..] ([0,0], [0..15])
        --OK? compress' [0..3] initialValues ([0,0], [0..15])
        --OK? compress' [0..3] initialValues $ head $ blocks 0 ([3,24,12,23,5,23,42,34,1,42,35,4,56,34,3,5,5,7])
        --OK? compress' [0..3] initialValues $ head $ blocks 0 $ B.unpack message
        foldl' (compress' salt) initialValues $ blocks 0 $ B.unpack message



-- temporary
doStuff :: B.ByteString -> IO ()
doStuff x = B.putStrLn x


-- temporary
main :: IO ()
main = B.readFile "blake.hs"
       >>= doStuff




-- for REPL testing of assertions
-- TODO: learn a real test framework
assert :: Eq a => String -> a -> a -> IO ()
assert statement x y = putStr (statement ++ "...  ")
                       >> if x == y
                          then putStrLn $ "OK"
                          else putStrLn $ "FAILED"




test_init_prep = (let getInitial s h (m,t) =  h ++ (zipWith xor (s ++ [t!!0, t!!0, t!!1, t!!1]) (take 8 constants)) 
                in getInitial [0,0,0,0] initialValues $ head $ blocks 0 [0])

test_init = assert "BLAKE-256, initial state on '0x00'" 
                   [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 
                    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
                    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 
                    0xA409382A, 0x299F31D8, 0x082EFA98, 0xEC4E6C89]
                   test_init_prep
           

test_round_1_prep = (\(m,t) -> blakeRound m test_init_prep 0) $ head $ blocks 0 [0]

test_round_1 description selection = assert ("BLAKE-256, one round on '0x00', given selection: " ++ description)
                                      (selection [0xE78B8DFE, 0x150054E7, 0xCABC8992, 0xD15E8984, 
                                               0x0669DF2A, 0x084E66E3, 0xA516C4B3, 0x339DED5B, 
                                               0x26051FB7, 0x09D18B27, 0x3A2E8FA8, 0x488C6059, 
                                               0x13E513E6, 0xB37ED53E, 0x16CAC7B9, 0x75AF6DF6])
                                      (selection test_round_1_prep)


test_round_1' = assert "BLAKE-256, round 1, modified to be identity"
                      ([0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 
                               0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
                               0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 
                               0xA409382A, 0x299F31D8, 0x082EFA98, 0xEC4E6C89])
                      (test_round_1_prep)



test = do
            test_init
            test_round_1 "!!  0" $ (!! 0)
            test_round_1 "!!  1" $ (!! 1)
            test_round_1 "!!  2" $ (!! 2)
            test_round_1 "!!  3" $ (!! 3)
            test_round_1 "!!  4" $ (!! 4)
            test_round_1 "!!  5" $ (!! 5)
            test_round_1 "!!  6" $ (!! 6)
            test_round_1 "!!  7" $ (!! 7)
            test_round_1 "!!  8" $ (!! 8)
            test_round_1 "!!  9" $ (!! 9)
            test_round_1 "!! 10" $ (!! 10)
            test_round_1 "!! 11" $ (!! 11)
            test_round_1 "!! 12" $ (!! 12)
            test_round_1 "!! 13" $ (!! 13)
            test_round_1 "!! 14" $ (!! 14)
            test_round_1 "!! 15" $ (!! 15)
            -- test_round_1'

