-- Copyright (c) 2011 Kevin Cantu <me@kevincantu.org>
--
-- A naive implementation of the Blake cryptographic hash: 
-- use at your own risk.

{-# LANGUAGE BangPatterns #-}

module SHA3.BLAKE ( blake256, blake512, blake224, blake384, toByteString ) where

import Data.Bits
import Data.Word
import Data.Int
import Data.List  -- needed for zipWith4
import qualified Data.ByteString.Lazy as B
import qualified Data.Vector.Storable as V
import Control.Parallel.Strategies


-- TODO: my function names often suck
-- TODO: wrangle some types into submission
-- TODO: may need to add error handling for excessively long inputs per the BLAKE paper
-- TODO: how about with vectors or repa or something?


-- BLAKE-224 initial values
initialValues224 :: V.Vector Word32
initialValues224 =
  V.fromList
    [ 0xC1059ED8, 0x367CD507, 
      0x3070DD17, 0xF70E5939, 
      0xFFC00B31, 0x68581511, 
      0x64F98FA7, 0xBEFA4FA4 ]


-- BLAKE-256 initial values
initialValues256 :: V.Vector Word32
initialValues256 = 
  V.fromList
    [ 0x6a09e667, 0xbb67ae85,
      0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c,
      0x1f83d9ab, 0x5be0cd19 ]


-- BLAKE-256 constants
constants256 :: V.Vector Word32
constants256 = 
  V.fromList
    [ 0x243f6a88, 0x85a308d3,
      0x13198a2e, 0x03707344,
      0xa4093822, 0x299f31d0,
      0x082efa98, 0xec4e6c89,
      0x452821e6, 0x38d01377,
      0xbe5466cf, 0x34e90c6c,
      0xc0ac29b7, 0xc97c50dd,
      0x3f84d5b5, 0xb5470917 ]


-- BLAKE-384 initial values
initialValues384 :: V.Vector Word64
initialValues384 =
  V.fromList
    [ 0xCBBB9D5DC1059ED8, 0x629A292A367CD507,
      0x9159015A3070DD17, 0x152FECD8F70E5939,
      0x67332667FFC00B31, 0x8EB44A8768581511,
      0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4 ]


-- BLAKE-512 initial values
initialValues512 :: V.Vector Word64
initialValues512 = 
  V.fromList
    [ 0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
      0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
      0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
      0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179 ]


-- BLAKE-512 constants
constants512 :: V.Vector Word64
constants512 = 
  V.fromList
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
--
-- TODO: currently this is only taking half our time?  should be more: optimize elsewhere?  but optimize this more, too
--
bitshiftX :: (Bits a, V.Storable a) 
          => V.Vector a         -- constants
          -> (Int,Int,Int,Int)  -- rotate by ...
          -> Int                -- i for which we're calculating G(i)
          -> (a,a,a,a)          -- 4 word col/diag
          -> V.Vector a         -- messageblock
          -> Int                -- round
          -> (a,a,a,a)          -- out: row or diagonal
bitshiftX constants (rot0,rot1,rot2,rot3) ii (a,b,c,d) messageblock rnd = 
                let 
                    -- get sigma
                    sigma n = sigmaTable !! (rnd `mod` 10) !! n

                    messageword n = messageblock V.! sigma n
                    constant    n = constants V.! sigma n

                    i2 = 2 * ii
            
                    -- compute the rnd
                    a'  = a  + b  + (messageword (i2) `xor` constant (i2 + 1))
                    d'  = (d `xor` a') `rotate` rot0
                    c'  = c + d' 
                    b'  = (b `xor` c') `rotate` rot1
                    a'' = a' + b' + (messageword (i2 + 1) `xor` constant (i2))
                    d'' = (d' `xor` a'') `rotate` rot2
                    c'' = c' + d'' 
                    b'' = (b' `xor` c'') `rotate` rot3
                in

                -- out
                (a'', b'', c'', d'')
--
-- BLAKE-256 bit shifting
bitshift256 :: Int -> (Word32,Word32,Word32,Word32) -> V.Vector Word32 -> Int -> (Word32,Word32,Word32,Word32)
bitshift256 = bitshiftX constants256 (-16, -12,  -8,  -7)

-- BLAKE-512 bit shifting
bitshift512 :: Int -> (Word64,Word64,Word64,Word64) -> V.Vector Word64 -> Int -> (Word64,Word64,Word64,Word64)
bitshift512 = bitshiftX constants512 (-32, -25, -16, -11)


        

-- generic round function
-- apply multiple G computations for a single round
{-
blakeRound :: (V.Storable a, Bits a)
           => (  Int           -- i for which we're calculating G(i)
              -> [a]           -- 4 word col/diag
              -> V.Vector a    -- 16w message
              -> Int           -- round number
              -> V.Vector a    -- 4w result
              )                         -- function to do bitshifting
           -> V.Vector a                -- 16w message block
           -> V.Vector a                -- 16w state
           -> Int                       -- round number
           -> V.Vector a                -- 16w result
-}

blakeRound bitshift messageblock state rnd = 
    let 
        -- perform one G
        g (ii,four) = bitshift ii four messageblock rnd


        -- apply G to columns
        -- then rotate result back into order
        applyColumns state = 
            let
                s' = (V.!) state
            in
                parMap rdeepseq g
                    [(0, (s' 0, s' 4, s'  8, s' 12)),
                     (1, (s' 1, s' 5, s'  9, s' 13)),
                     (2, (s' 2, s' 6, s' 10, s' 14)),
                     (3, (s' 3, s' 7, s' 11, s' 15))]

                        {- 4, [0,5,10,15]
                           5, [1,6,11,12]
                           6, [2,7, 8,13]
                           7, [3,4, 9,14] -}

        -- apply G to diagonals
        -- then rotate result back into order
        applyDiagonals [(c00,c01,c02,c03),
                        (c10,c11,c12,c13),
                        (c20,c21,c22,c23),
                        (c30,c31,c32,c33)] = 

                parMap rdeepseq g
                    [(4,(c00, c11, c22, c33)),
                     (5,(c10, c21, c32, c03)),
                     (6,(c20, c31, c02, c13)),
                     (7,(c30, c01, c12, c23))]


        -- unwind the diagonal results
        manualSpin [(d00,d01,d02,d03),
                    (d10,d11,d12,d13),
                    (d20,d21,d22,d23),
                    (d30,d31,d32,d33)] = 

                V.fromList [d00, d10, d20, d30, 
                            d31, d01, d11, d21, 
                            d22, d32, d02, d12, 
                            d13, d23, d33, d03]


    in
        manualSpin $ applyDiagonals $ applyColumns state





-- initial 16 word state for compressing a block
-- here, my counter 't' contains [high,low] words 
-- rather than reverse it in `blocks` below, i changed the numbering here
initialState :: (Bits a, V.Storable a)
             => V.Vector a
             -> V.Vector a
             -> [a]
             -> [a]
             -> V.Vector a

initialState constants h s t = 
    let
        partialConstants = V.take 8 constants
        counter          = V.fromList [t!!1, t!!1, t!!0, t!!0]
        stateAndCount    = V.fromList s V.++ counter
        chainPlusStuff   = V.zipWith xor stateAndCount partialConstants
    in
        h V.++ chainPlusStuff


-- BLAKE-256 compression of one message block
-- rounds is the number of rounds to iterate
-- h is a chain         0-7
-- m is a message block 0-15
-- s is a salt          0-3
-- t is a counter       0-1
-- return h'
--compress :: Int -> Hash -> MessageBlock -> Salt -> Counter -> Hash
compress bitshift rounds constants s h (m,t) =
    let 
        -- e.g., do 14 rounds on this messageblock for 256-bit
        -- WARNING: this lazy foldl dramatically reduces heap use...
        v = foldl (blakeRound bitshift m) (initialState constants h s t) [0..rounds-1]
    in

    -- finalize
    V.zipWith4 xor4 h ((V.fromList s) V.++ (V.fromList s)) (V.take 8 v) (V.drop 8 v)
                where xor4 a b c d = a `xor` b `xor` c `xor` d  -- can xor be folded?


-- convert words to bytes in a ByteString
-- the word array input typically needs a type annotation
toByteString :: (Integral a, Bits a) => Int -> [a] -> B.ByteString
toByteString size mydata =
    let
        octets = size `div` 8
        g w n = w `shiftR` (n*8)
        toBytes w = map (g w) $ reverse [0..octets-1]
    in
        B.pack $ map fromIntegral $ toBytes =<< mydata


-- BLAKE padding
-- blocks of twice the hash size, which is 8 words
-- with a counter per block
--
-- 256
blocks224 :: B.ByteString -> [(V.Vector Word32, [Word32])]
blocks224 = blocksX makeWords32 32 0x00
--
-- 256
blocks256 :: B.ByteString -> [(V.Vector Word32, [Word32])]
blocks256 = blocksX makeWords32 32 0x01
--
-- 384
blocks384 :: B.ByteString -> [(V.Vector Word64, [Word64])]
blocks384 = blocksX makeWords64 64 0x00
--
-- 512
blocks512 :: B.ByteString -> [(V.Vector Word64, [Word64])]
blocks512 = blocksX makeWords64 64 0x01



-- TODO: I'd rather slice the input instead of making new vectors
--
blocksX :: (Bits a, Integral a, Num a, V.Storable a) 
        => (B.ByteString -> [a]) 
        -> Int64
        -> Word8 
        -> B.ByteString 
        -> [( V.Vector a, [a] )]

blocksX makeWords wordSize paddingTerminator message' = 
    let
        loop counter message = 
            let 

                -- split bytes at 16 words of type a
                (m, ms) = B.splitAt (wordSize * 2) message

                -- block length in bits
                len = 8 * B.length m

                -- cumulative block length in bits
                counter' = (counter :: Integer) + fromIntegral len

                counterMSW   = fromIntegral $ counter' `shiftR` (fromIntegral wordSize :: Int)
                counterLSW   = fromIntegral counter'

                splitCounter = [counterMSW, counterLSW]

            in
                if len < (16 * wordSize) || ms == B.empty
                then -- final
                    let
                        simplePadding' = simplePadding len wordSize paddingTerminator
                        final = makeWords (B.append m simplePadding') ++ splitCounter

                    in
                        case length final of
                            -- each message block is padded to 16 words
                            16 -> [( (V.fromList final),           splitCounter )]
                            32 -> [( (V.fromList $ take 16 final), splitCounter ), 
                                   ( (V.fromList $ drop 16 final), [0,0] )]
                            _  -> error "we have created a monster! padding --> nonsense"
                        
                else -- regular
                    ((V.fromList $ makeWords m), splitCounter) : loop counter' ms

    in
        loop 0 message'


-- how do I make it generic
-- even though ByteString isn't an [a]?
-- experiment: extra function for the end
nfoldl n fn1 fn2 xs =
    let
        (x, xs') = B.splitAt n xs
    in
        if (B.length x) < n || xs' == B.empty
        then
            [fn2 x]
        else
            fn1 x : nfoldl n fn1 fn2 xs'


-- turn a ByteString into an integer
growWord :: (Integral a, Bits a) 
         => B.ByteString 
         -> a

growWord = B.foldl' shiftAcc 0
           where shiftAcc acc x = (fromIntegral acc `shift` 8) + fromIntegral x


makeWords32 :: B.ByteString -> [Word32]
makeWords32 ss = nfoldl 4 growWord growWord ss


makeWords64 :: B.ByteString -> [Word64]
makeWords64 ss = nfoldl 8 growWord growWord ss


-- pad a last block of message as needed
-- TODO: simplify

simplePadding :: Int64         -- block bitlength
              -> Int64         -- word bitlength
              -> Word8         -- 0x01 or 0x00
              -> B.ByteString  -- padded space, e.g. 0b1000...00001

simplePadding len wordSize paddingTerminator = 
    let
        targetbits = (14 * wordSize) - 2                       -- length zero padding will be used to build, 446 or 894
        zerobits   = (targetbits - len) `mod` (16 * wordSize)  -- where len is bytes in this data
        zerobytes  = (zerobits - 7 - 7) `div` 8                -- the number of 0x00 between the 0x80 and 0x01
        zbs        = B.take zerobytes (B.repeat 0)             -- the bytestring of 0x00
    in 
        case zerobits of 
            z | z == 6 -> B.singleton $ 0x80 + paddingTerminator        -- ^ one byte -- TODO: THIS CASE IS NOT TESTED?
            z | z >  6 -> 0x80 `B.cons` zbs `B.snoc` paddingTerminator  -- ^ more bytes
            _          -> error "assumption: adjustment of the input bits should be 0 `mod` 8 "


--blake :: Int -> Salt -> [Word8] -> Hash
blake bitshift rounds constants blocks initialValues salt message =
    let
    in
      if length salt /= 4
      then error "blake: your salt is not four words"
      else V.toList $ foldl' (compress bitshift rounds constants salt) initialValues $ blocks message
     

-- TODO: refactor, now that we've converted both the messages, outputs, and salts to ByteString

blake256 :: B.ByteString -> B.ByteString -> B.ByteString
blake256 salt message = 
    let
        blake' :: [Word32] -> B.ByteString -> [Word32]
        blake' = blake bitshift256 14 constants256 blocks256 initialValues256

        salt' = makeWords32 salt
       
    in
        toByteString 32 $ blake' salt' message



blake512 :: B.ByteString -> B.ByteString -> B.ByteString
blake512 salt message =
    let
        blake' :: [Word64] -> B.ByteString -> [Word64]
        blake' = blake bitshift512 16 constants512 blocks512 initialValues512
    in
        toByteString 64 $ blake' (makeWords64 salt) message
        

blake224 :: B.ByteString -> B.ByteString -> B.ByteString
blake224 salt message =
    let
        blake' :: [Word32] -> B.ByteString -> [Word32]
        blake' s m = take 7 $ blake bitshift256 14 constants256 blocks224 initialValues224 s m

        salt' = makeWords32 salt
    in
        toByteString 32 $ blake' salt' message


blake384 :: B.ByteString -> B.ByteString -> B.ByteString
blake384 salt message =
    let
        blake' :: [Word64] -> B.ByteString -> [Word64]
        blake' s m = take 6 $ blake bitshift512 16 constants512 blocks384 initialValues384 s m

        salt' = makeWords64 salt
    in
        toByteString 64 $ blake' salt' message
        

