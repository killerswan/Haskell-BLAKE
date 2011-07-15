-- Copyright (c) 2011 Kevin Cantu <me@kevincantu.org>
--
-- A naive implementation of the Blake cryptographic hash: 
-- use at your own risk.

{-# LANGUAGE BangPatterns #-}

module SHA3.BLAKE ( blake256, blake512, blake224, blake384 ) where

import Data.Bits
import Data.Word
import Data.Int
import Data.List
import qualified Data.ByteString.Lazy as B
import qualified Data.Vector.Storable as V
import Control.Parallel.Strategies


-- TODO: my function names often suck
-- TODO: wrangle some types into submission
-- TODO: may need to add error handling for excessively long inputs per the BLAKE paper




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

-- generic bit shifting
bitshift :: (Bits a, V.Storable a) 
          => BLAKE a
          -> Int                -- i for which we're calculating G(i)
          -> (a,a,a,a)          -- 4 word col/diag
          -> V.Vector a         -- messageblock
          -> Int                -- round
          -> (a,a,a,a)          -- out: row or diagonal
bitshift config ii (a,b,c,d) messageblock rnd = 
                let 
                    -- configurable...
                    constants' = constants config
                    (rot0,rot1,rot2,rot3) = rotations config

                    -- get sigma
                    sigma n = sigmaTable !! (rnd `mod` 10) !! n

                    messageword n = messageblock V.! sigma n
                    constant    n = constants' V.! sigma n

                    i2 = 2 * ii
            
                    -- compute the rnd
                    a'  = a  + b  + (messageword (i2) `xor` constant (i2 + 1))
                    d'  = (d `xor` a') `rotateR` rot0
                    c'  = c + d' 
                    b'  = (b `xor` c') `rotateR` rot1
                    a'' = a' + b' + (messageword (i2 + 1) `xor` constant (i2))
                    d'' = (d' `xor` a'') `rotateR` rot2
                    c'' = c' + d'' 
                    b'' = (b' `xor` c'') `rotateR` rot3
                in

                -- out
                (a'', b'', c'', d'')


        

-- generic round function
-- apply multiple G computations for a single round
-- TODO:
-- Why is this slower with parallel column and then diagonal calcs? Laziness?
-- With rdeepseq, particularly, this cuts the heap by about 2/3, though!
blakeRound :: (V.Storable a, Bits a)
           => BLAKE a
           -> V.Vector a
           -> V.Vector a
           -> Int
           -> V.Vector a
blakeRound config messageblock state rnd = 
    let 
        -- perform one G
        g (ii,four) = bitshift config ii four messageblock rnd


        -- apply G to columns
        -- then rotate result back into order
        applyColumns state' = 
            let
                s' = (V.!) state'
            in
                --parMap rdeepseq g
                map g
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

                --parMap rdeepseq g
                map g
                    [(4,(c00, c11, c22, c33)),
                     (5,(c10, c21, c32, c03)),
                     (6,(c20, c31, c02, c13)),
                     (7,(c30, c01, c12, c23))]

        applyDiagonals _ = error "applyDiagonals: fail"


        -- unwind the diagonal results
        manualSpin [(d00,d01,d02,d03),
                    (d10,d11,d12,d13),
                    (d20,d21,d22,d23),
                    (d30,d31,d32,d33)] = 

                V.fromList [d00, d10, d20, d30, 
                            d31, d01, d11, d21, 
                            d22, d32, d02, d12, 
                            d13, d23, d33, d03]

        manualSpin _ = error "manualSpin: fail"

    in
        manualSpin $ applyDiagonals $ applyColumns state



-- initial 16 word state
-- here, my counter 't' contains [high,low] words 
-- rather than reverse it in `blocks` below, i changed the numbering here
initialState :: (V.Storable a, Bits a)
             => BLAKE a
             -> V.Vector a
             -> [a]
             -> [a]
             -> V.Vector a

initialState config h s t = 
    let
        -- configurable...
        constants' = constants config

        partialConstants = V.take 8 constants'
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
compress :: (V.Storable a, Bits a)
         => BLAKE a
         -> [a]
         -> V.Vector a
         -> (V.Vector a, [a])
         -> V.Vector a

compress config salt h (m,t) =
    let 
        -- configurable...
        rounds' = rounds config

        initial = initialState config h salt t

        -- e.g., do 14 rounds on this messageblock for 256-bit
        -- WARNING: this lazy foldl dramatically reduces heap use...
        v = foldl (blakeRound config m) initial [0..rounds'-1]

        -- split it in half
        (v0,v1) = V.splitAt 8 v

        -- salt
        s' = V.fromList salt
        s'' = s' V.++ s'
    in

    -- finalize
    V.zipWith4 xor4 h
                    s''
                    v0
                    v1
       where xor4 a b c d = a `xor` b `xor` c `xor` d


-- convert words to bytes in a ByteString
-- the word array input typically needs a type annotation
toByteString :: (Integral a, Bits a, V.Storable a) => Int -> V.Vector a -> B.ByteString
toByteString size mydata =
    let
        octets = size `div` 8
        g w n = w `shiftR` (n*8)
        toBytes w = V.map (g w) $ V.fromList $ reverse [0..octets-1]
    in
        B.pack $ V.toList $ V.map fromIntegral $ V.concatMap toBytes mydata


-- BLAKE padding
-- blocks of twice the hash size, which is 8 words
-- with a counter per block
-- TODO: I'd rather slice the input instead of making new vectors
blocks :: (Bits a, Integral a, Num a, V.Storable a) 
        => BLAKE a
        -> B.ByteString 
        -> [( V.Vector a, [a] )]

blocks config message' = 
    let
        -- configurable...
        wordSize' = wordSize config

        -- recurse with accumulating counter
        loop counter message = 
            let 

                -- split bytes at 16 words of type a
                (m, ms) = B.splitAt (wordSize' * 2) message

                -- block length in bits
                len = 8 * B.length m

                -- cumulative block length in bits
                counter' = (counter :: Integer) + fromIntegral len

                counterMSW   = fromIntegral $ counter' `shiftR` (fromIntegral wordSize' :: Int)
                counterLSW   = fromIntegral counter'

                splitCounter = [counterMSW, counterLSW]

            in
                if len < (16 * wordSize') || ms == B.empty
                then -- final
                    let
                        padded = m `B.append` makePadding config len         -- ^ padded message block
                        final  = makeWords wordSize' padded ++ splitCounter  -- ^ block including counter

                    in
                        case length final of
                            -- each message block is padded to 16 words
                            16 -> [( (V.fromList final),           splitCounter )]
                            32 -> [( (V.fromList $ take 16 final), splitCounter ), 
                                   ( (V.fromList $ drop 16 final), [0,0] )]
                            _  -> error "we have created a monster! padding --> nonsense"
                        
                else -- regular
                    ((V.fromList $ makeWords wordSize' m), splitCounter) : loop counter' ms

    in
        loop 0 message'


-- how do I make it generic
-- even though ByteString isn't an [a]?
nfoldl :: Int64 -> (B.ByteString -> a) -> B.ByteString -> [a]
nfoldl n fn xs =
    let
        (x, xs') = B.splitAt n xs
    in
        case B.length x of
            0              -> []
            len | len < n  -> error "nfoldl: didn't have n remaining"
            _              -> fn x : nfoldl n fn xs'


-- turn a ByteString into an integer
growWord :: (Integral a, Bits a) => B.ByteString -> a
growWord = B.foldl' shiftAcc 0
           where shiftAcc acc x = (fromIntegral acc `shift` 8) + fromIntegral x

-- turn many ByteStrings into integers
makeWords :: (Bits a, Integral a) => Int64 -> B.ByteString -> [a]
makeWords n ss = nfoldl (n `div` 8) growWord ss


-- pad a last block of message as needed
-- TODO: simplify

makePadding :: BLAKE a
            -> Int64         -- block bitlength
            -> B.ByteString  -- padded space, e.g. 0b1000...00001

makePadding config len = 
    let
        -- configurable...
        wordSize' = wordSize config
        paddingTerminator' = paddingTerminator config

        targetbits = (14 * wordSize') - 2                       -- length zero padding will be used to build, 446 or 894
        zerobits   = (targetbits - len) `mod` (16 * wordSize')  -- where len is bytes in this data
        zerobytes  = (zerobits - 7 - 7) `div` 8                 -- the number of 0x00 between the 0x80 and 0x01
        zbs        = B.take zerobytes (B.repeat 0)              -- the bytestring of 0x00
    in 
        case zerobits of 
            z | z == 6 -> B.singleton $ 0x80 + paddingTerminator'        -- ^ one byte -- TODO: THIS CASE IS NOT TESTED?
            z | z >  6 -> 0x80 `B.cons` zbs `B.snoc` paddingTerminator'  -- ^ more bytes
            _          -> error "assumption: adjustment of the input bits should be 0 `mod` 8 "


blake :: (V.Storable a, Bits a, Integral a) 
      => BLAKE a 
      -> B.ByteString 
      -> B.ByteString 
      -> B.ByteString

blake config salt message =
    let
      -- configurable...
      initialValues' = initialValues config
      wordSize' = wordSize config
      fromWtoB' = fromWtoB config

      salt' = makeWords wordSize' salt
      
    in
      if length salt' /= 4
      then error "blake: your salt is not four words"
      else fromWtoB' $ foldl' (compress config salt') initialValues' $ blocks config message


-- hold configuration data for different versions of BLAKE
data BLAKE a =
   BLAKE { initialValues      :: V.Vector a
         , constants          :: V.Vector a
         , rotations          :: (Int, Int, Int, Int)
         , rounds             :: Int
         , paddingTerminator  :: Word8
         , wordSize           :: Int64
         , fromWtoB           :: V.Vector a -> B.ByteString
         } 


blake256 :: B.ByteString -> B.ByteString -> B.ByteString
blake256 salt message = 
    let
        config = BLAKE { initialValues = initialValues256
                       , constants = constants256
                       , rotations = (16,12,8,7)
                       , rounds = 14
                       , paddingTerminator = 0x01
                       , wordSize = 32
                       , fromWtoB = toByteString 32 :: V.Vector Word32 -> B.ByteString
                       }
    in
        blake config salt message


blake512 :: B.ByteString -> B.ByteString -> B.ByteString
blake512 salt message =
    let
        config = BLAKE { initialValues = initialValues512
                       , constants = constants512
                       , rotations = (32,25,16,11)
                       , rounds = 16
                       , paddingTerminator = 0x01
                       , wordSize = 64
                       , fromWtoB = toByteString 64 :: V.Vector Word64 -> B.ByteString
                       }
    in
        blake config salt message

        
blake224 :: B.ByteString -> B.ByteString -> B.ByteString
blake224 salt message =
    let
        config = BLAKE { initialValues = initialValues224
                       , constants = constants256
                       , rotations = (16,12,8,7)
                       , rounds = 14
                       , paddingTerminator = 0x00
                       , wordSize = 32
                       , fromWtoB = toByteString 32 :: V.Vector Word32 -> B.ByteString
                       }
    in
        B.take 28 $ blake config salt message


blake384 :: B.ByteString -> B.ByteString -> B.ByteString
blake384 salt message =
    let
        config = BLAKE { initialValues = initialValues384
                       , constants = constants512
                       , rotations = (32,25,16,11)
                       , rounds = 16
                       , paddingTerminator = 0x00
                       , wordSize = 64
                       , fromWtoB = toByteString 64 :: V.Vector Word64 -> B.ByteString
                       }
    in
        B.take 48 $ blake config salt message
        

