-- Copyright (c) 2011 Kevin Cantu <me@kevincantu.org>
--
-- A naive implementation of the Blake cryptographic hash: 
-- use at your own risk.

import Test.HUnit
import SHA3.BLAKE
import qualified Data.ByteString.Lazy as B
import Data.Bits
import Data.Word


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


zeroByteString n = B.pack $ take n $ repeat 0


test_toByteString :: Test
test_toByteString = 
    TestCase $ do
        assertEqual "some sample numbers..."
            (toByteString 32 ([0x99887766, 0x55443322, 0x11001122] :: [Word32]))
            (B.pack [0x99,0x88,0x77,0x66, 0x55,0x44,0x33,0x22, 0x11,0x00,0x11,0x22])

        
test_blake256 :: Test 
test_blake256 = 
    TestCase $ do
        assertEqual "BLAKE-256 of '0x00'" 
            (toByteString 32 ([0x0CE8D4EF, 0x4DD7CD8D, 0x62DFDED9, 0xD4EDB0A7, 0x74AE6A41, 0x929A74DA, 0x23109E8F, 0x11139C87] :: [Word32]))
            (blake256 (zeroByteString 16) (B.pack [0])) 

        assertEqual "BLAKE-256 of 72 by '0x00'" 
            (toByteString 32 ([0xD419BAD3, 0x2D504FB7, 0xD44D460C, 0x42C5593F, 0xE544FA4C, 0x135DEC31, 0xE21BD9AB, 0xDCC22D41] :: [Word32]))
            (blake256 (zeroByteString 16) (zeroByteString 72))


test_blake512 :: Test 
test_blake512 = 
    TestCase $ do
        assertEqual "BLAKE-512 of '0x00'"
            (toByteString 64 ([0x97961587F6D970FA, 0xBA6D2478045DE6D1, 0xFABD09B61AE50932, 0x054D52BC29D31BE4,
             0xFF9102B9F69E2BBD, 0xB83BE13D4B9C0609, 0x1E5FA0B48BD081B6, 0x34058BE0EC49BEB3] :: [Word64]))
            (blake512 (zeroByteString 32) $ B.pack [0]) 
            
        assertEqual "BLAKE-512 of 144 by '0x00'"
            (toByteString 64 ([0x313717D608E9CF75, 0x8DCB1EB0F0C3CF9F, 0xC150B2D500FB33F5, 0x1C52AFC99D358A2F,
             0x1374B8A38BBA7974, 0xE7F6EF79CAB16F22, 0xCE1E649D6E01AD95, 0x89C213045D545DDE] :: [Word64]))
            (blake512 (zeroByteString 32) (zeroByteString 144)) 


test_blake384 :: Test 
test_blake384 = 
    TestCase $ do
        assertEqual "BLAKE-384 of '0x00'"
            (toByteString 64 ([0x10281F67E135E90A, 0xE8E882251A355510, 0xA719367AD70227B1, 
             0x37343E1BC122015C, 0x29391E8545B5272D, 0x13A7C2879DA3D807] :: [Word64]))
            (blake384 (zeroByteString 32) $ B.pack [0]) 

        assertEqual "BLAKE-384 of 144 by '0x00'"
            (toByteString 64 ([0x0B9845DD429566CD, 0xAB772BA195D271EF, 0xFE2D0211F16991D7, 
             0x66BA749447C5CDE5, 0x69780B2DAA66C4B2, 0x24A2EC2E5D09174C] :: [Word64]))
            (blake384 (zeroByteString 32) (zeroByteString 144))


test_blake224 :: Test 
test_blake224 = 
    TestCase $ do
        assertEqual "BLAKE-224 of '0x00'"
            (toByteString 32 ([0x4504CB03, 0x14FB2A4F, 0x7A692E69, 0x6E487912, 0xFE3F2468, 0xFE312C73, 0xA5278EC5] :: [Word32]))
            (blake224 (zeroByteString 16) (B.pack [0])) 

        assertEqual "BLAKE-224 of 72 by '0x00'" 
            (toByteString 32 ([0xF5AA00DD, 0x1CB847E3, 0x140372AF, 0x7B5C46B4, 0x888D82C8, 0xC0A91791, 0x3CFB5D04] :: [Word32]))
            (blake224 (zeroByteString 16) (zeroByteString 72))


tests :: Test
tests = TestList [ "BLAKE-256"            ~: test_blake256
                 , "BLAKE-512"            ~: test_blake512
                 , "BLAKE-224"            ~: test_blake224
                 , "BLAKE-384"            ~: test_blake384
                 , "Conversion to ByteStrings" ~: test_toByteString
                 ]


main :: IO ()
main = runTestTT tests >>= putStrLn . show  -- TODO: what output does cabal need?


