-- Copyright (c) 2011 Kevin Cantu <me@kevincantu.org>
--
-- A naive implementation of the Blake cryptographic hash: 
-- use at your own risk.

import Test.HUnit
import SHA3.BLAKE
import qualified Data.ByteString.Lazy as B


-- BLAKE-256 --------------------------------------------------------------------------

test_blocks1 = 
    "message padding into blocks, 8 zeroes" ~:
    (blocks [0]) ~=? [( [0x00800000, 0x00000000, 0x00000000, 0x00000000, 
                           0x00000000, 0x00000000, 0x00000000, 0x00000000,
                           0x00000000, 0x00000000, 0x00000000, 0x00000000, 
                           0x00000000, 0x00000001, 0x00000000, 0x00000008], [0,8])]


test_blocks2 = 
    "message padding into blocks, 567 zeroes" ~:
    (blocks $ take 72 $ repeat 0) ~=? [((take 16 $ repeat 0),                            [0,0x200]),
                                         ([0,0,0x80000000,0,0,0,0,0,0,0,0,0,0,1,0,0x240], [0,0x240])]


test_init = 
    let test_init_prep = (\ s h (m,t) -> initialState h s t) [0,0,0,0] initialValues $ head $ blocks [0]
    in
    "BLAKE-256, initial state on '0x00'" ~: 
    test_init_prep ~=? [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 
                        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
                        0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 
                        0xA409382A, 0x299F31D8, 0x082EFA98, 0xEC4E6C89]


{-
test_round_1 = 
    let test_init_prep    = (\ s h (m,t) -> initialState h s t) [0,0,0,0] initialValues $ head $ blocks [0]
        test_round_1_prep = (\ (m,t) -> blakeRound m test_init_prep 0) $ head $ blocks [0]
    in
    "BLAKE-256, one round on '0x00'" ~:
    test_round_1_prep ~=? [0xE78B8DFE, 0x150054E7, 0xCABC8992, 0xD15E8984, 
                           0x0669DF2A, 0x084E66E3, 0xA516C4B3, 0x339DED5B, 
                           0x26051FB7, 0x09D18B27, 0x3A2E8FA8, 0x488C6059, 
                           0x13E513E6, 0xB37ED53E, 0x16CAC7B9, 0x75AF6DF6]
-}


test_blake256 = 
    TestCase $ do
        assertEqual "BLAKE-256 of '0x00'" 
            (blake256 [0,0,0,0] [0]) [0x0CE8D4EF, 0x4DD7CD8D, 0x62DFDED9, 0xD4EDB0A7,
                                      0x74AE6A41, 0x929A74DA, 0x23109E8F, 0x11139C87]

        assertEqual "BLAKE-256 of 72 by '0x00'" 
            (blake256 [0,0,0,0] $ take 72 $ repeat 0) [0xD419BAD3, 0x2D504FB7, 0xD44D460C, 0x42C5593F, 
                                                       0xE544FA4C, 0x135DEC31, 0xE21BD9AB, 0xDCC22D41]


-- BLAKE-512 --------------------------------------------------------------------------




-- all --------------------------------------------------------------------------

tests = TestList
                 [ "init"                 ~: test_init,
                   "blocks, 1"            ~: test_blocks1,
                   "blocks, 2"            ~: test_blocks2,
                   --"round function, once" ~: test_round_1,
                   "BLAKE-256"            ~: test_blake256 ]


main = runTestTT tests


