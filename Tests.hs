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
    (blocks 256 [0]) ~=? [( [0x00800000, 0x00000000, 0x00000000, 0x00000000, 
                             0x00000000, 0x00000000, 0x00000000, 0x00000000,
                             0x00000000, 0x00000000, 0x00000000, 0x00000000, 
                             0x00000000, 0x00000001, 0x00000000, 0x00000008], [0,8])]


test_blocks2 = 
    "message padding into blocks, 567 zeroes" ~:
    (blocks 256 $ take 72 $ repeat 0) ~=? [((take 16 $ repeat 0),                            [0,0x200]),
                                           ([0,0,0x80000000,0,0,0,0,0,0,0,0,0,0,1,0,0x240], [0,0x240])]


test_init = 
    let test_init_prep = (\ s h (m,t) -> initialState h s t) [0,0,0,0] initialValues $ head $ blocks 256 [0]
    in
    "BLAKE-256, initial state on '0x00'" ~: 
    test_init_prep ~=? [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 
                        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
                        0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 
                        0xA409382A, 0x299F31D8, 0x082EFA98, 0xEC4E6C89]


test_round_1 = 
    let block1 = head $ blocks 256 [0]
        test_init_prep    = (\ s h (m,t) -> initialState h s t) [0,0,0,0] initialValues block1
        test_round_1_prep = (\ (m,t) -> blakeRound 256 m test_init_prep 0) block1
    in
    "BLAKE-256, one round on '0x00'" ~:
    test_round_1_prep ~=? [0xE78B8DFE, 0x150054E7, 0xCABC8992, 0xD15E8984, 
                           0x0669DF2A, 0x084E66E3, 0xA516C4B3, 0x339DED5B, 
                           0x26051FB7, 0x09D18B27, 0x3A2E8FA8, 0x488C6059, 
                           0x13E513E6, 0xB37ED53E, 0x16CAC7B9, 0x75AF6DF6]


test_blake256 = 
    TestCase $ do
        assertEqual "BLAKE-256 of '0x00'" 
            (blake256 [0,0,0,0] [0]) [0x0CE8D4EF, 0x4DD7CD8D, 0x62DFDED9, 0xD4EDB0A7,
                                      0x74AE6A41, 0x929A74DA, 0x23109E8F, 0x11139C87]

        assertEqual "BLAKE-256 of 72 by '0x00'" 
            (blake256 [0,0,0,0] $ take 72 $ repeat 0) [0xD419BAD3, 0x2D504FB7, 0xD44D460C, 0x42C5593F, 
                                                       0xE544FA4C, 0x135DEC31, 0xE21BD9AB, 0xDCC22D41]

{-
test_blake512 = 
    TestCase $ do
        assertEqual "BLAKE-512 of '0x00'"
            (blake512 [0,0,0,0] [0]) 
            [0x97961587F6D970FA, 0xBA6D2478045DE6D1, 0xFABD09B61AE50932, 0x054D52BC29D31BE4,
             0xFF9102B9F69E2BBD, 0xB83BE13D4B9C0609, 0x1E5FA0B48BD081B6, 0x34058BE0EC49BEB3]
            
        assertEqual "BLAKE-512 of 144 by '0x00'"
            (blake512 [0,0,0,0] $ take 144 $ repeat 0) 
            [0x313717D608E9CF75, 0x8DCB1EB0F0C3CF9F, 0xC150B2D500FB33F5, 0x1C52AFC99D358A2F,
             0x1374B8A38BBA7974, 0xE7F6EF79CAB16F22, 0xCE1E649D6E01AD95, 0x89C213045D545DDE]


test_blake384 = 
    TestCase $ do
        assertEqual "BLAKE-384 of '0x00'"
            (blake384 [0,0,0,0] [0]) 
            [0x10281F67E135E90A, 0xE8E882251A355510, 0xA719367AD70227B1, 0x37343E1BC122015C, 0x29391E8545B5272D, 0x13A7C2879DA3D807]

        assertEqual "BLAKE-512 of 144 by '0x00'"
            (blake512 [0,0,0,0] $ take 144 $ repeat 0) 
            [0x0B9845DD429566CD, 0xAB772BA195D271EF, 0xFE2D0211F16991D7, 0x66BA749447C5CDE5, 0x69780B2DAA66C4B2, 0x24A2EC2E5D09174C]


test_blake224 = 
    TestCase $ do
        assertEqual "BLAKE-224 of '0x00'"
            (blake224 [0,0,0,0] [0]) 
            [0x4504CB03, 0x14FB2A4F, 0x7A692E69, 0x6E487912, 0xFE3F2468, 0xFE312C73, 0xA5278EC5]

        assertEqual "BLAKE-256 of 72 by '0x00'" 
            (blake256 [0,0,0,0] $ take 72 $ repeat 0)
            [0xF5AA00DD, 0x1CB847E3, 0x140372AF, 0x7B5C46B4, 0x888D82C8, 0xC0A91791, 0x3CFB5D04]

-}


-- BLAKE-512 --------------------------------------------------------------------------




-- all --------------------------------------------------------------------------

tests = TestList
                 [ "init"                 ~: test_init,
                   "blocks, 1"            ~: test_blocks1,
                   "blocks, 2"            ~: test_blocks2,
                   "round function, once" ~: test_round_1,
                   "BLAKE-256"            ~: test_blake256 --,
                -- "BLAKE-224"            ~: test_blake224,
                -- "BLAKE-512"            ~: test_blake512,
                -- "BLAKE-384"            ~: test_blake384,
                 ]


main = runTestTT tests


