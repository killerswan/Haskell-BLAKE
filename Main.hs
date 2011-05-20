import Data.Digest.BLAKE
import Data.Bits
import qualified Data.ByteString.Lazy as B
import System


hexchar n w = case 0xF .&. (w `shift` (-4 * n)) of
                0x0 -> '0'
                0x1 -> '1'
                0x2 -> '2'
                0x3 -> '3'
                0x4 -> '4'
                0x5 -> '5'
                0x6 -> '6'
                0x7 -> '7'
                0x8 -> '8'
                0x9 -> '9'
                0xa -> 'a'
                0xb -> 'b'
                0xc -> 'c'
                0xd -> 'd'
                0xe -> 'e'
                0xf -> 'f'


hex32 w = hc 7 : hc 6 : hc 5 : hc 4 : hc 3 : hc 2 : hc 1 : hc 0 : []
        where hc n = hexchar n w


printHash salt path = do
                    msg <- B.readFile path
                    hash <- return $ concatMap hex32 $ blake256 salt msg
                    putStrLn $ hash ++ " *" ++ path


main = do 
            args <- getArgs
            sequence $ map (printHash [0,0,0,0]) args


