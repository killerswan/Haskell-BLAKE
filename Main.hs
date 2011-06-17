-- Copyright (c) 2011 Kevin Cantu <me@kevincantu.org>
--
-- A naive implementation of the Blake cryptographic hash: 
-- use at your own risk.

import SHA3.BLAKE
import Data.Bits
import qualified Data.ByteString.Lazy as B
import System
import Text.Printf


hex xs = (printf "%08x") =<< xs


printHash salt path = 
    do
        msg <- B.readFile path
        hash <- return $ hex $ blake256 salt (B.unpack msg)
        putStrLn $ hash ++ " *" ++ path


main = 
    do 
        args <- getArgs
        sequence $ map (printHash [0,0,0,0]) args

    -- TODO: add option parsing so we can check when a -c flag and file of hashes is given

