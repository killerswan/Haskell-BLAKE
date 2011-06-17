-- Copyright (c) 2011 Kevin Cantu <me@kevincantu.org>
--
-- A naive implementation of the Blake cryptographic hash: 
-- use at your own risk.

import SHA3.BLAKE
import Data.Bits
import qualified Data.ByteString.Lazy as B
import System
import Text.Printf


-- print a list of numbers as a hex string
hex32 ws = (printf "%08x") =<< ws
hex64 ws = (printf "%016x") =<< ws


-- print out the BLAKE hash followed by the file name
-- generic
printHashX hex blake salt path = 
    do
        msg <- B.readFile path
        hash <- return $ hex $ blake salt (B.unpack msg)
        putStrLn $ hash ++ " *" ++ path

-- 256
printHash256 = printHashX hex32 blake256

-- 512
printHash512 = printHashX hex64 blake512


main = 
    do 
        args <- getArgs
        sequence $ map (printHash256 [0,0,0,0]) args

    -- TODO: add option parsing so we can check when a -c flag and file of hashes is given

