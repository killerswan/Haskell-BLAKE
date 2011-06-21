-- Copyright (c) 2011 Kevin Cantu <me@kevincantu.org>
--
-- A naive implementation of the Blake cryptographic hash: 
-- use at your own risk.

module Main (main) where

import SHA3.BLAKE
import Data.Bits
import qualified Data.ByteString.Lazy as B
import System
import List
import IO
import Char
import Text.Printf
import Control.Monad
import System.Console.GetOpt

data Options = Options { help      :: Bool
                       , check     :: Bool
                       , algorithm :: Integer
                       , salt      :: Integer 
                       }

defaultOpts :: Options
defaultOpts = Options { help = False
                      , check = False
                      , algorithm = 256
                      , salt = 0
                      }

options :: [ OptDescr (Options -> IO Options) ]
options = [ Option "a" ["algorithm"] 
                   (ReqArg
                        (\arg opt -> let alg = read arg :: Integer
                                     in case alg of 
                                            x | x == 256 || x == 512 -> return opt { salt = alg }
                                            otherwise -> error "please choose a working algorithm size")
                        "BITS")
                   "256, 512, 224, 384 (default: 256)"

          , Option "c" ["check"] 
                   (NoArg $ \opt -> return opt { check = True })
                   "positive integer salt (default: 0)"

          , Option "s" ["salt"] 
                   (ReqArg
                        (\arg opt -> let i = read arg :: Integer
                                     in 
                                     if i >= 0
                                     then return opt { salt = i }
                                     else error "please specify a positive salt")
                        "SALT")
                   "positive integer salt (default: 0)"

          , Option "h" ["help"] 
                   (NoArg  $ \_ -> do
                        prg <- getProgName
                        hPutStrLn stderr $ usageInfo prg options
                        exitWith ExitSuccess)
                   "display this help and exit"

          , Option "v" ["version"] 
                   (NoArg $ \_ -> do
                        me <- getProgName
                        hPutStrLn stderr $ me ++ " version A"
                        exitWith ExitSuccess)
                   "display version and exit"
          ]


-- TODO: may need to add error handling 
--       for excessively long inputs per the BLAKE paper)



-- print a list of numbers as a hex string
hex32 ws = (printf "%08x" ) =<< ws
hex64 ws = (printf "%016x") =<< ws


-- print out the BLAKE hash followed by the file name
-- generic
printHashX hex blake salt path message = 
    do
        hash <- return $ hex $ blake salt $ B.unpack message
        putStrLn $ hash ++ " *" ++ path

-- 256
printHash256 = printHashX hex32 blake256

-- 512
printHash512 = printHashX hex64 blake512


hashInput salt = 
  do 
    message <- B.getContents
    printHash256 [0,0,0,0] "-" message


hashFile salt path =
  do
    message <- if path == "-"
               then B.getContents 
               else B.readFile path
    printHash256 [0,0,0,0] path message


main = 
    do 
        args <- getArgs

        let (actions, nonOptions, errors) = getOpt RequireOrder options args
        opts <- foldl (>>=) (return defaultOpts) actions
        
        let Options { check = check,
                      algorithm = algorithm,
                      salt = salt} = opts

        if length nonOptions > 0
        then mapM_ (hashFile [0,0,0,0]) nonOptions
        else hashInput [0,0,0,0]


