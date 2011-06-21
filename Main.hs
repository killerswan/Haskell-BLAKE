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
                       , salt0     :: Integer 
                       , salt1     :: Integer 
                       , salt2     :: Integer 
                       , salt3     :: Integer 
                       }

defaultOpts :: Options
defaultOpts = Options { help = False
                      , check = False
                      , algorithm = 256
                      , salt0 = 0
                      , salt1 = 0
                      , salt2 = 0
                      , salt3 = 0
                      }

options :: [ OptDescr (Options -> IO Options) ]
options = [ Option "a" ["algorithm"] 
                   (ReqArg
                        (\arg opt -> let alg = read arg :: Integer
                                     in case alg of 
                                            x | x == 256 || x == 512 -> return opt { algorithm = alg }
                                            otherwise -> error "please choose a working algorithm size")
                        "BITS")
                   "256, 512, 224, 384 (default: 256)"

          , Option "c" ["check"] 
                   (NoArg $ \opt -> return opt { check = True })
                   "positive integer salt (default: 0)"

{-
          , Option "s" ["salt"] 
                   (ReqArg
                        (\arg opt -> let s = read arg :: Integer
                                     in 
                                     if s >= 0
                                     then return opt { salt = s }
                                     else error "please specify a positive salt")
                        "SALT")
                   "positive integer salt (default: 0)"
-}
          , Option "" ["salt0"] 
                   (ReqArg
                        (\arg opt -> let s = read arg :: Integer
                                     in 
                                     if s >= 0
                                     then return opt { salt0 = s }
                                     else error "please specify a positive salt")
                        "SALT")
                   "positive integer salt, word 1/4 (default: 0)"

          , Option "" ["salt1"] 
                   (ReqArg
                        (\arg opt -> let s = read arg :: Integer
                                     in 
                                     if s >= 0
                                     then return opt { salt1 = s }
                                     else error "please specify a positive salt")
                        "SALT")
                   "positive integer salt, word 2/4 (default: 0)"

          , Option "" ["salt2"] 
                   (ReqArg
                        (\arg opt -> let s = read arg :: Integer
                                     in 
                                     if s >= 0
                                     then return opt { salt2 = s }
                                     else error "please specify a positive salt")
                        "SALT")
                   "positive integer salt, word 3/4 (default: 0)"

          , Option "" ["salt3"] 
                   (ReqArg
                        (\arg opt -> let s = read arg :: Integer
                                     in 
                                     if s >= 0
                                     then return opt { salt3 = s }
                                     else error "please specify a positive salt")
                        "SALT")
                   "positive integer salt, word 4/4 (default: 0)"

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


hashInput f salt = 
  do 
    message <- B.getContents
    f salt "-" message


hashFile f salt path =
    if path == "-"
    then hashInput f salt
    else
      do
        message <- B.readFile path
        f salt path message


main = 
    do 
        args <- getArgs

        let (actions, nonOptions, errors) = getOpt RequireOrder options args
        opts <- foldl (>>=) (return defaultOpts) actions
        
        let Options { check     = check
                    , algorithm = algorithm
                    , salt0      = salt0
                    , salt1     = salt1
                    , salt2     = salt2
                    , salt3     = salt3
                    } = opts


        case algorithm of 
          256 -> 
            let salt = map fromIntegral [salt0,salt1,salt2,salt3]
            in
            case length nonOptions of
              0 -> hashInput printHash256 salt
              _ -> mapM_ (hashFile printHash256 salt) nonOptions

          512 ->
            let salt = map fromIntegral [salt0,salt1,salt2,salt3]
            in
            case length nonOptions of
              0 -> hashInput printHash512 salt
              _ -> mapM_ (hashFile printHash512 salt) nonOptions

          _   -> error "unavailable algorithm size"


