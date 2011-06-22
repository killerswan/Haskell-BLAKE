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
printHash getHash salt path message = 
    do
        hash <- return $ getHash (map fromIntegral salt) message
        putStrLn $ hash ++ " *" ++ path

-- compute a hash in hex
getHashX hex blake salt message = hex $ blake salt $ B.unpack message

-- specifically, BLAKE-256
getHash256   = getHashX hex32 blake256
printHash256 = printHash getHash256

-- specifically, BLAKE-512
getHash512   = getHashX hex64 blake512
printHash512 = printHash getHash512


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


-- print the hashes of each of a list of files and/or stdin
printHashes 256 salt []    = hashInput printHash256 salt
printHashes 512 salt []    = hashInput printHash512 salt
printHashes 256 salt paths = mapM_ (hashFile printHash256 salt) paths
printHashes 512 salt paths = mapM_ (hashFile printHash512 salt) paths
printHashes _   _    _     = error "unavailable algorithm size"




-- check the hashes within each of a list of files and/or stdin
checkHashes 256 salt []    = checkInput checkHash256 salt
checkHashes 512 salt []    = checkInput checkHash512 salt
checkHashes 256 salt paths = mapM_ (checkFile checkHash256 salt) paths
checkHashes 512 salt paths = mapM_ (checkFile checkHash512 salt) paths
checkHashes _   _    _     = error "unavailable algorithm size"


-- check hashes on lines of stdin
checkInput f salt =
  do
    ll <- getContents
    mapM_ (f salt) $ lines ll 


-- check hashes on lines of a file
checkFile f salt path = 
    if path == "-"
    then checkInput f salt
    else
      do
        ll <- readFile path
        mapM_ (f salt) $ lines ll
         


-- check one hash line (i.e., aas98d4a654...5756 *README.txt)
-- generic
checkHash getHash hsize salt line = 
  do
    let savedHash = take (hsize)     line
    let path      = drop (hsize + 2) line

    message    <- B.readFile path

    let testedHash = getHash (map fromIntegral salt) message

    if testedHash == savedHash
    then putStrLn $ path ++ ": OK"
    else putStrLn $ path ++ ": FAILED"
--
-- 256
checkHash256 = checkHash getHash256 64
--
-- 512
checkHash512 = checkHash getHash512 128




main = 
    do 
        args <- getArgs

        let (actions, nonOptions, errors) = getOpt RequireOrder options args
        opts <- foldl (>>=) (return defaultOpts) actions
        
        let Options { check     = check
                    , algorithm = algorithmBits
                    , salt0     = salt0
                    , salt1     = salt1
                    , salt2     = salt2
                    , salt3     = salt3
                    } = opts

        -- are we in check mode?
        let run = if check 
                  then checkHashes
                  else printHashes

        -- either check or print hashes
        run algorithmBits [salt0,salt1,salt2,salt3] nonOptions

