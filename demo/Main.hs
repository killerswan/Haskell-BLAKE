-- |
-- Copyright   : (c) 2011 Kevin Cantu
--
-- License     : BSD-style
-- Maintainer  : Kevin Cantu <me@kevincantu.org>
-- Stability   : experimental
--
-- A demo program providing a command line `blakesum` utility which behaves 
-- much like the sha512sum or shasum software available for various platforms


module Main (main) where

import Data.Digest.SHA3.Candidate.BLAKE
import qualified Data.ByteString.Lazy as B
import System
import IO
import System.Console.GetOpt
import qualified Data.Text.Lazy as T
import qualified Data.Text.Lazy.Encoding as E
import Data.Word


-- command line options
data Options = Options { help      :: Bool
                       , check     :: Bool
                       , algorithm :: Integer
                       , salt_     :: B.ByteString
                       }


-- command line defaults
defaultOpts :: Options
defaultOpts = Options { help        = False
                      , check       = False
                      , algorithm   = 512
                      , salt_       = B.take 32 $ B.repeat 0
                      }


-- command line description
-- this format is kinda bone headed:
--   [Option short [long] (property setter-function hint) description]
options :: [ OptDescr (Options -> IO Options) ]
options = [ Option "a" ["algorithm"] 
                   (ReqArg
                        (\arg opt -> let alg = read arg :: Integer
                                     in
                                       if elem alg [256,512,224,384]
                                       then return opt { algorithm = alg }
                                       else error "please choose a working algorithm size")
                        "BITS")
                   "256, 512, 224, 384 (default: 512)"

          , Option "c" ["check"] 
                   (NoArg $ \opt -> return opt { check = True })
                   "check saved hashes"

          , Option "s" ["salt"] 
                   (ReqArg
                        (\arg opt -> let s = (read ("[" ++ arg ++ "]")) :: [Word8]
                                     in 
                                     if (length $ filter (<0) s) > 0
                                     then error "please specify a salt of positive numbers"
                                     else return opt { salt_ = B.pack s })
                        "SALT")
                   "one positive uint per byte, salt: \"0,0,...0,0\""

          , Option "h" ["help"] 
                   (NoArg  $ \_ -> do
                        prg <- getProgName
                        hPutStrLn stderr $ usageInfo prg options
                        exitWith ExitSuccess)
                   "display this help and exit"

          , Option "v" ["version"] 
                   (NoArg $ \_ -> do
                        me <- getProgName
                        hPutStrLn stderr $ me ++ " version 0.3"
                        exitWith ExitSuccess)
                   "display version and exit"
          ]


-- apply a function (which uses the path) to a list of files and/or stdin
fileMapWithPath :: ( FilePath -> B.ByteString -> IO () ) -> [FilePath] -> IO ()
fileMapWithPath f paths = 
    let    
        -- apply f to stdin
        stdinF :: IO ()
        stdinF = B.getContents >>= f "-"

        -- apply f to a file (or stdin, when "-")
        fileF :: FilePath -> IO ()
        fileF "-"  = stdinF
        fileF path = (B.readFile path >>= f path) `catch` (\e -> hPutStrLn stderr (show e))
    in
        case paths of
            [] -> stdinF
            _  -> mapM_ fileF paths


-- apply a function to a list of files and/or stdin
fileMap :: ( B.ByteString -> IO () ) -> [FilePath] -> IO ()
fileMap f paths = fileMapWithPath (\_ -> f) paths



-- compute a hash, return text
getHash256 :: B.ByteString -> B.ByteString -> T.Text
getHash256 salt message = textDigest $ blake256 salt message
getHash224 :: B.ByteString -> B.ByteString -> T.Text
getHash224 salt message = textDigest $ blake224 salt message
getHash512 :: B.ByteString -> B.ByteString -> T.Text
getHash512 salt message = textDigest $ blake512 salt message
getHash384 :: B.ByteString -> B.ByteString -> T.Text
getHash384 salt message = textDigest $ blake384 salt message


-- print out the BLAKE hash followed by the file name
printHash :: (B.ByteString -> B.ByteString -> T.Text)
          -> B.ByteString
          -> String
          -> B.ByteString
          -> IO ()

printHash getHash salt path message = 
    do
        hash <- return $ getHash salt message
        B.putStrLn $ E.encodeUtf8 $ T.concat [hash, T.pack " *", T.pack path]


-- check one hash line (i.e., aas98d4a654...5756 *README.txt)
checkHash :: (B.ByteString -> B.ByteString -> T.Text)
          -> B.ByteString
          -> T.Text
          -> IO ()

checkHash getHash salt line = 
    let
        [savedHash, path]  = T.splitOn (T.pack " *") line
        printStatus status = B.putStrLn $ E.encodeUtf8 $ T.append path $ T.pack $ ": " ++ status
    in
        (do
            message <- B.readFile (T.unpack path)

            printStatus $ if savedHash == getHash salt message
                          then "OK"
                          else "FAILED"

        ) `catch` (\e -> hPutStrLn stderr (show e) 
                         >> printStatus "FAILED open or read")


-- print hashes of given files
printHashes :: Num a => a -> B.ByteString -> [FilePath] -> IO ()
printHashes alg salt paths =
    let
        printHash' =
            case alg of 
                256 -> printHash getHash256
                224 -> printHash getHash224
                512 -> printHash getHash512
                384 -> printHash getHash384
                _   -> error "unavailable algorithm size"
    in
        fileMapWithPath (printHash' salt) paths


-- check hashes within given files
checkHashes :: Num a => a -> B.ByteString -> [FilePath] -> IO ()
checkHashes alg salt paths =
    let
        -- check message (file) of hashes
        checkHashesInMessage f salt' = mapM_ (checkHash f salt') 


        checkHashes' =
            case alg of
                256 -> checkHashesInMessage getHash256
                224 -> checkHashesInMessage getHash224
                512 -> checkHashesInMessage getHash512
                384 -> checkHashesInMessage getHash384
                _   -> error "unavailable algorithm size"
    in
        fileMap ((checkHashes' salt) . T.lines . E.decodeUtf8) paths


main :: IO ()
main = 
    do 
        args <- getArgs

        -- call getOpt with the option description
        -- ignoring errors
        let (actions, nonOptions, _) = getOpt Permute options args

        -- process the defaults with those actions
        -- returns command line properties
        opts <- foldl (>>=) (return defaultOpts) actions
        
        -- assign the results
        -- via destructuring assignment
        let Options { check     = check'
                    , algorithm = algorithm'
                    , salt_     = salt'
                    } = opts

        let salt'' = case algorithm' of
                        256 | B.length salt' == 16 -> salt'
                        512 | B.length salt' == 32 -> salt'
                        _   -> error "salt should be 32 (default) or 16 bytes"

        -- are we in check mode?
        let run = if check'
                  then checkHashes -- ^ verify hashes listed in given files
                  else printHashes -- ^ output hashes of given files

        -- either check or print hashes
        run algorithm' salt'' nonOptions


