
module System.OpenBSD
( Promise(..)
, Permission
, pledge
, pledgeChild
, unveil
, unsafeUnveil
, finishUnsafeUnveil
) where

import Foreign.Ptr
import Foreign.C.Types
import Foreign.C.String
import Foreign.C.Error

-- | Sets of system calls we can grant an application (see pledge (2))
data Promise = STDIO
             | RPATH
             | WPATH
             | CPATH
             | DPATH
             | TMPPATH
             | INET
             | MCAST
             | FATTR
             | CHOWN
             | FLOCK
             | UNIX
             | DNS
             | GETPW
             | SENDFD
             | RECVFD
             | TAPE
             | TTY
             | PROC
             | EXEC
             | PROT_EXEC
             | SETTIME
             | PS
             | VMINFO
             | ID
             | PF
             | ROUTE
             | WROUTE
             | AUDIO
             | VIDEO
             | BPF
             | UNVEIL
             | ERROR
             deriving (Eq)

instance Show Promise where
    show STDIO     = "stdio"
    show RPATH     = "rpath"
    show WPATH     = "wpath"
    show CPATH     = "cpath"
    show DPATH     = "dpath"
    show TMPPATH   = "tmppath"
    show INET      = "inet"
    show MCAST     = "mcast"
    show FATTR     = "fattr"
    show CHOWN     = "chown"
    show FLOCK     = "flock"
    show UNIX      = "unix"
    show DNS       = "dns"
    show GETPW     = "getpw"
    show SENDFD    = "sendfd"
    show RECVFD    = "recvfd"
    show TAPE      = "tape"
    show TTY       = "tty"
    show PROC      = "proc"
    show EXEC      = "exec"
    show PROT_EXEC = "prot_exec"
    show SETTIME   = "settime"
    show PS        = "ps"
    show VMINFO    = "vminfo"
    show ID        = "id"
    show PF        = "pf"
    show ROUTE     = "route"
    show WROUTE    = "wroute"
    show AUDIO     = "audio"
    show VIDEO     = "video"
    show BPF       = "bpf"
    show UNVEIL    = "unveil"
    show ERROR     = "error"

data Permission = Read   -- ^ Make path available for read operations
                | Write   -- ^ Make path available for write operations
                | Execute -- ^ Make path available for execute operations
                | Create  -- ^ Allow path to be created and removed
                deriving (Eq)

instance Show Permission where
    show Read    = "r"
    show Write   = "w"
    show Execute = "x"
    show Create  = "c"

foreign import ccall "unistd.h pledge" c_pledge :: CString -> CString -> IO CInt
foreign import ccall "unistd.h unveil" c_unveil :: CString -> CString -> IO CInt

promiseList :: [Promise] -> String
promiseList = unwords . map show

permList :: [Permission] -> String
permList = concatMap show

-- | Limit the current process to the provided system-call subsets
pledge :: [Promise] -> IO ()
pledge proms = withCString (promiseList proms) $ \p -> do
    ret <- c_pledge p nullPtr
    if ret == 0
       then return ()
       else throwErrno "Pledge Failed"
    
-- | Limit child processes (of the future) to the provided system-call subsets
pledgeChild :: [Promise] -> IO ()
pledgeChild proms = withCString (promiseList proms) $ \p -> do
    ret <- c_pledge nullPtr p
    if ret == 0
       then return ()
       else throwErrno "PledgeChild Failed"

-- | Limit application to the following path with the following permissions.
-- This can be called many times but must be followed by finishUnsafeUnveil
unsafeUnveil :: FilePath -> [Permission] -> IO ()
unsafeUnveil path perm = withCString path $ \c_path ->
                         withCString (permList perm) $ \c_perm -> do
                           ret <- c_unveil c_path c_perm
                           if ret == 0 then return ()
                                       else throwErrno "Unveil failed"

-- | Prevent any other filepaths from being exposed to the application
finishUnsafeUnveil :: IO ()
finishUnsafeUnveil = do
    ret <- c_unveil nullPtr nullPtr
    if ret == 0 then return ()
                else throwErrno "Unveil Failed"

-- | Limit application to th given filepaths with corresponding permissions
unveil :: [(FilePath, [Permission])] -> IO ()
unveil dirs = mapM_ (uncurry unsafeUnveil) dirs >> finishUnsafeUnveil
