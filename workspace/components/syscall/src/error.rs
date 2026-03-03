pub use strat9_abi::errno::*;

use num_enum::{IntoPrimitive, TryFromPrimitive};

const ERRNO_MAX: isize = 4095;

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive, thiserror::Error)]
#[must_use]
#[repr(usize)]
pub enum Error {
    #[error("Operation not permitted")]
    PermissionDenied = EPERM,
    #[error("No such file or directory")]
    NotFound = ENOENT,
    #[error("Interrupted system call")]
    Interrupted = EINTR,
    #[error("Input/output error")]
    IoError = EIO,
    #[error("Argument list too long")]
    ArgumentListTooLong = E2BIG,
    #[error("Exec format error")]
    ExecFormatError = ENOEXEC,
    #[error("Bad file descriptor")]
    BadHandle = EBADF,
    #[error("No child processes")]
    NoChildren = ECHILD,
    #[error("Resource temporarily unavailable")]
    Again = EAGAIN,
    #[error("Cannot allocate memory")]
    OutOfMemory = ENOMEM,
    #[error("Permission denied")]
    AccessDenied = EACCES,
    #[error("Bad address")]
    Fault = EFAULT,
    #[error("File exists")]
    AlreadyExists = EEXIST,
    #[error("Invalid argument")]
    InvalidArgument = EINVAL,
    #[error("Not a typewriter")]
    NotATty = ENOTTY,
    #[error("No space left on device")]
    NoSpace = ENOSPC,
    #[error("Broken pipe")]
    Pipe = EPIPE,
    #[error("Function not implemented")]
    NotImplemented = ENOSYS,
    #[error("Not supported")]
    NotSupported = ENOTSUP,
    #[error("No buffer space available")]
    QueueFull = ENOBUFS,
    #[error("Connection timed out")]
    TimedOut = ETIMEDOUT,
    #[error("Unknown error (errno={0})")]
    #[num_enum(catch_all)]
    Unknown(usize),
}

impl Error {
    #[inline]
    pub fn from_errno(errno: usize) -> Self {
        Self::try_from(errno).unwrap_or(Error::Unknown(errno))
    }

    #[inline]
    pub fn to_errno(&self) -> usize {
        usize::from(*self)
    }

    #[inline]
    pub fn demux(ret: usize) -> core::result::Result<usize, Error> {
        let ret_s = ret as isize;
        if ret_s >= -ERRNO_MAX && ret_s < 0 {
            Err(Error::from_errno((-ret_s) as usize))
        } else {
            Ok(ret)
        }
    }

    #[inline]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Error::Interrupted | Error::Again)
    }

    #[inline]
    pub fn name(&self) -> &'static str {
        match self {
            Error::PermissionDenied => "EPERM",
            Error::NotFound => "ENOENT",
            Error::Interrupted => "EINTR",
            Error::IoError => "EIO",
            Error::ArgumentListTooLong => "E2BIG",
            Error::ExecFormatError => "ENOEXEC",
            Error::BadHandle => "EBADF",
            Error::NoChildren => "ECHILD",
            Error::Again => "EAGAIN",
            Error::OutOfMemory => "ENOMEM",
            Error::AccessDenied => "EACCES",
            Error::Fault => "EFAULT",
            Error::AlreadyExists => "EEXIST",
            Error::InvalidArgument => "EINVAL",
            Error::NotATty => "ENOTTY",
            Error::NoSpace => "ENOSPC",
            Error::Pipe => "EPIPE",
            Error::NotSupported => "ENOTSUP",
            Error::NotImplemented => "ENOSYS",
            Error::QueueFull => "ENOBUFS",
            Error::TimedOut => "ETIMEDOUT",
            Error::Unknown(_) => "E???",
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
