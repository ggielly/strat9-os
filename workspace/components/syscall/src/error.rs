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
    #[error("No such process")]
    NoSuchProcess = ESRCH,
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
    #[error("Not a directory")]
    NotADirectory = ENOTDIR,
    #[error("Is a directory")]
    IsADirectory = EISDIR,
    #[error("Invalid argument")]
    InvalidArgument = EINVAL,
    #[error("Not a typewriter")]
    NotATty = ENOTTY,
    #[error("No space left on device")]
    NoSpace = ENOSPC,
    #[error("Broken pipe")]
    Pipe = EPIPE,
    #[error("Result too large")]
    RangeError = ERANGE,
    #[error("File name too long")]
    NameTooLong = ENAMETOOLONG,
    #[error("Function not implemented")]
    NotImplemented = ENOSYS,
    #[error("Directory not empty")]
    NotEmpty = ENOTEMPTY,
    #[error("Too many levels of symbolic links")]
    SymlinkLoop = ELOOP,
    #[error("Not supported")]
    NotSupported = ENOTSUP,
    #[error("Address already in use")]
    AddressInUse = EADDRINUSE,
    #[error("No buffer space available")]
    QueueFull = ENOBUFS,
    #[error("Connection timed out")]
    TimedOut = ETIMEDOUT,
    #[error("Connection refused")]
    ConnectionRefused = ECONNREFUSED,
    #[error("Unknown error (errno={0})")]
    #[num_enum(catch_all)]
    Unknown(usize),
}

impl Error {
    #[inline]
    /// Convert a raw errno value into a typed `Error`.
    pub fn from_errno(errno: usize) -> Self {
        Self::try_from(errno).unwrap_or(Error::Unknown(errno))
    }

    #[inline]
    /// Convert this error to its numeric errno representation.
    pub fn to_errno(&self) -> usize {
        usize::from(*self)
    }

    #[inline]
    /// Decode a raw syscall return value into `Result`.
    pub fn demux(ret: usize) -> core::result::Result<usize, Error> {
        // Strat9 syscall ABI encodes errors as negative errno values in RAX.
        let ret_s = ret as isize;
        if ret_s >= -ERRNO_MAX && ret_s < 0 {
            Err(Error::from_errno((-ret_s) as usize))
        } else {
            Ok(ret)
        }
    }

    #[inline]
    /// Return true when retrying later may succeed (`EINTR`/`EAGAIN`).
    pub fn is_retryable(&self) -> bool {
        matches!(self, Error::Interrupted | Error::Again)
    }

    #[inline]
    /// Return the canonical symbolic errno name.
    pub fn name(&self) -> &'static str {
        match self {
            Error::PermissionDenied => "EPERM",
            Error::NotFound => "ENOENT",
            Error::NoSuchProcess => "ESRCH",
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
            Error::NotADirectory => "ENOTDIR",
            Error::IsADirectory => "EISDIR",
            Error::InvalidArgument => "EINVAL",
            Error::NotATty => "ENOTTY",
            Error::NoSpace => "ENOSPC",
            Error::Pipe => "EPIPE",
            Error::RangeError => "ERANGE",
            Error::NameTooLong => "ENAMETOOLONG",
            Error::NotImplemented => "ENOSYS",
            Error::NotEmpty => "ENOTEMPTY",
            Error::SymlinkLoop => "ELOOP",
            Error::NotSupported => "ENOTSUP",
            Error::AddressInUse => "EADDRINUSE",
            Error::QueueFull => "ENOBUFS",
            Error::TimedOut => "ETIMEDOUT",
            Error::ConnectionRefused => "ECONNREFUSED",
            Error::Unknown(_) => "E???",
        }
    }
}

/// Result type used by the syscall API.
pub type Result<T> = core::result::Result<T, Error>;
