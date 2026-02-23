//! Syscall error handling (no_std).
//!
//! Kernel return values follow the Linux convention: on error, RAX contains
//! `-errno` (signed integer, two's complement).

use core::fmt;

// Errno constants (aligned with kernel / POSIX)
pub const EPERM: usize = 1;
pub const ENOENT: usize = 2;
pub const EINTR: usize = 4;
pub const EIO: usize = 5;
pub const E2BIG: usize = 7;
pub const ENOEXEC: usize = 8;
pub const EBADF: usize = 9;
pub const ECHILD: usize = 10;
pub const EAGAIN: usize = 11;
pub const ENOMEM: usize = 12;
pub const EACCES: usize = 13;
pub const EFAULT: usize = 14;
pub const EEXIST: usize = 17;
pub const EINVAL: usize = 22;
pub const ENOTTY: usize = 25;
pub const ENOSPC: usize = 28;
pub const ENOSYS: usize = 38;
pub const EPIPE: usize = 32;
pub const ENOTSUP: usize = 52;
pub const ENOBUFS: usize = 105;
pub const ETIMEDOUT: usize = 110;

/// Range of negative errno values returned by the kernel (Linux-style).
const ERRNO_MAX: isize = 4095;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    PermissionDenied,
    NotFound,
    Interrupted,
    Io,
    ArgumentListTooLong,
    ExecFormatError,
    BadFileDescriptor,
    NoChildren,
    Again,
    OutOfMemory,
    AccessDenied,
    Fault,
    AlreadyExists,
    Invalid,
    NotATty,
    NoSpace,
    Pipe,
    NotSupported,
    NotImplemented,
    QueueFull,
    TimedOut,
}

impl Error {
    /// Build an error from a positive errno code (e.g. 2 for ENOENT).
    pub fn from_errno(errno: usize) -> Self {
        match errno {
            EPERM => Error::PermissionDenied,
            ENOENT => Error::NotFound,
            EINTR => Error::Interrupted,
            EIO => Error::Io,
            E2BIG => Error::ArgumentListTooLong,
            ENOEXEC => Error::ExecFormatError,
            EBADF => Error::BadFileDescriptor,
            ECHILD => Error::NoChildren,
            EAGAIN => Error::Again,
            ENOMEM => Error::OutOfMemory,
            EACCES => Error::AccessDenied,
            EFAULT => Error::Fault,
            EEXIST => Error::AlreadyExists,
            EINVAL => Error::Invalid,
            ENOTTY => Error::NotATty,
            ENOSPC => Error::NoSpace,
            EPIPE => Error::Pipe,
            ENOTSUP => Error::NotSupported,
            ENOSYS => Error::NotImplemented,
            ENOBUFS => Error::QueueFull,
            ETIMEDOUT => Error::TimedOut,
            _ => Error::Io,
        }
    }

    /// Return the corresponding positive errno code.
    pub fn to_errno(&self) -> usize {
        match self {
            Error::PermissionDenied => EPERM,
            Error::NotFound => ENOENT,
            Error::Interrupted => EINTR,
            Error::Io => EIO,
            Error::ArgumentListTooLong => E2BIG,
            Error::ExecFormatError => ENOEXEC,
            Error::BadFileDescriptor => EBADF,
            Error::NoChildren => ECHILD,
            Error::Again => EAGAIN,
            Error::OutOfMemory => ENOMEM,
            Error::AccessDenied => EACCES,
            Error::Fault => EFAULT,
            Error::AlreadyExists => EEXIST,
            Error::Invalid => EINVAL,
            Error::NotATty => ENOTTY,
            Error::NoSpace => ENOSPC,
            Error::Pipe => EPIPE,
            Error::NotSupported => ENOTSUP,
            Error::NotImplemented => ENOSYS,
            Error::QueueFull => ENOBUFS,
            Error::TimedOut => ETIMEDOUT,
        }
    }

    /// Demultiplex the raw syscall return value (RAX).
    /// The kernel returns `-errno` on error (Linux convention).
    #[inline]
    pub fn demux(ret: usize) -> core::result::Result<usize, Error> {
        let ret_s = ret as isize;
        if ret_s >= -ERRNO_MAX && ret_s < 0 {
            Err(Error::from_errno((-ret_s) as usize))
        } else {
            Ok(ret)
        }
    }

    /// `true` if the syscall can be retried (EINTR, EAGAIN).
    #[inline]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Error::Interrupted | Error::Again)
    }

    /// Short errno name for logging (no_std, no allocation).
    #[inline]
    pub fn name(&self) -> &'static str {
        match self {
            Error::PermissionDenied => "EPERM",
            Error::NotFound => "ENOENT",
            Error::Interrupted => "EINTR",
            Error::Io => "EIO",
            Error::ArgumentListTooLong => "E2BIG",
            Error::ExecFormatError => "ENOEXEC",
            Error::BadFileDescriptor => "EBADF",
            Error::NoChildren => "ECHILD",
            Error::Again => "EAGAIN",
            Error::OutOfMemory => "ENOMEM",
            Error::AccessDenied => "EACCES",
            Error::Fault => "EFAULT",
            Error::AlreadyExists => "EEXIST",
            Error::Invalid => "EINVAL",
            Error::NotATty => "ENOTTY",
            Error::NoSpace => "ENOSPC",
            Error::Pipe => "EPIPE",
            Error::NotSupported => "ENOTSUP",
            Error::NotImplemented => "ENOSYS",
            Error::QueueFull => "ENOBUFS",
            Error::TimedOut => "ETIMEDOUT",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::PermissionDenied => write!(f, "Operation not permitted"),
            Error::NotFound => write!(f, "No such file or directory"),
            Error::Interrupted => write!(f, "Interrupted system call"),
            Error::Io => write!(f, "Input/output error"),
            Error::ArgumentListTooLong => write!(f, "Argument list too long"),
            Error::ExecFormatError => write!(f, "Exec format error"),
            Error::BadFileDescriptor => write!(f, "Bad file descriptor"),
            Error::NoChildren => write!(f, "No child processes"),
            Error::Again => write!(f, "Resource temporarily unavailable"),
            Error::OutOfMemory => write!(f, "Cannot allocate memory"),
            Error::AccessDenied => write!(f, "Permission denied"),
            Error::Fault => write!(f, "Bad address"),
            Error::AlreadyExists => write!(f, "File exists"),
            Error::Invalid => write!(f, "Invalid argument"),
            Error::NotATty => write!(f, "Not a typewriter"),
            Error::NoSpace => write!(f, "No space left on device"),
            Error::Pipe => write!(f, "Broken pipe"),
            Error::NotSupported => write!(f, "Not supported"),
            Error::NotImplemented => write!(f, "Function not implemented"),
            Error::QueueFull => write!(f, "No buffer space available"),
            Error::TimedOut => write!(f, "Connection timed out"),
        }
    }
}

impl core::error::Error for Error {}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

// Result type alias
pub type Result<T> = core::result::Result<T, Error>;
