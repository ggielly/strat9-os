//! Syscall error handling (no_std).
//!
//! Kernel return values follow the Linux convention: on error, RAX contains
//! `-errno` (signed integer, two's complement).

use num_enum::{IntoPrimitive, TryFromPrimitive};

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
pub const EPIPE: usize = 32;
pub const ENOSYS: usize = 38;
pub const ENOTSUP: usize = 52;
pub const ENOBUFS: usize = 105;
pub const ETIMEDOUT: usize = 110;

const ERRNO_MAX: isize = 4095;

/// Syscall error type for userspace programs.
///
/// Discriminant values match POSIX errno codes. The `Unknown` catch-all
/// variant preserves unrecognized errno values for forward compatibility.
///
/// Conversions via `From<usize>` (from errno) and `Into<usize>` (to errno)
/// are derived by `num_enum` and replace the hand-rolled match tables.
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
    /// Build an error from a positive errno code (e.g. 2 for ENOENT).
    ///
    /// Never panics: the `#[num_enum(catch_all)]` variant guarantees
    /// exhaustive mapping — unrecognized codes land in `Unknown(n)`.
    #[inline]
    pub fn from_errno(errno: usize) -> Self {
        Self::try_from(errno).unwrap_or(Error::Unknown(errno))
    }

    /// Return the corresponding positive errno code.
    #[inline]
    pub fn to_errno(&self) -> usize {
        usize::from(*self)
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
