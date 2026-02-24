//! Syscall error codes for Strat9-OS.
//!
//! Errors are returned as negative values in RAX, matching Linux errno conventions
//! for familiarity. The dispatcher converts `SyscallError` to a negative i64
//! which is then stored in RAX as u64 (two's complement).

use core::fmt;

/// Syscall error codes (returned as negative values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum SyscallError {
    /// Operation not permitted (EPERM)
    PermissionDenied = -1,
    /// No such entity / port not found (ENOENT)
    NotFound = -2,
    /// Interrupted system call (EINTR)
    Interrupted = -4,
    /// I/O error (EIO)
    IoError = -5,
    /// Argument list too long (E2BIG)
    ArgumentListTooLong = -7,
    /// Exec format error (ENOEXEC)
    ExecFormatError = -8,
    /// Bad file/handle descriptor (EBADF)
    BadHandle = -9,
    /// No child processes (ECHILD)
    NoChildren = -10,
    /// Resource temporarily unavailable (EAGAIN)
    Again = -11,
    /// Out of memory (ENOMEM)
    OutOfMemory = -12,
    /// Permission denied / access check failed (EACCES)
    AccessDenied = -13,
    /// Bad address / memory fault (EFAULT)
    Fault = -14,
    /// File or resource already exists (EEXIST)
    AlreadyExists = -17,
    /// Invalid argument (EINVAL)
    InvalidArgument = -22,
    /// Inappropriate ioctl for device (ENOTTY)
    NotATty = -25,
    /// No space left on device (ENOSPC)
    NoSpace = -28,
    /// Broken pipe (EPIPE)
    Pipe = -32,
    /// Function not implemented (ENOSYS)
    NotImplemented = -38,
    /// Operation not supported (ENOTSUP)
    NotSupported = -52,
    /// No buffer space available / queue full (ENOBUFS)
    QueueFull = -105,
    /// Operation timed out (ETIMEDOUT)
    TimedOut = -110,
}

impl SyscallError {
    /// Convert to the raw value stored in RAX (negative i64 as u64).
    #[inline]
    pub fn to_raw(self) -> u64 {
        (self as i64) as u64
    }

    /// Create a SyscallError from a raw negative status code.
    pub fn from_code(code: i64) -> Self {
        match code {
            -1 => SyscallError::PermissionDenied,
            -2 => SyscallError::NotFound,
            -4 => SyscallError::Interrupted,
            -5 => SyscallError::IoError,
            -7 => SyscallError::ArgumentListTooLong,
            -8 => SyscallError::ExecFormatError,
            -9 => SyscallError::BadHandle,
            -10 => SyscallError::NoChildren,
            -11 => SyscallError::Again,
            -12 => SyscallError::OutOfMemory,
            -13 => SyscallError::AccessDenied,
            -14 => SyscallError::Fault,
            -17 => SyscallError::AlreadyExists,
            -22 => SyscallError::InvalidArgument,
            -25 => SyscallError::NotATty,
            -28 => SyscallError::NoSpace,
            -32 => SyscallError::Pipe,
            -38 => SyscallError::NotImplemented,
            -52 => SyscallError::NotSupported,
            -105 => SyscallError::QueueFull,
            -110 => SyscallError::TimedOut,
            _ => SyscallError::InvalidArgument,
        }
    }

    /// `true` if the caller should retry (EINTR, EAGAIN).
    #[inline]
    pub fn is_retryable(self) -> bool {
        matches!(self, SyscallError::Interrupted | SyscallError::Again)
    }

    /// Short errno name for kernel log messages.
    #[inline]
    pub fn name(self) -> &'static str {
        match self {
            SyscallError::PermissionDenied => "EPERM",
            SyscallError::NotFound => "ENOENT",
            SyscallError::Interrupted => "EINTR",
            SyscallError::IoError => "EIO",
            SyscallError::ArgumentListTooLong => "E2BIG",
            SyscallError::ExecFormatError => "ENOEXEC",
            SyscallError::BadHandle => "EBADF",
            SyscallError::NoChildren => "ECHILD",
            SyscallError::Again => "EAGAIN",
            SyscallError::OutOfMemory => "ENOMEM",
            SyscallError::AccessDenied => "EACCES",
            SyscallError::Fault => "EFAULT",
            SyscallError::AlreadyExists => "EEXIST",
            SyscallError::InvalidArgument => "EINVAL",
            SyscallError::NotATty => "ENOTTY",
            SyscallError::NoSpace => "ENOSPC",
            SyscallError::Pipe => "EPIPE",
            SyscallError::NotImplemented => "ENOSYS",
            SyscallError::NotSupported => "ENOTSUP",
            SyscallError::QueueFull => "ENOBUFS",
            SyscallError::TimedOut => "ETIMEDOUT",
        }
    }
}

impl fmt::Display for SyscallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyscallError::PermissionDenied => write!(f, "Operation not permitted"),
            SyscallError::NotFound => write!(f, "No such file or directory"),
            SyscallError::Interrupted => write!(f, "Interrupted system call"),
            SyscallError::IoError => write!(f, "Input/output error"),
            SyscallError::ArgumentListTooLong => write!(f, "Argument list too long"),
            SyscallError::ExecFormatError => write!(f, "Exec format error"),
            SyscallError::BadHandle => write!(f, "Bad file descriptor"),
            SyscallError::NoChildren => write!(f, "No child processes"),
            SyscallError::Again => write!(f, "Resource temporarily unavailable"),
            SyscallError::OutOfMemory => write!(f, "Cannot allocate memory"),
            SyscallError::AccessDenied => write!(f, "Permission denied"),
            SyscallError::Fault => write!(f, "Bad address"),
            SyscallError::AlreadyExists => write!(f, "File exists"),
            SyscallError::InvalidArgument => write!(f, "Invalid argument"),
            SyscallError::NotATty => write!(f, "Not a typewriter"),
            SyscallError::NoSpace => write!(f, "No space left on device"),
            SyscallError::Pipe => write!(f, "Broken pipe"),
            SyscallError::NotImplemented => write!(f, "Function not implemented"),
            SyscallError::NotSupported => write!(f, "Not supported"),
            SyscallError::QueueFull => write!(f, "No buffer space available"),
            SyscallError::TimedOut => write!(f, "Connection timed out"),
        }
    }
}

// ── From impls for kernel-internal error types ──────────────────────────────

impl From<crate::drivers::virtio::block::BlockError> for SyscallError {
    fn from(err: crate::drivers::virtio::block::BlockError) -> Self {
        use crate::drivers::virtio::block::BlockError;
        match err {
            BlockError::IoError => SyscallError::IoError,
            BlockError::InvalidSector => SyscallError::InvalidArgument,
            BlockError::BufferTooSmall => SyscallError::InvalidArgument,
            BlockError::NotReady => SyscallError::Again,
        }
    }
}

impl From<crate::ipc::channel::ChannelError> for SyscallError {
    fn from(err: crate::ipc::channel::ChannelError) -> Self {
        use crate::ipc::channel::ChannelError;
        match err {
            ChannelError::WouldBlock => SyscallError::Again,
            ChannelError::Disconnected => SyscallError::Pipe,
        }
    }
}
