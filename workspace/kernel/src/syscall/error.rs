//! Syscall error codes for Strat9-OS.
//!
//! Errors are returned as negative values in RAX, matching Linux errno conventions
//! for familiarity. The dispatcher converts `SyscallError` to a negative i64
//! which is then stored in RAX as u64 (two's complement).

/// Syscall error codes (returned as negative values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum SyscallError {
    /// Permission denied (EPERM)
    PermissionDenied = -1,
    /// No such entity / port not found (ENOENT)
    NotFound = -2,
    /// Interrupted system call (EINTR)
    Interrupted = -4,
    /// I/O error (EIO)
    IoError = -5,
    /// Bad file/handle descriptor (EBADF)
    BadHandle = -9,
    /// No child processes (ECHILD)
    NoChildren = -10,
    /// Resource temporarily unavailable (EAGAIN)
    Again = -11,
    /// Out of memory : no pages available (ENOMEM)
    OutOfMemory = -12,
    /// Bad address / memory fault (EFAULT)
    Fault = -14,
    /// File or resource already exists (EEXIST)
    AlreadyExists = -17,
    /// Invalid argument (EINVAL)
    InvalidArgument = -22,
    /// Argument list too long (E2BIG)
    ArgumentListTooLong = -7,
    /// Exec format error (ENOEXEC)
    ExecFormatError = -8,
    /// Function not implemented (ENOSYS)
    NotImplemented = -38,
    /// No buffer space available / queue full (ENOBUFS)
    QueueFull = -105,
    /// Operation timed out (ETIMEDOUT)
    TimedOut = -110,
}

impl SyscallError {
    /// Convert to the raw value stored in RAX (negative i64 as u64).
    pub fn to_raw(self) -> u64 {
        (self as i64) as u64
    }

    /// Create a SyscallError from a status code.
    pub fn from_code(code: i64) -> Self {
        match code {
            -1 => SyscallError::PermissionDenied,
            -4 => SyscallError::Interrupted,
            -5 => SyscallError::IoError,
            -9  => SyscallError::BadHandle,
            -10 => SyscallError::NoChildren,
            -11 => SyscallError::Again,
            -12 => SyscallError::OutOfMemory,
            -14 => SyscallError::Fault,
            -17 => SyscallError::AlreadyExists,
            -22 => SyscallError::InvalidArgument,
            -7 => SyscallError::ArgumentListTooLong,
            -8 => SyscallError::ExecFormatError,
            -38 => SyscallError::NotImplemented,
            -110 => SyscallError::TimedOut,
            _ => SyscallError::InvalidArgument,
        }
    }
}
