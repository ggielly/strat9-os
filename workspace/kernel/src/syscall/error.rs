//! Syscall error codes for Strat9-OS.
//!
//! Errors are returned as negative values in RAX, matching Linux errno conventions.
//! The dispatcher converts `SyscallError` to a negative i64 stored in RAX as u64.

use num_enum::{IntoPrimitive, TryFromPrimitive};

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive, thiserror::Error)]
#[must_use]
#[repr(i64)]
pub enum SyscallError {
    #[error("Operation not permitted")]
    PermissionDenied = -1,
    #[error("No such file or directory")]
    NotFound = -2,
    #[error("Interrupted system call")]
    Interrupted = -4,
    #[error("Input/output error")]
    IoError = -5,
    #[error("Argument list too long")]
    ArgumentListTooLong = -7,
    #[error("Exec format error")]
    ExecFormatError = -8,
    #[error("Bad file descriptor")]
    BadHandle = -9,
    #[error("No child processes")]
    NoChildren = -10,
    #[error("Resource temporarily unavailable")]
    Again = -11,
    #[error("Cannot allocate memory")]
    OutOfMemory = -12,
    #[error("Permission denied")]
    AccessDenied = -13,
    #[error("Bad address")]
    Fault = -14,
    #[error("File exists")]
    AlreadyExists = -17,
    #[error("Invalid argument")]
    InvalidArgument = -22,
    #[error("Not a typewriter")]
    NotATty = -25,
    #[error("No space left on device")]
    NoSpace = -28,
    #[error("Broken pipe")]
    Pipe = -32,
    #[error("Function not implemented")]
    NotImplemented = -38,
    #[error("Not supported")]
    NotSupported = -52,
    #[error("No buffer space available")]
    QueueFull = -105,
    #[error("Connection timed out")]
    TimedOut = -110,
}

impl SyscallError {
    #[inline]
    pub fn to_raw(self) -> u64 {
        (self as i64) as u64
    }

    pub fn from_code(code: i64) -> Self {
        Self::try_from(code).unwrap_or(SyscallError::InvalidArgument)
    }

    #[inline]
    pub fn is_retryable(self) -> bool {
        matches!(self, SyscallError::Interrupted | SyscallError::Again)
    }

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

// ── From impls for kernel-internal error types ──────────────────────────────

impl From<core::str::Utf8Error> for SyscallError {
    #[inline]
    fn from(_: core::str::Utf8Error) -> Self {
        SyscallError::InvalidArgument
    }
}

impl From<crate::ostd::util::Error> for SyscallError {
    fn from(err: crate::ostd::util::Error) -> Self {
        use crate::ostd::util::Error;
        match err {
            Error::OutOfMemory => SyscallError::OutOfMemory,
            Error::InvalidArgument => SyscallError::InvalidArgument,
            Error::NotFound => SyscallError::NotFound,
            Error::AlreadyExists => SyscallError::AlreadyExists,
            Error::PermissionDenied => SyscallError::PermissionDenied,
            Error::Busy => SyscallError::Again,
            Error::PageFault => SyscallError::Fault,
            Error::ArchError(_) => SyscallError::IoError,
        }
    }
}

impl From<crate::ostd::mm::MapError> for SyscallError {
    fn from(err: crate::ostd::mm::MapError) -> Self {
        use crate::ostd::mm::MapError;
        match err {
            MapError::OutOfBounds => SyscallError::InvalidArgument,
            MapError::NotOwner => SyscallError::PermissionDenied,
            MapError::AlreadyMapped => SyscallError::AlreadyExists,
            MapError::InvalidAddress => SyscallError::InvalidArgument,
            MapError::OutOfMemory => SyscallError::OutOfMemory,
            MapError::ArchError(_) => SyscallError::IoError,
        }
    }
}

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

impl From<crate::ipc::port::IpcError> for SyscallError {
    fn from(err: crate::ipc::port::IpcError) -> Self {
        use crate::ipc::port::IpcError;
        match err {
            IpcError::PortNotFound => SyscallError::NotFound,
            IpcError::NotOwner => SyscallError::PermissionDenied,
            IpcError::PortDestroyed => SyscallError::Pipe,
        }
    }
}

impl From<crate::drivers::net::NetError> for SyscallError {
    fn from(err: crate::drivers::net::NetError) -> Self {
        use crate::drivers::net::NetError;
        match err {
            NetError::NoPacket => SyscallError::Again,
            NetError::TxQueueFull => SyscallError::QueueFull,
            NetError::BufferTooSmall => SyscallError::InvalidArgument,
            NetError::NotReady => SyscallError::Again,
            NetError::LinkDown => SyscallError::IoError,
            NetError::DeviceNotFound => SyscallError::NotImplemented,
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
