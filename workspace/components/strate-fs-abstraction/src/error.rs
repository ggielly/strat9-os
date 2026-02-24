//! Filesystem error types.
//!
//! This module defines a comprehensive error type for filesystem operations,
//! designed to map to appropriate Windows NTSTATUS codes.

pub type FsResult<T> = Result<T, FsError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FsError {
    #[error("Buffer too small")]
    BufferTooSmall,
    #[error("End of file")]
    EndOfFile,
    #[error("Disk I/O error")]
    DiskError,
    #[error("Device not ready")]
    DeviceNotReady,
    #[error("Filesystem corrupted")]
    Corrupted,
    #[error("Invalid block type")]
    InvalidBlockType,
    #[error("Invalid magic number")]
    InvalidMagic,
    #[error("Unsupported version")]
    UnsupportedVersion,
    #[error("Invalid block address")]
    InvalidBlockAddress,
    #[error("Inode not found")]
    InodeNotFound,
    #[error("Not found")]
    NotFound,
    #[error("Not a directory")]
    NotADirectory,
    #[error("Is a directory")]
    IsADirectory,
    #[error("Invalid path")]
    InvalidPath,
    #[error("Path too long")]
    PathTooLong,
    #[error("Arithmetic overflow")]
    ArithmeticOverflow,
    #[error("Security violation")]
    SecurityViolation,
    #[error("Alignment error")]
    AlignmentError,
    #[error("Out of memory")]
    OutOfMemory,
    #[error("No space left")]
    NoSpace,
    #[error("Too many open files")]
    TooManyOpenFiles,
    #[error("Invalid UTF-8")]
    InvalidUtf8,
    #[error("Invalid UTF-16")]
    InvalidUtf16,
    #[error("String too long")]
    StringTooLong,
    #[error("Not implemented")]
    NotImplemented,
    #[error("Not supported")]
    NotSupported,
    #[error("Read-only filesystem")]
    ReadOnly,
    #[error("Already exists")]
    AlreadyExists,
    #[error("Directory not empty")]
    NotEmpty,
    #[error("Invalid argument")]
    InvalidArgument,
    #[error("Permission denied")]
    PermissionDenied,
    #[error("Cross-device link")]
    CrossDeviceLink,
    #[error("Too many symbolic links")]
    TooManySymlinks,
    #[error("File too large")]
    FileTooLarge,
    #[error("Unknown filesystem")]
    UnknownFilesystem,
}

impl FsError {
    /// Converts to Windows NTSTATUS code.
    pub const fn to_ntstatus(self) -> i32 {
        match self {
            FsError::BufferTooSmall => 0xC0000023_u32 as i32,
            FsError::EndOfFile => 0xC0000011_u32 as i32,
            FsError::DiskError => 0xC000016A_u32 as i32,
            FsError::DeviceNotReady => 0xC00000A3_u32 as i32,
            FsError::Corrupted => 0xC0000032_u32 as i32,
            FsError::InvalidBlockType => 0xC0000032_u32 as i32,
            FsError::InvalidMagic => 0xC000014F_u32 as i32,
            FsError::UnsupportedVersion => 0xC000019C_u32 as i32,
            FsError::InvalidBlockAddress => 0xC0000015_u32 as i32,
            FsError::InodeNotFound => 0xC000000F_u32 as i32,
            FsError::NotFound => 0xC0000034_u32 as i32,
            FsError::NotADirectory => 0xC0000103_u32 as i32,
            FsError::IsADirectory => 0xC00000BA_u32 as i32,
            FsError::InvalidPath => 0xC0000033_u32 as i32,
            FsError::PathTooLong => 0xC0000106_u32 as i32,
            FsError::ArithmeticOverflow => 0xC0000095_u32 as i32,
            FsError::SecurityViolation => 0xC0000005_u32 as i32,
            FsError::AlignmentError => 0x80000002_u32 as i32,
            FsError::OutOfMemory => 0xC000009A_u32 as i32,
            FsError::NoSpace => 0xC000007F_u32 as i32,
            FsError::TooManyOpenFiles => 0xC000011F_u32 as i32,
            FsError::InvalidUtf8 => 0xC000000D_u32 as i32,
            FsError::InvalidUtf16 => 0xC000000D_u32 as i32,
            FsError::StringTooLong => 0x80000005_u32 as i32,
            FsError::NotImplemented => 0xC0000002_u32 as i32,
            FsError::NotSupported => 0xC00000BB_u32 as i32,
            FsError::ReadOnly => 0xC00000A2_u32 as i32,
            FsError::AlreadyExists => 0xC0000035_u32 as i32,
            FsError::NotEmpty => 0xC0000101_u32 as i32,
            FsError::InvalidArgument => 0xC000000D_u32 as i32,
            FsError::PermissionDenied => 0xC0000022_u32 as i32,
            FsError::CrossDeviceLink => 0xC00000D4_u32 as i32,
            FsError::TooManySymlinks => 0xC0000280_u32 as i32,
            FsError::FileTooLarge => 0xC0000904_u32 as i32,
            FsError::UnknownFilesystem => 0xC000014F_u32 as i32,
        }
    }

    /// Returns `true` if this is a security-related error.
    pub const fn is_security_error(self) -> bool {
        matches!(
            self,
            FsError::ArithmeticOverflow | FsError::SecurityViolation
        )
    }

    /// Returns `true` if this error indicates corrupted data.
    pub const fn is_corruption_error(self) -> bool {
        matches!(
            self,
            FsError::Corrupted
                | FsError::InvalidMagic
                | FsError::InvalidBlockAddress
                | FsError::InvalidBlockType
        )
    }
}

#[cfg(feature = "syscall")]
impl From<FsError> for strat9_syscall::error::Error {
    fn from(e: FsError) -> Self {
        use strat9_syscall::error::Error as SE;
        match e {
            FsError::BufferTooSmall => SE::InvalidArgument,
            FsError::EndOfFile => SE::IoError,
            FsError::DiskError => SE::IoError,
            FsError::DeviceNotReady => SE::Again,
            FsError::Corrupted | FsError::InvalidBlockType | FsError::InvalidMagic => SE::IoError,
            FsError::UnsupportedVersion => SE::NotSupported,
            FsError::InvalidBlockAddress => SE::InvalidArgument,
            FsError::InodeNotFound | FsError::NotFound => SE::NotFound,
            FsError::NotADirectory | FsError::IsADirectory => SE::InvalidArgument,
            FsError::InvalidPath | FsError::PathTooLong => SE::InvalidArgument,
            FsError::ArithmeticOverflow | FsError::SecurityViolation => SE::Fault,
            FsError::AlignmentError => SE::Fault,
            FsError::OutOfMemory => SE::OutOfMemory,
            FsError::NoSpace => SE::NoSpace,
            FsError::TooManyOpenFiles => SE::Again,
            FsError::InvalidUtf8 | FsError::InvalidUtf16 | FsError::StringTooLong => SE::InvalidArgument,
            FsError::NotImplemented => SE::NotImplemented,
            FsError::NotSupported | FsError::ReadOnly => SE::NotSupported,
            FsError::AlreadyExists => SE::AlreadyExists,
            FsError::NotEmpty => SE::InvalidArgument,
            FsError::InvalidArgument => SE::InvalidArgument,
            FsError::PermissionDenied => SE::PermissionDenied,
            FsError::CrossDeviceLink => SE::NotSupported,
            FsError::TooManySymlinks => SE::IoError,
            FsError::FileTooLarge => SE::NoSpace,
            FsError::UnknownFilesystem => SE::NotSupported,
        }
    }
}
