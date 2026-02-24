//! Filesystem error types.
//!
//! This module defines a comprehensive error type for filesystem operations,
//! designed to map to appropriate Windows NTSTATUS codes.

use core::fmt;

/// Result type for filesystem operations.
pub type FsResult<T> = Result<T, FsError>;

/// Comprehensive error type for filesystem operations.
///
/// Each variant corresponds to a specific failure mode and can be mapped
/// to an appropriate NTSTATUS code for Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    // ─── I/O Errors ───────────────────────────────────────────────────
    /// Buffer provided is too small for the operation.
    /// Maps to: STATUS_BUFFER_TOO_SMALL (0xC0000023)
    BufferTooSmall,

    /// End of file reached during read operation.
    /// Maps to: STATUS_END_OF_FILE (0xC0000011)
    EndOfFile,

    /// Disk I/O error occurred.
    /// Maps to: STATUS_DISK_OPERATION_FAILED (0xC000016A)
    DiskError,

    /// Device not ready (e.g., media removed).
    /// Maps to: STATUS_DEVICE_NOT_READY (0xC00000A3)
    DeviceNotReady,

    // ─── Filesystem Structure Errors ──────────────────────────────────
    /// Filesystem structure is corrupted or invalid.
    /// Maps to: STATUS_DISK_CORRUPT_ERROR (0xC0000032)
    Corrupted,

    /// Block type is invalid for the current operation (e.g., using
    /// an intermediate-node operation on a leaf or vice versa).
    /// Maps to: STATUS_DISK_CORRUPT_ERROR (0xC0000032)
    InvalidBlockType,

    /// Invalid magic number in filesystem structure.
    /// Maps to: STATUS_UNRECOGNIZED_VOLUME (0xC000014F)
    InvalidMagic,

    /// Unsupported filesystem version.
    /// Maps to: STATUS_FS_DRIVER_REQUIRED (0xC000019C)
    UnsupportedVersion,

    /// Invalid block or sector address.
    /// Maps to: STATUS_NONEXISTENT_SECTOR (0xC0000015)
    InvalidBlockAddress,

    /// Inode not found.
    /// Maps to: STATUS_NO_SUCH_FILE (0xC000000F)
    InodeNotFound,

    // ─── Path Errors ──────────────────────────────────────────────────
    /// File or directory not found.
    /// Maps to: STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034)
    NotFound,

    /// Path component is not a directory.
    /// Maps to: STATUS_NOT_A_DIRECTORY (0xC0000103)
    NotADirectory,

    /// Path is a directory when a file was expected.
    /// Maps to: STATUS_FILE_IS_A_DIRECTORY (0xC00000BA)
    IsADirectory,

    /// Invalid path syntax or characters.
    /// Maps to: STATUS_OBJECT_NAME_INVALID (0xC0000033)
    InvalidPath,

    /// Path exceeds maximum length.
    /// Maps to: STATUS_NAME_TOO_LONG (0xC0000106)
    PathTooLong,

    // ─── Security Errors ──────────────────────────────────────────────
    /// Arithmetic overflow detected (potential security issue).
    /// Maps to: STATUS_INTEGER_OVERFLOW (0xC0000095)
    ArithmeticOverflow,

    /// Security violation (e.g., malicious metadata detected).
    /// Maps to: STATUS_ACCESS_VIOLATION (0xC0000005)
    SecurityViolation,

    /// Invalid data alignment.
    /// Maps to: STATUS_DATATYPE_MISALIGNMENT (0x80000002)
    AlignmentError,

    // ─── Resource Errors ──────────────────────────────────────────────
    /// Out of memory.
    /// Maps to: STATUS_INSUFFICIENT_RESOURCES (0xC000009A)
    OutOfMemory,

    /// No space left on device.
    /// Maps to: STATUS_DISK_FULL (0xC000007F)
    NoSpace,

    /// Too many open files.
    /// Maps to: STATUS_TOO_MANY_OPENED_FILES (0xC000011F)
    TooManyOpenFiles,

    // ─── Unicode Errors ───────────────────────────────────────────────
    /// Invalid UTF-8 sequence.
    /// Maps to: STATUS_INVALID_PARAMETER (0xC000000D)
    InvalidUtf8,

    /// Invalid UTF-16 sequence.
    /// Maps to: STATUS_INVALID_PARAMETER (0xC000000D)
    InvalidUtf16,

    /// String is too long for target buffer.
    /// Maps to: STATUS_BUFFER_OVERFLOW (0x80000005)
    StringTooLong,

    // ─── Feature Errors ───────────────────────────────────────────────
    /// Feature not implemented.
    /// Maps to: STATUS_NOT_IMPLEMENTED (0xC0000002)
    NotImplemented,

    /// Operation not supported on this filesystem.
    /// Maps to: STATUS_NOT_SUPPORTED (0xC00000BB)
    NotSupported,

    /// Read-only filesystem.
    /// Maps to: STATUS_MEDIA_WRITE_PROTECTED (0xC00000A2)
    ReadOnly,

    // ─── VFS Errors ───────────────────────────────────────────────────
    /// File or directory already exists.
    /// Maps to: STATUS_OBJECT_NAME_COLLISION (0xC0000035)
    AlreadyExists,

    /// Directory is not empty.
    /// Maps to: STATUS_DIRECTORY_NOT_EMPTY (0xC0000101)
    NotEmpty,

    /// Invalid argument provided.
    /// Maps to: STATUS_INVALID_PARAMETER (0xC000000D)
    InvalidArgument,

    /// Access denied (permission error).
    /// Maps to: STATUS_ACCESS_DENIED (0xC0000022)
    PermissionDenied,

    /// Cross-device link (rename across filesystems).
    /// Maps to: STATUS_NOT_SAME_DEVICE (0xC00000D4)
    CrossDeviceLink,

    /// Too many symbolic links encountered.
    /// Maps to: STATUS_REPARSE_POINT_NOT_RESOLVED (0xC0000280)
    TooManySymlinks,

    /// File too large for the filesystem.
    /// Maps to: STATUS_FILE_TOO_LARGE (0xC0000904)
    FileTooLarge,

    /// Unknown filesystem type.
    /// Maps to: STATUS_UNRECOGNIZED_VOLUME (0xC000014F)
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

    /// Returns a human-readable description.
    pub const fn as_str(self) -> &'static str {
        match self {
            FsError::BufferTooSmall => "Buffer too small",
            FsError::EndOfFile => "End of file",
            FsError::DiskError => "Disk I/O error",
            FsError::DeviceNotReady => "Device not ready",
            FsError::Corrupted => "Filesystem corrupted",
            FsError::InvalidBlockType => "Invalid block type",
            FsError::InvalidMagic => "Invalid magic number",
            FsError::UnsupportedVersion => "Unsupported version",
            FsError::InvalidBlockAddress => "Invalid block address",
            FsError::InodeNotFound => "Inode not found",
            FsError::NotFound => "Not found",
            FsError::NotADirectory => "Not a directory",
            FsError::IsADirectory => "Is a directory",
            FsError::InvalidPath => "Invalid path",
            FsError::PathTooLong => "Path too long",
            FsError::ArithmeticOverflow => "Arithmetic overflow",
            FsError::SecurityViolation => "Security violation",
            FsError::AlignmentError => "Alignment error",
            FsError::OutOfMemory => "Out of memory",
            FsError::NoSpace => "No space left",
            FsError::TooManyOpenFiles => "Too many open files",
            FsError::InvalidUtf8 => "Invalid UTF-8",
            FsError::InvalidUtf16 => "Invalid UTF-16",
            FsError::StringTooLong => "String too long",
            FsError::NotImplemented => "Not implemented",
            FsError::NotSupported => "Not supported",
            FsError::ReadOnly => "Read-only filesystem",
            FsError::AlreadyExists => "Already exists",
            FsError::NotEmpty => "Directory not empty",
            FsError::InvalidArgument => "Invalid argument",
            FsError::PermissionDenied => "Permission denied",
            FsError::CrossDeviceLink => "Cross-device link",
            FsError::TooManySymlinks => "Too many symbolic links",
            FsError::FileTooLarge => "File too large",
            FsError::UnknownFilesystem => "Unknown filesystem",
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

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(feature = "syscall")]
impl From<FsError> for strat9_syscall::error::Error {
    fn from(e: FsError) -> Self {
        use strat9_syscall::error::Error as SE;
        match e {
            FsError::BufferTooSmall => SE::Invalid,
            FsError::EndOfFile => SE::Io,
            FsError::DiskError => SE::Io,
            FsError::DeviceNotReady => SE::Again,
            FsError::Corrupted | FsError::InvalidBlockType | FsError::InvalidMagic => SE::Io,
            FsError::UnsupportedVersion => SE::NotSupported,
            FsError::InvalidBlockAddress => SE::Invalid,
            FsError::InodeNotFound | FsError::NotFound => SE::NotFound,
            FsError::NotADirectory | FsError::IsADirectory => SE::Invalid,
            FsError::InvalidPath | FsError::PathTooLong => SE::Invalid,
            FsError::ArithmeticOverflow | FsError::SecurityViolation => SE::Fault,
            FsError::AlignmentError => SE::Fault,
            FsError::OutOfMemory => SE::OutOfMemory,
            FsError::NoSpace => SE::NoSpace,
            FsError::TooManyOpenFiles => SE::Again,
            FsError::InvalidUtf8 | FsError::InvalidUtf16 | FsError::StringTooLong => SE::Invalid,
            FsError::NotImplemented => SE::NotImplemented,
            FsError::NotSupported | FsError::ReadOnly => SE::NotSupported,
            FsError::AlreadyExists => SE::AlreadyExists,
            FsError::NotEmpty => SE::Invalid,
            FsError::InvalidArgument => SE::Invalid,
            FsError::PermissionDenied => SE::PermissionDenied,
            FsError::CrossDeviceLink => SE::NotSupported,
            FsError::TooManySymlinks => SE::Io,
            FsError::FileTooLarge => SE::NoSpace,
            FsError::UnknownFilesystem => SE::NotSupported,
        }
    }
}
