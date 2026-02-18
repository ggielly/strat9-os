//! Filesystem abstraction layer.
//!
//! This crate provides common abstractions for filesystem drivers:
//!
//! - [`FsError`]: Comprehensive error type for filesystem operations
//! - [`CheckedOps`]: Safe arithmetic operations with overflow detection
//! - [`WindowsString`]: UTF-8 to UTF-16 conversion for Windows APIs
//! - [`VfsFileSystem`]: Core trait for filesystem implementations (with `alloc`
//!   feature)
//! - [`FsCapabilities`]: Filesystem capability flags
//! - [`VfsFileInfo`], [`VfsDirEntry`]: VFS data types
//!
//! # Features
//!
//! - `alloc`: Enables `Vec` and `String` support, VFS traits
//! - `std`: Enables full standard library support

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod capabilities;
pub mod error;
pub mod safe_math;
pub mod types;
pub mod unicode;
#[cfg(feature = "alloc")]
pub mod vfs;

// Re-exports for convenience
pub use capabilities::FsCapabilities;
pub use error::{FsError, FsResult};
pub use safe_math::CheckedOps;
pub use types::{OpenFlags, RenameFlags, VfsFileInfo, VfsFileType, VfsTimestamp};
#[cfg(feature = "alloc")]
pub use types::{VfsDirEntry, VfsVolumeInfo};
#[cfg(feature = "alloc")]
pub use unicode::WindowsString;
#[cfg(feature = "alloc")]
pub use vfs::{BlockDevice, VfsFileSystem, VfsFileSystemExt};
