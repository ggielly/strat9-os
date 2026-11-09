/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

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
