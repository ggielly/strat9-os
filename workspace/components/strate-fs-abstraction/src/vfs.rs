//! Virtual File System (VFS) traits.
//!
//! This module defines the core traits that all filesystem implementations
//! must implement to be usable through the VFS layer.
//!
//! # Architecture
//!
//! The VFS layer provides a uniform interface between the platform-specific
//! code (WinFsp, FUSE, etc.) and the filesystem implementations (XFS, ext4,
//! etc.).
//!
//! ```text
//! Platform Layer (WinFsp/FUSE)
//!          │
//!          ▼
//!    ┌─────────────┐
//!    │ VFS Traits  │  ◄── This module
//!    └─────────────┘
//!          │
//!    ┌─────┼─────┐
//!    ▼     ▼     ▼
//!   XFS  ext4  btrfs
//! ```
//!
//! # Design Principles
//!
//! 1. **Stateless Operations**: The `VfsFileSystem` trait operates on inode
//!    numbers. File handles and state are managed by the platform layer.
//!
//! 2. **Inode-Centric**: All operations use inode numbers as the primary
//!    identifier. This matches the Unix/Linux filesystem model.
//!
//! 3. **Thread Safety**: All traits require `Send + Sync` for concurrent
//!    access.
//!
//! 4. **Default Implementations**: Write operations have default
//!    implementations that return `ReadOnly` error, making read-only
//!    filesystems easy to implement.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{string::String, sync::Arc, vec::Vec};

#[cfg(feature = "alloc")]
use crate::types::{VfsDirEntry, VfsVolumeInfo};
use crate::{
    capabilities::FsCapabilities,
    error::{FsError, FsResult},
    types::{RenameFlags, VfsFileInfo, VfsTimestamp},
};

/// Main filesystem trait.
///
/// All filesystem implementations must implement this trait to be usable
/// through the VFS layer. The trait is designed to be object-safe, allowing
/// use of `dyn VfsFileSystem`.
///
/// # Thread Safety
///
/// Implementations must be thread-safe (`Send + Sync`). Multiple threads
/// may call methods concurrently on the same filesystem instance.
///
/// # Error Handling
///
/// All methods return `FsResult<T>` which wraps `Result<T, FsError>`.
/// Implementations should map their internal errors to appropriate `FsError`
/// variants.
#[cfg(feature = "alloc")]
pub trait VfsFileSystem: Send + Sync {
    // =========================================================================
    // Identification & Capabilities
    // =========================================================================

    /// Returns the filesystem type name.
    ///
    /// This should be a short, lowercase identifier like "xfs", "ext4",
    /// "btrfs".
    fn fs_type(&self) -> &'static str;

    /// Returns the filesystem capabilities.
    ///
    /// The VFS layer uses this to:
    /// - Reject unsupported operations early
    /// - Report correct information to applications
    /// - Adapt behavior (e.g., case sensitivity)
    fn capabilities(&self) -> &FsCapabilities;

    // =========================================================================
    // Volume Operations
    // =========================================================================

    /// Returns the root directory inode number.
    ///
    /// For most Unix filesystems, this is inode 2.
    fn root_inode(&self) -> u64;

    /// Returns volume information.
    ///
    /// This includes total/free space, filesystem type, and other metadata.
    fn get_volume_info(&self) -> FsResult<VfsVolumeInfo>;

    /// Synchronizes all pending writes to disk.
    ///
    /// For read-only filesystems, this is a no-op.
    fn sync(&self) -> FsResult<()> {
        Ok(())
    }

    // =========================================================================
    // Inode Operations
    // =========================================================================

    /// Returns file metadata for an inode.
    ///
    /// # Arguments
    /// * `ino` - Inode number
    ///
    /// # Errors
    /// * `FsError::InodeNotFound` - Inode doesn't exist
    fn stat(&self, ino: u64) -> FsResult<VfsFileInfo>;

    /// Looks up an entry in a directory by name.
    ///
    /// # Arguments
    /// * `parent_ino` - Parent directory inode
    /// * `name` - Entry name to look up
    ///
    /// # Errors
    /// * `FsError::NotFound` - Entry doesn't exist
    /// * `FsError::NotADirectory` - Parent is not a directory
    fn lookup(&self, parent_ino: u64, name: &str) -> FsResult<VfsFileInfo>;

    /// Resolves a path to an inode number.
    ///
    /// # Arguments
    /// * `path` - Path relative to filesystem root (e.g., "/dir/file" or
    ///   "dir/file")
    ///
    /// # Errors
    /// * `FsError::NotFound` - Path component doesn't exist
    /// * `FsError::NotADirectory` - Path component is not a directory
    fn resolve_path(&self, path: &str) -> FsResult<u64>;

    // =========================================================================
    // Read Operations
    // =========================================================================

    /// Reads data from a file.
    ///
    /// # Arguments
    /// * `ino` - File inode
    /// * `offset` - Starting offset in bytes
    /// * `buf` - Buffer to read into
    ///
    /// # Returns
    /// Number of bytes actually read. May be less than `buf.len()` at EOF.
    ///
    /// # Errors
    /// * `FsError::IsADirectory` - Inode is a directory
    fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> FsResult<usize>;

    /// Reads directory entries.
    ///
    /// # Arguments
    /// * `ino` - Directory inode
    ///
    /// # Returns
    /// Vector of directory entries. Does NOT include "." and ".." entries.
    ///
    /// # Errors
    /// * `FsError::NotADirectory` - Inode is not a directory
    fn readdir(&self, ino: u64) -> FsResult<Vec<VfsDirEntry>>;

    /// Reads symlink target.
    ///
    /// # Arguments
    /// * `ino` - Symlink inode
    ///
    /// # Returns
    /// The symlink target path as a string.
    ///
    /// # Errors
    /// * `FsError::NotSupported` - Inode is not a symlink
    fn readlink(&self, ino: u64) -> FsResult<String>;

    // =========================================================================
    // Write Operations (optional - check capabilities first)
    // =========================================================================

    /// Writes data to a file.
    ///
    /// # Arguments
    /// * `ino` - File inode
    /// * `offset` - Starting offset in bytes
    /// * `data` - Data to write
    ///
    /// # Returns
    /// Number of bytes written.
    ///
    /// # Errors
    /// * `FsError::ReadOnly` - Filesystem is read-only
    /// * `FsError::NoSpace` - No space left on device
    fn write(&self, ino: u64, offset: u64, data: &[u8]) -> FsResult<usize> {
        let _ = (ino, offset, data);
        Err(FsError::ReadOnly)
    }

    /// Creates a new regular file.
    ///
    /// # Arguments
    /// * `parent_ino` - Parent directory inode
    /// * `name` - New file name
    /// * `mode` - Unix permission mode (e.g., 0o644)
    ///
    /// # Returns
    /// File info of the newly created file.
    ///
    /// # Errors
    /// * `FsError::ReadOnly` - Filesystem is read-only
    fn create_file(&self, parent_ino: u64, name: &str, mode: u32) -> FsResult<VfsFileInfo> {
        let _ = (parent_ino, name, mode);
        Err(FsError::ReadOnly)
    }

    /// Creates a new directory.
    ///
    /// # Arguments
    /// * `parent_ino` - Parent directory inode
    /// * `name` - New directory name
    /// * `mode` - Unix permission mode (e.g., 0o755)
    ///
    /// # Returns
    /// File info of the newly created directory.
    ///
    /// # Errors
    /// * `FsError::ReadOnly` - Filesystem is read-only
    fn create_directory(&self, parent_ino: u64, name: &str, mode: u32) -> FsResult<VfsFileInfo> {
        let _ = (parent_ino, name, mode);
        Err(FsError::ReadOnly)
    }

    /// Creates a symbolic link.
    ///
    /// # Arguments
    /// * `parent_ino` - Parent directory inode
    /// * `name` - Symlink name
    /// * `target` - Symlink target path
    ///
    /// # Returns
    /// File info of the newly created symlink.
    fn create_symlink(&self, parent_ino: u64, name: &str, target: &str) -> FsResult<VfsFileInfo> {
        let _ = (parent_ino, name, target);
        Err(FsError::ReadOnly)
    }

    /// Creates a hard link.
    ///
    /// # Arguments
    /// * `target_ino` - Inode to link to
    /// * `parent_ino` - Parent directory for new link
    /// * `name` - Name of new link
    ///
    /// # Returns
    /// Updated file info (with incremented nlink).
    fn link(&self, target_ino: u64, parent_ino: u64, name: &str) -> FsResult<VfsFileInfo> {
        let _ = (target_ino, parent_ino, name);
        Err(FsError::ReadOnly)
    }

    /// Removes a file or empty directory.
    ///
    /// # Arguments
    /// * `parent_ino` - Parent directory inode
    /// * `name` - Name of entry to remove
    /// * `target_ino` - Inode of the target (for validation)
    ///
    /// # Errors
    /// * `FsError::ReadOnly` - Filesystem is read-only
    /// * `FsError::NotFound` - Entry doesn't exist
    /// * `FsError::IsADirectory` - Target is a non-empty directory
    fn unlink(&self, parent_ino: u64, name: &str, target_ino: u64) -> FsResult<()> {
        let _ = (parent_ino, name, target_ino);
        Err(FsError::ReadOnly)
    }

    /// Renames or moves a file or directory.
    ///
    /// # Arguments
    /// * `old_parent` - Source parent directory inode
    /// * `old_name` - Source entry name
    /// * `new_parent` - Destination parent directory inode
    /// * `new_name` - Destination entry name
    /// * `flags` - Rename behavior flags
    fn rename(
        &self,
        old_parent: u64,
        old_name: &str,
        new_parent: u64,
        new_name: &str,
        flags: RenameFlags,
    ) -> FsResult<()> {
        let _ = (old_parent, old_name, new_parent, new_name, flags);
        Err(FsError::ReadOnly)
    }

    /// Sets file size (truncate or extend).
    ///
    /// # Arguments
    /// * `ino` - File inode
    /// * `size` - New file size
    fn set_size(&self, ino: u64, size: u64) -> FsResult<()> {
        let _ = (ino, size);
        Err(FsError::ReadOnly)
    }

    /// Sets file timestamps.
    ///
    /// # Arguments
    /// * `ino` - File inode
    /// * `atime` - New access time (None to keep current)
    /// * `mtime` - New modification time (None to keep current)
    fn set_times(
        &self,
        ino: u64,
        atime: Option<VfsTimestamp>,
        mtime: Option<VfsTimestamp>,
    ) -> FsResult<()> {
        let _ = (ino, atime, mtime);
        Err(FsError::ReadOnly)
    }

    // =========================================================================
    // Cache Management
    // =========================================================================

    /// Invalidates cached data for an inode.
    ///
    /// Called when external changes may have occurred or after write
    /// operations.
    fn invalidate_inode(&self, ino: u64);

    /// Invalidates all cached data.
    ///
    /// Called during unmount or when major changes occur.
    fn invalidate_all_caches(&self);
}

// =============================================================================
// Object-Safe Extensions
// =============================================================================

/// Extension trait for cloning boxed filesystems.
#[cfg(feature = "alloc")]
pub trait VfsFileSystemExt {
    /// Wraps the filesystem in an Arc for shared ownership.
    fn into_arc(self) -> Arc<dyn VfsFileSystem>
    where
        Self: Sized + 'static;
}

#[cfg(feature = "alloc")]
impl<T: VfsFileSystem + 'static> VfsFileSystemExt for T {
    fn into_arc(self) -> Arc<dyn VfsFileSystem> {
        Arc::new(self)
    }
}

// =============================================================================
// BlockDevice Trait (for filesystem implementations)
// =============================================================================

/// Block device trait for reading raw disk data.
///
/// Filesystem implementations use this to read from the underlying storage.
#[cfg(feature = "alloc")]
pub trait BlockDevice: Send + Sync {
    /// Reads data from the device at the specified offset.
    ///
    /// # Arguments
    /// * `offset` - Byte offset to read from
    /// * `buf` - Buffer to read into
    ///
    /// # Returns
    /// Number of bytes read.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize>;

    /// Writes data to the device at the specified offset.
    ///
    /// # Arguments
    /// * `offset` - Byte offset to write at
    /// * `data` - Data to write
    ///
    /// # Returns
    /// Number of bytes written.
    fn write_at(&self, offset: u64, data: &[u8]) -> FsResult<usize> {
        let _ = (offset, data);
        Err(FsError::ReadOnly)
    }

    /// Returns the total size of the device in bytes.
    fn size(&self) -> u64;

    /// Returns the sector size (typically 512 or 4096).
    fn sector_size(&self) -> u32 {
        512
    }

    /// Flushes any cached writes to the device.
    fn flush(&self) -> FsResult<()> {
        Ok(())
    }
}
