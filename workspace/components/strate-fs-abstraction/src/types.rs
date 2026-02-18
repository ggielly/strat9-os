//! Common VFS data types.
//!
//! This module defines the core data structures used across the VFS layer,
//! including file information, directory entries, and volume information.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "std")]
use std::time::SystemTime;

/// File type enumeration.
///
/// Maps to both Unix mode bits and Windows file attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum VfsFileType {
    /// Regular file
    RegularFile = 1,
    /// Directory
    Directory = 2,
    /// Symbolic link
    Symlink = 3,
    /// Block device
    BlockDevice = 4,
    /// Character device
    CharDevice = 5,
    /// Named pipe (FIFO)
    Fifo = 6,
    /// Unix domain socket
    Socket = 7,
    /// Unknown or unsupported type
    Unknown = 0,
}

impl VfsFileType {
    /// Create from Unix mode bits (S_IFMT field).
    pub const fn from_mode(mode: u32) -> Self {
        match mode & 0o170000 {
            0o100000 => VfsFileType::RegularFile,
            0o040000 => VfsFileType::Directory,
            0o120000 => VfsFileType::Symlink,
            0o060000 => VfsFileType::BlockDevice,
            0o020000 => VfsFileType::CharDevice,
            0o010000 => VfsFileType::Fifo,
            0o140000 => VfsFileType::Socket,
            _ => VfsFileType::Unknown,
        }
    }

    /// Convert to Unix mode bits (S_IFMT field).
    pub const fn to_mode_bits(self) -> u32 {
        match self {
            VfsFileType::RegularFile => 0o100000,
            VfsFileType::Directory => 0o040000,
            VfsFileType::Symlink => 0o120000,
            VfsFileType::BlockDevice => 0o060000,
            VfsFileType::CharDevice => 0o020000,
            VfsFileType::Fifo => 0o010000,
            VfsFileType::Socket => 0o140000,
            VfsFileType::Unknown => 0,
        }
    }

    /// Check if this is a regular file.
    pub const fn is_file(self) -> bool {
        matches!(self, VfsFileType::RegularFile)
    }

    /// Check if this is a directory.
    pub const fn is_dir(self) -> bool {
        matches!(self, VfsFileType::Directory)
    }

    /// Check if this is a symbolic link.
    pub const fn is_symlink(self) -> bool {
        matches!(self, VfsFileType::Symlink)
    }
}

impl Default for VfsFileType {
    fn default() -> Self {
        VfsFileType::Unknown
    }
}

/// Unix timestamp representation (seconds since epoch).
///
/// Used when `std` feature is not available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VfsTimestamp {
    /// Seconds since Unix epoch (1970-01-01 00:00:00 UTC)
    pub secs: i64,
    /// Nanoseconds (0-999_999_999)
    pub nsecs: u32,
}

impl VfsTimestamp {
    /// Create a new timestamp.
    pub const fn new(secs: i64, nsecs: u32) -> Self {
        Self { secs, nsecs }
    }

    /// Create from seconds only.
    pub const fn from_secs(secs: i64) -> Self {
        Self { secs, nsecs: 0 }
    }

    /// Convert to Windows FILETIME (100-nanosecond intervals since 1601-01-01).
    pub const fn to_filetime(&self) -> u64 {
        // Windows epoch is 11644473600 seconds before Unix epoch
        const WINDOWS_EPOCH_OFFSET: i64 = 11644473600;
        let windows_secs = self.secs + WINDOWS_EPOCH_OFFSET;
        if windows_secs < 0 {
            return 0;
        }
        (windows_secs as u64) * 10_000_000 + (self.nsecs / 100) as u64
    }

    /// Create from Windows FILETIME.
    pub const fn from_filetime(ft: u64) -> Self {
        const WINDOWS_EPOCH_OFFSET: i64 = 11644473600;
        let secs = (ft / 10_000_000) as i64 - WINDOWS_EPOCH_OFFSET;
        let nsecs = ((ft % 10_000_000) * 100) as u32;
        Self { secs, nsecs }
    }
}

#[cfg(feature = "std")]
impl From<SystemTime> for VfsTimestamp {
    fn from(time: SystemTime) -> Self {
        match time.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(duration) => Self {
                secs: duration.as_secs() as i64,
                nsecs: duration.subsec_nanos(),
            },
            Err(e) => {
                let duration = e.duration();
                Self {
                    secs: -(duration.as_secs() as i64),
                    nsecs: duration.subsec_nanos(),
                }
            }
        }
    }
}

#[cfg(feature = "std")]
impl From<VfsTimestamp> for SystemTime {
    fn from(ts: VfsTimestamp) -> Self {
        use std::time::Duration;
        if ts.secs >= 0 {
            SystemTime::UNIX_EPOCH + Duration::new(ts.secs as u64, ts.nsecs)
        } else {
            SystemTime::UNIX_EPOCH - Duration::new((-ts.secs) as u64, ts.nsecs)
        }
    }
}

/// File metadata structure.
///
/// Contains all metadata about a file or directory that can be
/// retrieved without reading file contents.
#[derive(Debug, Clone)]
pub struct VfsFileInfo {
    /// Inode number (unique file identifier within filesystem)
    pub ino: u64,
    /// File size in bytes
    pub size: u64,
    /// Number of 512-byte blocks allocated
    pub blocks: u64,
    /// Preferred I/O block size
    pub block_size: u32,
    /// Unix permission mode (including file type bits)
    pub mode: u32,
    /// File type (derived from mode, but cached for convenience)
    pub file_type: VfsFileType,
    /// Number of hard links
    pub nlink: u32,
    /// Owner user ID
    pub uid: u32,
    /// Owner group ID
    pub gid: u32,
    /// Device ID (for device files)
    pub rdev: u64,
    /// Last access time
    pub atime: VfsTimestamp,
    /// Last modification time
    pub mtime: VfsTimestamp,
    /// Last status change time (inode change)
    pub ctime: VfsTimestamp,
    /// Creation/birth time (if supported by filesystem)
    pub crtime: Option<VfsTimestamp>,
}

impl VfsFileInfo {
    /// Check if this is a regular file.
    pub const fn is_file(&self) -> bool {
        self.file_type.is_file()
    }

    /// Check if this is a directory.
    pub const fn is_dir(&self) -> bool {
        self.file_type.is_dir()
    }

    /// Check if this is a symbolic link.
    pub const fn is_symlink(&self) -> bool {
        self.file_type.is_symlink()
    }

    /// Get Unix permission bits only (without file type).
    pub const fn permissions(&self) -> u32 {
        self.mode & 0o7777
    }
}

impl Default for VfsFileInfo {
    fn default() -> Self {
        Self {
            ino: 0,
            size: 0,
            blocks: 0,
            block_size: 4096,
            mode: 0,
            file_type: VfsFileType::Unknown,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            atime: VfsTimestamp::default(),
            mtime: VfsTimestamp::default(),
            ctime: VfsTimestamp::default(),
            crtime: None,
        }
    }
}

/// Directory entry structure.
///
/// Represents a single entry within a directory.
#[derive(Debug, Clone)]
#[cfg(feature = "alloc")]
pub struct VfsDirEntry {
    /// Entry name (filename only, not full path)
    pub name: String,
    /// Inode number of the target file/directory
    pub ino: u64,
    /// File type (may be Unknown if filesystem doesn't store it)
    pub file_type: VfsFileType,
    /// Offset cookie for readdir continuation
    pub offset: u64,
}

#[cfg(feature = "alloc")]
impl VfsDirEntry {
    /// Create a new directory entry.
    pub fn new(name: impl Into<String>, ino: u64, file_type: VfsFileType) -> Self {
        Self {
            name: name.into(),
            ino,
            file_type,
            offset: 0,
        }
    }

    /// Create with an explicit offset.
    pub fn with_offset(
        name: impl Into<String>,
        ino: u64,
        file_type: VfsFileType,
        offset: u64,
    ) -> Self {
        Self {
            name: name.into(),
            ino,
            file_type,
            offset,
        }
    }
}

/// Volume/filesystem information.
///
/// Contains information about the filesystem as a whole.
#[derive(Debug, Clone)]
#[cfg(feature = "alloc")]
pub struct VfsVolumeInfo {
    /// Total size of the filesystem in bytes
    pub total_bytes: u64,
    /// Free space in bytes
    pub free_bytes: u64,
    /// Available space for non-privileged users
    pub available_bytes: u64,
    /// Total number of inodes
    pub total_inodes: u64,
    /// Number of free inodes
    pub free_inodes: u64,
    /// Filesystem block size
    pub block_size: u32,
    /// Maximum filename length
    pub max_filename_len: u32,
    /// Filesystem type name (e.g., "xfs", "ext4")
    pub fs_type: String,
    /// Volume label (if any)
    pub volume_label: Option<String>,
    /// Filesystem UUID (if available)
    pub uuid: Option<[u8; 16]>,
}

#[cfg(feature = "alloc")]
impl Default for VfsVolumeInfo {
    fn default() -> Self {
        Self {
            total_bytes: 0,
            free_bytes: 0,
            available_bytes: 0,
            total_inodes: 0,
            free_inodes: 0,
            block_size: 4096,
            max_filename_len: 255,
            fs_type: String::new(),
            volume_label: None,
            uuid: None,
        }
    }
}

/// Rename operation flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct RenameFlags {
    /// Replace target if it exists
    pub replace_if_exists: bool,
    /// Atomically exchange source and target
    pub exchange: bool,
    /// Fail if target exists (mutually exclusive with replace_if_exists)
    pub no_replace: bool,
}

/// File open flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenFlags {
    /// Open for reading
    pub read: bool,
    /// Open for writing
    pub write: bool,
    /// Create if doesn't exist
    pub create: bool,
    /// Fail if exists (with create)
    pub exclusive: bool,
    /// Truncate to zero length
    pub truncate: bool,
    /// Append mode (writes go to end)
    pub append: bool,
    /// Open directory
    pub directory: bool,
}
