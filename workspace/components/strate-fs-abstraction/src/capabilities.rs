//! Filesystem capability flags.
//!
//! This module defines the capabilities that a filesystem implementation
//! can advertise, allowing the VFS layer to adapt its behavior accordingly.

/// Filesystem capabilities.
///
/// These flags describe what features a filesystem supports.
/// The VFS layer uses this information to:
/// - Reject unsupported operations early
/// - Adapt behavior (e.g., case sensitivity)
/// - Provide accurate information to applications
#[derive(Debug, Clone)]
pub struct FsCapabilities {
    // === Access Mode ===
    /// Filesystem is read-only (no write operations allowed)
    pub read_only: bool,

    // === Naming ===
    /// Filesystem is case-sensitive (Linux default)
    pub case_sensitive: bool,

    /// Filesystem preserves case even if not case-sensitive
    pub case_preserving: bool,

    /// Maximum filename length in bytes
    pub max_filename_len: usize,

    /// Maximum full path length in bytes
    pub max_path_len: usize,

    // === Links ===
    /// Supports symbolic links
    pub supports_symlinks: bool,

    /// Supports hard links
    pub supports_hardlinks: bool,

    // === File Features ===
    /// Supports sparse files (holes in files)
    pub supports_sparse_files: bool,

    /// Maximum file size in bytes
    pub max_file_size: u64,

    // === Extended Attributes ===
    /// Supports extended attributes (xattr)
    pub supports_xattr: bool,

    /// Supports POSIX ACLs
    pub supports_acl: bool,

    // === Timestamps ===
    /// Supports sub-second timestamp precision
    pub supports_nanoseconds: bool,

    /// Supports creation/birth time (crtime)
    pub supports_crtime: bool,
}

impl FsCapabilities {
    /// Exbibyte constant (2^60) for max_file_size declarations.
    const EIB: u64 = 1 << 60;

    /// Create capabilities for a typical read-only Linux filesystem.
    pub const fn read_only_linux() -> Self {
        Self {
            read_only: true,
            case_sensitive: true,
            case_preserving: true,
            max_filename_len: 255,
            max_path_len: 4096,
            supports_symlinks: true,
            supports_hardlinks: true,
            supports_sparse_files: true,
            max_file_size: i64::MAX as u64,
            supports_xattr: false,
            supports_acl: false,
            supports_nanoseconds: true,
            supports_crtime: false,
        }
    }

    /// Create capabilities for a writable Linux filesystem.
    pub const fn writable_linux() -> Self {
        Self {
            read_only: false,
            ..Self::read_only_linux()
        }
    }

    /// Create default XFS capabilities.
    pub const fn xfs() -> Self {
        Self {
            read_only: false,
            case_sensitive: true,
            case_preserving: true,
            max_filename_len: 255,
            max_path_len: 4096,
            supports_symlinks: true,
            supports_hardlinks: true,
            supports_sparse_files: true,
            // XFS max file size: 8 EiB on 64-bit systems (was wrongly
            // computed as 8 PiB — the literal chain had only five 1024s).
            max_file_size: 8 * Self::EIB,
            supports_xattr: true,
            supports_acl: true,
            supports_nanoseconds: true,
            supports_crtime: true, // XFS v5 has crtime
        }
    }

    /// Create default ext4 capabilities.
    pub const fn ext4() -> Self {
        Self {
            read_only: false,
            case_sensitive: true,
            case_preserving: true,
            max_filename_len: 255,
            max_path_len: 4096,
            supports_symlinks: true,
            supports_hardlinks: true,
            supports_sparse_files: true,
            max_file_size: 16 * 1024 * 1024 * 1024 * 1024, // 16 TiB
            supports_xattr: true,
            supports_acl: true,
            supports_nanoseconds: true,
            supports_crtime: true,
        }
    }

    /// Create default btrfs capabilities.
    pub const fn btrfs() -> Self {
        Self {
            read_only: false,
            case_sensitive: true,
            case_preserving: true,
            max_filename_len: 255,
            max_path_len: 4096,
            supports_symlinks: true,
            supports_hardlinks: true,
            supports_sparse_files: true,
            // btrfs theoretical max file size is 16 EiB, which does NOT fit
            // in u64 (2^64). Clamp to u64::MAX like other metadata that
            // saturates; callers treat it as "unbounded".
            max_file_size: u64::MAX,
            supports_xattr: true,
            supports_acl: true,
            supports_nanoseconds: true,
            supports_crtime: true,
        }
    }

    /// Check if write operations are allowed.
    pub const fn can_write(&self) -> bool {
        !self.read_only
    }
}

impl Default for FsCapabilities {
    /// Implements default.
    fn default() -> Self {
        Self::read_only_linux()
    }
}
