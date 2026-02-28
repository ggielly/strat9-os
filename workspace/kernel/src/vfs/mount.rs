//! Mount table and path resolution.
//!
//! Maps path prefixes to schemes (like Plan 9 namespaces).

use super::scheme::DynScheme;
use crate::syscall::error::SyscallError;
use spin::{RwLock, Lazy};
use alloc::{string::String, vec::Vec};

/// A mount point binding a path prefix to a scheme.
#[derive(Clone)]
struct Mount {
    /// Path prefix (e.g., "/dev", "/net").
    prefix: String,
    /// Scheme handling this mount.
    scheme: DynScheme,
}

/// Global mount table.
pub struct MountTable {
    mounts: Vec<Mount>,
}

impl MountTable {
    pub fn new() -> Self {
        MountTable {
            mounts: Vec::new(),
        }
    }

    /// Mount a scheme at a path prefix.
    ///
    /// Returns an error if the prefix is already mounted.
    pub fn mount(&mut self, prefix: &str, scheme: DynScheme) -> Result<(), SyscallError> {
        if prefix.is_empty() || !prefix.starts_with('/') {
            return Err(SyscallError::InvalidArgument);
        }

        // Normalize path (remove trailing slash except for root)
        let prefix = if prefix.len() > 1 && prefix.ends_with('/') {
            &prefix[..prefix.len() - 1]
        } else {
            prefix
        };

        // Check for duplicate mount
        if self.mounts.iter().any(|m| m.prefix == prefix) {
            return Err(SyscallError::AlreadyExists);
        }

        self.mounts.push(Mount {
            prefix: String::from(prefix),
            scheme,
        });

        // Sort by prefix length (longest first) for correct resolution
        self.mounts
            .sort_by(|a, b| b.prefix.len().cmp(&a.prefix.len()));

        Ok(())
    }

    /// Unmount a path prefix.
    pub fn unmount(&mut self, prefix: &str) -> Result<(), SyscallError> {
        let pos = self
            .mounts
            .iter()
            .position(|m| m.prefix == prefix)
            .ok_or(SyscallError::BadHandle)?;
        self.mounts.remove(pos);
        Ok(())
    }

    /// Resolve a path to (scheme, relative_path).
    ///
    /// Returns the longest matching mount point.
    pub fn resolve(&self, path: &str) -> Result<(DynScheme, String), SyscallError> {
        if !path.starts_with('/') {
            return Err(SyscallError::InvalidArgument);
        }

        for mount in &self.mounts {
            if path == mount.prefix {
                return Ok((mount.scheme.clone(), String::new()));
            } else if path.starts_with(&mount.prefix) {
                let is_root = mount.prefix == "/";
                let next_byte = path.as_bytes().get(mount.prefix.len());
                if is_root || next_byte == Some(&b'/') {
                    let relative = if is_root {
                        &path[1..]
                    } else {
                        &path[mount.prefix.len() + 1..]
                    };
                    return Ok((mount.scheme.clone(), String::from(relative)));
                }
            }
        }

        Err(SyscallError::BadHandle)
    }

    /// List all mount points.
    pub fn list(&self) -> Vec<String> {
        self.mounts.iter().map(|m| m.prefix.clone()).collect()
    }
}

static GLOBAL_MOUNTS: Lazy<RwLock<MountTable>> = Lazy::new(|| RwLock::new(MountTable::new()));

/// Mount a scheme at a global path.
pub fn mount(prefix: &str, scheme: DynScheme) -> Result<(), SyscallError> {
    GLOBAL_MOUNTS.write().mount(prefix, scheme)
}

/// Unmount a global path.
pub fn unmount(prefix: &str) -> Result<(), SyscallError> {
    GLOBAL_MOUNTS.write().unmount(prefix)
}

/// Resolve a path using the global mount table.
pub fn resolve(path: &str) -> Result<(DynScheme, String), SyscallError> {
    GLOBAL_MOUNTS.read().resolve(path)
}

/// List all global mount points.
pub fn list_mounts() -> Vec<String> {
    GLOBAL_MOUNTS.read().list()
}

// ============================================================================
// Per-Process Namespace (future extension)
// ============================================================================

/// Per-process namespace (private mount table).
///
/// Currently unused but reserved for future per-process namespaces.
pub struct Namespace {
    mounts: MountTable,
}

impl Namespace {
    pub fn new() -> Self {
        Namespace {
            mounts: MountTable::new(),
        }
    }

    /// Clone the global mount table.
    pub fn from_global() -> Self {
        let global = GLOBAL_MOUNTS.read();
        Namespace {
            mounts: MountTable {
                mounts: global.mounts.clone(),
            },
        }
    }

    pub fn mount(&mut self, prefix: &str, scheme: DynScheme) -> Result<(), SyscallError> {
        self.mounts.mount(prefix, scheme)
    }

    pub fn unmount(&mut self, prefix: &str) -> Result<(), SyscallError> {
        self.mounts.unmount(prefix)
    }

    pub fn resolve(&self, path: &str) -> Result<(DynScheme, String), SyscallError> {
        self.mounts.resolve(path)
    }
}

impl Default for Namespace {
    fn default() -> Self {
        Self::new()
    }
}
