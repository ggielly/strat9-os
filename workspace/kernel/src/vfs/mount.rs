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

//! Mount table and path resolution.
//!
//! Maps path prefixes to schemes (like Plan 9 namespaces).

use super::scheme::DynScheme;
use crate::{process::Pid, syscall::error::SyscallError};
use alloc::{string::String, vec::Vec};
use spin::{Lazy, RwLock};

/// A mount point binding a path prefix to a scheme.
#[derive(Clone)]
struct Mount {
    /// Path prefix (e.g., "/dev", "/net").
    prefix: String,
    /// Scheme handling this mount.
    scheme: DynScheme,
    /// Binder identity (task tgid) for mounts created by `SYS_IPC_BIND_PORT`.
    owner: Option<Pid>,
}

/// Global mount table.
pub struct MountTable {
    mounts: Vec<Mount>,
}

impl MountTable {
    /// Creates a new instance.
    pub fn new() -> Self {
        MountTable { mounts: Vec::new() }
    }

    /// Mount a scheme at a path prefix.
    ///
    /// Returns an error if the prefix is already mounted.
    pub fn mount(
        &mut self,
        prefix: &str,
        scheme: DynScheme,
        owner: Option<Pid>,
    ) -> Result<(), SyscallError> {
        if prefix.is_empty() || !prefix.starts_with('/') {
            return Err(SyscallError::InvalidArgument);
        }

        // Normalize path (remove trailing slash except for root)
        let prefix = normalize(prefix);

        // Check for duplicate mount
        if self.mounts.iter().any(|m| m.prefix == prefix) {
            return Err(SyscallError::AlreadyExists);
        }

        self.mounts.push(Mount {
            prefix: String::from(prefix),
            scheme,
            owner,
        });

        // Sort by prefix length (longest first) for correct resolution
        self.mounts
            .sort_by(|a, b| b.prefix.len().cmp(&a.prefix.len()));

        Ok(())
    }

    /// Mount a path prefix, replacing an existing mount with the same prefix.
    ///
    /// Used by strate hot-restart: a new instance takes over the namespace
    /// entry atomically.  Callers must enforce the policy (only a `NET`/`DRV`
    /// silo may replace `/net`, for example).
    pub fn mount_replace(
        &mut self,
        prefix: &str,
        scheme: DynScheme,
        owner: Option<Pid>,
    ) -> Result<(), SyscallError> {
        if prefix.is_empty() || !prefix.starts_with('/') {
            return Err(SyscallError::InvalidArgument);
        }
        let prefix = normalize(prefix);
        self.mounts.retain(|m| m.prefix.as_str() != prefix);
        self.mounts.push(Mount {
            prefix: String::from(prefix),
            scheme,
            owner,
        });
        self.mounts
            .sort_by(|a, b| b.prefix.len().cmp(&a.prefix.len()));
        Ok(())
    }

    /// Unmount a path prefix.
    pub fn unmount(&mut self, prefix: &str) -> Result<(), SyscallError> {
        let prefix = normalize(prefix);
        let pos = self
            .mounts
            .iter()
            .position(|m| m.prefix == prefix)
            .ok_or(SyscallError::BadHandle)?;
        self.mounts.remove(pos);
        Ok(())
    }

    /// Recorded owner of `prefix`: outer `None` means "not mounted", inner
    /// `None` means mounted by the kernel/shell (untracked).
    pub fn owner_of(&self, prefix: &str) -> Option<Option<Pid>> {
        let prefix = normalize(prefix);
        self.mounts
            .iter()
            .find(|m| m.prefix == prefix)
            .map(|m| m.owner)
    }

    /// Remove every mount owned by `owner` (last-thread exit cleanup).
    pub fn unmount_owned_by(&mut self, owner: Pid) {
        self.mounts.retain(|m| m.owner != Some(owner));
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

        Err(SyscallError::NotFound)
    }

    /// List all mount points.
    pub fn list(&self) -> Vec<String> {
        self.mounts.iter().map(|m| m.prefix.clone()).collect()
    }

    /// Number of mounted prefixes.
    pub fn len(&self) -> usize {
        self.mounts.len()
    }

    /// True when nothing is mounted.
    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }
}

/// Strip a trailing slash (except from root) for mount table lookups.
fn normalize(prefix: &str) -> &str {
    if prefix.len() > 1 && prefix.ends_with('/') {
        &prefix[..prefix.len() - 1]
    } else {
        prefix
    }
}

static GLOBAL_MOUNTS: Lazy<RwLock<MountTable>> = Lazy::new(|| RwLock::new(MountTable::new()));

/// Mount a scheme at a global path.
pub fn mount(prefix: &str, scheme: DynScheme, owner: Option<Pid>) -> Result<(), SyscallError> {
    GLOBAL_MOUNTS.write().mount(prefix, scheme, owner)
}

/// Mount, replacing an existing prefix (strate hot-restart).
pub fn mount_replace(
    prefix: &str,
    scheme: DynScheme,
    owner: Option<Pid>,
) -> Result<(), SyscallError> {
    GLOBAL_MOUNTS.write().mount_replace(prefix, scheme, owner)
}

/// Unmount a global path.
pub fn unmount(prefix: &str) -> Result<(), SyscallError> {
    GLOBAL_MOUNTS.write().unmount(prefix)
}

/// Recorded owner of a global mount point (see `MountTable::owner_of`).
pub fn owner_of(prefix: &str) -> Option<Option<Pid>> {
    GLOBAL_MOUNTS.read().owner_of(prefix)
}

/// Remove every global mount owned by `owner`.
pub fn unmount_owned_by(owner: Pid) {
    GLOBAL_MOUNTS.write().unmount_owned_by(owner);
}

/// Resolve a path using the global mount table.
pub fn resolve(path: &str) -> Result<(DynScheme, String), SyscallError> {
    GLOBAL_MOUNTS.read().resolve(path)
}

/// List all global mount points.
pub fn list_mounts() -> Vec<String> {
    GLOBAL_MOUNTS.read().list()
}

/// Number of mounted prefixes.
///
/// `list_mounts` clones every prefix into a fresh `Vec`, which is the right cost
/// for a listing but wasteful for a counter such as the `env` computed value.
pub fn mount_count() -> usize {
    GLOBAL_MOUNTS.read().len()
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
    /// Creates a new instance.
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

    /// Performs the mount operation.
    pub fn mount(&mut self, prefix: &str, scheme: DynScheme) -> Result<(), SyscallError> {
        self.mounts.mount(prefix, scheme, None)
    }

    /// Performs the unmount operation.
    pub fn unmount(&mut self, prefix: &str) -> Result<(), SyscallError> {
        self.mounts.unmount(prefix)
    }

    /// Performs the resolve operation.
    pub fn resolve(&self, path: &str) -> Result<(DynScheme, String), SyscallError> {
        self.mounts.resolve(path)
    }
}

impl Default for Namespace {
    /// Builds a default instance.
    fn default() -> Self {
        Self::new()
    }
}
