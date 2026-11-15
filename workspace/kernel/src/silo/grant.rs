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

//! Per-subsystem silo grants (`SYS_SILO_GRANT`).
//!
//! Pure policy functions operate on decoded [`GrantEntry`] values and never
//! touch user pointers. The syscall gathers descriptors and path bytes first,
//! then calls [`parse_desc`] with the already-copied bytes.
//!
//! Enforcement is deny-by-default once a silo declares a grant of a kind.
//! A silo with no grant of a kind keeps the previous unrestricted behavior.

use alloc::{string::String, sync::Arc, vec::Vec};
use strat9_abi::data::{
    SiloGrantDesc, SILO_GRANT_ACCESS_WRITE, SILO_GRANT_DMA, SILO_GRANT_IRQ, SILO_GRANT_PATH,
    SILO_GRANT_PCI,
};

use crate::{process::current_task_clone, syscall::error::SyscallError};

use super::{is_admin_task, SILO_MANAGER};

/// Maximum accepted PATH grant length in bytes.
pub const MAX_GRANT_PATH_LEN: usize = 1024;

/// Kind of a silo grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantKind {
    Path,
    Irq,
    Pci,
    Dma,
}

impl GrantKind {
    fn from_raw(raw: u32) -> Result<Self, SyscallError> {
        match raw {
            SILO_GRANT_PATH => Ok(GrantKind::Path),
            SILO_GRANT_IRQ => Ok(GrantKind::Irq),
            SILO_GRANT_PCI => Ok(GrantKind::Pci),
            SILO_GRANT_DMA => Ok(GrantKind::Dma),
            _ => Err(SyscallError::InvalidArgument),
        }
    }
}

/// A decoded, kernel-owned grant entry.
#[derive(Debug, Clone)]
pub struct GrantEntry {
    kind: GrantKind,
    write: bool,
    id: u64,
    path: Option<Arc<str>>,
    len: u64,
}

impl GrantEntry {
    /// Grant kind.
    pub fn kind(&self) -> GrantKind {
        self.kind
    }

    /// Whether write access is allowed (PATH only).
    pub fn write(&self) -> bool {
        self.write
    }

    /// Kind-specific identifier (IRQ line, PCI id, DMA budget; 0 for PATH).
    pub fn id(&self) -> u64 {
        self.id
    }

    /// PATH grant string, if this is a PATH grant.
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Kind-specific length (PATH byte length; 0 otherwise).
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether two entries address the same subject (PATH compares strings).
    pub fn same_subject(&self, other: &Self) -> bool {
        if self.kind != other.kind {
            return false;
        }
        match (&self.path, &other.path) {
            (Some(a), Some(b)) => a == b,
            _ => self.id == other.id,
        }
    }

    /// Merge `other` into `self`, widening write access only.
    pub fn merge_from(&mut self, other: &Self) {
        self.write |= other.write;
    }
}

/// Decode and validate a wire descriptor.
///
/// For PATH the caller must supply the already-copied path bytes (`Some`);
/// they must be valid UTF-8 and at most [`MAX_GRANT_PATH_LEN`] bytes. For all
/// other kinds `path_bytes` is ignored.
pub fn parse_desc(
    desc: &SiloGrantDesc,
    path_bytes: Option<&[u8]>,
) -> Result<GrantEntry, SyscallError> {
    let kind = GrantKind::from_raw(desc.kind)?;
    if desc.access & !SILO_GRANT_ACCESS_WRITE != 0 {
        return Err(SyscallError::InvalidArgument);
    }
    let write = desc.access & SILO_GRANT_ACCESS_WRITE != 0;

    match kind {
        GrantKind::Path => {
            if desc.len == 0 || desc.len > MAX_GRANT_PATH_LEN as u64 {
                return Err(SyscallError::InvalidArgument);
            }
            let bytes = path_bytes.ok_or(SyscallError::InvalidArgument)?;
            if bytes.len() != desc.len as usize {
                return Err(SyscallError::InvalidArgument);
            }
            let text = core::str::from_utf8(bytes).map_err(|_| SyscallError::InvalidArgument)?;
            Ok(GrantEntry {
                kind,
                write,
                id: 0,
                path: Some(Arc::from(String::from(text))),
                len: desc.len,
            })
        }
        GrantKind::Irq => Ok(GrantEntry {
            kind,
            write,
            id: desc.id,
            path: None,
            len: desc.len,
        }),
        GrantKind::Pci => {
            let device = ((desc.id >> 8) & 0xff) as u8;
            let function = (desc.id & 0xff) as u8;
            if device > 0x1f || function > 0x07 {
                return Err(SyscallError::InvalidArgument);
            }
            Ok(GrantEntry {
                kind,
                write,
                id: desc.id,
                path: None,
                len: desc.len,
            })
        }
        GrantKind::Dma => {
            if desc.len != 0 {
                return Err(SyscallError::InvalidArgument);
            }
            Ok(GrantEntry {
                kind,
                write,
                id: desc.id,
                path: None,
                len: desc.len,
            })
        }
    }
}

/// Whether `path` is permitted by the PATH grants.
///
/// No PATH grant means unrestricted. Otherwise an exact match or a subtree
/// match (`grant_path + "/"`) is required, and write access needs a writable
/// grant.
pub fn path_allows(grants: &[GrantEntry], path: &str, need_write: bool) -> bool {
    let mut any = false;
    for grant in grants {
        if grant.kind != GrantKind::Path {
            continue;
        }
        any = true;
        let Some(grant_path) = grant.path() else {
            continue;
        };
        let matches = path == grant_path
            || (path.len() > grant_path.len()
                && path.starts_with(grant_path)
                && path.as_bytes()[grant_path.len()] == b'/');
        if matches && (!need_write || grant.write) {
            return true;
        }
    }
    !any
}

/// Whether `addr = (bus, device, function)` is permitted by the PCI grants.
///
/// No PCI grant means unrestricted. Otherwise only an exact match is allowed.
pub fn pci_allows(grants: &[GrantEntry], addr: (u8, u8, u8)) -> bool {
    let want = packed_pci(addr.0, addr.1, addr.2);
    let mut any = false;
    for grant in grants {
        if grant.kind != GrantKind::Pci {
            continue;
        }
        any = true;
        if grant.id == want {
            return true;
        }
    }
    !any
}

/// Effective DMA byte budget: `config_max` unless DMA grants narrow it.
pub fn dma_limit(grants: &[GrantEntry], config_max: u64) -> u64 {
    let mut any = false;
    let mut sum: u64 = 0;
    for grant in grants {
        if grant.kind != GrantKind::Dma {
            continue;
        }
        any = true;
        sum = sum.saturating_add(grant.id);
    }
    if !any {
        return config_max;
    }
    let cap = if config_max == 0 {
        u64::MAX
    } else {
        config_max
    };
    core::cmp::min(cap, sum)
}

/// Pack a PCI address into the grant `id` representation.
pub fn packed_pci(bus: u8, device: u8, function: u8) -> u64 {
    ((bus as u64) << 16) | ((device as u64) << 8) | function as u64
}

/// Enforce PATH grants for the current task.
///
/// Tasks outside a silo and admin tasks are unrestricted. A task whose silo
/// has no PATH grant is unrestricted.
pub fn check_current_task_path(path: &str, need_write: bool) -> Result<(), SyscallError> {
    let Some(task) = current_task_clone() else {
        return Ok(());
    };
    if is_admin_task(&task) {
        return Ok(());
    }
    let mgr = SILO_MANAGER.lock();
    let Some(silo_id) = mgr.silo_for_task(task.id) else {
        return Ok(());
    };
    let silo = mgr.get(silo_id)?;
    if path_allows(silo.grants.as_slice(), path, need_write) {
        Ok(())
    } else {
        Err(SyscallError::PermissionDenied)
    }
}

/// Enforce PCI grants for the current task.
pub fn check_current_task_pci(bus: u8, device: u8, function: u8) -> Result<(), SyscallError> {
    let Some(task) = current_task_clone() else {
        return Ok(());
    };
    if is_admin_task(&task) {
        return Ok(());
    }
    let mgr = SILO_MANAGER.lock();
    let Some(silo_id) = mgr.silo_for_task(task.id) else {
        return Ok(());
    };
    let silo = mgr.get(silo_id)?;
    if pci_allows(silo.grants.as_slice(), (bus, device, function)) {
        Ok(())
    } else {
        Err(SyscallError::PermissionDenied)
    }
}

/// Packed PCI addresses the current task may see, or `None` for unrestricted.
///
/// Used by `SYS_PCI_ENUM` to filter the enumerated device list exactly once.
pub fn current_task_pci_filter() -> Option<Vec<u64>> {
    let task = current_task_clone()?;
    if is_admin_task(&task) {
        return None;
    }
    let mgr = SILO_MANAGER.lock();
    let silo_id = mgr.silo_for_task(task.id)?;
    let silo = mgr.get(silo_id).ok()?;
    let mut ids = Vec::new();
    for grant in silo.grants.iter() {
        if grant.kind == GrantKind::Pci {
            ids.push(grant.id);
        }
    }
    if ids.is_empty() {
        None
    } else {
        Some(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path_grant(path: &str, write: bool) -> GrantEntry {
        GrantEntry {
            kind: GrantKind::Path,
            write,
            id: 0,
            path: Some(Arc::from(path)),
            len: path.len() as u64,
        }
    }

    fn id_grant(kind: GrantKind, id: u64) -> GrantEntry {
        GrantEntry {
            kind,
            write: false,
            id,
            path: None,
            len: 0,
        }
    }

    #[test]
    fn no_path_grant_allows_everything() {
        assert!(path_allows(&[], "/any/path", true));
        assert!(path_allows(&[id_grant(GrantKind::Irq, 3)], "/any", true));
    }

    #[test]
    fn path_grant_exact_and_subtree() {
        let grants = [path_grant("/srv/data", false)];
        assert!(path_allows(&grants, "/srv/data", false));
        assert!(path_allows(&grants, "/srv/data/file", false));
        assert!(!path_allows(&grants, "/srv/database", false));
        assert!(!path_allows(&grants, "/srv", false));
    }

    #[test]
    fn path_write_requires_writable_grant() {
        let ro = [path_grant("/srv/data", false)];
        assert!(path_allows(&ro, "/srv/data/x", false));
        assert!(!path_allows(&ro, "/srv/data/x", true));

        let rw = [path_grant("/srv/data", true)];
        assert!(path_allows(&rw, "/srv/data/x", true));
    }

    #[test]
    fn pci_grant_is_exact() {
        assert!(pci_allows(&[], (0, 1, 0)));
        let grants = [id_grant(GrantKind::Pci, packed_pci(0, 1, 0))];
        assert!(pci_allows(&grants, (0, 1, 0)));
        assert!(!pci_allows(&grants, (0, 1, 1)));
        assert!(!pci_allows(&grants, (1, 1, 0)));
    }

    #[test]
    fn dma_limit_uses_min_of_sum_and_config() {
        // No DMA grant: config wins.
        assert_eq!(dma_limit(&[], 4096), 4096);
        assert_eq!(dma_limit(&[], 0), 0);

        let one = [id_grant(GrantKind::Dma, 1024)];
        assert_eq!(dma_limit(&one, 0), 1024);
        assert_eq!(dma_limit(&one, 2048), 1024);

        let two = [
            id_grant(GrantKind::Dma, 1024),
            id_grant(GrantKind::Dma, 512),
        ];
        assert_eq!(dma_limit(&two, 0), 1536);
        assert_eq!(dma_limit(&two, 1024), 1024);
    }

    #[test]
    fn dma_limit_saturates() {
        let grants = [
            id_grant(GrantKind::Dma, u64::MAX),
            id_grant(GrantKind::Dma, 8),
        ];
        assert_eq!(dma_limit(&grants, 0), u64::MAX);
    }
}
