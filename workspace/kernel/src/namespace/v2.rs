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

//! IPC ABI v2 namespace bindings (§8).
//!
//! Maps full namespace paths to endpoints owned by a silo. This table is
//! independent of the v1 prefix table in [`super`]: binding has no side
//! effect and existing SEND handles keep working after an unbind.

use crate::{ipc::v2::endpoint::Endpoint, sync::SpinLock, syscall::error::SyscallError};
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
};
use core::sync::atomic::{AtomicU64, Ordering};

struct NsV2Entry {
    ep: Arc<Endpoint>,
    owner_silo: u32,
}

static NS_V2: SpinLock<BTreeMap<String, NsV2Entry>> = SpinLock::new(BTreeMap::new());
/// Boot-lifetime connection id source; ids are never reused.
static NEXT_CONN: AtomicU64 = AtomicU64::new(1);

/// Resolve `path` to its bound endpoint.
pub fn lookup_ep(path: &str) -> Option<Arc<Endpoint>> {
    NS_V2.lock().get(path).map(|entry| entry.ep.clone())
}

/// Return whether `path` is bound and owned by `silo`.
pub fn is_owned_by(path: &str, silo: u32) -> bool {
    NS_V2
        .lock()
        .get(path)
        .is_some_and(|entry| entry.owner_silo == silo)
}

/// Bind `ep` at `path` on behalf of `owner_silo`.
///
/// An existing entry is only replaced when `replace` is set and the caller
/// owns it (`owner_silo == owner_silo`) or is the silo admin.
pub fn bind(
    path: &str,
    ep: Arc<Endpoint>,
    owner_silo: u32,
    replace: bool,
    admin: bool,
) -> Result<(), SyscallError> {
    let mut ns = NS_V2.lock();
    if let Some(existing) = ns.get(path) {
        if !replace || (existing.owner_silo != owner_silo && !admin) {
            return Err(SyscallError::AlreadyExists);
        }
    }
    ns.insert(path.to_string(), NsV2Entry { ep, owner_silo });
    Ok(())
}

/// Remove `path` when `caller_silo` owns it or the caller is the silo admin.
pub fn unbind(path: &str, caller_silo: u32, admin: bool) -> Result<(), SyscallError> {
    let mut ns = NS_V2.lock();
    let Some(entry) = ns.get(path) else {
        return Err(SyscallError::NotFound);
    };
    if entry.owner_silo != caller_silo && !admin {
        return Err(SyscallError::PermissionDenied);
    }
    ns.remove(path);
    Ok(())
}

/// Allocate a fresh connection id, unique for this boot.
pub fn next_conn() -> u64 {
    NEXT_CONN.fetch_add(1, Ordering::Relaxed)
}
