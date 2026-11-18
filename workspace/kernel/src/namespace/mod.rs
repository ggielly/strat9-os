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

//! Minimal namespace binding (temporary global table).
//!
//! Maps path prefixes to IPC ports for scheme dispatch.

pub mod v2;

use crate::{
    process::Pid,
    sync::SpinLock,
    syscall::error::SyscallError,
};
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
};

/// One namespace entry plus the thread group that bound it.
struct Binding {
    port_id: u64,
    /// Binder identity: the owning task's thread-group id.
    owner: Pid,
}

struct Namespace {
    bindings: BTreeMap<String, Binding>,
}

impl Namespace {
    /// Creates a new instance.
    const fn new() -> Self {
        Namespace {
            bindings: BTreeMap::new(),
        }
    }
}

static NAMESPACE: SpinLock<Namespace> = SpinLock::new(Namespace::new());

/// Performs the bind operation.
///
/// `owner` is the binder identity (task tgid); it authorises a later
/// [`unbind`] and lets [`bind`] take over a stale entry.
pub fn bind(path: &str, port_id: u64, owner: Pid) -> Result<(), SyscallError> {
    if path.is_empty() || !path.starts_with('/') {
        return Err(SyscallError::InvalidArgument);
    }
    let mut ns = NAMESPACE.lock();
    ns.bindings.insert(path.to_string(), Binding { port_id, owner });
    Ok(())
}

/// Performs the unbind operation.
pub fn unbind(path: &str) -> Result<(), SyscallError> {
    let mut ns = NAMESPACE.lock();
    ns.bindings.remove(path).ok_or(SyscallError::BadHandle)?;
    Ok(())
}

/// Return the recorded owner of `path`, or `None` when it is not bound.
pub fn owner_of(path: &str) -> Option<Pid> {
    NAMESPACE.lock().bindings.get(path).map(|b| b.owner)
}

/// Remove every binding owned by `owner` (called on last-thread exit).
pub fn release_owned_by(owner: Pid) {
    NAMESPACE
        .lock()
        .bindings
        .retain(|_, binding| binding.owner != owner);
}

/// List all current namespace bindings (path -> port_id).
pub fn list_all_bindings() -> alloc::vec::Vec<(String, u64)> {
    let ns = NAMESPACE.lock();
    ns.bindings
        .iter()
        .map(|(k, v)| (k.clone(), v.port_id))
        .collect()
}

/// Resolve a path to the longest matching prefix.
///
/// Returns (port_id, remaining_path).
pub fn resolve(path: &str) -> Option<(u64, String)> {
    let ns = NAMESPACE.lock();
    let mut best: Option<(&String, &Binding)> = None;
    for (prefix, binding) in ns.bindings.iter() {
        if path.starts_with(prefix) {
            // Ensure prefix boundary (exact match or next char is '/')
            if path.len() == prefix.len() || path.as_bytes().get(prefix.len()) == Some(&b'/') {
                match best {
                    Some((best_prefix, _)) if best_prefix.len() >= prefix.len() => {}
                    _ => best = Some((prefix, binding)),
                }
            }
        }
    }
    best.map(|(prefix, binding)| {
        let remaining = path[prefix.len()..].to_string();
        (binding.port_id, remaining)
    })
}
