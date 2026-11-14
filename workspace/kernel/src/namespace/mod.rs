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

use crate::{sync::SpinLock, syscall::error::SyscallError};
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
};

struct Namespace {
    bindings: BTreeMap<String, u64>,
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
pub fn bind(path: &str, port_id: u64) -> Result<(), SyscallError> {
    if path.is_empty() || !path.starts_with('/') {
        return Err(SyscallError::InvalidArgument);
    }
    let mut ns = NAMESPACE.lock();
    ns.bindings.insert(path.to_string(), port_id);
    Ok(())
}

/// Performs the unbind operation.
pub fn unbind(path: &str) -> Result<(), SyscallError> {
    let mut ns = NAMESPACE.lock();
    ns.bindings.remove(path).ok_or(SyscallError::BadHandle)?;
    Ok(())
}

/// List all current namespace bindings (path -> port_id).
pub fn list_all_bindings() -> alloc::vec::Vec<(String, u64)> {
    let ns = NAMESPACE.lock();
    ns.bindings.iter().map(|(k, v)| (k.clone(), *v)).collect()
}

/// Resolve a path to the longest matching prefix.
///
/// Returns (port_id, remaining_path).
pub fn resolve(path: &str) -> Option<(u64, String)> {
    let ns = NAMESPACE.lock();
    let mut best: Option<(&String, &u64)> = None;
    for (prefix, port) in ns.bindings.iter() {
        if path.starts_with(prefix) {
            // Ensure prefix boundary (exact match or next char is '/')
            if path.len() == prefix.len() || path.as_bytes().get(prefix.len()) == Some(&b'/') {
                match best {
                    Some((best_prefix, _)) if best_prefix.len() >= prefix.len() => {}
                    _ => best = Some((prefix, port)),
                }
            }
        }
    }
    best.map(|(prefix, port)| {
        let remaining = path[prefix.len()..].to_string();
        (*port, remaining)
    })
}
