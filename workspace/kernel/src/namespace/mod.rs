//! Minimal namespace binding (temporary global table).
//!
//! Maps path prefixes to IPC ports for scheme dispatch.

use crate::{sync::SpinLock, syscall::error::SyscallError};
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
};

struct Namespace {
    bindings: BTreeMap<String, u64>,
}

impl Namespace {
    const fn new() -> Self {
        Namespace {
            bindings: BTreeMap::new(),
        }
    }
}

static NAMESPACE: SpinLock<Namespace> = SpinLock::new(Namespace::new());

pub fn bind(path: &str, port_id: u64) -> Result<(), SyscallError> {
    if path.is_empty() || !path.starts_with('/') {
        return Err(SyscallError::InvalidArgument);
    }
    let mut ns = NAMESPACE.lock();
    ns.bindings.insert(path.to_string(), port_id);
    Ok(())
}

pub fn unbind(path: &str) -> Result<(), SyscallError> {
    let mut ns = NAMESPACE.lock();
    ns.bindings.remove(path).ok_or(SyscallError::BadHandle)?;
    Ok(())
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
