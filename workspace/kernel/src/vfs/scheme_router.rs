//! Scheme Router (SR) - central registry for all schemes.
//!
//! The Scheme Router manages scheme registration and provides
//! a unified interface for mounting schemes in the VFS namespace.
//!
//! # Usage
//!
//! ```rust,no_run
//! // Register a scheme
//! let scheme_id = scheme_router::register("my_scheme", my_scheme);
//!
//! // Mount at a path
//! mount_scheme("my_scheme", "/my/path")?;
//! ```

use crate::{
    ipc::port::PortId,
    sync::SpinLock,
    syscall::error::SyscallError,
    vfs::scheme::{DynScheme, IpcScheme, KernelScheme},
};
use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};

/// Scheme registry entry
pub struct SchemeEntry {
    pub name: String,
    pub scheme: DynScheme,
}

/// Global scheme router
static SCHEME_ROUTER: SpinLock<SchemeRouter> = SpinLock::new(SchemeRouter::new());
static INITFS_KERNEL_SCHEME: SpinLock<Option<Arc<KernelScheme>>> = SpinLock::new(None);

/// Scheme router state
pub struct SchemeRouter {
    /// Registered schemes by name
    schemes: BTreeMap<String, SchemeEntry>,
    /// Next scheme ID
    next_id: u64,
}

impl SchemeRouter {
    const fn new() -> Self {
        Self {
            schemes: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Register a new scheme
    pub fn register(&mut self, name: &str, scheme: DynScheme) -> Result<u64, SyscallError> {
        if self.schemes.contains_key(name) {
            return Err(SyscallError::AlreadyExists);
        }

        let id = self.next_id;
        self.next_id += 1;

        self.schemes.insert(
            String::from(name),
            SchemeEntry {
                name: String::from(name),
                scheme,
            },
        );

        Ok(id)
    }

    /// Get a scheme by name
    pub fn get(&self, name: &str) -> Option<DynScheme> {
        self.schemes.get(name).map(|e| e.scheme.clone())
    }

    /// List all registered schemes
    pub fn list(&self) -> Vec<String> {
        self.schemes.keys().cloned().collect()
    }

    /// Unregister a scheme
    pub fn unregister(&mut self, name: &str) -> Result<(), SyscallError> {
        self.schemes
            .remove(name)
            .map(|_| ())
            .ok_or(SyscallError::BadHandle)
    }
}

/// Register a scheme globally
pub fn register_scheme(name: &str, scheme: DynScheme) -> Result<u64, SyscallError> {
    SCHEME_ROUTER.lock().register(name, scheme)
}

/// Get a scheme by name
pub fn get_scheme(name: &str) -> Option<DynScheme> {
    SCHEME_ROUTER.lock().get(name)
}

/// Mount a registered scheme at a path
pub fn mount_scheme(name: &str, path: &str) -> Result<(), SyscallError> {
    let scheme = get_scheme(name).ok_or(SyscallError::BadHandle)?;
    crate::vfs::mount::mount(path, scheme)
}

/// Initialize built-in schemes
pub fn init_builtin_schemes() -> Result<(), SyscallError> {
    // Create kernel scheme for /initfs
    let kernel_scheme = Arc::new(KernelScheme::new());
    register_scheme("kernel", kernel_scheme.clone())?;
    mount_scheme("kernel", "/initfs")?;
    *INITFS_KERNEL_SCHEME.lock() = Some(kernel_scheme);

    log::info!("[SchemeRouter] Built-in schemes initialized");
    Ok(())
}

/// Register a static file in the kernel-backed /initfs scheme.
pub fn register_initfs_file(path: &str, base: *const u8, len: usize) -> Result<(), SyscallError> {
    let scheme = INITFS_KERNEL_SCHEME
        .lock()
        .clone()
        .ok_or(SyscallError::BadHandle)?;
    scheme.register(path, base, len);
    Ok(())
}

/// Create and register an IPC scheme for a userspace server
pub fn register_ipc_scheme(name: &str, port_id: PortId) -> Result<u64, SyscallError> {
    let ipc_scheme = Arc::new(IpcScheme::new(port_id));
    register_scheme(name, ipc_scheme)
}

/// List all registered schemes (for debugging)
pub fn list_schemes() -> Vec<String> {
    SCHEME_ROUTER.lock().list()
}
