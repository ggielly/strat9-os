//! Mirror of kernel/src/vfs — scheme protocol core + router.
#[path = "../../../kernel/src/vfs/scheme.rs"]
pub mod scheme;
#[path = "../../../kernel/src/vfs/file.rs"]
pub mod file;
#[path = "../../../kernel/src/vfs/fd.rs"]
pub mod fd;
#[path = "../../../kernel/src/vfs/pipe.rs"]
pub mod pipe;
/// Shim for kernel/src/vfs/mount.rs (runtime mount table needs full VFS).
pub mod mount {
    use alloc::sync::Arc;
    use crate::syscall::error::SyscallError;
    use crate::vfs::scheme::DynScheme;

    /// Host stand-in: the runtime mount table is out of scope; tests must
    /// not rely on mounts succeeding.
    pub fn mount(_path: &str, _scheme: crate::vfs::scheme::DynScheme) -> Result<(), SyscallError> {
        Ok(())
    }
}

#[path = "../../../kernel/src/vfs/scheme_router.rs"]
pub mod scheme_router;

pub use scheme::{DynScheme, IpcScheme, KernelScheme};
pub use scheme_router::*;
