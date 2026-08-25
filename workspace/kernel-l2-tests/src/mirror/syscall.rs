//! Mirror of kernel/src/syscall — only what pure modules reference.
//!
//! The kernel's own `SyscallError` mirrors the component-side enum; on the
//! host we reuse the `strat9-syscall` crate's identical `Error` type so
//! namespace tests exercise real semantics without pulling the dispatcher.
pub mod error {
    pub use strat9_syscall::error::Error as SyscallError;
}
