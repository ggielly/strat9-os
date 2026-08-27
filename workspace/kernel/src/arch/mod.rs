// The x86_64 backend must only be compiled when targeting x86_64: the
// `x86_64` crate and its inline asm do not exist on other architectures.
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "riscv64")]
pub mod riscv64;

#[cfg(target_arch = "x86_64")]
pub mod facade;

#[cfg(target_arch = "x86_64")]
pub use facade::*;

#[cfg(target_arch = "riscv64")]
pub mod facade_riscv;

#[cfg(target_arch = "riscv64")]
pub use crate::arch::facade_riscv::*;

/// riscv64 stub of the `x86_64` crate surface (runtime-panicking).
/// Aliased as `crate::arch::x86_64` so call-sites not yet migrated keep
/// resolving; every item traps at runtime until its jalon lands.
#[cfg(target_arch = "riscv64")]
pub mod x86_64_stub {
    include!("xshim_riscv_stub.rs");
}

#[cfg(target_arch = "riscv64")]
pub use x86_64_stub as x86_64;

/// Neutral shim mirroring the used subset of the `x86_64` crate
/// (address types, page sizes, paging flags). Available on all arches:
/// on x86_64 it re-exports the real crate types, elsewhere it provides
/// neutral equivalents.
pub mod xshim;
