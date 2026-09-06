//! Mirror of kernel/src/syscall — real error mapping + time shim.
//!
//! The real error.rs needs three error enums from hardware-bound modules;
//! they are provided as minimal shims below with identical variants so the
//! `From` impls in the included file compile unchanged.

#[path = "../../../kernel/src/syscall/error.rs"]
pub mod error;

/// Mirror of kernel/src/syscall/time.rs surface used by pure modules.
pub mod time {
    /// Host-real clock (kernel derives it from scheduler ticks).
    pub fn current_time_ns() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}
