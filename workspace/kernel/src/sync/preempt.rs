//! Preemption guard — disables preemption for the lifetime of the guard.
//!
//! ## When to use
//!
//! Use `PreemptGuard` to protect **per-CPU data structures** that are only
//! accessed from the CPU that owns them. Because no other CPU can touch
//! them, a spin-lock is unnecessary — disabling preemption (so the current
//! CPU cannot switch tasks mid-operation) is sufficient.
//!
//! ```rust,ignore
//! let _guard = PreemptGuard::new();
//! // safe to read/write per-CPU data here
//! // guard is dropped at end of scope → preemption re-enabled
//! ```
//!
//! ## What it does NOT protect
//!
//! `PreemptGuard` does **not** protect against concurrent access from other
//! CPUs. For shared data, use [`crate::sync::SpinLock`] instead.
//!
//! ## Nesting
//!
//! Guards can be nested: each `PreemptGuard::new()` increments the per-CPU
//! preemption depth and each `drop` decrements it. Preemption is re-enabled
//! only when the depth reaches 0.

use crate::arch::x86_64::percpu;

/// RAII guard that disables preemption on the current CPU.
///
/// Preemption is restored when this value is dropped.
#[must_use = "dropping a PreemptGuard immediately re-enables preemption"]
pub struct PreemptGuard {
    /// Marker to prevent Send — the guard must be dropped on the same CPU
    /// it was created on.
    _not_send: core::marker::PhantomData<*mut ()>,
}

impl PreemptGuard {
    /// Disable preemption and return the guard.
    #[inline]
    pub fn new() -> Self {
        percpu::preempt_disable();
        PreemptGuard {
            _not_send: core::marker::PhantomData,
        }
    }
}

impl Drop for PreemptGuard {
    #[inline]
    fn drop(&mut self) {
        percpu::preempt_enable();
    }
}
