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

//! Preemption guard : disables preemption for the lifetime of the guard.
//!
//! ## When to use
//!
//! Use `PreemptGuard` to protect **per-CPU data structures** that are only
//! accessed from the CPU that owns them. Because no other CPU can touch
//! them, a spin-lock is unnecessary : disabling preemption (so the current
//! CPU cannot switch tasks mid-operation) is sufficient.
//!
//! ```rust,ignore
//! let _guard = PreemptGuard::new();
//! // safe to read/write per-CPU data here
//! // guard is dropped at end of scope => preemption re-enabled
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
//! only when the depth reaches 0; at that point a reschedule requested during
//! the critical section is serviced immediately (deferred-preemption call in
//! `percpu::preempt_enable`).

use crate::arch::percpu;

/// RAII guard that disables preemption on the current CPU.
///
/// Preemption is restored when this value is dropped.
#[must_use = "dropping a PreemptGuard immediately re-enables preemption"]
pub struct PreemptGuard {
    /// Marker to prevent Send : the guard must be dropped on the same CPU
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
    /// Performs the drop operation.
    #[inline]
    fn drop(&mut self) {
        percpu::preempt_enable();
    }
}
