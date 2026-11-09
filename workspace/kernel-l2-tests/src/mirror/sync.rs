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

//! Mirror of kernel/src/sync: real primitives + fake irq submodule.
//!
//! File-backed so that `use super::{...}` inside the included sources
//! resolves against this module exactly like in the kernel tree.

// Fake IRQ layer replaces kernel/src/sync/irq.rs (x86 cli/sti).
#[path = "../fake_irq.rs"]
#[path = "../fake_irq.rs"]
pub mod irq;

#[path = "../../../kernel/src/sync/fixed_queue.rs"]
pub mod fixed_queue;
#[path = "../../../kernel/src/sync/guardian.rs"]
pub mod guardian;
#[path = "../../../kernel/src/sync/preempt.rs"]
pub mod preempt;
#[path = "../../../kernel/src/sync/spinlock.rs"]
pub mod spinlock;
#[path = "../../../kernel/src/sync/waitqueue.rs"]
pub mod waitqueue;

pub use fixed_queue::FixedQueue;
pub use guardian::{Guardian, IrqDisabled, PreemptDisabled};
pub use irq::{with_irqs_disabled, IrqDisabledToken};
pub use irq::irq_probe_token;
pub use preempt::PreemptGuard;
pub use waitqueue::{WaitCondition, WaitQueue};
pub use spinlock::{
    debug_clear_watch_lock_addr, debug_set_trace_buddy_addr, debug_set_trace_lock_addr,
    debug_set_trace_slab_addr, debug_set_watch_lock_addr,
};
pub use spinlock::{SpinLock, SpinLockGuard};
