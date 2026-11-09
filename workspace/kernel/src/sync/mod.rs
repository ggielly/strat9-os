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

// Synchronization primitives module

mod fixed_queue;
pub mod guardian;
mod irq;
pub mod preempt;
mod spinlock;
pub mod waitqueue;

pub use fixed_queue::FixedQueue;
pub use guardian::{Guardian, IrqDisabled, PreemptDisabled};
pub use irq::{with_irqs_disabled, IrqDisabledToken};
pub use preempt::PreemptGuard;
pub use spinlock::{
    debug_clear_watch_lock_addr, debug_set_trace_buddy_addr, debug_set_trace_lock_addr,
    debug_set_trace_slab_addr, debug_set_watch_lock_addr, SpinLock, SpinLockGuard,
};
pub use waitqueue::{WaitCondition, WaitQueue};
