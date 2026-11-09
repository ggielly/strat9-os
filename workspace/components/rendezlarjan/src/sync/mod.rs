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

//! Userspace synchronization primitives built on Strat9 futexes.
//!
//! The uncontended fast path is pure atomics (zero syscalls); contention
//! falls back to `SYS_FUTEX_WAIT`/`SYS_FUTEX_WAKE` through the kernel's
//! 256-bucket futex table with robust-list cleanup on thread death.

mod barrier;
mod condvar;
mod mutex;
mod once;
mod rwlock;
mod semaphore;

pub use barrier::Barrier;
pub use condvar::Condvar;
pub use mutex::Mutex;
pub use once::Once;
pub use rwlock::RwLock;
pub use semaphore::Semaphore;

use strat9_syscall::call;

const FUTEX_WAIT: usize = 0;
const FUTEX_WAKE: usize = 1;

/// Block the calling thread until the 32-bit value at `uaddr` differs from
/// `expected` (or spuriously). Treats `EAGAIN` (value changed) and `EINTR`
/// as "recheck and continue".
#[inline]
pub(crate) fn futex_wait(addr: &core::sync::atomic::AtomicU32, expected: u32) {
    // SAFETY: the atomic lives in our address space and outlives the wait;
    // the pointer is only used for its address by the kernel.
    unsafe {
        let _ = call::futex(
            core::ptr::addr_of!(*addr) as *mut i32,
            FUTEX_WAIT,
            expected as i32,
            0,
            core::ptr::null_mut(),
        );
    }
}

/// Wake up to `nwait` threads blocked on `addr`.
#[inline]
pub(crate) fn futex_wake(addr: &core::sync::atomic::AtomicU32, nwait: i32) {
    // SAFETY: see futex_wait.
    unsafe {
        let _ = call::futex(
            core::ptr::addr_of!(*addr) as *mut i32,
            FUTEX_WAKE,
            nwait,
            0,
            core::ptr::null_mut(),
        );
    }
}

/// Wake every waiter on `addr`.
#[inline]
pub(crate) fn futex_wake_all(addr: &core::sync::atomic::AtomicU32) {
    futex_wake(addr, i32::MAX);
}
