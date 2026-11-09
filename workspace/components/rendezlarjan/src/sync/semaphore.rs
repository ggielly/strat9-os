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

//! Counting semaphore: atomic fast path, futex_wait when exhausted.
//!
//! `wait()` parks only when no permit is available (`count <= 0`); the futex
//! value-change protocol makes lost wakeups impossible (a concurrent `post()`
//! between the load and the park fails the futex compare immediately).

use super::{futex_wait, futex_wake};
use core::sync::atomic::{AtomicU32, Ordering};

/// Counting semaphore.
pub struct Semaphore {
    count: AtomicU32,
}

impl Semaphore {
    /// Creates a semaphore with `initial` permits.
    pub const fn new(initial: i32) -> Self {
        debug_assert!(initial >= 0);
        Semaphore {
            count: AtomicU32::new(if initial > 0 { initial as u32 } else { 0 }),
        }
    }

    /// Acquire one permit, blocking when none are available.
    pub fn wait(&self) {
        loop {
            let cur = self.count.load(Ordering::Acquire);
            if cur > 0
                && self
                    .count
                    .compare_exchange(cur, cur - 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                return;
            }
            // No permit: park. Returns immediately if the count changed.
            futex_wait(&self.count, cur);
        }
    }

    /// Try to acquire without blocking.
    pub fn try_wait(&self) -> bool {
        let mut cur = self.count.load(Ordering::Relaxed);
        loop {
            if cur <= 0 {
                return false;
            }
            match self
                .count
                .compare_exchange(cur, cur - 1, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Release one permit and wake one waiter if any were parked.
    pub fn post(&self) {
        self.count.fetch_add(1, Ordering::Release);
        futex_wake(&self.count, 1);
    }

    /// Current permit count (approximate under concurrency).
    pub fn permits(&self) -> u32 {
        self.count.load(Ordering::Acquire)
    }
}
