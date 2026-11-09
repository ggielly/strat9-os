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

//! Futex-based condition variable: sequence counter + recheck loop.
//!
//! No lost wakeups: the caller loads the sequence *while still holding the
//! mutex*; any `notify_*` after that point bumps the counter, so the futex
//! wait immediately returns and the recheck loop observes the predicate.

use super::{futex_wait, futex_wake, futex_wake_all};
use core::sync::atomic::{AtomicU32, Ordering};

/// Condition variable paired with a [`Mutex`](super::Mutex).
pub struct Condvar {
    seq: AtomicU32,
}

impl Condvar {
    /// Creates a new condition variable.
    pub const fn new() -> Self {
        Condvar {
            seq: AtomicU32::new(0),
        }
    }

    /// Atomically release `mutex` and sleep until notified.
    ///
    /// Standard usage (Hart recheck loop):
    ///
    /// ```ignore
    /// while !predicate() { cv.wait(&mutex); }
    /// ```
    pub fn wait(&self, mutex: &super::Mutex) {
        let cur = self.seq.load(Ordering::Acquire);
        mutex.unlock();
        futex_wait(&self.seq, cur);
        mutex.lock();
    }

    /// Wake one waiting thread.
    pub fn notify_one(&self) {
        self.seq.fetch_add(1, Ordering::Release);
        futex_wake(&self.seq, 1);
    }

    /// Wake all waiting threads.
    pub fn notify_all(&self) {
        self.seq.fetch_add(1, Ordering::Release);
        futex_wake_all(&self.seq);
    }
}

impl Default for Condvar {
    fn default() -> Self {
        Self::new()
    }
}
