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

//! Futex-based mutex: 0 = free, 1 = locked, 2 = locked + waiters.

use super::{futex_wait, futex_wake};
use core::sync::atomic::{AtomicU32, Ordering};

const FREE: u32 = 0;
const LOCKED: u32 = 1;
const CONTENDED: u32 = 2;

/// Fast userspace mutex.
///
/// Uncontended lock/unlock is a single CAS / swap with no syscall. On
/// contention the state moves to `CONTENDED` and losers sleep on the futex.
pub struct Mutex {
    state: AtomicU32,
}

impl Mutex {
    /// Creates an unlocked mutex.
    pub const fn new() -> Self {
        Mutex {
            state: AtomicU32::new(FREE),
        }
    }

    /// Acquire the mutex, blocking when contended.
    pub fn lock(&self) {
        // Fast path: FREE -> LOCKED.
        if self
            .state
            .compare_exchange(FREE, LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
        // Slow path: mark contended and sleep until we own it.
        let mut state = self.state.load(Ordering::Relaxed);
        loop {
            match state {
                FREE => {
                    if self
                        .state
                        .compare_exchange(FREE, CONTENDED, Ordering::Acquire, Ordering::Relaxed)
                        .is_ok()
                    {
                        return;
                    }
                    state = self.state.load(Ordering::Relaxed);
                }
                _ => {
                    if state != CONTENDED
                        && self
                            .state
                            .compare_exchange(
                                state,
                                CONTENDED,
                                Ordering::Release,
                                Ordering::Relaxed,
                            )
                            .is_err()
                    {
                        state = self.state.load(Ordering::Relaxed);
                        continue;
                    }
                    futex_wait(&self.state, CONTENDED);
                    state = self.state.load(Ordering::Relaxed);
                }
            }
        }
    }

    /// Try to acquire without blocking. Returns `false` when already locked.
    pub fn try_lock(&self) -> bool {
        self.state
            .compare_exchange(FREE, LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Release the mutex and wake one waiter if any exist.
    pub fn unlock(&self) {
        let prev = self.state.swap(FREE, Ordering::Release);
        if prev == CONTENDED {
            futex_wake(&self.state, 1);
        }
    }
}

impl Default for Mutex {
    fn default() -> Self {
        Self::new()
    }
}
