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

//! One-time initialization: atomic state + spin (acceptable for v1).
//!
//! Futex-backed handoff is listed as a future improvement; the spin window
//! only covers the duration of the initializer itself.

use core::sync::atomic::{AtomicU8, Ordering};

const NEW: u8 = 0;
const RUNNING: u8 = 1;
const DONE: u8 = 2;

/// Executes a closure at most once, even under concurrency.
pub struct Once {
    state: AtomicU8,
}

impl Once {
    /// Creates an uninitialized cell.
    pub const fn new() -> Self {
        Once {
            state: AtomicU8::new(NEW),
        }
    }

    /// Run `f` exactly once; all other callers observe completion before
    /// returning (spinning while the winner executes).
    pub fn call<F: FnOnce()>(&self, f: F) {
        match self
            .state
            .compare_exchange(NEW, RUNNING, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {
                f();
                self.state.store(DONE, Ordering::Release);
            }
            Err(DONE) => return,
            Err(RUNNING) | Err(_) => {
                // Someone else is initializing: wait for DONE.
                while self.state.load(Ordering::Acquire) != DONE {
                    core::hint::spin_loop();
                }
            }
        }
    }

    /// Whether the initialization already completed.
    pub fn is_completed(&self) -> bool {
        self.state.load(Ordering::Acquire) == DONE
    }
}

impl Default for Once {
    fn default() -> Self {
        Self::new()
    }
}
