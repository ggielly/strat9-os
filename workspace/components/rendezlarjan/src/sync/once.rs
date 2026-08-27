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
