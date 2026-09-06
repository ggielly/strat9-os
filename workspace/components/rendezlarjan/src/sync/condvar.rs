//! Futex-based condition variable: sequence counter + recheck loop.
//!
//! No lost wakeups: the caller loads the sequence *while still holding the
//! mutex*; any `notify_*` after that point bumps the counter, so the futex
//! wait immediately returns and the recheck loop observes the predicate.

use super::{futex_wait, futex_wake_all, futex_wake};
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
