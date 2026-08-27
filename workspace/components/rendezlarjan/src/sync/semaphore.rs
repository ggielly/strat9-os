//! Counting semaphore: atomic fast path, futex_wait when exhausted.
//!
//! `wait()` parks only when no permit is available (`count <= 0`); the futex
//! value-change protocol makes lost wakeups impossible (a concurrent `post()`
//! between the load and the park fails the futex compare immediately).

use super::{futex_wake, futex_wait};
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
