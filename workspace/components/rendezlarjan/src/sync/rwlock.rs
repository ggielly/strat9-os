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

//! Futex-based reader/writer lock.
//!
//! State encoding: bits 0..30 = active readers, bit 31 = writer flag.

use super::{futex_wait, futex_wake_all};
use core::sync::atomic::{AtomicU32, Ordering};

const WRITER: u32 = 1 << 31;
const READER_MASK: u32 = WRITER - 1;
/// Refuse the 2^31st concurrent reader (wraps into WRITER bit).
const READER_SATURATION: u32 = READER_MASK;

/// Reader/writer lock with atomic fast paths.
pub struct RwLock {
    state: AtomicU32,
}

impl RwLock {
    /// Creates an unlocked rwlock.
    pub const fn new() -> Self {
        RwLock {
            state: AtomicU32::new(0),
        }
    }

    /// Acquire the read lock. Blocks only while a writer holds or wants the lock.
    pub fn read(&self) {
        loop {
            let state = self.state.load(Ordering::Acquire);
            if state & WRITER == 0 && state != READER_SATURATION {
                if self
                    .state
                    .compare_exchange(state, state + 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return;
                }
                continue;
            }
            futex_wait(&self.state, state);
        }
    }

    /// Try to acquire the read lock without blocking.
    pub fn try_read(&self) -> bool {
        let state = self.state.load(Ordering::Acquire);
        state & WRITER == 0
            && state != READER_SATURATION
            && self
                .state
                .compare_exchange(state, state + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
    }

    /// Release one read hold; wakes waiters when the last reader leaves.
    pub fn read_unlock(&self) {
        let prev = self.state.fetch_sub(1, Ordering::Release);
        debug_assert_ne!(prev & READER_MASK, 0, "read_unlock without read hold");
        // Last reader out: writers may be waiting on any nonzero value.
        if prev & READER_MASK == 1 {
            futex_wake_all(&self.state);
        }
    }

    /// Acquire the write lock (exclusive).
    pub fn write(&self) {
        loop {
            let state = self.state.load(Ordering::Acquire);
            if state == 0 {
                if self
                    .state
                    .compare_exchange(0, WRITER, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return;
                }
                continue;
            }
            futex_wait(&self.state, state);
        }
    }

    /// Try to acquire the write lock without blocking.
    pub fn try_write(&self) -> bool {
        self.state
            .compare_exchange(0, WRITER, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Release the write lock and wake all waiters.
    pub fn write_unlock(&self) {
        debug_assert_eq!(
            self.state.load(Ordering::Relaxed),
            WRITER,
            "write_unlock without write hold"
        );
        self.state.store(0, Ordering::Release);
        futex_wake_all(&self.state);
    }
}

impl Default for RwLock {
    fn default() -> Self {
        Self::new()
    }
}
