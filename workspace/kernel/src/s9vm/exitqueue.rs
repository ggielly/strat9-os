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

//! s9vm — bounded exit event queue.
//!
//! Each world has an event queue (fixed size) that the execution layer
//! fills and that the policy consumes via
//! `SYS_VMM_EXIT_HANDLER`. The queue is **bounded**: a producer cannot
//! grow kernel memory, and a slow consumer causes an
//! explicit refusal (`Full`) rather than silent loss.
//!
//! Pure module (host-testable): it depends only on the ABI.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use strat9_abi::vmm::VmmExitEvent;

/// Default capacity of an exit queue.
pub const DEFAULT_CAPACITY: usize = 64;

/// Queue errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    /// Queue full.
    Full,
    /// Queue empty.
    Empty,
}

/// Bounded queue of exit events.
#[derive(Debug)]
pub struct ExitQueue {
    entries: VecDeque<VmmExitEvent>,
    capacity: usize,
    dropped: u64,
}

impl ExitQueue {
    /// Creates a queue with the given capacity (at least 1).
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity),
            capacity: capacity.max(1),
            dropped: 0,
        }
    }

    /// Capacity.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of pending events.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of events refused since creation (diagnostics).
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Adds an event. Returns `Full` if the queue is full; no
    /// data is silently overwritten.
    pub fn push(&mut self, event: VmmExitEvent) -> Result<(), QueueError> {
        if self.entries.len() >= self.capacity {
            self.dropped = self.dropped.saturating_add(1);
            return Err(QueueError::Full);
        }
        self.entries.push_back(event);
        Ok(())
    }

    /// Removes the oldest event.
    pub fn pop(&mut self) -> Result<VmmExitEvent, QueueError> {
        self.entries.pop_front().ok_or(QueueError::Empty)
    }

    /// Empties the queue and returns the removed events.
    pub fn drain(&mut self) -> Vec<VmmExitEvent> {
        self.entries.drain(..).collect()
    }

    /// Empties the queue.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl Default for ExitQueue {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}
