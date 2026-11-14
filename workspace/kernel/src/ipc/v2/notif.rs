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

//! Notification objects (IPC ABI v2, §7).

use super::endpoint::Endpoint;
use crate::{
    sync::{SpinLock, WaitQueue},
    syscall::error::SyscallError,
};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_NOTIF_ID: AtomicU64 = AtomicU64::new(1);

/// A 64-bit OR-coalescing signal word with an optional endpoint binding.
pub struct Notification {
    id: u64,
    word: AtomicU64,
    waitq: WaitQueue,
    bound: SpinLock<Option<Arc<Endpoint>>>,
}

impl Notification {
    /// Create a notification.
    pub fn create() -> Arc<Notification> {
        Arc::new(Notification {
            id: NEXT_NOTIF_ID.fetch_add(1, Ordering::Relaxed),
            word: AtomicU64::new(0),
            waitq: WaitQueue::new(),
            bound: SpinLock::new(None),
        })
    }

    /// Internal object id.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Signal `bits`: OR into the word and raise the bound endpoint's pending
    /// bits. `bits` is already masked by the caller (handle badge).
    pub fn signal(&self, bits: u64) -> Result<(), SyscallError> {
        self.word.fetch_or(bits, Ordering::Release);
        let bound = self.bound.lock().clone();
        if let Some(ep) = bound {
            let mut state = ep.state.lock();
            if state.alive
                && state
                    .bound_notif
                    .as_ref()
                    .map(|n| n.id() == self.id)
                    .unwrap_or(false)
            {
                state.pending_bits |= bits;
                drop(state);
                ep.recv_waitq.wake_one();
            }
        }
        self.waitq.wake_one();
        Ok(())
    }

    /// Wait for non-zero bits, atomically read and clear them.
    ///
    /// `deadline_ns` (absolute, [`crate::sync::scheduler_clock_ns`]) bounds the
    /// whole wait, including retries after another waiter took the bits.
    pub fn wait(&self, nonblock: bool, deadline_ns: Option<u64>) -> Result<u64, SyscallError> {
        loop {
            let bits = self.word.swap(0, Ordering::Acquire);
            if bits != 0 {
                return Ok(bits);
            }
            if nonblock {
                return Err(SyscallError::Again);
            }
            let outcome = self.waitq.wait_until_deadline(deadline_ns, || {
                if self.word.load(Ordering::Acquire) != 0 {
                    Some(Ok(()))
                } else if crate::process::signal::has_pending_signals() {
                    // A signal interrupts the blocking wait (§5.2).
                    Some(Err(SyscallError::Interrupted))
                } else {
                    None
                }
            });
            outcome.unwrap_or(Err(SyscallError::TimedOut))?;
        }
    }

    /// Install the endpoint Arc on the notification side.
    pub fn bind_arc(&self, ep: Arc<Endpoint>) {
        *self.bound.lock() = Some(ep);
    }

    /// Clear the binding if it still points at `endpoint_id`.
    pub fn unbind_if(&self, endpoint_id: u64) {
        let mut bound = self.bound.lock();
        if let Some(ep) = bound.as_ref() {
            if ep.id() == endpoint_id {
                *bound = None;
            }
        }
    }
}
