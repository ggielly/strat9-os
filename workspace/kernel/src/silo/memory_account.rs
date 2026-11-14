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

//! Allocation-free quota accounting, independent of the silo registry lock.

use crate::{sync::SpinLock, syscall::error::SyscallError};

pub(crate) struct SiloMemoryAccount {
    budget: SpinLock<MemoryBudget>,
    /// IPC v2 object and in-flight counters of the same silo (§12).
    ipc: SiloIpcAccount,
}

/// IPC v2 resource limits per silo (spec §12).
pub(crate) mod ipc_limits {
    /// Live endpoints created by the silo.
    pub const ENDPOINTS: u64 = 256;
    /// Live notifications created by the silo.
    pub const NOTIFICATIONS: u64 = 256;
    /// Bytes (header + data) of messages queued by the silo's senders.
    pub const QUEUED_BYTES: u64 = 1024 * 1024;
    /// Handles carried by messages queued by the silo's senders.
    pub const INFLIGHT_HANDLES: u64 = 1024;
}

/// One IPC v2 resource counted by [`SiloIpcAccount`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IpcResource {
    Endpoints,
    Notifications,
    QueuedBytes,
    InflightHandles,
}

/// Lock-free IPC v2 counters of one silo (spec §12).
///
/// Charged by the IPC layer through RAII guards (`ipc::v2::quota::IpcCharge`)
/// and released in their `Drop`, so dequeue, endpoint close and process death
/// all release uniformly. `waitq` wakes senders blocked on the queued-bytes /
/// in-flight-handle limits.
pub(crate) struct SiloIpcAccount {
    counters: [core::sync::atomic::AtomicU64; 4],
    pub(crate) waitq: crate::sync::WaitQueue,
}

impl SiloIpcAccount {
    const fn new() -> Self {
        use core::sync::atomic::AtomicU64;
        Self {
            counters: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            waitq: crate::sync::WaitQueue::new(),
        }
    }

    fn slot(res: IpcResource) -> (usize, u64) {
        match res {
            IpcResource::Endpoints => (0, ipc_limits::ENDPOINTS),
            IpcResource::Notifications => (1, ipc_limits::NOTIFICATIONS),
            IpcResource::QueuedBytes => (2, ipc_limits::QUEUED_BYTES),
            IpcResource::InflightHandles => (3, ipc_limits::INFLIGHT_HANDLES),
        }
    }

    /// Charge `amount`; `false` (nothing charged) when it would exceed the limit.
    pub(crate) fn try_charge(&self, res: IpcResource, amount: u64) -> bool {
        use core::sync::atomic::Ordering;
        if amount == 0 {
            return true;
        }
        let (index, limit) = Self::slot(res);
        self.counters[index]
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(amount).filter(|next| *next <= limit)
            })
            .is_ok()
    }

    /// Release `amount` previously charged and wake blocked senders.
    pub(crate) fn release(&self, res: IpcResource, amount: u64) {
        if amount == 0 {
            return;
        }
        self.release_quiet(res, amount);
        if matches!(res, IpcResource::QueuedBytes | IpcResource::InflightHandles) {
            self.waitq.wake_all();
        }
    }

    /// Release without waking `waitq`: for rollbacks evaluated under the
    /// wait-queue lock itself.
    pub(crate) fn release_quiet(&self, res: IpcResource, amount: u64) {
        use core::sync::atomic::Ordering;
        if amount == 0 {
            return;
        }
        let (index, _) = Self::slot(res);
        let _ = self.counters[index].try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
            debug_assert!(used >= amount, "IPC quota released more than charged");
            Some(used.saturating_sub(amount))
        });
    }

    /// Current usage of `res`.
    pub(crate) fn used(&self, res: IpcResource) -> u64 {
        let (index, _) = Self::slot(res);
        self.counters[index].load(core::sync::atomic::Ordering::Acquire)
    }
}

impl core::fmt::Debug for SiloMemoryAccount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let budget = self.budget.lock();
        f.debug_struct("SiloMemoryAccount")
            .field("used", &budget.used)
            .field("max", &budget.max)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_reservation_does_not_change_usage() {
        let account = SiloMemoryAccount::new(8192);
        account.charge(4096).unwrap();
        assert!(matches!(
            account.charge(4097),
            Err(SyscallError::OutOfMemory)
        ));
        assert_eq!(account.used(), 4096);
        account.release(4096);
        account.charge(8192).unwrap();
        assert_eq!(account.used(), 8192);
    }

    #[test]
    fn limit_update_cannot_undercut_live_reservations() {
        let account = SiloMemoryAccount::new(0);
        account.charge(8192).unwrap();
        assert!(account.set_max(4096).is_err());
        assert_eq!(account.used(), 8192);
        account.release(4096);
        account.set_max(4096).unwrap();
        assert!(account.charge(1).is_err());
    }

    #[test]
    fn unlimited_budget_still_checks_overflow() {
        let account = SiloMemoryAccount::new(0);
        account.charge(u64::MAX).unwrap();
        assert!(account.charge(1).is_err());
        assert_eq!(account.used(), u64::MAX);
    }
}

#[derive(Debug)]
struct MemoryBudget {
    used: u64,
    max: u64,
}

impl SiloMemoryAccount {
    pub(crate) fn new(max: u64) -> Self {
        Self {
            budget: SpinLock::new(MemoryBudget { used: 0, max }),
            ipc: SiloIpcAccount::new(),
        }
    }

    /// IPC v2 counters of this silo.
    pub(crate) fn ipc(&self) -> &SiloIpcAccount {
        &self.ipc
    }

    pub(crate) fn charge(&self, bytes: u64) -> Result<(), SyscallError> {
        let mut budget = self.budget.lock();
        let next = budget
            .used
            .checked_add(bytes)
            .ok_or(SyscallError::OutOfMemory)?;
        if budget.max != 0 && next > budget.max {
            return Err(SyscallError::OutOfMemory);
        }
        budget.used = next;
        Ok(())
    }

    pub(crate) fn release(&self, bytes: u64) {
        let mut budget = self.budget.lock();
        // Release-in-race stays non-panicking, but a double free must be caught
        // in debug builds instead of silently underflowing usage.
        debug_assert!(budget.used >= bytes, "silo memory double release");
        budget.used = budget.used.saturating_sub(bytes);
    }

    pub(crate) fn used(&self) -> u64 {
        self.budget.lock().used
    }

    pub(crate) fn set_max(&self, max: u64) -> Result<(), SyscallError> {
        let mut budget = self.budget.lock();
        if max != 0 && budget.used > max {
            return Err(SyscallError::InvalidArgument);
        }
        budget.max = max;
        Ok(())
    }
}
