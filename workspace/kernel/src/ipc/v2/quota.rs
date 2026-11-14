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

//! Silo IPC quotas (IPC ABI v2, §12).
//!
//! Every charge is an RAII guard stored in the object it pays for (endpoint,
//! notification, queued message, memory object). The guard releases in its
//! `Drop`, so dequeue, close, cancellation and process death all release the
//! same way, and a handle closed by another silo never touches the closer's
//! account.
//!
//! The account is reached through the caller's address space
//! (`AddressSpace::silo_memory_account`), not through the silo registry lock,
//! so a contended registry can never skip a charge. Tasks outside any silo
//! (kernel, early boot) are not charged.

use crate::{
    process::process::Process,
    silo::{IpcResource, SiloMemoryAccount},
    syscall::error::SyscallError,
};
use alloc::sync::Arc;

/// Silo account of `process`, if it belongs to a silo.
pub(crate) fn account_of(process: &Process) -> Option<Arc<SiloMemoryAccount>> {
    process.address_space_arc().silo_memory_account()
}

/// An IPC counter charge, released on drop.
pub struct IpcCharge {
    account: Arc<SiloMemoryAccount>,
    res: IpcResource,
    amount: u64,
}

impl IpcCharge {
    /// Try to charge `amount` of `res`; `None` when over the limit.
    pub(crate) fn try_new(
        account: &Arc<SiloMemoryAccount>,
        res: IpcResource,
        amount: u64,
    ) -> Option<Self> {
        account.ipc().try_charge(res, amount).then(|| IpcCharge {
            account: account.clone(),
            res,
            amount,
        })
    }
}

impl Drop for IpcCharge {
    fn drop(&mut self) {
        self.account.ipc().release(self.res, self.amount);
    }
}

/// A silo memory charge (MemObject backing), released on drop.
pub struct MemCharge {
    account: Arc<SiloMemoryAccount>,
    bytes: u64,
}

impl Drop for MemCharge {
    fn drop(&mut self) {
        self.account.release(self.bytes);
    }
}

/// Charge one object of `res` (endpoint, notification) for `process`.
///
/// Returns `Ok(None)` for unaccounted tasks, `ENOMEM` over the limit.
pub(crate) fn charge_object(
    process: &Process,
    res: IpcResource,
) -> Result<Option<IpcCharge>, SyscallError> {
    match account_of(process) {
        None => Ok(None),
        Some(account) => IpcCharge::try_new(&account, res, 1)
            .map(Some)
            .ok_or(SyscallError::OutOfMemory),
    }
}

/// Charge `bytes` of MemObject backing to `process`'s silo memory budget.
pub(crate) fn charge_memory(
    process: &Process,
    bytes: u64,
) -> Result<Option<MemCharge>, SyscallError> {
    match account_of(process) {
        None => Ok(None),
        Some(account) => {
            account
                .charge(bytes)
                .map_err(|_| SyscallError::OutOfMemory)?;
            Ok(Some(MemCharge { account, bytes }))
        }
    }
}

/// Charges carried by one queued message.
#[derive(Default)]
pub struct InFlightCharge {
    _bytes: Option<IpcCharge>,
    _handles: Option<IpcCharge>,
}

/// Charge a message about to be queued: `bytes` (header + data) and
/// `handles` transferred capabilities, against the **sender's** silo.
///
/// Over the limit, a non-blocking sender gets `EAGAIN`; a blocking one waits
/// (bounded by `deadline_ns`, then `ETIMEDOUT`) until messages of the same
/// silo are dequeued. A pending signal interrupts the wait (`EINTR`).
pub(crate) fn charge_message(
    process: &Process,
    bytes: u64,
    handles: u64,
    nonblock: bool,
    deadline_ns: Option<u64>,
) -> Result<InFlightCharge, SyscallError> {
    let Some(account) = account_of(process) else {
        return Ok(InFlightCharge::default());
    };
    // Runs under the account wait-queue lock when blocking: it must not wake
    // that queue, so a partial charge is rolled back with `release_quiet`.
    let try_both = || -> Option<InFlightCharge> {
        let ipc = account.ipc();
        if !ipc.try_charge(IpcResource::QueuedBytes, bytes) {
            return None;
        }
        if !ipc.try_charge(IpcResource::InflightHandles, handles) {
            ipc.release_quiet(IpcResource::QueuedBytes, bytes);
            return None;
        }
        Some(InFlightCharge {
            _bytes: Some(IpcCharge {
                account: account.clone(),
                res: IpcResource::QueuedBytes,
                amount: bytes,
            }),
            _handles: Some(IpcCharge {
                account: account.clone(),
                res: IpcResource::InflightHandles,
                amount: handles,
            }),
        })
    };
    if let Some(charge) = try_both() {
        return Ok(charge);
    }
    if nonblock {
        return Err(SyscallError::Again);
    }
    account
        .ipc()
        .waitq
        .wait_until_deadline(deadline_ns, || {
            if let Some(charge) = try_both() {
                return Some(Ok(charge));
            }
            if crate::process::signal::has_pending_signals() {
                return Some(Err(SyscallError::Interrupted));
            }
            None
        })
        .unwrap_or(Err(SyscallError::TimedOut))
}
