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

//! Asynchronous I/O syscall handlers.
//!
//! Dispatches SQEs to VFS backends via `AsyncScheme`,
//! drains completions, and blocks when `min_complete > 0`.

use alloc::sync::Arc;
use strat9_abi::data::AsyncRingLayout;

use crate::{memory::UserSliceWrite, syscall::error::SyscallError};

use super::{complete, dispatch, ring::RingError};

#[derive(Debug, Clone, Copy)]
pub struct AsyncRingMapping {
    pub sq_base: u64,
    pub cq_base: u64,
    pub sq_size: u64,
    pub cq_size: u64,
    pub entries: u32,
}

fn require_owned_ring_by_id(ring_id: u64) -> Result<Arc<super::ring::Ring>, SyscallError> {
    let task = crate::process::current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let ring = super::ring::find_ring(ring_id).ok_or(SyscallError::BadHandle)?;

    if ring.owner_pid != task.pid {
        return Err(SyscallError::PermissionDenied);
    }

    Ok(ring)
}

/// SYS_ASYNC_SETUP(entries: u32, flags: u32) => ring_id: u64
pub fn sys_async_setup(entries: u64, _flags: u64) -> Result<u64, SyscallError> {
    let Some(task) = crate::process::current_task_clone() else {
        return Err(SyscallError::PermissionDenied);
    };
    let pid = task.pid;
    let entries = entries as u32;

    super::ring::Ring::create(pid, entries).map_err(|e| match e {
        RingError::Alloc => SyscallError::OutOfMemory,
        RingError::NotFound => SyscallError::BadHandle,
        RingError::TooManyRings => SyscallError::OutOfMemory,
    })
}

/// SYS_ASYNC_MAP(ring_id: u64, out_ptr: *mut AsyncRingLayout) -> total_mapped_bytes: u64
pub fn sys_async_map(ring_id: u64, out_ptr: u64) -> Result<u64, SyscallError> {
    if out_ptr == 0 {
        return Err(SyscallError::Fault);
    }

    let task = crate::process::current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let ring = require_owned_ring_by_id(ring_id)?;

    let mapping = ring
        .map_into_process(&task.process.address_space_arc())
        .map_err(|_| SyscallError::OutOfMemory)?;

    let abi = AsyncRingLayout {
        sq_base: mapping.sq_base,
        cq_base: mapping.cq_base,
        sq_size: mapping.sq_size,
        cq_size: mapping.cq_size,
        entries: mapping.entries,
        _reserved: 0,
    };

    let out = UserSliceWrite::new(out_ptr, core::mem::size_of::<AsyncRingLayout>())?;
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &abi as *const AsyncRingLayout as *const u8,
            core::mem::size_of::<AsyncRingLayout>(),
        )
    };
    out.copy_from(bytes);

    Ok(mapping.sq_size.saturating_add(mapping.cq_size))
}

/// SYS_ASYNC_ENTER(ring_id: u64, to_submit: u32, min_complete: u32, flags: u32) => completed: u64
pub fn sys_async_enter(
    ring_id: u64,
    to_submit: u64,
    min_complete: u64,
    _flags: u64,
) -> Result<u64, SyscallError> {
    let ring = require_owned_ring_by_id(ring_id)?;

    let to_submit = to_submit as u32;
    let min_complete = min_complete as u32;

    // dispatch submitted SQEs to backends
    if to_submit > 0 {
        dispatch::drain_submissions(ring_id, to_submit);
    }

    crate::hardware::storage::ahci::flush_deferred_async_read_completions(ring_id);

    // Drain up to `min_complete` completions.  The caller wants at least
    // that many, so if fewer are available we block below.  Passing  `min_complete` as the "max" argument to `drain_completions` is correct.
    // We never need more than `min_complete` in one round and the blocking path will loop via `wait_until` if needed.
    // Retry parked IPC v2 operations in this (owner) context; any that
    // complete post their CQE before the drain below.
    let task = crate::process::current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    crate::ipc::v2::async_ops::poll(&task.process, ring_id);

    let mut completed = complete::drain_completions(ring_id, min_complete);

    // If caller asked for more completions than available, block and wait.
    // An IPC v2 event (`ipc_kick`) ends the wait without a completion so the
    // parked operations are retried here, outside the wait-queue lock.
    while completed == 0 && min_complete > 0 {
        let woke = ring.wq.wait_until(|| {
            if ring.destroyed.load(core::sync::atomic::Ordering::Acquire) != 0 {
                return Some(Some(0));
            }

            crate::hardware::storage::ahci::flush_deferred_async_read_completions(ring_id);

            let ready = complete::drain_completions(ring_id, min_complete);
            if ready > 0 {
                return Some(Some(ready));
            }
            if ring.ipc_kick.swap(0, core::sync::atomic::Ordering::AcqRel) != 0 {
                return Some(None);
            }
            if crate::process::signal::has_pending_signals() {
                return Some(Some(0));
            }
            None
        });
        match woke {
            Some(n) => {
                completed = n;
                break;
            }
            None => {
                crate::ipc::v2::async_ops::poll(&task.process, ring_id);
                completed = complete::drain_completions(ring_id, min_complete);
            }
        }
    }

    Ok(completed as u64)
}

/// SYS_ASYNC_CANCEL(ring_id: u64, user_data: u64, flags: u32) => result: u64
pub fn sys_async_cancel(ring_id: u64, user_data: u64, flags: u64) -> Result<u64, SyscallError> {
    let _ = require_owned_ring_by_id(ring_id)?;

    if flags != 0 {
        return Err(SyscallError::InvalidArgument);
    }

    crate::ipc::v2::async_ops::cancel(ring_id, user_data)?;

    Ok(0)
}

/// SYS_ASYNC_DESTROY(ring_id: u64, flags: u32) => result: u64
pub fn sys_async_destroy(ring_id: u64, _flags: u64) -> Result<u64, SyscallError> {
    let _ = require_owned_ring_by_id(ring_id)?;

    super::ring::destroy_ring(ring_id).map_err(|e| match e {
        RingError::Alloc => SyscallError::OutOfMemory,
        RingError::NotFound => SyscallError::BadHandle,
        RingError::TooManyRings => SyscallError::InvalidArgument,
    })?;

    Ok(0)
}
