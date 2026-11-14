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

//! Semaphore syscall handlers.
//!
//! Provides capability-enforced semaphore operations: create, wait, try_wait,
//! post, close.

use super::error::SyscallError;
use crate::{
    capability::{get_capability_manager, CapId, CapPermissions, ResourceType},
    ipc::semaphore::{self, SemId},
    process::current_task_clone,
};

fn resolve_sem(handle: u64, require_write: bool) -> Result<SemId, SyscallError> {
    crate::silo::enforce_cap_for_current_task(handle)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.process.capabilities.get() };
    let required = if require_write {
        CapPermissions {
            read: false,
            write: true,
            execute: false,
            grant: false,
            revoke: false,
        }
    } else {
        CapPermissions {
            read: true,
            write: false,
            execute: false,
            grant: false,
            revoke: false,
        }
    };
    let cap = caps
        .get_with_permissions(CapId::from_raw(handle), required)
        .ok_or(SyscallError::PermissionDenied)?;
    if cap.resource_type != ResourceType::Semaphore {
        return Err(SyscallError::BadHandle);
    }
    let sem_id = SemId::from_u64(cap.resource as u64);
    if semaphore::get_semaphore(sem_id).is_none() {
        return Err(SyscallError::BadHandle);
    }
    Ok(sem_id)
}

/// SYS_SEM_CREATE: create a semaphore with an initial count.
pub fn sys_sem_create(initial: u64) -> Result<u64, SyscallError> {
    let initial = u32::try_from(initial).map_err(|_| SyscallError::InvalidArgument)?;
    let sem_id = semaphore::create_semaphore(initial).map_err(|e| match e {
        semaphore::SemaphoreError::InvalidValue => SyscallError::InvalidArgument,
        semaphore::SemaphoreError::WouldBlock => SyscallError::Again,
        semaphore::SemaphoreError::Destroyed => SyscallError::Pipe,
        semaphore::SemaphoreError::NotFound => SyscallError::NotFound,
        semaphore::SemaphoreError::Interrupted => SyscallError::Interrupted,
    })?;

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let cap = get_capability_manager().create_capability(
        ResourceType::Semaphore,
        sem_id.as_u64() as usize,
        CapPermissions {
            read: true,
            write: true,
            execute: false,
            grant: true,
            revoke: true,
        },
    );
    let cap_id = unsafe { (&*task.process.capabilities.get()).insert(cap) };
    Ok(cap_id.as_u64())
}

/// SYS_SEM_WAIT: decrement the semaphore (blocking if zero).
pub fn sys_sem_wait(handle: u64) -> Result<u64, SyscallError> {
    let sem_id = resolve_sem(handle, true)?;
    semaphore::get_semaphore(sem_id)
        .ok_or(SyscallError::BadHandle)?
        .wait()
        .map_err(|e| match e {
            semaphore::SemaphoreError::WouldBlock => SyscallError::Again,
            semaphore::SemaphoreError::Destroyed => SyscallError::Pipe,
            semaphore::SemaphoreError::Interrupted => SyscallError::Interrupted,
            _ => SyscallError::IoError,
        })?;
    Ok(0)
}

/// SYS_SEM_TRYWAIT: non-blocking decrement.
pub fn sys_sem_trywait(handle: u64) -> Result<u64, SyscallError> {
    let sem_id = resolve_sem(handle, true)?;
    match semaphore::get_semaphore(sem_id)
        .ok_or(SyscallError::BadHandle)?
        .try_wait()
    {
        Ok(()) => Ok(0),
        Err(semaphore::SemaphoreError::WouldBlock) => Err(SyscallError::Again),
        Err(_) => Err(SyscallError::IoError),
    }
}

/// SYS_SEM_POST: increment the semaphore (wake a waiter).
pub fn sys_sem_post(handle: u64) -> Result<u64, SyscallError> {
    let sem_id = resolve_sem(handle, true)?;
    semaphore::get_semaphore(sem_id)
        .ok_or(SyscallError::BadHandle)?
        .post()
        .map_err(|e| match e {
            semaphore::SemaphoreError::WouldBlock => SyscallError::Again,
            semaphore::SemaphoreError::Destroyed => SyscallError::Pipe,
            _ => SyscallError::IoError,
        })?;
    Ok(0)
}

/// SYS_SEM_CLOSE: destroy a semaphore.
pub fn sys_sem_close(handle: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(handle)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.process.capabilities.get() };
    let cap = caps
        .get(CapId::from_raw(handle))
        .ok_or(SyscallError::BadHandle)?;
    if cap.resource_type != ResourceType::Semaphore {
        return Err(SyscallError::BadHandle);
    }
    let sem_id = SemId::from_u64(cap.resource as u64);

    let cap = caps
        .remove(CapId::from_raw(handle))
        .ok_or(SyscallError::BadHandle)?;

    crate::capability::release_capability(&cap, Some(task.id));
    let _ = semaphore::destroy_semaphore(sem_id);
    Ok(0)
}
