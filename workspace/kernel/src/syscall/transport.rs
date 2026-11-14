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

//! Syscall handlers for the IPC transport layer (N1/N2/N3).
//!
//! Provides userspace access to the TransportManager:
//! - `SYS_TRANSPORT_CREATE` (260): create a transport between two silos
//! - `SYS_TRANSPORT_SEND`   (261): send a message
//! - `SYS_TRANSPORT_RECV`   (262): receive a message
//! - `SYS_TRANSPORT_CLOSE`  (263): close a transport
//! - `SYS_TRANSPORT_INFO`   (264): query transport info

use crate::{
    capability::{get_capability_manager, CapId, CapPermissions, ResourceType},
    ipc::transport::{
        IpcConsumer, IpcError, IpcProducer, IpcTransport, TransportConfig, TransportId,
        TransportLevel, TransportManager,
    },
    memory::{UserSliceRead, UserSliceWrite},
    process::current_task_clone,
    silo::{self, SiloId},
    syscall::error::SyscallError,
};
use alloc::vec;

/// Global transport manager instance.
pub(crate) static TRANSPORT_MANAGER: TransportManager = TransportManager::new();

/// SYS_TRANSPORT_CREATE: create a transport between the caller's silo and `dst_silo`.
///
/// `config_flags` low 4 bits encode the desired minimum `TransportLevel`:
///   1 = TypeSafe, 2 = LockFree.  0 = use default (LockFree).
///   3 = Mmu is rejected (see below); any other non-zero value is invalid.
/// Bits 8..=23 encode `ring_capacity` (0 = default 256, max 4096).
///
/// Security (Phase 0): the N3 `TransportLevel::Mmu` path is rejected
/// unconditionally. Only the CR3 is migrated on that path while TSS/GS/FPU
/// and scheduler context stay wrong, so it is unsafe to expose. The N3 code
/// remains in place but is unreachable from this syscall.
pub fn sys_transport_create(dst_silo_val: u64, config_flags: u64) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let src_silo_id = silo::try_silo_id_for_task(&task).ok_or(SyscallError::BadHandle)?;
    let src_silo = SiloId::new(src_silo_id);
    let dst_silo = SiloId::new(dst_silo_val as u32);

    // Cross-silo transports require the silo admin capability. This is a
    // Phase 0 stopgap; per-endpoint capability authorization replaces it in
    // ABI v2.
    if src_silo_id != dst_silo_val as u32 && crate::silo::require_silo_admin().is_err() {
        return Err(SyscallError::PermissionDenied);
    }

    // Decode config_flags: bits [3:0] = min_level, bits [23:8] = ring_capacity.
    let level_raw = (config_flags & 0xF) as u8;
    let min_level = match level_raw {
        0 => TransportLevel::LockFree, // default
        1 => TransportLevel::TypeSafe,
        2 => TransportLevel::LockFree,
        3 => return Err(SyscallError::NotSupported), // Mmu rejected unconditionally
        _ => return Err(SyscallError::InvalidArgument),
    };
    let ring_capacity = {
        let cap = ((config_flags >> 8) & 0xFFFF) as u32;
        if cap == 0 {
            256
        } else if cap > 4096 {
            return Err(SyscallError::InvalidArgument);
        } else {
            cap
        }
    };

    let config = TransportConfig {
        min_level,
        ring_capacity: Some(ring_capacity),
        slot_size: Some(2048),
    };

    let result = TRANSPORT_MANAGER
        .establish(src_silo, dst_silo, config)
        .map_err(|_| SyscallError::NotSupported)?;

    let cap = get_capability_manager().create_capability(
        ResourceType::IpcTransport,
        result.id.as_u64() as usize,
        CapPermissions::read_write(),
    );

    // SAFETY: the capability table is internally synchronized.
    let caps = unsafe { &*task.process.capabilities.get() };
    let cap_id = caps.insert(cap);

    Ok(cap_id.as_u64())
}

/// SYS_TRANSPORT_SEND: send a message on a transport handle.
pub fn sys_transport_send(handle: u64, buf_ptr: u64, buf_len: u64) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: the capability table is internally synchronized.
    let caps = unsafe { &*task.process.capabilities.get() };

    let cap = caps
        .get_with_permissions(CapId::from_raw(handle), CapPermissions::read_write())
        .ok_or(SyscallError::BadHandle)?;

    if cap.resource_type != ResourceType::IpcTransport {
        return Err(SyscallError::BadHandle);
    }

    // Bound the message size to avoid an unbounded kernel allocation driven
    // by a syscall argument.
    const MAX_MSG_LEN: u64 = 64 * 1024;
    if buf_len == 0 || buf_len > MAX_MSG_LEN {
        return Err(SyscallError::InvalidArgument);
    }

    let len = buf_len as usize;
    let user_buf = UserSliceRead::new(buf_ptr, len)?;
    let data = user_buf.read_to_vec();

    let tid = TransportId::from_u64(cap.resource as u64);
    let endpoint = TRANSPORT_MANAGER
        .get_endpoint(tid)
        .ok_or(SyscallError::BadHandle)?;

    endpoint
        .send(&data)
        .map_err(|e| transport_to_syscall_err(e))?;

    // Increment sent stats
    TRANSPORT_MANAGER.stats.lock().sent += 1;

    log::trace!("transport_send: handle={} len={}", handle, len);
    Ok(len as u64)
}

/// SYS_TRANSPORT_RECV: receive a message from a transport handle.
pub fn sys_transport_recv(handle: u64, buf_ptr: u64, buf_len: u64) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: the capability table is internally synchronized.
    let caps = unsafe { &*task.process.capabilities.get() };

    let cap = caps
        .get_with_permissions(CapId::from_raw(handle), CapPermissions::read_write())
        .ok_or(SyscallError::BadHandle)?;

    if cap.resource_type != ResourceType::IpcTransport {
        return Err(SyscallError::BadHandle);
    }

    if buf_len == 0 {
        return Err(SyscallError::Fault);
    }

    let tid = TransportId::from_u64(cap.resource as u64);
    let endpoint = TRANSPORT_MANAGER
        .get_endpoint(tid)
        .ok_or(SyscallError::BadHandle)?;

    let user_buf = UserSliceWrite::new(buf_ptr, buf_len as usize)?;
    let mut kbuf = vec![0u8; buf_len as usize];
    let n = endpoint
        .recv(&mut kbuf)
        .map_err(|e| transport_to_syscall_err(e))?;
    user_buf.copy_from(&kbuf[..n]);

    // Increment received stats
    TRANSPORT_MANAGER.stats.lock().received += 1;

    log::trace!("transport_recv: handle={} n={}", handle, n);
    Ok(n as u64)
}

/// SYS_TRANSPORT_CLOSE: close a transport handle and release resources.
pub fn sys_transport_close(handle: u64) -> Result<u64, SyscallError> {
    use crate::capability::release_capability;

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let cap_id = CapId::from_raw(handle);
    // SAFETY: the capability table is internally synchronized.
    let caps = unsafe { &*task.process.capabilities.get() };
    if let Some(cap) = caps.remove(cap_id) {
        release_capability(&cap, Some(task.id));
        log::trace!("transport_close: handle={}", handle);
        Ok(0)
    } else {
        Err(SyscallError::BadHandle)
    }
}

/// SYS_TRANSPORT_INFO: query transport level and statistics.
pub fn sys_transport_info(handle: u64, out_ptr: u64) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: the capability table is internally synchronized.
    let caps = unsafe { &*task.process.capabilities.get() };

    let _cap = caps
        .get_with_permissions(CapId::from_raw(handle), CapPermissions::read_write())
        .ok_or(SyscallError::BadHandle)?;

    if out_ptr == 0 {
        return Err(SyscallError::Fault);
    }

    let tid = TransportId::from_u64(_cap.resource as u64);
    let endpoint = TRANSPORT_MANAGER
        .get_endpoint(tid)
        .ok_or(SyscallError::BadHandle)?;
    let level = endpoint.level() as u64;
    let out = UserSliceWrite::new(out_ptr, 8)?;
    out.copy_from(&level.to_ne_bytes());
    Ok(8)
}

/// Convert an IpcError to a SyscallError.
fn transport_to_syscall_err(e: IpcError) -> SyscallError {
    match e {
        IpcError::WouldBlock => SyscallError::Again,
        IpcError::Disconnected => SyscallError::Pipe,
        IpcError::MessageTooLarge => SyscallError::Fault,
        IpcError::BufferTooSmall => SyscallError::Fault,
        IpcError::TransportNotFound => SyscallError::BadHandle,
        IpcError::PermissionDenied => SyscallError::PermissionDenied,
        IpcError::TransportFailed => SyscallError::IoError,
        IpcError::InvalidRip => SyscallError::Fault,
        IpcError::TimedOut => SyscallError::TimedOut,
    }
}
