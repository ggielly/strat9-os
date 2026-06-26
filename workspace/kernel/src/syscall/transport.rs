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
pub fn sys_transport_create(dst_silo_val: u64, _config_flags: u64) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let src_silo_id = silo::try_silo_id_for_task(task.id).ok_or(SyscallError::BadHandle)?;
    let src_silo = SiloId::new(src_silo_id);
    let dst_silo = SiloId::new(dst_silo_val as u32);

    let config = TransportConfig {
        min_level: TransportLevel::LockFree,
        ring_capacity: Some(256),
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

    let mut caps = unsafe { (*task.process.capabilities.get()).clone() };
    let cap_id = caps.insert(cap);
    unsafe {
        *task.process.capabilities.get() = caps;
    }

    Ok(cap_id.as_u64())
}

/// SYS_TRANSPORT_SEND: send a message on a transport handle.
pub fn sys_transport_send(handle: u64, buf_ptr: u64, buf_len: u64) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.process.capabilities.get() };

    let cap = caps
        .get_with_permissions(CapId::from_raw(handle), CapPermissions::read_write())
        .ok_or(SyscallError::BadHandle)?;

    if cap.resource_type != ResourceType::IpcTransport {
        return Err(SyscallError::BadHandle);
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
    let caps = unsafe { &mut *task.process.capabilities.get() };
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
