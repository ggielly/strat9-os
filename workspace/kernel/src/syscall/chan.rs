//! Typed MPMC sync-channel syscall handlers.
//!
//! Provides bounded multi-producer, multi-consumer channels for
//! inter-process message passing (IPC-02).

use super::error::SyscallError;
use crate::{
    capability::{CapId, ResourceType},
    ipc::{
        channel::{self, ChanId},
        message::IpcMessage,
    },
    memory::{UserSliceRead, UserSliceWrite},
    process::current_task_clone,
};

const MSG_SIZE: usize = core::mem::size_of::<IpcMessage>();

/// SYS_CHAN_CREATE (220): create a bounded sync-channel.
pub fn sys_chan_create(capacity: u64) -> Result<u64, SyscallError> {
    let cap = capacity.clamp(1, 1024) as usize;
    let chan_id = channel::create_channel(cap);

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &mut *task.process.capabilities.get() };
    let cap_id = caps.insert(crate::capability::Capability {
        id: crate::capability::CapId::new(),
        permissions: crate::capability::CapPermissions {
            read: true,
            write: true,
            execute: false,
            grant: true,
            revoke: false,
        },
        resource_type: ResourceType::Channel,
        resource: chan_id.as_u64() as usize,
    });

    log::debug!(
        "syscall: CHAN_CREATE(cap={}) → chan={} handle={}",
        cap,
        chan_id,
        cap_id.as_u64()
    );
    Ok(cap_id.as_u64())
}

/// SYS_CHAN_SEND (221): send one `IpcMessage` to a channel, blocking if full.
pub fn sys_chan_send(handle: u64, msg_ptr: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(handle)?;

    let user_slice = UserSliceRead::new(msg_ptr, MSG_SIZE).map_err(SyscallError::from)?;
    let mut msg = IpcMessage::new(0);
    let n = user_slice.copy_to(unsafe {
        core::slice::from_raw_parts_mut(&mut msg as *mut IpcMessage as *mut u8, MSG_SIZE)
    });
    if n != MSG_SIZE {
        return Err(SyscallError::Fault);
    }

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    msg.sender = task.id.as_u64();

    let caps = unsafe { &*task.process.capabilities.get() };
    let cap = caps
        .get(CapId::from_raw(handle))
        .ok_or(SyscallError::BadHandle)?;
    if cap.resource_type != ResourceType::Channel || !cap.permissions.write {
        return Err(SyscallError::PermissionDenied);
    }
    let chan_id = ChanId::from_u64(cap.resource as u64);

    let chan = channel::get_channel(chan_id).ok_or(SyscallError::BadHandle)?;
    chan.send(msg).map_err(SyscallError::from)?;

    Ok(0)
}

/// SYS_CHAN_RECV (222): receive one `IpcMessage`, blocking if empty.
pub fn sys_chan_recv(handle: u64, msg_ptr: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(handle)?;

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.process.capabilities.get() };
    let cap = caps
        .get(CapId::from_raw(handle))
        .ok_or(SyscallError::BadHandle)?;
    if cap.resource_type != ResourceType::Channel || !cap.permissions.read {
        return Err(SyscallError::PermissionDenied);
    }
    let chan_id = ChanId::from_u64(cap.resource as u64);

    let chan = channel::get_channel(chan_id).ok_or(SyscallError::BadHandle)?;
    let msg = chan.recv().map_err(SyscallError::from)?;

    let user_slice = UserSliceWrite::new(msg_ptr, MSG_SIZE).map_err(SyscallError::from)?;
    let n = user_slice.copy_from(unsafe {
        core::slice::from_raw_parts(&msg as *const IpcMessage as *const u8, MSG_SIZE)
    });
    if n != MSG_SIZE {
        return Err(SyscallError::Fault);
    }

    Ok(0)
}

/// SYS_CHAN_TRY_RECV (223): non-blocking receive.
pub fn sys_chan_try_recv(handle: u64, msg_ptr: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(handle)?;

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.process.capabilities.get() };
    let cap = caps
        .get(CapId::from_raw(handle))
        .ok_or(SyscallError::BadHandle)?;
    if cap.resource_type != ResourceType::Channel || !cap.permissions.read {
        return Err(SyscallError::PermissionDenied);
    }
    let chan_id = ChanId::from_u64(cap.resource as u64);

    let chan = channel::get_channel(chan_id).ok_or(SyscallError::BadHandle)?;
    match chan.try_recv() {
        Ok(msg) => {
            let user_slice = UserSliceWrite::new(msg_ptr, MSG_SIZE).map_err(SyscallError::from)?;
            let n = user_slice.copy_from(unsafe {
                core::slice::from_raw_parts(&msg as *const IpcMessage as *const u8, MSG_SIZE)
            });
            if n != MSG_SIZE {
                return Err(SyscallError::Fault);
            }
            Ok(0)
        }
        Err(e) => Err(SyscallError::from(e)),
    }
}

/// SYS_CHAN_CLOSE (224): destroy a channel and wake all waiters.
pub fn sys_chan_close(handle: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(handle)?;

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &mut *task.process.capabilities.get() };
    let cap = caps
        .get(CapId::from_raw(handle))
        .ok_or(SyscallError::BadHandle)?;
    if cap.resource_type != ResourceType::Channel {
        return Err(SyscallError::BadHandle);
    }
    let chan_id = ChanId::from_u64(cap.resource as u64);
    let cap = caps
        .remove(CapId::from_raw(handle))
        .ok_or(SyscallError::BadHandle)?;
    debug_assert_eq!(cap.resource_type, ResourceType::Channel);
    crate::capability::release_capability(&cap, Some(task.id));

    log::debug!("syscall: CHAN_CLOSE(handle={}) → chan={}", handle, chan_id);
    Ok(0)
}
