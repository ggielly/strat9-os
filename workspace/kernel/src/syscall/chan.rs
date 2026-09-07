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

// ABI contract: userspace hardcodes MSG_SIZE = 256.  If IpcMessage's size
// changes, this assertion forces a deliberate review of the userspace ABI.
const _: () = assert!(MSG_SIZE == 256, "IpcMessage size changed : update userspace ABI");

/// SYS_CHAN_CREATE (220): create a bounded sync-channel.
pub fn sys_chan_create(capacity: u64) -> Result<u64, SyscallError> {
    let cap = capacity.clamp(1, 1024) as usize;

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;

    // Reserve quota before creating the channel.
    task.process.ipc_quota.try_reserve(cap)
        .map_err(|_| SyscallError::OutOfMemory)?;

    let chan_id = match channel::create_channel(cap) {
        id => id,
    };

    let caps = unsafe { &mut *task.process.capabilities.get() };
    let cap_id = crate::capability::CapId::new();
    let chan_cap = crate::capability::Capability {
        id: cap_id,
        permissions: crate::capability::CapPermissions {
            read: true,
            write: true,
            execute: false,
            grant: true,
            revoke: false,
        },
        resource_type: ResourceType::Channel,
        resource: chan_id.as_u64() as usize,
        // Badge defaults to capability ID; receivers see this in msg.sender.
        // When this capability is granted/delegated, the granter can supply
        // a custom badge so the receiver can distinguish individual clients.
        badge: cap_id.as_u64(),
    };
    let handle = caps.insert(chan_cap);

    log::debug!(
        "syscall: CHAN_CREATE(cap={}) => chan={} handle={}",
        cap,
        chan_id,
        handle.as_u64()
    );
    Ok(handle.as_u64())
}

/// SYS_CHAN_SEND (221): send one `IpcMessage` to a channel, blocking if full.
///
/// **P1 fix**: The kernel now injects `cap.badge` into `msg.sender` instead
/// of the raw task ID.  This follows the capability-endpoint model (seL4):
/// the receiver sees only the badge of the delegation chain, never the
/// sender's global identity.  A sender cannot forge the badge because the
/// kernel overwrites `msg.sender` after reading the message from user-space.
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
    let caps = unsafe { &*task.process.capabilities.get() };
    let cap = caps
        .get(CapId::from_raw(handle))
        .ok_or(SyscallError::BadHandle)?;
    if cap.resource_type != ResourceType::Channel || !cap.permissions.write {
        return Err(SyscallError::PermissionDenied);
    }
    let chan_id = ChanId::from_u64(cap.resource as u64);

    // Inject the capability badge : the receiver sees this in msg.sender,
    // not the sender's global task ID.  The badge is set at capability
    // creation time (defaults to cap_id) and can be overridden via grant.
    msg.sender = cap.badge;

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

    // Validate the destination buffer BEFORE consuming the message.
    // If the pointer is invalid, we return EFAULT without touching the queue.
    let user_slice = UserSliceWrite::new(msg_ptr, MSG_SIZE).map_err(SyscallError::from)?;

    let chan = channel::get_channel(chan_id).ok_or(SyscallError::BadHandle)?;
    let msg = chan.recv().map_err(SyscallError::from)?;

    let n = user_slice.copy_from(unsafe {
        core::slice::from_raw_parts(&msg as *const IpcMessage as *const u8, MSG_SIZE)
    });
    if n != MSG_SIZE {
        // Defensive: should not happen after buffer validation, but the
        // message has already been consumed
        return Err(SyscallError::Fault);
    }

    Ok(0)
}

/// SYS_CHAN_TRY_RECV (223): non-blocking receive.
///
/// **P0 fix**: Same as `sys_chan_recv` : validate the user destination buffer
/// before consuming the message from the queue.
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

    let user_slice = UserSliceWrite::new(msg_ptr, MSG_SIZE).map_err(SyscallError::from)?;

    let chan = channel::get_channel(chan_id).ok_or(SyscallError::BadHandle)?;
    match chan.try_recv() {
        Ok(msg) => {
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

/// SYS_CHAN_CLOSE (224): close a channel handle.

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
    let has_revoke = cap.permissions.revoke;

    // Look up the channel to get its capacity for quota release.
    let capacity = channel::get_channel(chan_id)
        .map(|c| c.capacity())
        .unwrap_or(0);

    let cap = caps
        .remove(CapId::from_raw(handle))
        .ok_or(SyscallError::BadHandle)?;
    debug_assert_eq!(cap.resource_type, ResourceType::Channel);

    // Release per-process IPC quota for this handle.
    task.process.ipc_quota.release(capacity);

    if has_revoke {
        // Full release: decrement global refcount and destroy channel if
        // this was the last capability referencing it.
        crate::capability::release_capability(&cap, Some(task.id));
    } else {
        // Local-only close: decrement the global refcount without triggering
        // channel destruction.  The channel stays alive until all other
        // capabilities (held by other processes) are also dropped.
        crate::capability::get_capability_manager().revoke_capability(cap.id);
    }

    log::debug!("syscall: CHAN_CLOSE(handle={}) => chan={}", handle, chan_id);
    Ok(0)
}
