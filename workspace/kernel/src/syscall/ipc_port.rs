//! IPC port syscall handlers.
//!
//! Provides capability-enforced wrappers around the low-level port IPC
//! primitives: create, send, recv, try_recv, call, reply, bind, unbind.

use super::error::SyscallError;
use crate::{
    capability::{get_capability_manager, CapId, CapPermissions, ResourceType},
    ipc::{
        message::IpcMessage,
        port::{self, PortId},
        reply,
    },
    memory::{UserSliceRead, UserSliceWrite},
    process::current_task_clone,
    silo,
};

/// SYS_IPC_CREATE_PORT: create an IPC port bound to the current task.
pub fn sys_ipc_create_port(_flags: u64) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let port_id = port::create_port(task.id);
    let cap = get_capability_manager().create_capability(
        ResourceType::IpcPort,
        port_id.as_u64() as usize,
        CapPermissions::all(),
    );
    let cap_id = unsafe { (&mut *task.process.capabilities.get()).insert(cap) };
    Ok(cap_id.as_u64())
}

/// SYS_IPC_SEND: send one IPC message to a port.
pub fn sys_ipc_send(port_handle: u64, msg_ptr: u64) -> Result<u64, SyscallError> {
    silo::enforce_cap_for_current_task(port_handle)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.process.capabilities.get() };
    let required = CapPermissions {
        read: false,
        write: true,
        execute: false,
        grant: false,
        revoke: false,
    };
    let cap = caps
        .get_with_permissions(CapId::from_raw(port_handle), required)
        .ok_or(SyscallError::PermissionDenied)?;
    if cap.resource_type != ResourceType::IpcPort {
        return Err(SyscallError::BadHandle);
    }

    const MSG_SIZE: usize = core::mem::size_of::<IpcMessage>();
    let user = UserSliceRead::new(msg_ptr, MSG_SIZE)?;
    let mut buf = [0u8; MSG_SIZE];
    user.copy_to(&mut buf);
    let mut msg = crate::ipc::message::ipc_message_from_raw(&buf);

    // Stamp identity
    msg.sender = task.id.as_u64();

    if msg.flags == 0 {
        if let Some((sid, _label, _mem_used, _mem_min, _mem_max)) =
            silo::silo_info_for_task(task.id)
        {
            if let Some(snapshot) = silo::list_silos_snapshot()
                .into_iter()
                .find(|s| s.id == sid)
            {
                let structured_label = crate::ipc::message::IpcLabel {
                    tier: snapshot.tier as u8,
                    family: 5,
                    compartment: sid as u16,
                };
                msg.flags = unsafe { core::mem::transmute(structured_label) };
            }
        }
    }

    let port_id = PortId::from_u64(cap.resource as u64);
    let port_obj = port::get_port(port_id).ok_or(SyscallError::BadHandle)?;
    port_obj.send(msg).map_err(SyscallError::from)?;
    Ok(0)
}

/// SYS_IPC_RECV: block until a message is received from a port.
pub fn sys_ipc_recv(port_handle: u64, msg_ptr: u64) -> Result<u64, SyscallError> {
    silo::enforce_cap_for_current_task(port_handle)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.process.capabilities.get() };
    let required = CapPermissions {
        read: true,
        write: false,
        execute: false,
        grant: false,
        revoke: false,
    };
    let cap = caps
        .get_with_permissions(CapId::from_raw(port_handle), required)
        .ok_or(SyscallError::PermissionDenied)?;
    if cap.resource_type != ResourceType::IpcPort {
        return Err(SyscallError::BadHandle);
    }

    let port_id = PortId::from_u64(cap.resource as u64);
    let port_obj = port::get_port(port_id).ok_or(SyscallError::BadHandle)?;
    let mut msg = port_obj.recv().map_err(SyscallError::from)?;

    // Handle transfer (optional): msg.flags contains a handle in the sender table.
    if msg.flags != 0 {
        let sender_id = crate::process::TaskId::from_u64(msg.sender);
        let sender = crate::process::get_task_by_id(sender_id).ok_or(SyscallError::BadHandle)?;
        let sender_caps = unsafe { &mut *sender.process.capabilities.get() };
        let dup = sender_caps
            .duplicate(CapId::from_raw(msg.flags as u64))
            .ok_or(SyscallError::PermissionDenied)?;

        let receiver = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
        let receiver_caps = unsafe { &mut *receiver.process.capabilities.get() };
        let new_id = super::dispatcher::insert_capability_with_retention(receiver_caps, dup)?;
        if new_id.as_u64() > u32::MAX as u64 {
            return Err(SyscallError::InvalidArgument);
        }
        msg.flags = new_id.as_u64() as u32;
    }

    const MSG_SIZE: usize = core::mem::size_of::<IpcMessage>();
    let mut buf = [0u8; MSG_SIZE];
    crate::ipc::message::ipc_message_to_raw(&msg, &mut buf);
    let user = UserSliceWrite::new(msg_ptr, MSG_SIZE)?;
    user.copy_from(&buf);
    Ok(0)
}

/// SYS_IPC_TRY_RECV: non-blocking receive from a port.
pub fn sys_ipc_try_recv(port_handle: u64, msg_ptr: u64) -> Result<u64, SyscallError> {
    silo::enforce_cap_for_current_task(port_handle)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.process.capabilities.get() };
    let required = CapPermissions {
        read: true,
        write: false,
        execute: false,
        grant: false,
        revoke: false,
    };
    let cap = caps
        .get_with_permissions(CapId::from_raw(port_handle), required)
        .ok_or(SyscallError::PermissionDenied)?;
    if cap.resource_type != ResourceType::IpcPort {
        return Err(SyscallError::BadHandle);
    }

    let port_id = PortId::from_u64(cap.resource as u64);
    let port_obj = port::get_port(port_id).ok_or(SyscallError::BadHandle)?;
    let msg_opt = port_obj.try_recv().map_err(SyscallError::from)?;

    let mut msg = match msg_opt {
        Some(m) => m,
        None => return Err(SyscallError::Again),
    };

    // Handle transfer (optional).
    if msg.flags != 0 {
        let sender_id = crate::process::TaskId::from_u64(msg.sender);
        let sender = crate::process::get_task_by_id(sender_id).ok_or(SyscallError::BadHandle)?;
        let sender_caps = unsafe { &mut *sender.process.capabilities.get() };
        let dup = sender_caps
            .duplicate(CapId::from_raw(msg.flags as u64))
            .ok_or(SyscallError::PermissionDenied)?;

        let receiver = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
        let receiver_caps = unsafe { &mut *receiver.process.capabilities.get() };
        let new_id = super::dispatcher::insert_capability_with_retention(receiver_caps, dup)?;
        if new_id.as_u64() > u32::MAX as u64 {
            return Err(SyscallError::InvalidArgument);
        }
        msg.flags = new_id.as_u64() as u32;
    }

    const MSG_SIZE: usize = core::mem::size_of::<IpcMessage>();
    let mut buf = [0u8; MSG_SIZE];
    crate::ipc::message::ipc_message_to_raw(&msg, &mut buf);
    let user = UserSliceWrite::new(msg_ptr, MSG_SIZE)?;
    user.copy_from(&buf);
    Ok(0)
}

/// SYS_IPC_CONNECT: open a port by namespace path, returns a capability handle.
pub fn sys_ipc_connect(path_ptr: u64, path_len: u64) -> Result<u64, SyscallError> {
    if path_ptr == 0 || path_len == 0 {
        return Err(SyscallError::Fault);
    }
    const MAX_PATH_LEN: usize = 4096;
    if path_len as usize > MAX_PATH_LEN {
        return Err(SyscallError::InvalidArgument);
    }
    let user = UserSliceRead::new(path_ptr, path_len as usize)?;
    let bytes = user.read_to_vec();
    let path = core::str::from_utf8(&bytes).map_err(SyscallError::from)?;

    let (port_raw, _remaining) = crate::namespace::resolve(path).ok_or(SyscallError::NotFound)?;
    let port_id = PortId::from_u64(port_raw);
    if port::get_port(port_id).is_none() {
        return Err(SyscallError::BadHandle);
    }

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let cap = get_capability_manager().create_capability(
        ResourceType::IpcPort,
        port_raw as usize,
        CapPermissions {
            read: true,
            write: true,
            execute: false,
            grant: false,
            revoke: false,
        },
    );
    let cap_id = unsafe { (&mut *task.process.capabilities.get()).insert(cap) };
    Ok(cap_id.as_u64())
}

/// SYS_IPC_CALL: synchronous RPC : send + block until reply arrives.
pub fn sys_ipc_call(port_handle: u64, msg_ptr: u64) -> Result<u64, SyscallError> {
    silo::enforce_cap_for_current_task(port_handle)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.process.capabilities.get() };
    let required = CapPermissions {
        read: false,
        write: true,
        execute: false,
        grant: false,
        revoke: false,
    };
    let cap = caps
        .get_with_permissions(CapId::from_raw(port_handle), required)
        .ok_or(SyscallError::PermissionDenied)?;
    if cap.resource_type != ResourceType::IpcPort {
        return Err(SyscallError::BadHandle);
    }

    const MSG_SIZE: usize = core::mem::size_of::<IpcMessage>();
    let user = UserSliceRead::new(msg_ptr, MSG_SIZE)?;
    let mut buf = [0u8; MSG_SIZE];
    user.copy_to(&mut buf);
    let mut msg = crate::ipc::message::ipc_message_from_raw(&buf);
    msg.sender = task.id.as_u64();
    if msg.flags != 0 {
        let transfer_required = CapPermissions {
            read: false,
            write: false,
            execute: false,
            grant: true,
            revoke: false,
        };
        if caps
            .get_with_permissions(CapId::from_raw(msg.flags as u64), transfer_required)
            .is_none()
        {
            return Err(SyscallError::PermissionDenied);
        }
    }

    let port_id = PortId::from_u64(cap.resource as u64);
    let port_obj = port::get_port(port_id).ok_or(SyscallError::BadHandle)?;
    let port_owner = port_obj.owner;
    port_obj.send(msg).map_err(SyscallError::from)?;

    let reply_msg = reply::wait_for_reply(task.id, port_owner);
    let mut out_buf = [0u8; MSG_SIZE];
    crate::ipc::message::ipc_message_to_raw(&reply_msg, &mut out_buf);
    let user = UserSliceWrite::new(msg_ptr, MSG_SIZE)?;
    user.copy_from(&out_buf);
    Ok(0)
}

/// SYS_IPC_REPLY: send a reply to a caller that used SYS_IPC_CALL.
pub fn sys_ipc_reply(msg_ptr: u64) -> Result<u64, SyscallError> {
    if msg_ptr == 0 {
        return Err(SyscallError::Fault);
    }
    const MSG_SIZE: usize = core::mem::size_of::<IpcMessage>();
    let user = UserSliceRead::new(msg_ptr, MSG_SIZE)?;
    let mut buf = [0u8; MSG_SIZE];
    user.copy_to(&mut buf);
    let msg = crate::ipc::message::ipc_message_from_raw(&buf);

    let target = crate::process::TaskId::from_u64(msg.sender);
    let mut msg = msg;
    if msg.flags != 0 {
        let sender = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
        let sender_caps = unsafe { &mut *sender.process.capabilities.get() };
        let dup = sender_caps
            .duplicate(CapId::from_raw(msg.flags as u64))
            .ok_or(SyscallError::PermissionDenied)?;

        let receiver = crate::process::get_task_by_id(target).ok_or(SyscallError::BadHandle)?;
        let receiver_caps = unsafe { &mut *receiver.process.capabilities.get() };
        let new_id = super::dispatcher::insert_capability_with_retention(receiver_caps, dup)?;
        if new_id.as_u64() > u32::MAX as u64 {
            return Err(SyscallError::InvalidArgument);
        }
        msg.flags = new_id.as_u64() as u32;
    }

    reply::deliver_reply(target, msg).map_err(|_| SyscallError::BadHandle)?;
    Ok(0)
}

/// SYS_IPC_BIND_PORT: register a port under a namespace path.
pub fn sys_ipc_bind_port(
    port_handle: u64,
    path_ptr: u64,
    path_len: u64,
) -> Result<u64, SyscallError> {
    silo::enforce_registry_bind_for_current_task()?;
    silo::enforce_cap_for_current_task(port_handle)?;
    if path_ptr == 0 || path_len == 0 {
        return Err(SyscallError::Fault);
    }
    const MAX_PATH_LEN: usize = 4096;
    if path_len as usize > MAX_PATH_LEN {
        return Err(SyscallError::InvalidArgument);
    }
    let user = UserSliceRead::new(path_ptr, path_len as usize)?;
    let bytes = user.read_to_vec();
    let path = core::str::from_utf8(&bytes).map_err(SyscallError::from)?;

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.process.capabilities.get() };
    let cap = caps
        .get_with_permissions(
            CapId::from_raw(port_handle),
            CapPermissions {
                read: true,
                write: true,
                execute: false,
                grant: true,
                revoke: false,
            },
        )
        .ok_or(SyscallError::PermissionDenied)?;
    if cap.resource_type != ResourceType::IpcPort {
        return Err(SyscallError::BadHandle);
    }

    crate::vfs::mount(
        path,
        alloc::sync::Arc::new(crate::vfs::IpcScheme::new(PortId::from_u64(
            cap.resource as u64,
        ))),
    )?;
    let _ = crate::namespace::bind(path, cap.resource as u64);
    let _ = silo::set_current_silo_label_from_path(path);

    // Bootstrap convenience: if a privileged userspace server binds root `/`
    // or a strate mountpoint, queue a bootstrap message.
    let should_bootstrap = path == "/" || path.starts_with("/srv/strate-fs-");
    if should_bootstrap {
        let mut seeded_handle: u32 = 0;
        if let Some(device) = crate::hardware::storage::virtio_block::get_device() {
            let volume_resource = device as *const _ as usize;
            let volume_perms = CapPermissions {
                read: true,
                write: true,
                execute: false,
                grant: true,
                revoke: true,
            };
            let volume_cap = get_capability_manager().create_capability(
                ResourceType::Volume,
                volume_resource,
                volume_perms,
            );
            let task_caps = unsafe { &mut *task.process.capabilities.get() };
            let id = task_caps.insert(volume_cap);
            let _ = silo::register_current_task_granted_resource(
                ResourceType::Volume,
                volume_resource,
                volume_perms,
            );
            if id.as_u64() <= u32::MAX as u64 {
                seeded_handle = id.as_u64() as u32;
            }
            log::info!(
                "ipc_bind_port('/'): seeded volume capability handle={} for task {:?}",
                id.as_u64(),
                task.id
            );
        }

        // Send a bootstrap message to the just-bound filesystem server.
        const BOOTSTRAP_MSG_TYPE: u32 = 0x10;
        let mut boot_msg = IpcMessage::new(BOOTSTRAP_MSG_TYPE);
        boot_msg.sender = task.id.as_u64();
        boot_msg.flags = seeded_handle;
        let label_owned = silo::current_task_silo_label().unwrap_or_else(|| {
            if path == "/" {
                alloc::string::String::from("root")
            } else {
                alloc::string::String::from(
                    path.rsplit('/')
                        .find(|part| !part.is_empty())
                        .unwrap_or("default"),
                )
            }
        });
        let label_bytes = label_owned.as_bytes();
        let max_len = boot_msg.payload.len().saturating_sub(1);
        let copy_len = core::cmp::min(label_bytes.len(), max_len);
        boot_msg.payload[0] = copy_len as u8;
        if copy_len > 0 {
            boot_msg.payload[1..1 + copy_len].copy_from_slice(&label_bytes[..copy_len]);
        }

        let port_id = PortId::from_u64(cap.resource as u64);
        if let Some(p) = port::get_port(port_id) {
            if p.send(boot_msg).is_ok() {
                log::info!(
                    "ipc_bind_port('{}'): queued bootstrap message (handle={}, label={})",
                    path,
                    seeded_handle,
                    label_owned
                );
            } else {
                log::warn!(
                    "ipc_bind_port('{}'): failed to queue bootstrap message",
                    path
                );
            }
        } else {
            log::warn!(
                "ipc_bind_port('{}'): bound port disappeared before bootstrap",
                path
            );
        }
    }
    Ok(0)
}

/// SYS_IPC_UNBIND_PORT: remove a namespace binding.
pub fn sys_ipc_unbind_port(path_ptr: u64, path_len: u64) -> Result<u64, SyscallError> {
    silo::require_silo_admin()?;
    if path_ptr == 0 || path_len == 0 {
        return Err(SyscallError::Fault);
    }
    const MAX_PATH_LEN: usize = 4096;
    if path_len as usize > MAX_PATH_LEN {
        return Err(SyscallError::InvalidArgument);
    }
    let user = UserSliceRead::new(path_ptr, path_len as usize)?;
    let bytes = user.read_to_vec();
    let path = core::str::from_utf8(&bytes).map_err(SyscallError::from)?;
    let _ = crate::namespace::unbind(path);
    crate::vfs::unmount(path)?;
    Ok(0)
}
