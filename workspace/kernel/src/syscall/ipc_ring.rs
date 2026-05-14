//! IPC ring-buffer syscall handlers.
//!
//! Provides shared-memory ring buffers for zero-copy IPC between processes.

use super::error::SyscallError;
use crate::{
    capability::{get_capability_manager, CapId, CapPermissions, ResourceType},
    ipc::shared_ring::{self, RingId},
    memory::UserSliceWrite,
    process::current_task_clone,
};

/// SYS_IPC_RING_CREATE: allocate a shared-memory ring buffer.
pub fn sys_ipc_ring_create(size: u64) -> Result<u64, SyscallError> {
    let sz = usize::try_from(size).map_err(|_| SyscallError::InvalidArgument)?;
    let ring_id = shared_ring::create_ring(sz).map_err(|e| match e {
        shared_ring::RingError::InvalidSize => SyscallError::InvalidArgument,
        shared_ring::RingError::Alloc => SyscallError::OutOfMemory,
        shared_ring::RingError::NotFound => SyscallError::NotFound,
    })?;

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let cap = get_capability_manager().create_capability(
        ResourceType::SharedRing,
        ring_id.as_u64() as usize,
        CapPermissions {
            read: true,
            write: true,
            execute: false,
            grant: true,
            revoke: true,
        },
    );
    let cap_id = unsafe { (&mut *task.process.capabilities.get()).insert(cap) };
    Ok(cap_id.as_u64())
}

/// SYS_IPC_RING_MAP: map a shared ring buffer into the caller's address space.
pub fn sys_ipc_ring_map(ring_handle: u64, out_ptr: u64) -> Result<u64, SyscallError> {
    crate::silo::enforce_cap_for_current_task(ring_handle)?;
    if out_ptr == 0 {
        return Err(SyscallError::Fault);
    }

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.process.capabilities.get() };
    let required = CapPermissions {
        read: true,
        write: true,
        execute: false,
        grant: false,
        revoke: false,
    };
    let cap = caps
        .get_with_permissions(CapId::from_raw(ring_handle), required)
        .ok_or(SyscallError::PermissionDenied)?;
    if cap.resource_type != ResourceType::SharedRing {
        return Err(SyscallError::BadHandle);
    }

    let ring_id = RingId::from_u64(cap.resource as u64);
    let ring_obj = shared_ring::get_ring(ring_id).ok_or(SyscallError::BadHandle)?;
    let frame_phys_addrs = ring_obj.frame_phys_addrs();
    let mapping_cap_ids = ring_obj.mapping_cap_ids().to_vec();
    let page_count = ring_obj.page_count();
    let map_size = page_count
        .checked_mul(4096)
        .ok_or(SyscallError::InvalidArgument)? as u64;

    let addr_space = task.process.address_space_arc();
    let base = addr_space
        .find_free_vma_range(
            super::mmap::MMAP_BASE,
            page_count,
            crate::memory::address_space::VmaPageSize::Small,
        )
        .ok_or(SyscallError::OutOfMemory)?;

    addr_space
        .map_shared_frames_with_cap_ids(
            base,
            &frame_phys_addrs,
            Some(&mapping_cap_ids),
            crate::memory::address_space::VmaFlags {
                readable: true,
                writable: true,
                executable: false,
                user_accessible: true,
            },
            crate::memory::address_space::VmaType::Anonymous,
        )
        .map_err(|_| SyscallError::OutOfMemory)?;

    let out = UserSliceWrite::new(out_ptr, core::mem::size_of::<u64>())?;
    out.copy_from(&base.to_ne_bytes());
    Ok(map_size)
}
