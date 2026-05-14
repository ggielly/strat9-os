//! Volume / block device syscall handlers.
//!
//! Implements sector-level read/write and info queries for storage volumes
//! accessed through capability handles.

use super::error::SyscallError;
use crate::{
    capability::{CapId, CapPermissions, ResourceType},
    hardware::storage::{
        ahci,
        virtio_block::{self, BlockDevice, SECTOR_SIZE},
    },
    memory::{UserSliceRead, UserSliceWrite},
    process::current_task_clone,
};

const MAX_SECTORS_PER_CALL: u64 = 256;

enum VolumeDeviceRef {
    Virtio(&'static virtio_block::VirtioBlockDevice),
    Ahci(&'static ahci::AhciController),
}

impl VolumeDeviceRef {
    fn sector_count(&self) -> u64 {
        match self {
            VolumeDeviceRef::Virtio(dev) => BlockDevice::sector_count(*dev),
            VolumeDeviceRef::Ahci(dev) => BlockDevice::sector_count(*dev),
        }
    }

    fn read_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), SyscallError> {
        match self {
            VolumeDeviceRef::Virtio(dev) => {
                BlockDevice::read_sector(*dev, sector, buf).map_err(SyscallError::from)
            }
            VolumeDeviceRef::Ahci(dev) => {
                BlockDevice::read_sector(*dev, sector, buf).map_err(SyscallError::from)
            }
        }
    }

    fn write_sector(&self, sector: u64, buf: &[u8]) -> Result<(), SyscallError> {
        match self {
            VolumeDeviceRef::Virtio(dev) => {
                BlockDevice::write_sector(*dev, sector, buf).map_err(SyscallError::from)
            }
            VolumeDeviceRef::Ahci(dev) => {
                BlockDevice::write_sector(*dev, sector, buf).map_err(SyscallError::from)
            }
        }
    }
}

fn resolve_volume_device(
    handle: u64,
    required: CapPermissions,
) -> Result<VolumeDeviceRef, SyscallError> {
    crate::silo::enforce_cap_for_current_task(handle)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let caps = unsafe { &*task.process.capabilities.get() };
    let cap = caps
        .get_with_permissions(CapId::from_raw(handle), required)
        .ok_or(SyscallError::PermissionDenied)?;
    if cap.resource_type != ResourceType::Volume {
        return Err(SyscallError::BadHandle);
    }

    let ptr = cap.resource as *const ();
    // Try Virtio first, then AHCI — compare stored pointer to the global device pointer.
    if let Some(dev) = virtio_block::get_device() {
        if dev as *const _ as *const () == ptr {
            return Ok(VolumeDeviceRef::Virtio(dev));
        }
    }
    if let Some(dev) = ahci::get_device() {
        if dev as *const _ as *const () == ptr {
            return Ok(VolumeDeviceRef::Ahci(dev));
        }
    }
    Err(SyscallError::BadHandle)
}

/// SYS_VOLUME_READ: read sectors from a block device.
pub fn sys_volume_read(
    handle: u64,
    sector: u64,
    buf_ptr: u64,
    sector_count: u64,
) -> Result<u64, SyscallError> {
    if sector_count == 0 || sector_count > MAX_SECTORS_PER_CALL {
        return Err(SyscallError::InvalidArgument);
    }

    let required = CapPermissions {
        read: true,
        write: false,
        execute: false,
        grant: false,
        revoke: false,
    };
    let device = resolve_volume_device(handle, required)?;
    let total_sectors = device.sector_count();
    if sector >= total_sectors || sector.saturating_add(sector_count) > total_sectors {
        return Err(SyscallError::InvalidArgument);
    }

    let mut kbuf = [0u8; SECTOR_SIZE];
    let probe_trace = sector == 0;

    for i in 0..sector_count {
        let cur_sector = sector.checked_add(i).ok_or(SyscallError::InvalidArgument)?;
        device.read_sector(cur_sector, &mut kbuf)?;
        let offset = (i as usize)
            .checked_mul(SECTOR_SIZE)
            .ok_or(SyscallError::InvalidArgument)?;
        let ptr = buf_ptr
            .checked_add(offset as u64)
            .ok_or(SyscallError::Fault)?;
        let user = UserSliceWrite::new(ptr, SECTOR_SIZE)?;
        user.copy_from(&kbuf);
        if probe_trace {
            crate::serial_println!(
                "[volume-read] copied to user handle={} sector={} ptr={:#x}",
                handle,
                cur_sector,
                ptr
            );
        }
    }

    Ok(sector_count)
}

/// SYS_VOLUME_WRITE: write sectors to a block device.
pub fn sys_volume_write(
    handle: u64,
    sector: u64,
    buf_ptr: u64,
    sector_count: u64,
) -> Result<u64, SyscallError> {
    if sector_count == 0 {
        return Ok(0);
    }
    if sector_count > MAX_SECTORS_PER_CALL {
        return Err(SyscallError::InvalidArgument);
    }

    let required = CapPermissions {
        read: false,
        write: true,
        execute: false,
        grant: false,
        revoke: false,
    };
    let device = resolve_volume_device(handle, required)?;
    let total_sectors = device.sector_count();
    if sector >= total_sectors || sector.saturating_add(sector_count) > total_sectors {
        return Err(SyscallError::InvalidArgument);
    }

    let mut kbuf = [0u8; SECTOR_SIZE];
    for i in 0..sector_count {
        let cur_sector = sector.checked_add(i).ok_or(SyscallError::InvalidArgument)?;
        let offset = (i as usize)
            .checked_mul(SECTOR_SIZE)
            .ok_or(SyscallError::InvalidArgument)?;
        let ptr = buf_ptr
            .checked_add(offset as u64)
            .ok_or(SyscallError::Fault)?;
        let user = UserSliceRead::new(ptr, SECTOR_SIZE)?;
        let data = user.read_to_vec();
        if data.len() != SECTOR_SIZE {
            return Err(SyscallError::InvalidArgument);
        }
        kbuf.copy_from_slice(&data);
        device.write_sector(cur_sector, &kbuf)?;
    }

    Ok(sector_count)
}

/// SYS_VOLUME_INFO: query total sector count of a volume device.
pub fn sys_volume_info(handle: u64) -> Result<u64, SyscallError> {
    let required = CapPermissions {
        read: true,
        write: false,
        execute: false,
        grant: false,
        revoke: false,
    };
    let device = resolve_volume_device(handle, required)?;
    Ok(device.sector_count())
}
