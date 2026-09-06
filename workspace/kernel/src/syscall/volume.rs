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

    fn read_sectors(&self, sector: u64, count: u16, buf: &mut [u8]) -> Result<(), SyscallError> {
        match self {
            VolumeDeviceRef::Virtio(dev) => {
                BlockDevice::read_sectors(*dev, sector, count, buf).map_err(SyscallError::from)
            }
            VolumeDeviceRef::Ahci(dev) => {
                BlockDevice::read_sectors(*dev, sector, count, buf).map_err(SyscallError::from)
            }
        }
    }

    fn write_sectors(&self, sector: u64, count: u16, buf: &[u8]) -> Result<(), SyscallError> {
        match self {
            VolumeDeviceRef::Virtio(dev) => {
                BlockDevice::write_sectors(*dev, sector, count, buf).map_err(SyscallError::from)
            }
            VolumeDeviceRef::Ahci(dev) => {
                BlockDevice::write_sectors(*dev, sector, count, buf).map_err(SyscallError::from)
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
    // Try Virtio first, then AHCI : compare stored pointer to the global device pointer.
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

    let count = sector_count as u16;
    let nbytes = (count as usize) * SECTOR_SIZE;

    // Allocate a single kernel buffer for the full transfer, then copy to user
    // in one shot. This eliminates the per-sector alloc/free overhead inside
    // the driver (see virtio_block.rs do_request / ahci.rs submit_cmd).
    let mut kbuf = alloc::vec![0u8; nbytes];
    let buf_slice = &mut kbuf[..nbytes];
    device.read_sectors(sector, count, buf_slice)?;

    let user = UserSliceWrite::new(buf_ptr, nbytes)?;
    user.copy_from(buf_slice);

    if sector == 0 {
        crate::serial_println!(
            "[volume-read] bulk handle={} sector={} count={} ptr={:#x}",
            handle,
            sector,
            sector_count,
            buf_ptr
        );
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

    let count = sector_count as u16;
    let nbytes = (count as usize) * SECTOR_SIZE;

    // Read the full user buffer into a single kernel buffer, then issue
    // a single multi-sector write. This eliminates the per-sector
    // UserSliceRead + driver alloc/free overhead.
    let user = UserSliceRead::new(buf_ptr, nbytes)?;
    let kbuf = user.read_to_vec();
    if kbuf.len() != nbytes {
        return Err(SyscallError::InvalidArgument);
    }
    device.write_sectors(sector, count, &kbuf)?;

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
