//! IOMMU syscall handlers (`SYS_IOMMU_*`, 440-449).
//!
//! P0 exposes only the software bookkeeping: domain creation, mapping,
//! unmapping, translation and a read-only summary.  `SYS_IOMMU_ACTIVATE`
//! reports whether a validated backend enabled translation; in P0 it always
//! returns `0`.
//!
//! Access is restricted to the `SYS` and `DRV` strate families and every
//! operation goes through an `IommuDomain` capability with explicit
//! [`DmaRights`].

use super::error::SyscallError;
use crate::{
    capability::{
        get_capability_manager, CapId, CapPermissions, DmaRights, ResourceType,
    },
    hardware::iommu::{self, DmaProt, DomainId, IommuError, Sbdf},
    memory::{UserSliceRead, UserSliceWrite},
    process::current_task_clone,
    silo::{self, StrateFamily},
};
use alloc::sync::Arc;
use strat9_abi::iommu::{IommuDomainInfo, IommuInfo, IommuMapDesc};

/// Only the system and driver strates may configure DMA isolation.
fn require_control() -> Result<(), SyscallError> {
    match silo::current_task_family() {
        Some(StrateFamily::SYS) | Some(StrateFamily::DRV) => Ok(()),
        _ => Err(SyscallError::PermissionDenied),
    }
}

fn map_error(err: IommuError) -> SyscallError {
    match err {
        IommuError::NotPresent | IommuError::BackendNotReady => SyscallError::NotSupported,
        IommuError::NoDomainSpace => SyscallError::OutOfMemory,
        IommuError::UnknownDomain | IommuError::NotMapped => SyscallError::NotFound,
        IommuError::InvalidRange | IommuError::Overlap | IommuError::AlreadyMapped => {
            SyscallError::InvalidArgument
        }
    }
}

/// Resolve an `IommuDomain` capability and enforce the required DMA rights.
fn domain_from_handle(handle: u64, required: DmaRights) -> Result<Arc<iommu::Domain>, SyscallError> {
    silo::enforce_cap_for_current_task(handle)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: the capability table belongs to the current process and this
    // syscall has exclusive access to its own task.
    let caps = unsafe { &*task.process.capabilities.get() };
    let cap = caps
        .get(CapId::from_raw(handle))
        .ok_or(SyscallError::BadHandle)?;
    if cap.resource_type != ResourceType::IommuDomain {
        return Err(SyscallError::BadHandle);
    }
    if !cap.dma.contains(required) {
        return Err(SyscallError::PermissionDenied);
    }
    iommu::get_domain(DomainId::from_raw(cap.resource as u16)).ok_or(SyscallError::BadHandle)
}

fn read_struct<T: Copy>(ptr: u64) -> Result<T, SyscallError> {
    if ptr == 0 {
        return Err(SyscallError::Fault);
    }
    let size = core::mem::size_of::<T>();
    // All IOMMU ABI structures are small fixed-size records.
    let mut raw = [0u8; 64];
    if size == 0 || size > raw.len() {
        return Err(SyscallError::InvalidArgument);
    }
    let slice = UserSliceRead::new(ptr, size)?;
    if slice.copy_to(&mut raw[..size]) != size {
        return Err(SyscallError::Fault);
    }
    // SAFETY: `raw[..size]` is fully initialized and `T` is `Copy`.
    Ok(unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const T) })
}

fn write_struct<T: Copy>(ptr: u64, value: &T) -> Result<(), SyscallError> {
    if ptr == 0 {
        return Err(SyscallError::Fault);
    }
    let slice = UserSliceWrite::new(ptr, core::mem::size_of::<T>())?;
    // SAFETY: reading `size_of::<T>()` bytes from a valid `&T`.
    let bytes = unsafe {
        core::slice::from_raw_parts(value as *const T as *const u8, core::mem::size_of::<T>())
    };
    slice.copy_from(bytes);
    Ok(())
}

/// SYS_IOMMU_INFO (440): write the platform summary.
pub fn sys_iommu_info(out_ptr: u64) -> Result<u64, SyscallError> {
    require_control()?;
    let discovery = crate::arch::iommu::discovery();
    let info = IommuInfo {
        present: discovery.present as u32,
        enabled: iommu::enabled() as u32,
        units: discovery.units,
        domains: iommu::domain_count() as u32,
        host_address_width: discovery.host_address_width,
        intr_remap: discovery.intr_remap as u8,
        x2apic_opt_out: discovery.x2apic_opt_out as u8,
        ready: discovery.ready as u8,
    };
    write_struct(out_ptr, &info)?;
    Ok(0)
}

/// SYS_IOMMU_DOMAIN_CREATE (441): bind a domain to a PCI function.
pub fn sys_iommu_domain_create(sbdf_raw: u64) -> Result<u64, SyscallError> {
    require_control()?;
    if sbdf_raw > u32::MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    let sbdf = Sbdf::from_u32(sbdf_raw as u32);
    let domain = iommu::domain_for(sbdf).map_err(map_error)?;
    let task = match current_task_clone() {
        Some(task) => task,
        None => {
            iommu::release_domain(&domain);
            return Err(SyscallError::PermissionDenied);
        }
    };

    let cap = get_capability_manager().create_dma_capability(
        ResourceType::IommuDomain,
        domain.id().raw() as usize,
        CapPermissions::read_write(),
        DmaRights::all(),
    );
    // SAFETY: as above: the table is owned by the calling process.
    let handle = unsafe { (&mut *task.process.capabilities.get()).insert(cap) };
    Ok(handle.as_u64())
}

/// SYS_IOMMU_DOMAIN_DESTROY (442): revoke all mappings of a domain.
pub fn sys_iommu_domain_destroy(handle: u64) -> Result<u64, SyscallError> {
    require_control()?;
    let domain = domain_from_handle(handle, DmaRights::none())?;
    if iommu::teardown(domain.id()) {
        Ok(0)
    } else {
        Err(SyscallError::NotFound)
    }
}

/// SYS_IOMMU_MAP (443): map a physical range into a domain.
pub fn sys_iommu_map(handle: u64, desc_ptr: u64) -> Result<u64, SyscallError> {
    require_control()?;
    let domain = domain_from_handle(handle, DmaRights { map: true, unmap: false, read: false, write: false, irq: false })?;
    let desc: IommuMapDesc = read_struct(desc_ptr)?;
    if desc.reserved != 0 {
        return Err(SyscallError::InvalidArgument);
    }
    if desc.prot > u8::MAX as u32 {
        return Err(SyscallError::InvalidArgument);
    }
    let prot = DmaProt::from_bits(desc.prot as u8).ok_or(SyscallError::InvalidArgument)?;
    if prot.is_empty() {
        return Err(SyscallError::InvalidArgument);
    }
    domain
        .map(desc.iova, desc.phys, desc.len, prot)
        .map_err(map_error)?;
    Ok(0)
}

/// SYS_IOMMU_UNMAP (444): remove mappings covering a range.
pub fn sys_iommu_unmap(handle: u64, iova: u64, len: u64) -> Result<u64, SyscallError> {
    require_control()?;
    let domain = domain_from_handle(handle, DmaRights { map: false, unmap: true, read: false, write: false, irq: false })?;
    let removed = domain.unmap(iova, len).map_err(map_error)?;
    Ok(removed as u64)
}

/// SYS_IOMMU_TRANSLATE (445): software IOVA -> physical translation.
pub fn sys_iommu_translate(handle: u64, iova: u64) -> Result<u64, SyscallError> {
    require_control()?;
    let domain = domain_from_handle(handle, DmaRights::none())?;
    domain
        .translate(iova)
        .map(|translation| translation.phys)
        .ok_or(SyscallError::NotFound)
}

/// SYS_IOMMU_ACTIVATE (446): try to enable hardware translation.
pub fn sys_iommu_activate() -> Result<u64, SyscallError> {
    require_control()?;
    Ok(iommu::activate() as u64)
}

/// SYS_IOMMU_DOMAIN_INFO (449): write one domain's identity and counters.
pub fn sys_iommu_domain_info(handle: u64, out_ptr: u64) -> Result<u64, SyscallError> {
    require_control()?;
    let domain = domain_from_handle(handle, DmaRights::none())?;
    let sbdf = domain.sbdf();
    let info = IommuDomainInfo {
        domain_id: domain.id().raw(),
        segment: sbdf.segment,
        bus: sbdf.bus,
        device: sbdf.device,
        function: sbdf.function,
        reserved: 0,
        generation: domain.generation(),
        mappings: domain.mapping_count() as u32,
        refs: domain.refs() as u32,
    };
    write_struct(out_ptr, &info)?;
    Ok(0)
}
