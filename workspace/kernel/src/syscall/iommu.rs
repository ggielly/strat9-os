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
    hardware::iommu::{self, DmaProt, Domain, DomainId, FaultPolicy, IommuError, Sbdf},
    memory::{UserSliceRead, UserSliceWrite},
    process::current_task_clone,
    silo::{self, DmaQuota, StrateFamily},
};
use alloc::{sync::Arc, vec, vec::Vec};
use strat9_abi::iommu::{
    IommuDomainInfo, IommuFault, IommuGroupInfo, IommuInfo, IommuMapDesc, IommuMsi,
    IommuReservedRegion, IommuStats,
};

/// Maximum number of descriptors accepted by one batch syscall.
const MAX_BATCH: u64 = 64;

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
        IommuError::Reserved => SyscallError::AccessDenied,
        IommuError::Quiesced => SyscallError::Again,
        IommuError::Unsupported => SyscallError::NotSupported,
        IommuError::Hardware => SyscallError::IoError,
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

fn read_array<T: Copy>(ptr: u64, count: u64) -> Result<Vec<T>, SyscallError> {
    if ptr == 0 || count == 0 || count > MAX_BATCH {
        return Err(SyscallError::InvalidArgument);
    }
    let size = core::mem::size_of::<T>();
    let bytes = (count as usize)
        .checked_mul(size)
        .ok_or(SyscallError::InvalidArgument)?;
    let slice = UserSliceRead::new(ptr, bytes)?;
    let mut raw = vec![0u8; bytes];
    if slice.copy_to(&mut raw) != bytes {
        return Err(SyscallError::Fault);
    }
    let mut out = Vec::with_capacity(count as usize);
    for chunk in raw.chunks_exact(size) {
        // SAFETY: `chunk` is exactly `size_of::<T>()` bytes and `T: Copy`.
        out.push(unsafe { core::ptr::read_unaligned(chunk.as_ptr() as *const T) });
    }
    Ok(out)
}

fn write_array<T: Copy>(ptr: u64, entries: &[T]) -> Result<(), SyscallError> {
    if entries.is_empty() {
        return Ok(());
    }
    let bytes = entries.len() * core::mem::size_of::<T>();
    let slice = UserSliceWrite::new(ptr, bytes)?;
    // SAFETY: the slice covers a valid `&[T]`.
    let raw = unsafe {
        core::slice::from_raw_parts(entries.as_ptr() as *const u8, bytes)
    };
    slice.copy_from(raw);
    Ok(())
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

fn quota_error() -> SyscallError {
    SyscallError::OutOfMemory
}

/// Enforce `dma_max_domains` before creating a new domain.
fn enforce_domain_quota(sid: Option<u32>, quota: Option<DmaQuota>) -> Result<(), SyscallError> {
    if let (Some(sid), Some(quota)) = (sid, quota) {
        if quota.max_domains != 0 {
            let (domains, _) = iommu::owner_usage(sid);
            if domains as u32 >= quota.max_domains {
                return Err(quota_error());
            }
        }
    }
    Ok(())
}

/// Enforce `dma_max_bytes` and the IOVA window for one mapping.
fn enforce_map_quota(
    domain: &Domain,
    quota: Option<DmaQuota>,
    iova: u64,
    len: u64,
) -> Result<(), SyscallError> {
    let Some(quota) = quota else {
        return Ok(());
    };
    if quota.iova_base != 0 && iova < quota.iova_base {
        return Err(SyscallError::AccessDenied);
    }
    if quota.iova_limit != 0 {
        let end = iova.checked_add(len).ok_or(SyscallError::InvalidArgument)?;
        if end > quota.iova_limit {
            return Err(SyscallError::AccessDenied);
        }
    }
    if quota.max_bytes != 0 {
        let used = domain
            .owner()
            .map(|sid| iommu::owner_usage(sid).1)
            .unwrap_or(0);
        let end = used.checked_add(len).ok_or(quota_error())?;
        if end > quota.max_bytes {
            return Err(quota_error());
        }
    }
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
    let sid = silo::current_task_sid();
    let quota = silo::current_task_dma_quota();
    enforce_domain_quota(sid, quota)?;
    let policy = quota
        .map(|quota| quota.fault_policy)
        .unwrap_or(FaultPolicy::Log);
    let domain = iommu::domain_for_owned(sbdf, sid, policy).map_err(map_error)?;
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
    let quota = silo::current_task_dma_quota();
    enforce_map_quota(&domain, quota, desc.iova, desc.len)?;
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

fn backend_error(error: crate::arch::iommu::IommuError) -> SyscallError {
    use crate::arch::iommu::IommuError as Backend;
    match error {
        Backend::NotPresent | Backend::NotReady | Backend::Unsupported => {
            SyscallError::NotSupported
        }
        Backend::Hardware | Backend::InvalidDomain => SyscallError::IoError,
    }
}

/// SYS_PCI_MSI_ALLOC (455): allocate an IRTE for a device vector.
pub fn sys_pci_msi_alloc(
    sbdf_raw: u64,
    vector: u64,
    out_ptr: u64,
) -> Result<u64, SyscallError> {
    require_control()?;
    if sbdf_raw > u32::MAX as u64 || vector > u8::MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    let sbdf = Sbdf::from_u32(sbdf_raw as u32);
    let allocation = crate::arch::iommu::allocate_msi(sbdf, vector as u8)
        .map_err(backend_error)?;
    let msi = IommuMsi {
        cookie: allocation.cookie,
        vector: vector as u32,
        address: allocation.address,
        data: allocation.data,
        reserved: 0,
    };
    write_struct(out_ptr, &msi)?;
    Ok(0)
}

/// SYS_PCI_MSI_FREE (456): release an IRTE.
pub fn sys_pci_msi_free(cookie: u64) -> Result<u64, SyscallError> {
    require_control()?;
    if cookie > u32::MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    crate::arch::iommu::free_msi(cookie as u32).map_err(backend_error)?;
    Ok(0)
}

/// SYS_IOMMU_FAULT_NEXT (447): pop one fault record.
pub fn sys_iommu_fault_next(out_ptr: u64) -> Result<u64, SyscallError> {
    require_control()?;
    let Some(fault) = iommu::next_fault() else {
        return Ok(0);
    };
    let abi = IommuFault {
        seq: fault.seq,
        timestamp_ns: fault.timestamp_ns,
        iova: fault.iova,
        domain_id: fault.domain.raw(),
        segment: fault.sbdf.segment,
        bus: fault.sbdf.bus,
        device: fault.sbdf.device,
        function: fault.sbdf.function,
        reason: fault.reason.as_raw(),
        action: fault.action.as_raw(),
        reserved: [0; 3],
        prot: fault.access.bits() as u32,
        owner: fault.owner.unwrap_or(u32::MAX),
    };
    write_struct(out_ptr, &abi)?;
    Ok(1)
}

/// SYS_IOMMU_DOMAIN_CTL (448): quiesce / resume / detach / policy.
pub fn sys_iommu_domain_ctl(
    handle: u64,
    command: u64,
    argument: u64,
) -> Result<u64, SyscallError> {
    require_control()?;
    let domain = domain_from_handle(handle, DmaRights::none())?;
    let id = domain.id();
    match command {
        0 => iommu::quiesce(id).map_err(map_error)?,
        1 => iommu::resume(id).map_err(map_error)?,
        2 => {
            if !iommu::detach(id) {
                return Err(SyscallError::NotFound);
            }
        }
        3 => iommu::refill_fault_budget(id, argument.min(u32::MAX as u64) as u32),
        4 => {
            if argument > 3 {
                return Err(SyscallError::InvalidArgument);
            }
            domain.set_fault_policy(FaultPolicy::from_raw(argument as u8));
        }
        _ => return Err(SyscallError::InvalidArgument),
    }
    Ok(0)
}

/// SYS_IOMMU_MAP_BATCH (450): map several ranges in one call.
pub fn sys_iommu_map_batch(
    handle: u64,
    desc_ptr: u64,
    count: u64,
) -> Result<u64, SyscallError> {
    require_control()?;
    let domain = domain_from_handle(
        handle,
        DmaRights {
            map: true,
            unmap: true,
            read: false,
            write: false,
            irq: false,
        },
    )?;
    let descs: Vec<IommuMapDesc> = read_array(desc_ptr, count)?;
    let quota = silo::current_task_dma_quota();

    let mut total = 0u64;
    for desc in &descs {
        if desc.reserved != 0 || desc.prot > u8::MAX as u32 {
            return Err(SyscallError::InvalidArgument);
        }
        if DmaProt::from_bits(desc.prot as u8)
            .map(|prot| prot.is_empty())
            .unwrap_or(true)
        {
            return Err(SyscallError::InvalidArgument);
        }
        if let Some(quota) = quota {
            if quota.iova_base != 0 && desc.iova < quota.iova_base {
                return Err(SyscallError::AccessDenied);
            }
            if quota.iova_limit != 0 {
                let end = desc
                    .iova
                    .checked_add(desc.len)
                    .ok_or(SyscallError::InvalidArgument)?;
                if end > quota.iova_limit {
                    return Err(SyscallError::AccessDenied);
                }
            }
        }
        total = total.checked_add(desc.len).ok_or_else(quota_error)?;
    }
    if let Some(quota) = quota {
        if quota.max_bytes != 0 {
            let used = domain
                .owner()
                .map(|sid| iommu::owner_usage(sid).1)
                .unwrap_or(0u64);
            if used.saturating_add(total) > quota.max_bytes {
                return Err(quota_error());
            }
        }
    }

    let mut mapped: Vec<(u64, u64)> = Vec::with_capacity(descs.len());
    for desc in &descs {
        let prot = DmaProt::from_bits(desc.prot as u8).unwrap_or(DmaProt::READ_WRITE);
        if let Err(err) = domain.map(desc.iova, desc.phys, desc.len, prot) {
            // Roll back the descriptors already committed by this batch.
            for (iova, len) in mapped.iter().rev() {
                let _ = domain.unmap(*iova, *len);
            }
            return Err(map_error(err));
        }
        mapped.push((desc.iova, desc.len));
    }
    Ok(mapped.len() as u64)
}

/// SYS_IOMMU_UNMAP_BATCH (451): unmap several ranges in one call.
pub fn sys_iommu_unmap_batch(
    handle: u64,
    desc_ptr: u64,
    count: u64,
) -> Result<u64, SyscallError> {
    require_control()?;
    let domain = domain_from_handle(
        handle,
        DmaRights {
            map: false,
            unmap: true,
            read: false,
            write: false,
            irq: false,
        },
    )?;
    let descs: Vec<IommuMapDesc> = read_array(desc_ptr, count)?;
    let mut removed = 0u64;
    for desc in &descs {
        removed = removed
            .saturating_add(domain.unmap(desc.iova, desc.len).map_err(map_error)? as u64);
    }
    Ok(removed)
}

/// SYS_IOMMU_STATS (452): global counters.
pub fn sys_iommu_stats(out_ptr: u64) -> Result<u64, SyscallError> {
    require_control()?;
    let stats = iommu::stats();
    let abi = IommuStats {
        domains_created: stats.domains_created,
        domains_destroyed: stats.domains_destroyed,
        maps: stats.maps,
        unmaps: stats.unmaps,
        faults: stats.faults,
        dropped_faults: stats.dropped_faults,
        activations: stats.activations,
        domains_live: iommu::domain_count() as u64,
    };
    write_struct(out_ptr, &abi)?;
    Ok(0)
}

/// SYS_IOMMU_GROUPS (453): coarse IOMMU groups.
pub fn sys_iommu_groups(
    out_ptr: u64,
    max_entries: u64,
) -> Result<u64, SyscallError> {
    require_control()?;
    if max_entries == 0 {
        return Ok(0);
    }
    let groups = iommu::groups();
    let count = groups.len().min(max_entries as usize);
    let entries: Vec<IommuGroupInfo> = groups
        .iter()
        .take(count)
        .map(|group| IommuGroupInfo {
            id: group.id,
            segment: group.segment,
            bus: group.bus,
            device_count: group.devices.len().min(u8::MAX as usize) as u8,
            reserved: 0,
        })
        .collect();
    write_array(out_ptr, &entries)?;
    Ok(count as u64)
}

/// SYS_IOMMU_RESERVED (454): firmware-reserved regions.
pub fn sys_iommu_reserved(
    out_ptr: u64,
    max_entries: u64,
) -> Result<u64, SyscallError> {
    require_control()?;
    if max_entries == 0 {
        return Ok(0);
    }
    let regions = iommu::reserved_regions();
    let count = regions.len().min(max_entries as usize);
    let entries: Vec<IommuReservedRegion> = regions
        .iter()
        .take(count)
        .map(|region| IommuReservedRegion {
            base: region.base,
            limit: region.limit,
            segment: region.segment,
            reserved: 0,
            device_count: region.devices.len() as u32,
            all_buses: region.all_bus_from.is_some() as u32,
            reserved2: 0,
        })
        .collect();
    write_array(out_ptr, &entries)?;
    Ok(count as u64)
}
