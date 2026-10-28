//! Wire formats for the IOMMU syscalls (`SYS_IOMMU_*`, 440-449).
//!
//! All structures are `repr(C)` and contain only fixed-width integers, so the
//! same layout is valid for the kernel and for user-space drivers.

/// Summary returned by `SYS_IOMMU_INFO`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IommuInfo {
    /// 1 when a DMAR/IVRS table was found.
    pub present: u32,
    /// 1 when hardware translation is actually enabled.
    pub enabled: u32,
    /// Number of remapping hardware units.
    pub units: u32,
    /// Number of live software domains.
    pub domains: u32,
    /// Host address width in bits.
    pub host_address_width: u8,
    /// 1 when interrupt remapping is advertised.
    pub intr_remap: u8,
    /// 1 when firmware asked to keep x2APIC disabled.
    pub x2apic_opt_out: u8,
    /// 1 when the backend may be activated.
    pub ready: u8,
}

/// One map request for `SYS_IOMMU_MAP`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IommuMapDesc {
    /// Device-visible address (must be page-aligned).
    pub iova: u64,
    /// Physical base address (must be page-aligned).
    pub phys: u64,
    /// Length in bytes (multiple of 4096).
    pub len: u64,
    /// `DmaProt` bits: bit 0 = device read, bit 1 = device write.
    pub prot: u32,
    /// Reserved, must be zero.
    pub reserved: u32,
}

/// Domain identity returned by `SYS_IOMMU_DOMAIN_INFO`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IommuDomainInfo {
    pub domain_id: u16,
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    /// Reserved, must be zero.
    pub reserved: u8,
    /// Monotonic map/unmap generation.
    pub generation: u64,
    /// Number of live mappings.
    pub mappings: u32,
    /// Logical reference count.
    pub refs: u32,
}

/// One fault record returned by `SYS_IOMMU_FAULT_NEXT`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IommuFault {
    pub seq: u64,
    pub timestamp_ns: u64,
    pub iova: u64,
    pub domain_id: u16,
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    /// 0=read, 1=write, 2=permission, 3=out-of-range.
    pub reason: u8,
    /// 0=logged, 1=notified, 2=owner revoked, 3=panic.
    pub action: u8,
    /// Reserved, must be zero.
    pub reserved: [u8; 3],
    /// Access bits of the faulting access.
    pub prot: u32,
    /// Owning silo SID, or `u32::MAX` for kernel domains.
    pub owner: u32,
}

/// One MSI message allocated through interrupt remapping.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IommuMsi {
    /// Opaque cookie for `SYS_PCI_MSI_FREE`.
    pub cookie: u32,
    /// Vector encoded in the IRTE.
    pub vector: u32,
    /// Message address to program in the device.
    pub address: u64,
    /// Message data (0 for an IRTE doorbell).
    pub data: u32,
    pub reserved: u32,
}

/// Global counters returned by `SYS_IOMMU_STATS`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IommuStats {
    pub domains_created: u64,
    pub domains_destroyed: u64,
    pub maps: u64,
    pub unmaps: u64,
    pub faults: u64,
    pub dropped_faults: u64,
    pub activations: u64,
    /// Number of live domains at the time of the call.
    pub domains_live: u64,
}

/// One coarse IOMMU group returned by `SYS_IOMMU_GROUPS`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IommuGroupInfo {
    pub id: u32,
    pub segment: u16,
    pub bus: u8,
    pub device_count: u8,
    pub reserved: u32,
}

/// One firmware-reserved region returned by `SYS_IOMMU_RESERVED`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IommuReservedRegion {
    pub base: u64,
    pub limit: u64,
    pub segment: u16,
    pub reserved: u16,
    pub device_count: u32,
    /// 1 when at least one whole bus range is covered.
    pub all_buses: u32,
    pub reserved2: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Wire sizes are part of the ABI: keep them stable.
    #[test]
    fn wire_sizes_are_stable() {
        assert_eq!(core::mem::size_of::<IommuInfo>(), 20);
        assert_eq!(core::mem::size_of::<IommuMapDesc>(), 32);
        assert_eq!(core::mem::size_of::<IommuDomainInfo>(), 24);
        assert_eq!(core::mem::size_of::<IommuFault>(), 48);
        assert_eq!(core::mem::size_of::<IommuStats>(), 64);
        assert_eq!(core::mem::size_of::<IommuGroupInfo>(), 12);
        assert_eq!(core::mem::size_of::<IommuReservedRegion>(), 32);
        assert_eq!(core::mem::size_of::<IommuMsi>(), 24);
    }

    #[test]
    fn map_desc_roundtrip() {
        let desc = IommuMapDesc {
            iova: 0x1_0000_0000,
            phys: 0x2000,
            len: 0x2000,
            prot: 3,
            reserved: 0,
        };
        assert_eq!(desc.prot, 3);
        assert_eq!(desc.len, 0x2000);
    }
}
