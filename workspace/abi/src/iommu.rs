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

#[cfg(test)]
mod tests {
    use super::*;

    // Wire sizes are part of the ABI: keep them stable.
    #[test]
    fn wire_sizes_are_stable() {
        assert_eq!(core::mem::size_of::<IommuInfo>(), 20);
        assert_eq!(core::mem::size_of::<IommuMapDesc>(), 32);
        assert_eq!(core::mem::size_of::<IommuDomainInfo>(), 24);
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
