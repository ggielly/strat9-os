//! Intel VT-d discovery (x86_64).
//!
//! P0 only parses the DMAR and records a [`Discovery`] summary.  The root
//! table, context entries and invalidation queues are intentionally **not**
//! programmed here: that is the P1 milestone, gated on a validated backend.
//!
//! Keeping the skeleton in place now gives the rest of the kernel a stable
//! `arch::iommu::backend()` to query, and lets the MSI path refuse an
//! un-encodable x2APIC destination instead of silently mis-routing interrupts.

use super::super::iommu::{Backend, Discovery, IommuError};
use crate::{
    hardware::iommu::DomainId,
    sync::SpinLock,
};

/// VT-d backend placeholder.
struct VtdSkeleton;

static VTD: VtdSkeleton = VtdSkeleton;
static DISCOVERY: SpinLock<Option<Discovery>> = SpinLock::new(None);

impl Backend for VtdSkeleton {
    fn name(&self) -> &'static str {
        "vt-d"
    }

    fn is_ready(&self) -> bool {
        // Deliberately false in P0: no root/context table is programmed yet.
        false
    }

    fn activate(&self) -> Result<(), IommuError> {
        Err(IommuError::NotReady)
    }

    fn invalidate_domain(&self, _domain: DomainId) {}

    fn interrupt_remapping(&self) -> bool {
        DISCOVERY
            .lock()
            .map(|discovery| discovery.intr_remap)
            .unwrap_or(false)
    }
}

/// Parse the DMAR and cache the summary.
pub fn init() -> Discovery {
    let discovery = probe();
    *DISCOVERY.lock() = Some(discovery);

    if discovery.present {
        // Log the first unit's register base: it is the most useful single
        // fact when comparing against an ESXi dump or a hardware datasheet.
        if let Some(dmar) = crate::acpi::get_dmar() {
            match dmar.drhds() {
                Ok(units) => {
                    for unit in &units {
                        log::info!(
                            "[IOMMU] DRHD seg={} base={:#x} include_all={} scopes={}",
                            unit.segment,
                            unit.register_base,
                            unit.include_pci_all(),
                            unit.scopes.len()
                        );
                    }
                }
                Err(err) => log::warn!("[IOMMU] DMAR DRHD parse error: {:?}", err),
            }
        }
    }

    discovery
}

/// Summary recorded by [`init`], or an absent summary before init.
pub fn discovery() -> Discovery {
    DISCOVERY
        .lock()
        .as_ref()
        .copied()
        .unwrap_or_else(Discovery::absent)
}

/// Backend handle, available only when a DMAR was found.
pub fn backend() -> Option<&'static dyn Backend> {
    let present = DISCOVERY
        .lock()
        .as_ref()
        .map(|discovery| discovery.present)
        .unwrap_or(false);
    if present {
        Some(&VTD)
    } else {
        None
    }
}

fn probe() -> Discovery {
    let Some(dmar) = crate::acpi::get_dmar() else {
        return Discovery::absent();
    };

    let units = dmar.drhds();
    let rmrrs = dmar.rmrrs();
    let atsrs = dmar.atsrs();

    let unit_count = units.as_ref().map(|v| v.len()).unwrap_or(0) as u32;
    let rmrr_count = rmrrs.as_ref().map(|v| v.len()).unwrap_or(0) as u32;
    let atsr_count = atsrs.as_ref().map(|v| v.len()).unwrap_or(0) as u32;

    Discovery {
        present: true,
        // P0: never claim readiness before the tables are actually programmed.
        ready: false,
        backend: "vt-d",
        units: unit_count,
        rmrrs: rmrr_count,
        atsrs: atsr_count,
        host_address_width: dmar.host_address_width(),
        intr_remap: dmar.intr_remap_supported(),
        x2apic_opt_out: dmar.x2apic_opt_out(),
    }
}
