//! IOMMU domain bookkeeping.
//!
//! The kernel parses DMAR (Intel) and IVRS (AMD) at boot but does not program
//! translation tables yet.  This module is the missing layer between a device
//! and the DMA allocator:
//!
//! * a [`Domain`] owns a bus/device/function and a set of IOVA mappings;
//! * `KernelDma::alloc_dma_for(domain, size)` allocates physical pages and
//!   records the mapping before returning the IOVA to the driver;
//! * when hardware translation is enabled, `activate()` programs the root
//!   table; until then the bookkeeping is still useful to reject double maps
//!   and to give hot-unplug a single place to revoke DMA.
//!
//! The actual root/context/PTE programming is architecture-specific and is
//! intentionally isolated behind `arch::iommu` (not implemented for x86_64
//! yet).  This file is the stable, testable API the rest of the kernel uses.

use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::sync::SpinLock;

/// Opaque domain identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainId(pub u16);

/// One IOVA → PA mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    pub iova: u64,
    pub phys: u64,
    pub len: u64,
    pub writable: bool,
}

/// A DMA domain attached to one PCI function.
#[derive(Debug)]
pub struct Domain {
    pub id: DomainId,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub mappings: Vec<Mapping>,
    pub active: bool,
}

static NEXT_DOMAIN: SpinLock<u16> = SpinLock::new(1);
static DOMAINS: SpinLock<Option<BTreeMap<DomainId, Domain>>> = SpinLock::new(None);
static HARDWARE_ENABLED: AtomicBool = AtomicBool::new(false);

fn with_domains<R>(f: impl FnOnce(&mut BTreeMap<DomainId, Domain>) -> R) -> R {
    let mut guard = DOMAINS.lock();
    let map = guard.get_or_insert_with(BTreeMap::new);
    f(map)
}

/// True when the firmware advertised an IOMMU (DMAR or IVRS).
pub fn firmware_present() -> bool {
    crate::acpi::get_dmar().is_some() || crate::acpi::get_ivrs().is_some()
}

/// True when translation is actually programmed.
pub fn enabled() -> bool {
    HARDWARE_ENABLED.load(Ordering::Acquire)
}

/// Create a domain for a PCI function.
pub fn create_domain(bus: u8, device: u8, function: u8) -> Option<DomainId> {
    let id = {
        let mut next = NEXT_DOMAIN.lock();
        let id = DomainId(*next);
        *next = (*next).wrapping_add(1);
        if *next == 0 {
            *next = 1;
        }
        id
    };
    with_domains(|map| {
        map.insert(
            id,
            Domain {
                id,
                bus,
                device,
                function,
                mappings: Vec::new(),
                active: false,
            },
        );
    });
    Some(id)
}

/// Record an IOVA mapping.  Fails on overlap.
pub fn map(domain: DomainId, iova: u64, phys: u64, len: u64, writable: bool) -> Result<(), &'static str> {
    if len == 0 {
        return Err("empty mapping");
    }
    let end = iova.checked_add(len).ok_or("IOVA overflow")?;
    with_domains(|map| {
        let Some(domain) = map.get_mut(&domain) else {
            return Err("unknown domain");
        };
        for existing in &domain.mappings {
            let existing_end = existing.iova.saturating_add(existing.len);
            if iova < existing_end && existing.iova < end {
                return Err("IOVA overlap");
            }
        }
        domain.mappings.push(Mapping {
            iova,
            phys,
            len,
            writable,
        });
        Ok(())
    })
}

/// Remove an IOVA mapping.
pub fn unmap(domain: DomainId, iova: u64) -> Result<(), &'static str> {
    with_domains(|map| {
        let Some(domain) = map.get_mut(&domain) else {
            return Err("unknown domain");
        };
        if let Some(pos) = domain.mappings.iter().position(|m| m.iova == iova) {
            domain.mappings.remove(pos);
            Ok(())
        } else {
            Err("mapping not found")
        }
    })
}

/// Translate an IOVA through the software table (debug/verification only).
pub fn translate(domain: DomainId, iova: u64) -> Option<u64> {
    with_domains(|map| {
        let domain = map.get(&domain)?;
        domain
            .mappings
            .iter()
            .find(|m| iova >= m.iova && iova < m.iova.saturating_add(m.len))
            .map(|m| m.phys + (iova - m.iova))
    })
}

/// Drop all mappings of a domain (hot-unplug).
pub fn teardown(domain: DomainId) -> bool {
    with_domains(|map| map.remove(&domain).is_some())
}

/// Number of active domains, for diagnostics.
pub fn domain_count() -> usize {
    with_domains(|map| map.len())
}

/// Enable hardware translation.  Returns `false` until the arch backend is
/// implemented; the software map remains authoritative for validation.
pub fn activate() -> bool {
    if !firmware_present() {
        return false;
    }
    // TODO(x86_64): build root/context tables from `DOMAINS`, program the
    // DMAR unit, invalidate caches, then set HARDWARE_ENABLED.
    false
}
