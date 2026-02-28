//! ACPI (Advanced Configuration and Power Interface) support.
//! Inspired by Theseus OS, MaestroOS, Aero, and Redox.
//!
//! Features:
//! - RSDP/RSDT/XSDT parsing
//! - MADT (interrupts, APICs)
//! - FADT (power management, DSDT)
//! - HPET (timers)
//! - MCFG (PCIe MMCONFIG)
//! - DMAR (IOMMU)
//! - WAET (VM optimization hints)
//! - BGRT (boot graphics)
//! - SLIT (NUMA distances)

pub mod bgrt;
pub mod dmar;
pub mod fadt;
pub mod hpet;
pub mod madt;
pub mod mcfg;
pub mod rsdt;
pub mod slit;
pub mod sdt;
pub mod waet;

use crate::{memory, sync::SpinLock};
use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use sdt::Sdt;

/// Stored RSDP virtual address (set during init)
static RSDP_VADDR: AtomicU64 = AtomicU64::new(0);

/// RSDP revision (0 = ACPI 1.0, 2+ = ACPI 2.0+)
static RSDP_REVISION: AtomicU64 = AtomicU64::new(0);

/// RSDP (Root System Descriptor Pointer) — ACPI 1.0
#[repr(C, packed)]
struct Rsdp {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
}

/// RSDP extended — ACPI 2.0+
#[repr(C, packed)]
struct Rsdp2 {
    base: Rsdp,
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    _reserved: [u8; 3],
}

/// Table storage to keep track of discovered ACPI tables
pub struct AcpiTables {
    tables: BTreeMap<[u8; 4], Vec<*const Sdt>>,
}

unsafe impl Send for AcpiTables {}
unsafe impl Sync for AcpiTables {}

static ACPI_TABLES: SpinLock<AcpiTables> = SpinLock::new(AcpiTables {
    tables: BTreeMap::new(),
});

/// ACPI initialization status
static ACPI_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Get ACPI revision
pub fn revision() -> u8 {
    RSDP_REVISION.load(Ordering::Relaxed) as u8
}

/// Check if ACPI is initialized
pub fn is_available() -> bool {
    ACPI_INITIALIZED.load(Ordering::Relaxed)
}

/// Get RSDP address
pub fn rsdp_address() -> u64 {
    RSDP_VADDR.load(Ordering::Relaxed)
}

/// Get BGRT table (boot graphics)
pub fn get_bgrt() -> Option<&'static bgrt::Bgrt> {
    bgrt::Bgrt::get()
}

/// Get SLIT table (NUMA distances)
pub fn get_slit() -> Option<&'static slit::Slit> {
    slit::Slit::get()
}

/// Get HPET table
pub fn get_hpet() -> Option<&'static hpet::HpetAcpiTable> {
    hpet::HpetAcpiTable::get()
}

/// Get FADT table
pub fn get_fadt() -> Option<&'static fadt::Fadt> {
    fadt::Fadt::get()
}

/// Get MADT table
pub fn get_madt() -> Option<&'static madt::MadtAcpiTable> {
    madt::MadtAcpiTable::get()
}

/// Get MCFG table
pub fn get_mcfg() -> Option<&'static mcfg::Mcfg> {
    mcfg::Mcfg::get()
}

/// Initialize the ACPI subsystem.
pub fn init(rsdp_vaddr: u64) -> Result<bool, &'static str> {
    if rsdp_vaddr == 0 {
        log::warn!("ACPI: No RSDP provided by bootloader");
        return Ok(false);
    }

    let rsdp = rsdp_vaddr as *const Rsdp;

    // Validate signature "RSD PTR "
    let sig = unsafe { (*rsdp).signature };
    if &sig != b"RSD PTR " {
        return Err("ACPI: Invalid RSDP signature");
    }

    // Validate RSDP checksum (first 20 bytes)
    if !validate_checksum(rsdp as *const u8, 20) {
        return Err("ACPI: RSDP checksum failed");
    }

    let revision = unsafe { (*rsdp).revision };

    // For ACPI 2.0+, validate extended checksum
    if revision >= 2 {
        let rsdp2 = rsdp_vaddr as *const Rsdp2;
        let length = unsafe { (*rsdp2).length } as usize;
        if !validate_checksum(rsdp as *const u8, length) {
            return Err("ACPI: RSDP extended checksum failed");
        }
    }

    RSDP_VADDR.store(rsdp_vaddr, Ordering::Relaxed);
    RSDP_REVISION.store(revision as u64, Ordering::Relaxed);

    log::info!("ACPI: RSDP validated (revision {})", revision);

    // Discover all tables via root RSDT/XSDT pointed by RSDP.
    discover_tables(rsdp_vaddr, revision)?;

    // Mark ACPI as initialized
    ACPI_INITIALIZED.store(true, Ordering::SeqCst);

    Ok(true)
}

fn validate_checksum(ptr: *const u8, len: usize) -> bool {
    let mut sum: u8 = 0;
    for i in 0..len {
        sum = sum.wrapping_add(unsafe { *ptr.add(i) });
    }
    sum == 0
}

fn discover_tables(rsdp_vaddr: u64, revision: u8) -> Result<(), &'static str> {
    let rxsdt = rsdt::RsdtXsdt::from_rsdp(rsdp_vaddr, revision)
        .ok_or("ACPI: Failed to find RSDT/XSDT from RSDP")?;
    let root_sdt = rxsdt.sdt();
    if root_sdt.length < core::mem::size_of::<Sdt>() as u32 {
        return Err("ACPI: Root SDT has invalid length");
    }
    let root_phys = memory::virt_to_phys(root_sdt as *const Sdt as u64);
    let root_len = root_sdt.length;
    memory::paging::ensure_identity_map_range(root_phys, root_len as u64);
    let root_sig = root_sdt.signature;
    let root_sig_str = core::str::from_utf8(&root_sig).unwrap_or("????");
    log::info!(
        "ACPI: root table {} phys={:#x} len={}",
        root_sig_str,
        root_phys,
        root_len
    );

    let mut acpi_tables = ACPI_TABLES.lock();
    let mut discovered = 0usize;

    for sdt_phys in rxsdt.addresses() {
        if sdt_phys == 0 {
            continue;
        }

        let (signature, sdt) = validate_sdt_at_phys(sdt_phys)?;

        // Keep all tables with the same signature (e.g., multiple SSDT).
        acpi_tables
            .tables
            .entry(signature)
            .or_insert_with(Vec::new)
            .push(sdt);
        discovered += 1;

        log::debug!(
            "ACPI: Discovered table {:?} at phys {:#x}",
            core::str::from_utf8(&signature).unwrap_or("????"),
            sdt_phys
        );
    }

    let unique = acpi_tables.tables.len();
    log::info!(
        "ACPI: discovered {} table entries ({} unique signatures)",
        discovered,
        unique
    );

    Ok(())
}

fn validate_sdt_at_phys(sdt_phys: u64) -> Result<([u8; 4], *const Sdt), &'static str> {
    // Map header first to read SDT length.
    memory::paging::ensure_identity_map_range(sdt_phys, core::mem::size_of::<Sdt>() as u64);
    let sdt_virt = memory::phys_to_virt(sdt_phys);
    let sdt = sdt_virt as *const Sdt;
    let length = unsafe { (*sdt).length as usize };
    if length < core::mem::size_of::<Sdt>() {
        return Err("ACPI: SDT length smaller than header");
    }
    memory::paging::ensure_identity_map_range(sdt_phys, length as u64);
    if !validate_checksum(sdt as *const u8, length) {
        return Err("ACPI: SDT checksum failed");
    }
    let signature = unsafe { (*sdt).signature };
    Ok((signature, sdt))
}

/// Find the first ACPI table by its 4-byte signature.
pub fn find_table(signature: &[u8; 4]) -> Option<*const Sdt> {
    let acpi_tables = ACPI_TABLES.lock();
    acpi_tables
        .tables
        .get(signature)
        .and_then(|tables| tables.first().copied())
}

/// Find all ACPI tables with the given 4-byte signature.
pub fn find_tables(signature: &[u8; 4]) -> Option<Vec<*const Sdt>> {
    let acpi_tables = ACPI_TABLES.lock();
    acpi_tables.tables.get(signature).cloned()
}

/// Get a typed reference to an ACPI table.
pub fn get_table<T>(signature: &[u8; 4]) -> Option<&'static T> {
    let ptr = find_table(signature)?;
    let sdt = unsafe { &*ptr };
    if (sdt.length as usize) < core::mem::size_of::<T>() {
        return None;
    }
    Some(unsafe { &*(ptr as *const T) })
}
