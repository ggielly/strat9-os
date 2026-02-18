//! ACPI table parsing (RSDP, RSDT, XSDT)
//!
//! Parses ACPI tables to discover hardware configuration.
//! The RSDP virtual address is provided by Limine via KernelArgs.

pub mod madt;

use crate::memory;
use core::sync::atomic::{AtomicU64, Ordering};

/// Stored RSDP virtual address (set during init)
static RSDP_VADDR: AtomicU64 = AtomicU64::new(0);

/// RSDP revision (0 = ACPI 1.0, 2+ = ACPI 2.0+)
static RSDP_REVISION: AtomicU64 = AtomicU64::new(0);

/// RSDP (Root System Description Pointer) — ACPI 1.0
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

/// System Description Table Header (common to all ACPI tables)
#[repr(C, packed)]
pub struct SdtHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
}

/// Validate checksum over a byte region
fn validate_checksum(ptr: *const u8, len: usize) -> bool {
    let mut sum: u8 = 0;
    for i in 0..len {
        // SAFETY: caller guarantees ptr..ptr+len is valid readable memory
        sum = sum.wrapping_add(unsafe { *ptr.add(i) });
    }
    sum == 0
}

/// Initialize the ACPI subsystem.
///
/// `rsdp_vaddr` is the virtual address of the RSDP provided by Limine.
/// Returns `Ok(true)` if ACPI is available, `Ok(false)` if RSDP address is 0,
/// or `Err` if validation fails.
pub fn init(rsdp_vaddr: u64) -> Result<bool, &'static str> {
    if rsdp_vaddr == 0 {
        log::warn!("ACPI: No RSDP provided by bootloader");
        return Ok(false);
    }

    let rsdp = rsdp_vaddr as *const Rsdp;

    // Validate signature "RSD PTR "
    // SAFETY: rsdp_vaddr is provided by Limine and points to valid ACPI data in HHDM
    let sig = unsafe { (*rsdp).signature };
    if &sig != b"RSD PTR " {
        return Err("ACPI: Invalid RSDP signature");
    }

    // Validate RSDP checksum (first 20 bytes)
    if !validate_checksum(rsdp as *const u8, 20) {
        return Err("ACPI: RSDP checksum failed");
    }

    // SAFETY: rsdp_vaddr is validated above
    let revision = unsafe { (*rsdp).revision };

    // For ACPI 2.0+, validate extended checksum
    if revision >= 2 {
        let rsdp2 = rsdp_vaddr as *const Rsdp2;
        // SAFETY: revision >= 2 guarantees the extended structure is present
        let length = unsafe { (*rsdp2).length } as usize;
        if !validate_checksum(rsdp as *const u8, length) {
            return Err("ACPI: RSDP extended checksum failed");
        }
    }

    RSDP_VADDR.store(rsdp_vaddr, Ordering::Relaxed);
    RSDP_REVISION.store(revision as u64, Ordering::Relaxed);

    log::info!("ACPI: RSDP validated (revision {})", revision);

    Ok(true)
}

/// Find an ACPI table by its 4-byte signature.
///
/// Walks the XSDT (ACPI 2.0+) or RSDT (ACPI 1.0) to find the table.
/// Returns a pointer to the SDT header, or None if not found.
///
/// # Safety
/// The returned pointer is valid as long as ACPI tables remain mapped (they do under HHDM).
pub fn find_table(signature: &[u8; 4]) -> Option<*const SdtHeader> {
    let rsdp_vaddr = RSDP_VADDR.load(Ordering::Relaxed);
    if rsdp_vaddr == 0 {
        return None;
    }

    let revision = RSDP_REVISION.load(Ordering::Relaxed);

    if revision >= 2 {
        // Use XSDT (64-bit pointers)
        let rsdp2 = rsdp_vaddr as *const Rsdp2;
        // SAFETY: RSDP was validated in init()
        let xsdt_phys = unsafe { (*rsdp2).xsdt_address };
        if xsdt_phys == 0 {
            // Fall through to RSDT
        } else {
            // Ensure XSDT is mapped
            memory::paging::ensure_identity_map(xsdt_phys);
            let xsdt_virt = memory::phys_to_virt(xsdt_phys);
            let xsdt_header = xsdt_virt as *const SdtHeader;

            // Validate XSDT
            // SAFETY: xsdt_virt is mapped via HHDM
            let xsdt_len = unsafe { (*xsdt_header).length } as usize;
            let header_size = core::mem::size_of::<SdtHeader>();
            if xsdt_len <= header_size {
                return None;
            }

            // Number of 64-bit entries after the header
            let entry_count = (xsdt_len - header_size) / 8;
            let entries_ptr = (xsdt_virt + header_size as u64) as *const u64;

            for i in 0..entry_count {
                // SAFETY: within bounds of XSDT table
                let entry_phys = unsafe { core::ptr::read_unaligned(entries_ptr.add(i)) };
                if entry_phys == 0 {
                    continue;
                }
                // Ensure the table we are checking is mapped
                memory::paging::ensure_identity_map(entry_phys);
                let entry_virt = memory::phys_to_virt(entry_phys);
                let entry_header = entry_virt as *const SdtHeader;
                // SAFETY: entry_virt is mapped via HHDM
                let entry_sig = unsafe { (*entry_header).signature };
                if &entry_sig == signature {
                    return Some(entry_header);
                }
            }
            return None;
        }
    }

    // Use RSDT (32-bit pointers)
    let rsdp = rsdp_vaddr as *const Rsdp;
    // SAFETY: RSDP was validated in init()
    let rsdt_phys = unsafe { (*rsdp).rsdt_address } as u64;
    if rsdt_phys == 0 {
        return None;
    }

    // Ensure RSDT is mapped
    memory::paging::ensure_identity_map(rsdt_phys);
    let rsdt_virt = memory::phys_to_virt(rsdt_phys);
    let rsdt_header = rsdt_virt as *const SdtHeader;

    // SAFETY: rsdt_virt is mapped via HHDM
    let rsdt_len = unsafe { (*rsdt_header).length } as usize;
    let header_size = core::mem::size_of::<SdtHeader>();
    if rsdt_len <= header_size {
        return None;
    }

    // Number of 32-bit entries after the header
    let entry_count = (rsdt_len - header_size) / 4;
    let entries_ptr = (rsdt_virt + header_size as u64) as *const u32;

    for i in 0..entry_count {
        // SAFETY: within bounds of RSDT table
        let entry_phys = unsafe { core::ptr::read_unaligned(entries_ptr.add(i)) } as u64;
        if entry_phys == 0 {
            continue;
        }
        // Ensure the table we are checking is mapped
        memory::paging::ensure_identity_map(entry_phys);
        let entry_virt = memory::phys_to_virt(entry_phys);
        let entry_header = entry_virt as *const SdtHeader;
        // SAFETY: entry_virt is mapped via HHDM
        let entry_sig = unsafe { (*entry_header).signature };
        if &entry_sig == signature {
            return Some(entry_header);
        }
    }

    None
}
