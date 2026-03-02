//! Support for MCFG (PCI Express MMCONFIG) ACPI table.

use super::sdt::Sdt;
use alloc::vec::Vec;
use zerocopy::FromBytes;

pub const MCFG_SIGNATURE: &[u8; 4] = b"MCFG";

#[derive(Clone, Copy, Debug, FromBytes)]
#[repr(C, packed)]
pub struct Mcfg {
    pub header: Sdt,
    pub _reserved: u64,
}

impl Mcfg {
    /// Finds the MCFG and returns a reference to it.
    pub fn get() -> Option<&'static Mcfg> {
        unsafe { super::find_table(MCFG_SIGNATURE).map(|ptr| &*(ptr as *const Mcfg)) }
    }
}

#[derive(Clone, Copy, Debug, FromBytes)]
#[repr(C, packed)]
struct McfgAllocation {
    base_address: u64,
    segment_group: u16,
    start_bus: u8,
    end_bus: u8,
    _reserved: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct McfgEntry {
    pub base_address: u64,
    pub segment_group: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

impl McfgEntry {
    pub fn bus_count(&self) -> u16 {
        (self.end_bus as u16).saturating_sub(self.start_bus as u16) + 1
    }
}

#[derive(Debug)]
pub struct McfgInfo {
    pub entries: Vec<McfgEntry>,
}

impl McfgInfo {
    pub fn entry_for_segment(&self, segment_group: u16) -> Option<&McfgEntry> {
        self.entries
            .iter()
            .find(|e| e.segment_group == segment_group)
    }
}

fn is_aligned_1m(addr: u64) -> bool {
    (addr & ((1 << 20) - 1)) == 0
}

fn should_skip_entry(entry: &McfgEntry) -> bool {
    if entry.base_address == 0 {
        return true;
    }
    if entry.start_bus > entry.end_bus {
        return true;
    }
    if !is_aligned_1m(entry.base_address) {
        return true;
    }
    false
}

fn overlaps(a: &McfgEntry, b: &McfgEntry) -> bool {
    if a.segment_group != b.segment_group {
        return false;
    }
    !(a.end_bus < b.start_bus || b.end_bus < a.start_bus)
}

pub fn parse_mcfg() -> Option<McfgInfo> {
    let mcfg_ptr = super::find_table(MCFG_SIGNATURE)? as *const Mcfg;
    let mcfg = unsafe { &*mcfg_ptr };

    let header_len = mcfg.header.length as usize;
    let min_len = core::mem::size_of::<Mcfg>();
    if header_len < min_len {
        log::error!("ACPI: MCFG length too small: {}", header_len);
        return None;
    }

    let alloc_len = core::mem::size_of::<McfgAllocation>();
    let entries_bytes = header_len - min_len;
    if entries_bytes % alloc_len != 0 {
        log::warn!(
            "ACPI: MCFG payload not aligned to allocation size (payload={}, alloc={})",
            entries_bytes,
            alloc_len
        );
    }

    let mut entries = Vec::new();
    let mut offset = mcfg_ptr as usize + min_len;
    let end = mcfg_ptr as usize + header_len;

    while offset + alloc_len <= end {
        let alloc = unsafe { core::ptr::read_unaligned(offset as *const McfgAllocation) };
        let candidate = McfgEntry {
            base_address: alloc.base_address,
            segment_group: alloc.segment_group,
            start_bus: alloc.start_bus,
            end_bus: alloc.end_bus,
        };
        if should_skip_entry(&candidate) {
            log::warn!(
                "ACPI: MCFG entry skipped (seg={} ecam={:#x} buses={}..{})",
                candidate.segment_group,
                candidate.base_address,
                candidate.start_bus,
                candidate.end_bus
            );
            offset += alloc_len;
            continue;
        }
        if entries.iter().any(|e| overlaps(e, &candidate)) {
            log::warn!(
                "ACPI: MCFG overlapping entry skipped (seg={} ecam={:#x} buses={}..{})",
                candidate.segment_group,
                candidate.base_address,
                candidate.start_bus,
                candidate.end_bus
            );
            offset += alloc_len;
            continue;
        }
        entries.push(candidate);
        offset += alloc_len;
    }

    if entries.is_empty() {
        log::warn!("ACPI: MCFG present but no usable allocation entries");
        return None;
    }

    Some(McfgInfo { entries })
}
