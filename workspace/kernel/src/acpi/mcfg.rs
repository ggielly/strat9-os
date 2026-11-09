/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

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
    /// Performs the bus count operation.
    pub fn bus_count(&self) -> u16 {
        (self.end_bus as u16).saturating_sub(self.start_bus as u16) + 1
    }
}

#[derive(Debug)]
pub struct McfgInfo {
    pub entries: Vec<McfgEntry>,
}

impl McfgInfo {
    /// Performs the entry for segment operation.
    pub fn entry_for_segment(&self, segment_group: u16) -> Option<&McfgEntry> {
        self.entries
            .iter()
            .find(|e| e.segment_group == segment_group)
    }
}

/// Returns whether aligned 1m.
fn is_aligned_1m(addr: u64) -> bool {
    (addr & ((1 << 20) - 1)) == 0
}

/// Performs the should skip entry operation.
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

/// Performs the overlaps operation.
fn overlaps(a: &McfgEntry, b: &McfgEntry) -> bool {
    if a.segment_group != b.segment_group {
        return false;
    }
    !(a.end_bus < b.start_bus || b.end_bus < a.start_bus)
}

/// Parses mcfg.
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
