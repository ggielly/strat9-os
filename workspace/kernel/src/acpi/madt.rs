//! Support for the MADT ACPI table,
//! which includes interrupt and multicore info.
//! Inspired by Theseus OS.

use super::sdt::Sdt;
use zerocopy::{FromBytes, FromZeroes};

pub const MADT_SIGNATURE: &[u8; 4] = b"APIC";

/// The fixed-size components of the MADT ACPI table.
#[derive(Clone, Copy, Debug, FromBytes, FromZeroes)]
#[repr(C, packed)]
pub struct MadtAcpiTable {
    pub header: Sdt,
    pub local_apic_phys_addr: u32,
    pub flags: u32,
}

impl MadtAcpiTable {
    /// Finds the MADT and returns a reference to it.
    pub fn get() -> Option<&'static MadtAcpiTable> {
        unsafe { super::find_table(MADT_SIGNATURE).map(|ptr| &*(ptr as *const MadtAcpiTable)) }
    }
}

/// A MADT entry record, which precedes each actual MADT entry.
#[derive(Clone, Copy, Debug, FromBytes, FromZeroes)]
#[repr(C, packed)]
struct EntryRecord {
    typ: u8,
    size: u8,
}

/// MADT Local APIC entry (Type 0)
#[derive(Copy, Clone, Debug, FromBytes, FromZeroes)]
#[repr(C, packed)]
pub struct MadtLocalApic {
    _header: EntryRecord,
    pub processor: u8,
    pub apic_id: u8,
    pub flags: u32,
}

/// MADT I/O APIC entry (Type 1)
#[derive(Copy, Clone, Debug, FromBytes, FromZeroes)]
#[repr(C, packed)]
pub struct MadtIoApic {
    _header: EntryRecord,
    pub id: u8,
    _reserved: u8,
    pub address: u32,
    pub gsi_base: u32,
}

/// MADT Interrupt Source Override (Type 2)
#[derive(Copy, Clone, Debug, FromBytes, FromZeroes)]
#[repr(C, packed)]
pub struct MadtIntSrcOverride {
    _header: EntryRecord,
    pub bus_source: u8,
    pub irq_source: u8,
    pub gsi: u32,
    pub flags: u16,
}

pub struct MadtInfo {
    pub local_apic_address: u32,
    pub flags: u32,
    pub local_apics: [Option<LocalApicEntry>; 32],
    pub local_apic_count: usize,
    pub io_apics: [Option<IoApicEntry>; 4],
    pub io_apic_count: usize,
    pub overrides: [Option<InterruptSourceOverride>; 16],
    pub override_count: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct LocalApicEntry {
    pub processor: u8,
    pub apic_id: u8,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct IoApicEntry {
    pub id: u8,
    pub address: u32,
    pub gsi_base: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct InterruptSourceOverride {
    pub bus_source: u8,
    pub irq_source: u8,
    pub gsi: u32,
    pub flags: u16,
}

impl InterruptSourceOverride {
    /// Get the polarity from the flags field.
    /// 0b00 = conforms to bus, 0b01 = active high, 0b11 = active low
    pub fn polarity(&self) -> u8 {
        (self.flags & 0x03) as u8
    }

    /// Get the trigger mode from the flags field.
    /// 0b00 = conforms to bus, 0b01 = edge, 0b11 = level
    pub fn trigger_mode(&self) -> u8 {
        ((self.flags >> 2) & 0x03) as u8
    }
}

impl MadtInfo {
    /// Look up an IRQ's GSI and polarity/trigger, applying source overrides.
    ///
    /// Returns (gsi, polarity, trigger_mode) for the given legacy IRQ.
    /// If no override exists, returns (irq as gsi, 0 = conform, 0 = conform).
    pub fn irq_to_gsi(&self, irq: u8) -> (u32, u8, u8) {
        for i in 0..self.override_count {
            if let Some(ref ovr) = self.overrides[i] {
                if ovr.irq_source == irq {
                    return (ovr.gsi, ovr.polarity(), ovr.trigger_mode());
                }
            }
        }
        // No override: GSI == IRQ, conform to bus defaults
        (irq as u32, 0, 0)
    }
}

pub fn parse_madt() -> Option<MadtInfo> {
    let madt_ptr = super::find_table(MADT_SIGNATURE)? as *const MadtAcpiTable;
    let madt = unsafe { &*madt_ptr };
    if madt.header.length < core::mem::size_of::<MadtAcpiTable>() as u32 {
        log::error!("ACPI: MADT length smaller than header");
        return None;
    }
    let madt_len = madt.header.length as usize;
    let mut sum: u8 = 0;
    for i in 0..madt_len {
        sum = sum.wrapping_add(unsafe { *((madt_ptr as *const u8).add(i)) });
    }
    if sum != 0 {
        log::error!("ACPI: MADT checksum failed");
        return None;
    }

    let mut info = MadtInfo {
        local_apic_address: madt.local_apic_phys_addr,
        flags: madt.flags,
        local_apics: [None; 32],
        local_apic_count: 0,
        io_apics: [None; 4],
        io_apic_count: 0,
        overrides: [None; 16],
        override_count: 0,
    };

    let total_length = madt_len;
    let entries_start = madt_ptr as usize + core::mem::size_of::<MadtAcpiTable>();
    let entries_end = madt_ptr as usize + total_length;
    let mut offset = entries_start;

    while offset + 2 <= entries_end {
        let record = unsafe { &*(offset as *const EntryRecord) };
        let entry_type = record.typ;
        let entry_size = record.size as usize;

        if entry_size < 2 || offset + entry_size > entries_end {
            break;
        }

        match entry_type {
            0 => {
                if info.local_apic_count < info.local_apics.len() {
                    let entry = unsafe { &*(offset as *const MadtLocalApic) };
                    info.local_apics[info.local_apic_count] = Some(LocalApicEntry {
                        processor: entry.processor,
                        apic_id: entry.apic_id,
                        flags: entry.flags,
                    });
                    info.local_apic_count += 1;
                }
            }
            1 => {
                if info.io_apic_count < info.io_apics.len() {
                    let entry = unsafe { &*(offset as *const MadtIoApic) };
                    info.io_apics[info.io_apic_count] = Some(IoApicEntry {
                        id: entry.id,
                        address: entry.address,
                        gsi_base: entry.gsi_base,
                    });
                    info.io_apic_count += 1;
                }
            }
            2 => {
                if info.override_count < info.overrides.len() {
                    let entry = unsafe { &*(offset as *const MadtIntSrcOverride) };
                    info.overrides[info.override_count] = Some(InterruptSourceOverride {
                        bus_source: entry.bus_source,
                        irq_source: entry.irq_source,
                        gsi: entry.gsi,
                        flags: entry.flags,
                    });
                    info.override_count += 1;
                }
            }
            _ => {}
        }
        offset += entry_size;
    }

    Some(info)
}
