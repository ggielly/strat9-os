//! MADT (Multiple APIC Description Table) parsing
//!
//! Extracts Local APIC address, I/O APIC entries, and interrupt source overrides.

use super::SdtHeader;

/// MADT table header (after SDT header)
#[repr(C, packed)]
struct Madt {
    header: SdtHeader,
    local_apic_address: u32,
    flags: u32,
    // Variable-length entries follow
}

/// MADT entry header (common to all entry types)
#[repr(C, packed)]
struct MadtEntryHeader {
    entry_type: u8,
    length: u8,
}

/// MADT entry type 0: Processor Local APIC
#[repr(C, packed)]
#[allow(dead_code)]
struct MadtLocalApic {
    header: MadtEntryHeader,
    acpi_processor_id: u8,
    apic_id: u8,
    flags: u32,
}

/// MADT entry type 1: I/O APIC
#[repr(C, packed)]
struct MadtIoApic {
    header: MadtEntryHeader,
    io_apic_id: u8,
    _reserved: u8,
    io_apic_address: u32,
    global_system_interrupt_base: u32,
}

/// MADT entry type 2: Interrupt Source Override
#[repr(C, packed)]
struct MadtInterruptOverride {
    header: MadtEntryHeader,
    bus_source: u8,
    irq_source: u8,
    global_system_interrupt: u32,
    flags: u16,
}

/// I/O APIC entry extracted from MADT
#[derive(Clone, Copy, Debug)]
pub struct IoApicEntry {
    pub io_apic_id: u8,
    pub io_apic_address: u32,
    pub gsi_base: u32,
}

/// Interrupt Source Override extracted from MADT
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

/// Parsed MADT information
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

/// Local APIC entry extracted from MADT
#[derive(Clone, Copy, Debug)]
pub struct LocalApicEntry {
    pub acpi_processor_id: u8,
    pub apic_id: u8,
    pub flags: u32,
}

impl LocalApicEntry {
    /// Whether this processor is enabled (flags bit 0).
    pub fn enabled(&self) -> bool {
        self.flags & 1 != 0
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

/// Parse the MADT table from ACPI.
///
/// Returns `Some(MadtInfo)` with discovered hardware, or `None` if MADT not found.
pub fn parse_madt() -> Option<MadtInfo> {
    let madt_ptr = super::find_table(b"APIC")? as *const Madt;

    // SAFETY: find_table returned a valid HHDM-mapped pointer.
    // Use raw pointer arithmetic for packed struct fields to avoid UB.
    let local_apic_address =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*madt_ptr).local_apic_address)) };
    let flags = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*madt_ptr).flags)) };
    let total_length =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*madt_ptr).header.length)) }
            as usize;

    let mut info = MadtInfo {
        local_apic_address,
        flags,
        local_apics: [None; 32],
        local_apic_count: 0,
        io_apics: [None; 4],
        io_apic_count: 0,
        overrides: [None; 16],
        override_count: 0,
    };

    // Walk variable-length entries starting after the fixed MADT header
    let entries_start = madt_ptr as usize + core::mem::size_of::<Madt>();
    let entries_end = madt_ptr as usize + total_length;
    let mut offset = entries_start;

    while offset + 2 <= entries_end {
        let entry_header = offset as *const MadtEntryHeader;
        // SAFETY: within MADT table bounds
        let entry_type = unsafe { (*entry_header).entry_type };
        let entry_length = unsafe { (*entry_header).length } as usize;

        if entry_length < 2 || offset + entry_length > entries_end {
            break;
        }

        match entry_type {
            // Type 0: Processor Local APIC (we just log it, don't need it for single-core)
            0 => {
                if info.local_apic_count < info.local_apics.len() {
                    let entry = offset as *const MadtLocalApic;
                    // SAFETY: type 0 entry is at least 8 bytes, within bounds
                    let acpi_processor_id = unsafe { (*entry).acpi_processor_id };
                    let apic_id = unsafe { (*entry).apic_id };
                    let flags = unsafe {
                        core::ptr::read_unaligned(core::ptr::addr_of!((*entry).flags))
                    };

                    let local = LocalApicEntry {
                        acpi_processor_id,
                        apic_id,
                        flags,
                    };

                    // Only store enabled processors; keep disabled for diagnostics if needed.
                    if local.enabled() {
                        info.local_apics[info.local_apic_count] = Some(local);
                        info.local_apic_count += 1;
                    }
                }
            }

            // Type 1: I/O APIC
            1 => {
                if info.io_apic_count < info.io_apics.len() {
                    let entry = offset as *const MadtIoApic;
                    // SAFETY: type 1 entry is at least 12 bytes, within bounds
                    let io_apic_id = unsafe { (*entry).io_apic_id };
                    let io_apic_address = unsafe {
                        core::ptr::read_unaligned(core::ptr::addr_of!((*entry).io_apic_address))
                    };
                    let gsi_base = unsafe {
                        core::ptr::read_unaligned(core::ptr::addr_of!(
                            (*entry).global_system_interrupt_base
                        ))
                    };

                    info.io_apics[info.io_apic_count] = Some(IoApicEntry {
                        io_apic_id,
                        io_apic_address,
                        gsi_base,
                    });
                    info.io_apic_count += 1;
                }
            }

            // Type 2: Interrupt Source Override
            2 => {
                if info.override_count < info.overrides.len() {
                    let entry = offset as *const MadtInterruptOverride;
                    // SAFETY: type 2 entry is at least 10 bytes, within bounds
                    let bus_source = unsafe { (*entry).bus_source };
                    let irq_source = unsafe { (*entry).irq_source };
                    let gsi = unsafe {
                        core::ptr::read_unaligned(core::ptr::addr_of!(
                            (*entry).global_system_interrupt
                        ))
                    };
                    let flags =
                        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*entry).flags)) };

                    info.overrides[info.override_count] = Some(InterruptSourceOverride {
                        bus_source,
                        irq_source,
                        gsi,
                        flags,
                    });
                    info.override_count += 1;
                }
            }

            // Other types (NMI, LAPIC NMI, etc.) — skip for now
            _ => {}
        }

        offset += entry_length;
    }

    log::info!(
        "MADT: LAPIC addr=0x{:08X}, {} Local APIC(s), {} I/O APIC(s), {} override(s)",
        info.local_apic_address,
        info.local_apic_count,
        info.io_apic_count,
        info.override_count
    );

    for i in 0..info.local_apic_count {
        if let Some(ref entry) = info.local_apics[i] {
            log::info!(
                "  Local APIC #{}: acpi_id={}, apic_id={}, flags=0x{:08X}",
                i,
                entry.acpi_processor_id,
                entry.apic_id,
                entry.flags
            );
        }
    }

    for i in 0..info.io_apic_count {
        if let Some(ref entry) = info.io_apics[i] {
            log::info!(
                "  I/O APIC #{}: id={}, addr=0x{:08X}, GSI base={}",
                i,
                entry.io_apic_id,
                entry.io_apic_address,
                entry.gsi_base
            );
        }
    }

    for i in 0..info.override_count {
        if let Some(ref ovr) = info.overrides[i] {
            log::info!(
                "  Override: IRQ{} -> GSI{} (pol={}, trig={})",
                ovr.irq_source,
                ovr.gsi,
                ovr.polarity(),
                ovr.trigger_mode()
            );
        }
    }

    Some(info)
}
