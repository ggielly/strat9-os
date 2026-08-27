//! IVRS (I/O Virtualization Reporting Structure) : AMD IOMMU ACPI table.
//!
//! Defines the structures and parser for the ACPI IVRS table (signature `IVRS`),
//! which describes AMD IOMMU hardware units, their capabilities, and which PCI
//! devices they serve.
//!
//! Reference: AMD I/O Virtualization Technology (IOMMU) Specification,
//!   revisions 3.00+ (sections 3.1–3.4).
//!   https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/specifications/48882_IOMMU.pdf
//!
//! ## Table layout
//!
//! ```text
//! ┌──────────────────────────────┐
//! │  SDT header ("IVRS")         │ 48 B (standard ACPI)
//! ├──────────────────────────────┤
//! │  IVInfo (u16)                │
//! │  Reserved (u8)               │
//! │  Flags (u8)                  │
//! │  Total length (u16)          │
//! │  Device entry count (u16)    │
//! │  Entry offset (u16)          │
//! ├──────────────────────────────┤
//! │  IVHD block (Type 0x10/11)   │ variable
//! │  ├── header                  │
//! │  ├── device entries ...      │
//! │  └── padding                 │
//! ├──────────────────────────────┤
//! │  IVMD block (Type 0x20/22)   │ variable
//! └──────────────────────────────┘
//! ```

use super::sdt::Sdt;
use zerocopy::FromBytes;

/// ACPI signature for the IVRS table.
pub const IVRS_SIGNATURE: &[u8; 4] = b"IVRS";

//  IVRS table header (fixed portion after SDT)

/// Fixed header of the IVRS ACPI table (AMD IOMMU).
#[derive(Clone, Copy, Debug, FromBytes)]
#[repr(C, packed)]
pub struct IvrsHeader {
    pub header: Sdt,
    /// Virtualisation information.
    pub ivinfo: u16,
    pub _reserved1: u8,
    /// Flags: bit 0 = Draint, bit 1 = Coherent.
    pub flags: u8,
    /// Total length of the IVRS table including all IVHD/IVMD blocks.
    pub total_length: u16,
    /// Number of device entries across all IVHD blocks.
    pub dev_entry_count: u16,
    /// Byte offset from the start of the table to the first IVHD/IVMD entry.
    pub entry_offset: u16,
}

impl IvrsHeader {
    /// Locate and return the IVRS table from ACPI.
    pub fn get() -> Option<&'static Self> {
        unsafe { super::find_table(IVRS_SIGNATURE).map(|ptr| &*(ptr as *const Self)) }
    }

    /// Check whether the Draint flag is set (all devices behind IOMMU).
    pub fn has_draint(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Check whether the Coherent flag is set (I/O coherent).
    pub fn is_coherent(&self) -> bool {
        self.flags & 0x02 != 0
    }

    /// Return the number of IVHD/IVMD entries.
    pub fn ivhd_ivmd_count(&self) -> usize {
        // Not directly stored; caller must walk entries.
        0
    }

    /// Iterate over all IVHD/IVMD blocks and device entries within IVHD blocks.
    pub fn entries(&self) -> IvrsEntryIter<'_> {
        IvrsEntryIter {
            base: self as *const Self as *const u8,
            offset: self.entry_offset as usize,
            total_len: self.header.length as usize,
            _phantom: core::marker::PhantomData,
        }
    }
}

/// IVHD (I/O Virtualization Hardware Definition) block type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IvhdType {
    /// Legacy IVHD block (type 0x10).
    LegacyV10 = 0x10,
    /// Extended IVHD block (type 0x11, adds MMIO base).
    ExtendedV11 = 0x11,
}

/// IVHD block flags.
#[derive(Clone, Copy, Debug)]
pub struct IvhdFlags(u8);

impl IvhdFlags {
    pub fn iotlb_support(&self) -> bool {
        self.0 & 0x01 != 0
    }
    pub fn prefetch_support(&self) -> bool {
        self.0 & 0x02 != 0
    }
    pub fn ppr_support(&self) -> bool {
        self.0 & 0x04 != 0
    }
}

/// Parsed IVHD (I/O Virtualization Hardware Definition) block.
///
/// Describes one AMD IOMMU hardware unit and the devices behind it.
#[derive(Clone, Debug)]
pub struct IvhdBlock {
    /// IVHD type (0x10 = legacy, 0x11 = extended).
    pub typ: IvhdType,
    /// Flags.
    pub flags: IvhdFlags,
    /// Length of this IVHD block (including device entries).
    pub length: u16,
    /// PCI device ID of the IOMMU itself.
    pub device_id: u16,
    /// Offset into PCI capability space for the IOMMU capabilities.
    pub capability_offset: u16,
    /// I/O APIC ID associated with this IOMMU.
    pub ioapic_id: u8,
    /// Physical base address of the IOMMU registers.
    pub iommu_base: u64,
    /// PCI segment group.
    pub pci_segment: u16,
    /// MMIO base address (only for extended type 0x11).
    pub mmio_base: Option<u64>,
    /// Raw pointer to the first device entry in this block.
    device_entries_off: u64,
    /// Length available for device entries.
    device_entries_len: usize,
}

/// Common prefix of all IVHD headers (20 bytes, shared by type 0x10 and 0x11).
#[derive(Clone, Copy, Debug, FromBytes)]
#[repr(C, packed)]
struct RawIvhdCommon {
    typ: u8,
    flags: u8,
    length: u16,
    device_id: u16,
    capability_offset: u16,
    ioapic_id: u8,
    _reserved: u8,
    iommu_base: u64,
    pci_segment: u16,
}

/// Raw IVHD type 0x11 (extended) appends an MMIO base after the common prefix.
#[derive(Clone, Copy, Debug, FromBytes)]
#[repr(C, packed)]
struct RawIvhdTail11 {
    mmio_base: u64,
}

/// IVMD (I/O Virtualisation Memory Definition) block.
///
/// Describes a region of physical memory that the IOMMU must treat
/// specially (e.g., reserved for interrupt remapping, or excluded from
/// translation).
#[derive(Clone, Copy, Debug)]
pub struct IvmdBlock {
    /// IVMD type (0x20 = reserved, 0x22 = non-translated).
    pub typ: u8,
    /// Flags.
    pub flags: u8,
    /// Length of this IVMD block.
    pub length: u16,
    /// Device ID associated with this memory region.
    pub device_id: u16,
    /// PCI segment group.
    pub pci_segment: u16,
    /// IOMMU base address (for exclusion ranges).
    pub iommu_base: u64,
    /// Reserved memory region: starting physical address.
    pub start_addr: u64,
    /// Reserved memory region: length.
    pub length_bytes: u64,
}

/// Raw IVMD block header : 24 bytes.
#[derive(Clone, Copy, Debug, FromBytes)]
#[repr(C, packed)]
struct RawIvmd {
    typ: u8,
    flags: u8,
    length: u16,
    device_id: u16,
    pci_segment: u16,
    iommu_base: u64,
    start_addr: u64,
    length_bytes: u64,
}

/// A device entry inside an IVHD block.
///
/// Each entry describes a PCI device (or range of devices) that belongs
/// to this IOMMU.
#[derive(Clone, Copy, Debug)]
pub struct IvhdDeviceEntry {
    /// Raw entry type byte (see AMD IOMMU spec §3.4).
    pub raw_type: u8,
    /// Device ID (BDF format: bus:device:function).
    pub device_id: u16,
    /// Data field (meaning depends on entry type).
    pub data: [u8; 4],
    /// Extended data (alias/extended device ID, if present).
    pub ext_data: Option<u16>,
    /// Is this a range entry (covering multiple consecutive device IDs)?
    pub is_range: bool,
    /// For range entries: the number of devices covered (1..256).
    pub range_count: u8,
}

/// Raw header common to all device entry types.
#[derive(Clone, Copy, Debug, FromBytes)]
#[repr(C, packed)]
struct RawDevEntryHdr {
    raw_type: u8,
    device_id: u16,
}

/// Iterator over IVHD/IVMD blocks and device entries therein.
pub struct IvrsEntryIter<'a> {
    base: *const u8,
    offset: usize,
    total_len: usize,
    _phantom: core::marker::PhantomData<&'a ()>,
}

impl<'a> IvrsEntryIter<'a> {
    /// Return the next block (IVHD or IVMD).
    pub fn next_block(&mut self) -> Option<IvrsBlock> {
        if self.offset >= self.total_len {
            return None;
        }
        let ptr = unsafe { self.base.add(self.offset) };
        let typ = unsafe { *ptr };

        match typ {
            0x10 | 0x11 => {
                // Use the common prefix to read shared fields, then cast for
                // the extended tail if needed.
                let common = unsafe { &*(ptr as *const RawIvhdCommon) };
                let block_len = common.length as usize;

                // Header sizes per AMD IOMMU spec §3.2.1:
                //   Type 0x10 (legacy): 24 bytes
                //   Type 0x11 (extended): 24 B + 8 B (MMIO base addr) = 32 bytes
                const IVHD10_HEADER_SIZE: usize = 24;
                const IVHD11_HEADER_SIZE: usize = 32;
                let actual_hdr_len = if typ == 0x10 {
                    IVHD10_HEADER_SIZE
                } else {
                    IVHD11_HEADER_SIZE
                };

                let entry_off = self.offset + actual_hdr_len;
                let entry_len = block_len.saturating_sub(actual_hdr_len);

                let mmio = if typ == 0x11 {
                    // MMIO base is at offset 24 in the extended header.
                    let tail = unsafe { &*(ptr.add(IVHD10_HEADER_SIZE) as *const RawIvhdTail11) };
                    Some(tail.mmio_base)
                } else {
                    None
                };

                let block = IvrsBlock::Ivhd(IvhdBlock {
                    typ: if typ == 0x10 {
                        IvhdType::LegacyV10
                    } else {
                        IvhdType::ExtendedV11
                    },
                    flags: IvhdFlags(common.flags),
                    length: common.length,
                    device_id: common.device_id,
                    capability_offset: common.capability_offset,
                    ioapic_id: common.ioapic_id,
                    iommu_base: common.iommu_base,
                    pci_segment: common.pci_segment,
                    mmio_base: mmio,
                    device_entries_off: entry_off as u64,
                    device_entries_len: entry_len,
                });

                self.offset += block_len;
                Some(block)
            }
            0x20 | 0x22 => {
                let raw = unsafe { &*(ptr as *const RawIvmd) };
                let block = IvrsBlock::Ivmd(IvmdBlock {
                    typ: raw.typ,
                    flags: raw.flags,
                    length: raw.length,
                    device_id: raw.device_id,
                    pci_segment: raw.pci_segment,
                    iommu_base: raw.iommu_base,
                    start_addr: raw.start_addr,
                    length_bytes: raw.length_bytes,
                });
                self.offset += raw.length as usize;
                Some(block)
            }
            _ => {
                // Unknown type : skip 4 bytes and continue.
                self.offset += 4;
                self.next_block()
            }
        }
    }
}

/// A block inside the IVRS table: either an IVHD (IOMMU definition) or
/// an IVMD (reserved memory definition).
#[derive(Clone, Debug)]
pub enum IvrsBlock {
    /// I/O Virtualization Hardware Definition : one IOMMU unit.
    Ivhd(IvhdBlock),
    /// I/O Virtualization Memory Definition : reserved memory region.
    Ivmd(IvmdBlock),
}

impl IvhdBlock {
    /// Iterate over device entries within this IVHD block.
    pub fn device_entries(&self) -> IvhdDevEntryIter<'_> {
        IvhdDevEntryIter {
            base: self.device_entries_off as *const u8,
            remaining: self.device_entries_len,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Return a human-readable summary of this IOMMU unit.
    pub fn summary(&self) -> alloc::string::String {
        use alloc::fmt::Write;
        let mut s = alloc::string::String::new();
        let _ = write!(
            s,
            "IVHD type={:?} flags={:#04x} dev_id={:#06x} cap_off={:#06x} ioapic={} iommu_base={:#018x} seg={}",
            self.typ,
            self.flags.0,
            self.device_id,
            self.capability_offset,
            self.ioapic_id,
            self.iommu_base,
            self.pci_segment,
        );
        if let Some(mmio) = self.mmio_base {
            let _ = write!(s, " mmio_base={:#018x}", mmio);
        }
        s
    }
}

/// Iterator over device entries inside an IVHD block.
pub struct IvhdDevEntryIter<'a> {
    base: *const u8,
    remaining: usize,
    _phantom: core::marker::PhantomData<&'a ()>,
}

impl<'a> IvhdDevEntryIter<'a> {
    /// Advance to the next device entry.
    pub fn next_entry(&mut self) -> Option<IvhdDeviceEntry> {
        if self.remaining < 1 {
            return None;
        }

        let ptr = self.base;
        let raw_type = unsafe { *ptr };
        let hdr = unsafe { &*(ptr as *const RawDevEntryHdr) };

        // Determine entry size based on type (AMD IOMMU spec §3.4).
        let (entry_size, is_range, range_count, ext_data) =
            decode_dev_entry_type(raw_type, hdr, ptr);
        if entry_size == 0 || entry_size > self.remaining {
            return None;
        }

        let data = [
            unsafe { *ptr.add(4) },
            unsafe { *ptr.add(5) },
            unsafe { *ptr.add(6) },
            unsafe { *ptr.add(7) },
        ];

        let entry = IvhdDeviceEntry {
            raw_type,
            device_id: hdr.device_id,
            data,
            ext_data,
            is_range,
            range_count,
        };

        self.base = unsafe { self.base.add(entry_size) };
        self.remaining -= entry_size;
        Some(entry)
    }

    /// Collect all remaining device entries into a Vec.
    pub fn collect(&mut self) -> alloc::vec::Vec<IvhdDeviceEntry> {
        let mut entries = alloc::vec::Vec::new();
        while let Some(e) = self.next_entry() {
            entries.push(e);
        }
        entries
    }
}

/// Decode a device entry type to determine size, range-ness, and ext data.
///
/// Returns `(entry_size, is_range, range_count, ext_data)`.
/// Returns `(0, ...)` if the type is unknown.
fn decode_dev_entry_type(
    raw_type: u8,
    hdr: &RawDevEntryHdr,
    ptr: *const u8,
) -> (usize, bool, u8, Option<u16>) {
    match raw_type {
        // 4-byte entries: special, select, range (no ext data).
        0x00 | 0x01 => (4, false, 0, None),
        0x02 | 0x03 => (4, false, 0, None),
        // Range entries (type & 0x03 == 0, size = 8).
        0x04 | 0x05 | 0x06 | 0x07 => {
            let count = unsafe { *ptr.add(4) }; // range count at byte 4
            (8, true, count, None)
        }
        // 8-byte entries: select (type = 0x20..0x23).
        0x20 | 0x21 | 0x22 | 0x23 => (8, false, 0, None),
        // 8-byte entries: alias (type = 0x40..0x43).
        0x40 | 0x41 | 0x42 | 0x43 => {
            let alias = unsafe { core::ptr::read_unaligned(ptr.add(4) as *const u16) };
            (8, false, 0, Some(alias))
        }
        // 8-byte entries: HID (type = 0x50..0x53).
        0x50 | 0x51 | 0x52 | 0x53 => (8, false, 0, None),
        // 8-byte entries: extended (type = 0x60..0x63).
        0x60 | 0x61 | 0x62 | 0x63 => {
            let ext = unsafe { core::ptr::read_unaligned(ptr.add(4) as *const u16) };
            (8, false, 0, Some(ext))
        }
        // 16-byte entries: extended range (type = 0x70..0x73).
        0x70 | 0x71 | 0x72 | 0x73 => {
            let ext = unsafe { core::ptr::read_unaligned(ptr.add(4) as *const u16) };
            let count = unsafe { *ptr.add(6) };
            (16, true, count, Some(ext))
        }
        // 8-byte entries: special (type = 0xF0).
        0xF0 => {
            let handle = unsafe { core::ptr::read_unaligned(ptr.add(4) as *const u16) };
            (8, false, 0, Some(handle))
        }
        _ => (0, false, 0, None), // unknown
    }
}

/// Top-level IVRS table wrapper.
pub struct Ivrs {
    header: &'static IvrsHeader,
}

impl Ivrs {
    /// Locate and parse the IVRS ACPI table.
    pub fn get() -> Option<Self> {
        IvrsHeader::get().map(|header| Ivrs { header })
    }

    /// Return a reference to the parsed header.
    pub fn header(&self) -> &'static IvrsHeader {
        self.header
    }

    /// Iterate over all IVHD/IVMD blocks.
    pub fn blocks(&self) -> IvrsEntryIter<'_> {
        self.header.entries()
    }

    /// Return the number of IOMMU units described by IVHD blocks.
    pub fn iommu_count(&self) -> usize {
        let mut count = 0;
        let mut iter = self.blocks();
        while let Some(block) = iter.next_block() {
            if matches!(block, IvrsBlock::Ivhd(_)) {
                count += 1;
            }
        }
        count
    }

    /// Collect all IVHD (IOMMU) blocks into a Vec.
    pub fn ivhd_blocks(&self) -> alloc::vec::Vec<IvhdBlock> {
        let mut blocks = alloc::vec::Vec::new();
        let mut iter = self.blocks();
        while let Some(block) = iter.next_block() {
            if let IvrsBlock::Ivhd(hd) = block {
                blocks.push(hd);
            }
        }
        blocks
    }

    /// Collect all IVMD (reserved memory) blocks into a Vec.
    pub fn ivmd_blocks(&self) -> alloc::vec::Vec<IvmdBlock> {
        let mut blocks = alloc::vec::Vec::new();
        let mut iter = self.blocks();
        while let Some(block) = iter.next_block() {
            if let IvrsBlock::Ivmd(md) = block {
                blocks.push(md);
            }
        }
        blocks
    }

    /// Dump a human-readable summary to the kernel log.
    pub fn dump(&self) {
        let dev_entry_count =
            unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(self.header.dev_entry_count)) };
        let entry_offset =
            unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(self.header.entry_offset)) };
        log::info!(
            "IVRS: Draint={} Coherent={} entries={} entry_offset={}",
            self.header.has_draint(),
            self.header.is_coherent(),
            dev_entry_count,
            entry_offset,
        );

        let mut ivhd_idx = 0;
        let mut iter = self.blocks();
        while let Some(block) = iter.next_block() {
            match block {
                IvrsBlock::Ivhd(hd) => {
                    log::info!("  IVHD #{}: {}", ivhd_idx, hd.summary());
                    let mut dev_iter = hd.device_entries();
                    let mut dev_count = 0;
                    while let Some(dev) = dev_iter.next_entry() {
                        log::debug!(
                            "    device type={:#04x} id={:#06x} data={:02x}{:02x}{:02x}{:02x}",
                            dev.raw_type,
                            dev.device_id,
                            dev.data[0],
                            dev.data[1],
                            dev.data[2],
                            dev.data[3],
                        );
                        dev_count += 1;
                    }
                    log::info!("    -> {} device entries", dev_count);
                    ivhd_idx += 1;
                }
                IvrsBlock::Ivmd(md) => {
                    log::info!(
                        "  IVMD: type={:#04x} flags={:#04x} dev_id={:#06x} iommu_base={:#018x} region={:#018x}-{:#018x}",
                        md.typ,
                        md.flags,
                        md.device_id,
                        md.iommu_base,
                        md.start_addr,
                        md.start_addr + md.length_bytes,
                    );
                }
            }
        }
    }
}
