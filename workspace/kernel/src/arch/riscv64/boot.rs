use core::{ptr, slice};

use crate::{
    boot::entry::{MemoryKind, MemoryRegion},
    memory::boot_alloc::{MAX_BOOT_ALLOC_REGIONS, MAX_PROTECTED_RANGES},
};

extern "C" {
    fn riscv_context_self_test();
}

pub const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_HEADER_SIZE: usize = 40;
const FDT_MIN_VERSION: u32 = 16;
const FDT_MAX_VERSION: u32 = 17;
const MAX_DTB_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_DTB_MEMORY_REGIONS: usize = 128;
pub const MAX_DTB_PLATFORM_REGIONS: usize = 64;
pub const MAX_DTB_VIRTIO_MMIO_DEVICES: usize = 32;
const MAX_FDT_DEPTH: usize = 32;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DtbError {
    Missing,
    InvalidMagic(u32),
    InvalidSize(usize),
    TooLarge(usize),
    UnsupportedVersion {
        version: u32,
        last_compatible_version: u32,
    },
    InvalidOffset {
        field: &'static str,
        offset: u32,
    },
    OutOfBounds {
        field: &'static str,
        offset: u32,
        length: u32,
        total_size: u32,
    },
    InvalidMemoryReservation {
        address: u64,
        size: u64,
    },
    MalformedStructure {
        offset: usize,
        token: u32,
    },
    MalformedProperty {
        offset: usize,
    },
    UnsupportedCellCount {
        property: &'static str,
        value: u32,
    },
    NoMemoryRegions,
    NoRamRegions,
    NoPlatformRegions,
    TooManyMemoryRegions,
    ZeroSizedMemoryRegion {
        index: usize,
    },
    OverlappingMemoryRegions {
        first: usize,
        second: usize,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct RiscvBootInfo {
    hart_id: usize,
    dtb: *const u8,
    dtb_len: usize,
    version: u32,
    struct_offset: usize,
    struct_len: usize,
    strings_offset: usize,
    strings_len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RiscvMemoryRegionKind {
    Ram,
    Reserved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RiscvMemoryRegion {
    pub base: u64,
    pub size: u64,
    pub kind: RiscvMemoryRegionKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RiscvPlatformRegion {
    pub base: u64,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RiscvVirtioMmioDevice {
    pub base: u64,
    pub size: u64,
    pub interrupt: Option<u32>,
}

impl RiscvVirtioMmioDevice {
    pub const EMPTY: Self = Self {
        base: 0,
        size: 0,
        interrupt: None,
    };
}

impl RiscvPlatformRegion {
    pub const EMPTY: Self = Self { base: 0, size: 0 };
}

impl RiscvMemoryRegion {
    pub const EMPTY: Self = Self {
        base: 0,
        size: 0,
        kind: RiscvMemoryRegionKind::Ram,
    };

    pub fn as_boot_region(self) -> crate::boot::entry::MemoryRegion {
        crate::boot::entry::MemoryRegion {
            base: self.base,
            size: self.size,
            kind: match self.kind {
                RiscvMemoryRegionKind::Ram => crate::boot::entry::MemoryKind::Free,
                RiscvMemoryRegionKind::Reserved => crate::boot::entry::MemoryKind::Reserved,
            },
        }
    }
}

impl RiscvBootInfo {
    pub unsafe fn from_handoff(hart_id: usize, dtb: *const u8) -> Result<Self, DtbError> {
        if dtb.is_null() {
            return Err(DtbError::Missing);
        }

        let magic = read_be_u32(dtb, 0);
        if magic != FDT_MAGIC {
            return Err(DtbError::InvalidMagic(magic));
        }

        let total_size = read_be_u32(dtb, 4) as usize;
        if total_size < FDT_HEADER_SIZE {
            return Err(DtbError::InvalidSize(total_size));
        }
        if total_size > MAX_DTB_SIZE {
            return Err(DtbError::TooLarge(total_size));
        }

        let off_dt_struct = read_be_u32(dtb, 8);
        let off_dt_strings = read_be_u32(dtb, 12);
        let off_mem_rsvmap = read_be_u32(dtb, 16);
        let version = read_be_u32(dtb, 20);
        let last_compatible_version = read_be_u32(dtb, 24);
        let size_dt_strings = read_be_u32(dtb, 32);
        let size_dt_struct = read_be_u32(dtb, 36);

        if !(FDT_MIN_VERSION..=FDT_MAX_VERSION).contains(&version)
            || last_compatible_version > FDT_MAX_VERSION
        {
            return Err(DtbError::UnsupportedVersion {
                version,
                last_compatible_version,
            });
        }

        validate_offset(off_dt_struct, total_size, "off_dt_struct")?;
        validate_offset(off_dt_strings, total_size, "off_dt_strings")?;
        validate_offset(off_mem_rsvmap, total_size, "off_mem_rsvmap")?;
        validate_range(off_dt_struct, size_dt_struct, total_size, "dt_struct")?;
        validate_range(off_dt_strings, size_dt_strings, total_size, "dt_strings")?;
        validate_reservation_map(dtb, off_mem_rsvmap, total_size)?;

        Ok(Self {
            hart_id,
            dtb,
            dtb_len: total_size,
            version,
            struct_offset: off_dt_struct as usize,
            struct_len: size_dt_struct as usize,
            strings_offset: off_dt_strings as usize,
            strings_len: size_dt_strings as usize,
        })
    }

    pub fn hart_id(&self) -> usize {
        self.hart_id
    }

    pub fn dtb_len(&self) -> usize {
        self.dtb_len
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn bytes(&self) -> &'static [u8] {
        unsafe { slice::from_raw_parts(self.dtb, self.dtb_len) }
    }

    pub fn memory_regions(&self, out: &mut [RiscvMemoryRegion]) -> Result<usize, DtbError> {
        let data = self.bytes();
        let struct_end = self.struct_offset.checked_add(self.struct_len).ok_or(
            DtbError::MalformedStructure {
                offset: self.struct_offset,
                token: 0,
            },
        )?;
        let mut cursor = self.struct_offset;
        let mut depth = 0usize;
        let mut memory_nodes = [false; MAX_FDT_DEPTH];
        let mut reserved_nodes = [false; MAX_FDT_DEPTH];
        let mut address_cells = [0u32; MAX_FDT_DEPTH];
        let mut size_cells = [0u32; MAX_FDT_DEPTH];
        let mut reg_offsets = [0usize; MAX_FDT_DEPTH];
        let mut reg_lens = [0usize; MAX_FDT_DEPTH];
        let mut count = 0usize;
        let mut ended = false;

        while cursor < struct_end {
            let token = read_be_u32_slice(data, cursor, struct_end)?;
            cursor += 4;

            match token {
                FDT_BEGIN_NODE => {
                    if depth >= MAX_FDT_DEPTH {
                        return Err(DtbError::MalformedStructure {
                            offset: cursor - 4,
                            token,
                        });
                    }

                    let name_start = cursor;
                    if name_start >= struct_end {
                        return Err(DtbError::MalformedProperty { offset: name_start });
                    }
                    let name_end = data[name_start..struct_end]
                        .iter()
                        .position(|byte| *byte == 0)
                        .map(|offset| name_start + offset)
                        .ok_or(DtbError::MalformedProperty { offset: name_start })?;

                    let name = core::str::from_utf8(&data[name_start..name_end])
                        .map_err(|_| DtbError::MalformedProperty { offset: name_start })?;
                    memory_nodes[depth] = name == "memory" || name.starts_with("memory@");
                    reserved_nodes[depth] =
                        name == "reserved-memory" || (depth > 0 && reserved_nodes[depth - 1]);
                    address_cells[depth] = if depth == 0 {
                        0
                    } else {
                        address_cells[depth - 1]
                    };
                    size_cells[depth] = if depth == 0 { 0 } else { size_cells[depth - 1] };
                    reg_offsets[depth] = 0;
                    reg_lens[depth] = 0;
                    depth += 1;
                    cursor = align4(name_end + 1);
                }
                FDT_END_NODE => {
                    if depth == 0 {
                        return Err(DtbError::MalformedStructure {
                            offset: cursor - 4,
                            token,
                        });
                    }
                    let node_index = depth - 1;
                    if (memory_nodes[node_index] || reserved_nodes[node_index])
                        && reg_lens[node_index] != 0
                    {
                        parse_reg(
                            data,
                            reg_offsets[node_index],
                            reg_offsets[node_index] + reg_lens[node_index],
                            address_cells[node_index],
                            size_cells[node_index],
                            if reserved_nodes[node_index] {
                                RiscvMemoryRegionKind::Reserved
                            } else {
                                RiscvMemoryRegionKind::Ram
                            },
                            out,
                            &mut count,
                        )?;
                    }
                    depth -= 1;
                }
                FDT_PROP => {
                    if depth == 0 {
                        return Err(DtbError::MalformedStructure {
                            offset: cursor - 4,
                            token,
                        });
                    }

                    let value_len = read_be_u32_slice(data, cursor, struct_end)? as usize;
                    let name_offset = read_be_u32_slice(data, cursor + 4, struct_end)? as usize;
                    cursor += 8;
                    let value_start = cursor;
                    let value_end =
                        value_start
                            .checked_add(value_len)
                            .ok_or(DtbError::MalformedProperty {
                                offset: value_start,
                            })?;
                    if value_end > struct_end {
                        return Err(DtbError::MalformedProperty {
                            offset: value_start,
                        });
                    }

                    let property =
                        string_at(data, self.strings_offset, self.strings_len, name_offset)?;
                    match property {
                        "#address-cells" => {
                            address_cells[depth - 1] =
                                read_cell_property(data, value_start, value_len, property)?;
                        }
                        "#size-cells" => {
                            size_cells[depth - 1] =
                                read_cell_property(data, value_start, value_len, property)?;
                        }
                        "reg" if memory_nodes[depth - 1] || reserved_nodes[depth - 1] => {
                            reg_offsets[depth - 1] = value_start;
                            reg_lens[depth - 1] = value_len;
                        }
                        _ => {}
                    }
                    cursor = align4(value_end);
                }
                FDT_NOP => {}
                FDT_END => {
                    if depth != 0 {
                        return Err(DtbError::MalformedStructure {
                            offset: cursor - 4,
                            token,
                        });
                    }
                    ended = true;
                    break;
                }
                _ => {
                    return Err(DtbError::MalformedStructure {
                        offset: cursor - 4,
                        token,
                    });
                }
            }
        }

        if !ended {
            return Err(DtbError::MalformedStructure {
                offset: struct_end,
                token: 0,
            });
        }
        if count == 0 {
            return Err(DtbError::NoMemoryRegions);
        }
        if !out[..count]
            .iter()
            .any(|region| region.kind == RiscvMemoryRegionKind::Ram)
        {
            return Err(DtbError::NoRamRegions);
        }
        Ok(count)
    }

    pub fn platform_regions(&self, out: &mut [RiscvPlatformRegion]) -> Result<usize, DtbError> {
        let data = self.bytes();
        let struct_end = self.struct_offset.checked_add(self.struct_len).ok_or(
            DtbError::MalformedStructure {
                offset: self.struct_offset,
                token: 0,
            },
        )?;
        let mut cursor = self.struct_offset;
        let mut depth = 0usize;
        let mut skip_nodes = [false; MAX_FDT_DEPTH];
        let mut address_cells = [0u32; MAX_FDT_DEPTH];
        let mut size_cells = [0u32; MAX_FDT_DEPTH];
        let mut reg_offsets = [0usize; MAX_FDT_DEPTH];
        let mut reg_lens = [0usize; MAX_FDT_DEPTH];
        let mut reg_address_cells = [0u32; MAX_FDT_DEPTH];
        let mut reg_size_cells = [0u32; MAX_FDT_DEPTH];
        let mut count = 0usize;
        let mut ended = false;

        while cursor < struct_end {
            let token = read_be_u32_slice(data, cursor, struct_end)?;
            cursor += 4;

            match token {
                FDT_BEGIN_NODE => {
                    if depth >= MAX_FDT_DEPTH {
                        return Err(DtbError::MalformedStructure {
                            offset: cursor - 4,
                            token,
                        });
                    }
                    let name_start = cursor;
                    if name_start >= struct_end {
                        return Err(DtbError::MalformedProperty { offset: name_start });
                    }
                    let name_end = data[name_start..struct_end]
                        .iter()
                        .position(|byte| *byte == 0)
                        .map(|offset| name_start + offset)
                        .ok_or(DtbError::MalformedProperty { offset: name_start })?;
                    let name = core::str::from_utf8(&data[name_start..name_end])
                        .map_err(|_| DtbError::MalformedProperty { offset: name_start })?;
                    let parent_skipped = depth > 0 && skip_nodes[depth - 1];
                    skip_nodes[depth] = parent_skipped
                        || name == "memory"
                        || name.starts_with("memory@")
                        || name == "reserved-memory"
                        || name == "cpus"
                        || name.starts_with("cpu@")
                        || name.starts_with("cluster")
                        || name == "pmu";
                    address_cells[depth] = if depth == 0 {
                        0
                    } else {
                        address_cells[depth - 1]
                    };
                    size_cells[depth] = if depth == 0 { 0 } else { size_cells[depth - 1] };
                    reg_offsets[depth] = 0;
                    reg_lens[depth] = 0;
                    reg_address_cells[depth] = 0;
                    reg_size_cells[depth] = 0;
                    depth += 1;
                    cursor = align4(name_end + 1);
                }
                FDT_END_NODE => {
                    if depth == 0 {
                        return Err(DtbError::MalformedStructure {
                            offset: cursor - 4,
                            token,
                        });
                    }
                    let node_index = depth - 1;
                    if !skip_nodes[node_index] && reg_lens[node_index] != 0 {
                        parse_platform_reg(
                            data,
                            reg_offsets[node_index],
                            reg_offsets[node_index] + reg_lens[node_index],
                            reg_address_cells[node_index],
                            reg_size_cells[node_index],
                            out,
                            &mut count,
                        )?;
                    }
                    depth -= 1;
                }
                FDT_PROP => {
                    if depth == 0 {
                        return Err(DtbError::MalformedStructure {
                            offset: cursor - 4,
                            token,
                        });
                    }
                    let value_len = read_be_u32_slice(data, cursor, struct_end)? as usize;
                    let name_offset = read_be_u32_slice(data, cursor + 4, struct_end)? as usize;
                    cursor += 8;
                    let value_start = cursor;
                    let value_end =
                        value_start
                            .checked_add(value_len)
                            .ok_or(DtbError::MalformedProperty {
                                offset: value_start,
                            })?;
                    if value_end > struct_end {
                        return Err(DtbError::MalformedProperty {
                            offset: value_start,
                        });
                    }
                    let property =
                        string_at(data, self.strings_offset, self.strings_len, name_offset)?;
                    match property {
                        "#address-cells" => {
                            address_cells[depth - 1] =
                                read_cell_property(data, value_start, value_len, property)?;
                        }
                        "#size-cells" => {
                            size_cells[depth - 1] =
                                read_cell_property(data, value_start, value_len, property)?;
                        }
                        "reg" if !skip_nodes[depth - 1] => {
                            reg_offsets[depth - 1] = value_start;
                            reg_lens[depth - 1] = value_len;
                            reg_address_cells[depth - 1] = address_cells[depth - 1];
                            reg_size_cells[depth - 1] = size_cells[depth - 1];
                        }
                        _ => {}
                    }
                    cursor = align4(value_end);
                }
                FDT_NOP => {}
                FDT_END => {
                    if depth != 0 {
                        return Err(DtbError::MalformedStructure {
                            offset: cursor - 4,
                            token,
                        });
                    }
                    ended = true;
                    break;
                }
                _ => {
                    return Err(DtbError::MalformedStructure {
                        offset: cursor - 4,
                        token,
                    });
                }
            }
        }

        if !ended {
            return Err(DtbError::MalformedStructure {
                offset: struct_end,
                token: 0,
            });
        }
        if count == 0 {
            return Err(DtbError::NoPlatformRegions);
        }
        Ok(count)
    }

    pub fn timebase_frequency(&self) -> Option<u64> {
        let data = self.bytes();
        let struct_end = self.struct_offset.checked_add(self.struct_len)?;
        let mut cursor = self.struct_offset;
        while cursor < struct_end {
            let token = read_be_u32_slice(data, cursor, struct_end).ok()?;
            cursor += 4;
            match token {
                FDT_BEGIN_NODE => {
                    let name_start = cursor;
                    if name_start >= struct_end {
                        return None;
                    }
                    let name_end = data[name_start..struct_end]
                        .iter()
                        .position(|byte| *byte == 0)?
                        + name_start;
                    cursor = align4(name_end + 1);
                }
                FDT_END_NODE | FDT_NOP => {}
                FDT_PROP => {
                    let value_len = read_be_u32_slice(data, cursor, struct_end).ok()? as usize;
                    let name_offset =
                        read_be_u32_slice(data, cursor + 4, struct_end).ok()? as usize;
                    cursor += 8;
                    let value_start = cursor;
                    let value_end = value_start.checked_add(value_len)?;
                    if value_end > struct_end {
                        return None;
                    }
                    if string_at(data, self.strings_offset, self.strings_len, name_offset).ok()?
                        == "timebase-frequency"
                    {
                        return match value_len {
                            4 => Some(read_be_u32_slice(data, value_start, value_end).ok()? as u64),
                            8 => {
                                let high =
                                    read_be_u32_slice(data, value_start, value_end).ok()? as u64;
                                let low = read_be_u32_slice(data, value_start + 4, value_end)
                                    .ok()? as u64;
                                Some((high << 32) | low)
                            }
                            _ => None,
                        };
                    }
                    cursor = align4(value_end);
                }
                FDT_END => break,
                _ => return None,
            }
        }
        None
    }

    pub fn has_isa_extension(&self, extension: &str) -> bool {
        let data = self.bytes();
        let Some(struct_end) = self.struct_offset.checked_add(self.struct_len) else {
            return false;
        };
        let mut cursor = self.struct_offset;
        while cursor < struct_end {
            let Ok(token) = read_be_u32_slice(data, cursor, struct_end) else {
                return false;
            };
            cursor += 4;
            match token {
                FDT_BEGIN_NODE => {
                    let Some(name_end) = data[cursor.min(struct_end)..struct_end]
                        .iter()
                        .position(|byte| *byte == 0)
                        .map(|offset| cursor + offset)
                    else {
                        return false;
                    };
                    cursor = align4(name_end + 1);
                }
                FDT_END_NODE | FDT_NOP => {}
                FDT_PROP => {
                    let Ok(value_len) = read_be_u32_slice(data, cursor, struct_end) else {
                        return false;
                    };
                    let Ok(name_offset) = read_be_u32_slice(data, cursor + 4, struct_end) else {
                        return false;
                    };
                    let value_len = value_len as usize;
                    let name_offset = name_offset as usize;
                    cursor += 8;
                    let Some(value_end) = cursor.checked_add(value_len) else {
                        return false;
                    };
                    if value_end > struct_end {
                        return false;
                    }
                    let Ok(property) =
                        string_at(data, self.strings_offset, self.strings_len, name_offset)
                    else {
                        cursor = align4(value_end);
                        continue;
                    };
                    if property == "riscv,isa" || property == "riscv,isa-extensions" {
                        if let Ok(text) = core::str::from_utf8(&data[cursor..value_end]) {
                            if text
                                .split(|character: char| {
                                    character == ','
                                        || character == '_'
                                        || character.is_ascii_whitespace()
                                })
                                .any(|token| token == extension)
                            {
                                return true;
                            }
                        }
                    }
                    cursor = align4(value_end);
                }
                FDT_END => break,
                _ => return false,
            }
        }
        false
    }

    pub fn pci_base(&self) -> Option<u64> {
        let data = self.bytes();
        let struct_end = self.struct_offset.checked_add(self.struct_len)?;
        let mut cursor = self.struct_offset;
        let mut depth = 0usize;
        let mut pci_nodes = [false; MAX_FDT_DEPTH];
        let mut address_cells = [0u32; MAX_FDT_DEPTH];
        let mut size_cells = [0u32; MAX_FDT_DEPTH];
        let mut reg_offsets = [0usize; MAX_FDT_DEPTH];
        let mut reg_lens = [0usize; MAX_FDT_DEPTH];
        let mut reg_address_cells = [0u32; MAX_FDT_DEPTH];
        let mut reg_size_cells = [0u32; MAX_FDT_DEPTH];
        while cursor < struct_end {
            let token = read_be_u32_slice(data, cursor, struct_end).ok()?;
            cursor += 4;
            match token {
                FDT_BEGIN_NODE => {
                    let name_start = cursor;
                    let name_end = data[name_start..struct_end]
                        .iter()
                        .position(|byte| *byte == 0)?
                        + name_start;
                    let name = core::str::from_utf8(&data[name_start..name_end]).ok()?;
                    pci_nodes[depth] = name == "pci" || name.starts_with("pci@");
                    address_cells[depth] = if depth == 0 {
                        0
                    } else {
                        address_cells[depth - 1]
                    };
                    size_cells[depth] = if depth == 0 { 0 } else { size_cells[depth - 1] };
                    reg_offsets[depth] = 0;
                    reg_lens[depth] = 0;
                    reg_address_cells[depth] = 0;
                    reg_size_cells[depth] = 0;
                    depth += 1;
                    cursor = align4(name_end + 1);
                }
                FDT_END_NODE => {
                    if depth == 0 {
                        return None;
                    }
                    let node_index = depth - 1;
                    if pci_nodes[node_index] && reg_lens[node_index] != 0 {
                        let mut regions = [RiscvPlatformRegion::EMPTY; 1];
                        let mut count = 0usize;
                        parse_platform_reg(
                            data,
                            reg_offsets[node_index],
                            reg_offsets[node_index] + reg_lens[node_index],
                            reg_address_cells[node_index],
                            reg_size_cells[node_index],
                            &mut regions,
                            &mut count,
                        )
                        .ok()?;
                        return regions.first().map(|region| region.base);
                    }
                    depth -= 1;
                }
                FDT_PROP => {
                    let value_len = read_be_u32_slice(data, cursor, struct_end).ok()? as usize;
                    let name_offset =
                        read_be_u32_slice(data, cursor + 4, struct_end).ok()? as usize;
                    cursor += 8;
                    let value_start = cursor;
                    let value_end = value_start.checked_add(value_len)?;
                    if value_end > struct_end {
                        return None;
                    }
                    let property =
                        string_at(data, self.strings_offset, self.strings_len, name_offset).ok()?;
                    match property {
                        "#address-cells" => {
                            address_cells[depth - 1] =
                                read_cell_property(data, value_start, value_len, property).ok()?;
                        }
                        "#size-cells" => {
                            size_cells[depth - 1] =
                                read_cell_property(data, value_start, value_len, property).ok()?;
                        }
                        "reg" if pci_nodes[depth - 1] => {
                            reg_offsets[depth - 1] = value_start;
                            reg_lens[depth - 1] = value_len;
                            reg_address_cells[depth - 1] = address_cells[depth - 1];
                            reg_size_cells[depth - 1] = size_cells[depth - 1];
                        }
                        _ => {}
                    }
                    cursor = align4(value_end);
                }
                FDT_NOP => {}
                FDT_END => break,
                _ => return None,
            }
        }
        None
    }

    pub fn virtio_mmio_devices(
        &self,
        out: &mut [RiscvVirtioMmioDevice],
    ) -> Result<usize, DtbError> {
        let data = self.bytes();
        let struct_end = self.struct_offset.checked_add(self.struct_len).ok_or(
            DtbError::MalformedStructure {
                offset: self.struct_offset,
                token: 0,
            },
        )?;
        let mut cursor = self.struct_offset;
        let mut depth = 0usize;
        let mut device_nodes = [false; MAX_FDT_DEPTH];
        let mut address_cells = [0u32; MAX_FDT_DEPTH];
        let mut size_cells = [0u32; MAX_FDT_DEPTH];
        let mut reg_offsets = [0usize; MAX_FDT_DEPTH];
        let mut reg_lens = [0usize; MAX_FDT_DEPTH];
        let mut reg_address_cells = [0u32; MAX_FDT_DEPTH];
        let mut reg_size_cells = [0u32; MAX_FDT_DEPTH];
        let mut interrupt_offsets = [0usize; MAX_FDT_DEPTH];
        let mut interrupt_lens = [0usize; MAX_FDT_DEPTH];
        let mut count = 0usize;
        let mut ended = false;

        while cursor < struct_end {
            let token = read_be_u32_slice(data, cursor, struct_end)?;
            cursor += 4;
            match token {
                FDT_BEGIN_NODE => {
                    if depth >= MAX_FDT_DEPTH {
                        return Err(DtbError::MalformedStructure {
                            offset: cursor - 4,
                            token,
                        });
                    }
                    let name_start = cursor;
                    let name_end = data[name_start..struct_end]
                        .iter()
                        .position(|byte| *byte == 0)
                        .map(|offset| name_start + offset)
                        .ok_or(DtbError::MalformedProperty { offset: name_start })?;
                    let name = core::str::from_utf8(&data[name_start..name_end])
                        .map_err(|_| DtbError::MalformedProperty { offset: name_start })?;
                    device_nodes[depth] = name == "virtio_mmio" || name.starts_with("virtio_mmio@");
                    address_cells[depth] = if depth == 0 {
                        0
                    } else {
                        address_cells[depth - 1]
                    };
                    size_cells[depth] = if depth == 0 { 0 } else { size_cells[depth - 1] };
                    reg_offsets[depth] = 0;
                    reg_lens[depth] = 0;
                    reg_address_cells[depth] = 0;
                    reg_size_cells[depth] = 0;
                    interrupt_offsets[depth] = 0;
                    interrupt_lens[depth] = 0;
                    depth += 1;
                    cursor = align4(name_end + 1);
                }
                FDT_END_NODE => {
                    if depth == 0 {
                        return Err(DtbError::MalformedStructure {
                            offset: cursor - 4,
                            token,
                        });
                    }
                    let node_index = depth - 1;
                    if device_nodes[node_index] && reg_lens[node_index] != 0 {
                        let mut region = [RiscvPlatformRegion::EMPTY; 1];
                        let mut region_count = 0usize;
                        parse_platform_reg(
                            data,
                            reg_offsets[node_index],
                            reg_offsets[node_index] + reg_lens[node_index],
                            reg_address_cells[node_index],
                            reg_size_cells[node_index],
                            &mut region,
                            &mut region_count,
                        )?;
                        if region_count != 0 {
                            if count >= out.len() {
                                return Err(DtbError::TooManyMemoryRegions);
                            }
                            let interrupt = if interrupt_lens[node_index] >= 4 {
                                Some(read_be_u32_slice(
                                    data,
                                    interrupt_offsets[node_index],
                                    interrupt_offsets[node_index] + 4,
                                )?)
                            } else {
                                None
                            };
                            out[count] = RiscvVirtioMmioDevice {
                                base: region[0].base,
                                size: region[0].size,
                                interrupt,
                            };
                            count += 1;
                        }
                    }
                    depth -= 1;
                }
                FDT_PROP => {
                    if depth == 0 {
                        return Err(DtbError::MalformedStructure {
                            offset: cursor - 4,
                            token,
                        });
                    }
                    let value_len = read_be_u32_slice(data, cursor, struct_end)? as usize;
                    let name_offset = read_be_u32_slice(data, cursor + 4, struct_end)? as usize;
                    cursor += 8;
                    let value_start = cursor;
                    let value_end =
                        value_start
                            .checked_add(value_len)
                            .ok_or(DtbError::MalformedProperty {
                                offset: value_start,
                            })?;
                    if value_end > struct_end {
                        return Err(DtbError::MalformedProperty {
                            offset: value_start,
                        });
                    }
                    let property =
                        string_at(data, self.strings_offset, self.strings_len, name_offset)?;
                    match property {
                        "#address-cells" => {
                            address_cells[depth - 1] =
                                read_cell_property(data, value_start, value_len, property)?;
                        }
                        "#size-cells" => {
                            size_cells[depth - 1] =
                                read_cell_property(data, value_start, value_len, property)?;
                        }
                        "reg" if device_nodes[depth - 1] => {
                            reg_offsets[depth - 1] = value_start;
                            reg_lens[depth - 1] = value_len;
                            reg_address_cells[depth - 1] = address_cells[depth - 1];
                            reg_size_cells[depth - 1] = size_cells[depth - 1];
                        }
                        "interrupts" if device_nodes[depth - 1] => {
                            interrupt_offsets[depth - 1] = value_start;
                            interrupt_lens[depth - 1] = value_len;
                        }
                        _ => {}
                    }
                    cursor = align4(value_end);
                }
                FDT_NOP => {}
                FDT_END => {
                    if depth != 0 {
                        return Err(DtbError::MalformedStructure {
                            offset: cursor - 4,
                            token,
                        });
                    }
                    ended = true;
                    break;
                }
                _ => {
                    return Err(DtbError::MalformedStructure {
                        offset: cursor - 4,
                        token,
                    });
                }
            }
        }

        if !ended {
            return Err(DtbError::MalformedStructure {
                offset: struct_end,
                token: 0,
            });
        }
        Ok(count)
    }

    pub fn plic_base(&self) -> Option<u64> {
        let data = self.bytes();
        let struct_end = self.struct_offset.checked_add(self.struct_len)?;
        let mut cursor = self.struct_offset;
        let mut depth = 0usize;
        let mut plic_nodes = [false; MAX_FDT_DEPTH];
        let mut address_cells = [0u32; MAX_FDT_DEPTH];
        let mut size_cells = [0u32; MAX_FDT_DEPTH];
        let mut reg_offsets = [0usize; MAX_FDT_DEPTH];
        let mut reg_lens = [0usize; MAX_FDT_DEPTH];
        let mut reg_address_cells = [0u32; MAX_FDT_DEPTH];
        let mut reg_size_cells = [0u32; MAX_FDT_DEPTH];
        while cursor < struct_end {
            let token = read_be_u32_slice(data, cursor, struct_end).ok()?;
            cursor += 4;
            match token {
                FDT_BEGIN_NODE => {
                    let name_start = cursor;
                    let name_end = data[name_start..struct_end]
                        .iter()
                        .position(|byte| *byte == 0)?
                        + name_start;
                    let name = core::str::from_utf8(&data[name_start..name_end]).ok()?;
                    plic_nodes[depth] = name == "plic" || name.starts_with("plic@");
                    address_cells[depth] = if depth == 0 {
                        0
                    } else {
                        address_cells[depth - 1]
                    };
                    size_cells[depth] = if depth == 0 { 0 } else { size_cells[depth - 1] };
                    reg_offsets[depth] = 0;
                    reg_lens[depth] = 0;
                    reg_address_cells[depth] = 0;
                    reg_size_cells[depth] = 0;
                    depth += 1;
                    cursor = align4(name_end + 1);
                }
                FDT_END_NODE => {
                    if depth == 0 {
                        return None;
                    }
                    let node_index = depth - 1;
                    if plic_nodes[node_index] && reg_lens[node_index] != 0 {
                        let mut regions = [RiscvPlatformRegion::EMPTY; 1];
                        let mut count = 0usize;
                        parse_platform_reg(
                            data,
                            reg_offsets[node_index],
                            reg_offsets[node_index] + reg_lens[node_index],
                            reg_address_cells[node_index],
                            reg_size_cells[node_index],
                            &mut regions,
                            &mut count,
                        )
                        .ok()?;
                        return regions.first().map(|region| region.base);
                    }
                    depth -= 1;
                }
                FDT_PROP => {
                    let value_len = read_be_u32_slice(data, cursor, struct_end).ok()? as usize;
                    let name_offset =
                        read_be_u32_slice(data, cursor + 4, struct_end).ok()? as usize;
                    cursor += 8;
                    let value_start = cursor;
                    let value_end = value_start.checked_add(value_len)?;
                    if value_end > struct_end {
                        return None;
                    }
                    let property =
                        string_at(data, self.strings_offset, self.strings_len, name_offset).ok()?;
                    match property {
                        "#address-cells" => {
                            address_cells[depth - 1] =
                                read_cell_property(data, value_start, value_len, property).ok()?;
                        }
                        "#size-cells" => {
                            size_cells[depth - 1] =
                                read_cell_property(data, value_start, value_len, property).ok()?;
                        }
                        "reg" if plic_nodes[depth - 1] => {
                            reg_offsets[depth - 1] = value_start;
                            reg_lens[depth - 1] = value_len;
                            reg_address_cells[depth - 1] = address_cells[depth - 1];
                            reg_size_cells[depth - 1] = size_cells[depth - 1];
                        }
                        _ => {}
                    }
                    cursor = align4(value_end);
                }
                FDT_NOP => {}
                FDT_END => break,
                _ => return None,
            }
        }
        None
    }

    pub fn validate_memory_regions(regions: &[RiscvMemoryRegion]) -> Result<(), DtbError> {
        for (index, region) in regions.iter().enumerate() {
            if region.size == 0 {
                return Err(DtbError::ZeroSizedMemoryRegion { index });
            }
            let end =
                region
                    .base
                    .checked_add(region.size)
                    .ok_or(DtbError::InvalidMemoryReservation {
                        address: region.base,
                        size: region.size,
                    })?;
            for (previous_index, previous) in regions[..index].iter().enumerate() {
                if previous.size == 0 || previous.kind != region.kind {
                    continue;
                }
                let previous_end = previous.base.checked_add(previous.size).ok_or(
                    DtbError::InvalidMemoryReservation {
                        address: previous.base,
                        size: previous.size,
                    },
                )?;
                if region.base < previous_end && previous.base < end {
                    return Err(DtbError::OverlappingMemoryRegions {
                        first: previous_index,
                        second: index,
                    });
                }
            }
        }
        Ok(())
    }
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn read_be_u32_slice(data: &[u8], offset: usize, limit: usize) -> Result<u32, DtbError> {
    let end = offset
        .checked_add(4)
        .ok_or(DtbError::MalformedProperty { offset })?;
    if end > limit || end > data.len() {
        return Err(DtbError::MalformedProperty { offset });
    }
    Ok(u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

fn string_at<'a>(
    data: &'a [u8],
    strings_offset: usize,
    strings_len: usize,
    name_offset: usize,
) -> Result<&'a str, DtbError> {
    if name_offset >= strings_len {
        return Err(DtbError::MalformedProperty {
            offset: name_offset,
        });
    }
    let start = strings_offset
        .checked_add(name_offset)
        .ok_or(DtbError::MalformedProperty {
            offset: name_offset,
        })?;
    let end_limit = strings_offset
        .checked_add(strings_len)
        .ok_or(DtbError::MalformedProperty {
            offset: name_offset,
        })?;
    if start >= end_limit || end_limit > data.len() {
        return Err(DtbError::MalformedProperty {
            offset: name_offset,
        });
    }
    let name_end = data[start..end_limit]
        .iter()
        .position(|byte| *byte == 0)
        .map(|offset| start + offset)
        .ok_or(DtbError::MalformedProperty {
            offset: name_offset,
        })?;
    core::str::from_utf8(&data[start..name_end]).map_err(|_| DtbError::MalformedProperty {
        offset: name_offset,
    })
}

fn read_cell_property(
    data: &[u8],
    offset: usize,
    len: usize,
    _property: &'static str,
) -> Result<u32, DtbError> {
    if len != 4 {
        return Err(DtbError::MalformedProperty { offset });
    }
    let value = read_be_u32_slice(data, offset, data.len())?;
    Ok(value)
}

fn read_cells(
    data: &[u8],
    offset: usize,
    cells: u32,
    limit: usize,
    property: &'static str,
) -> Result<u64, DtbError> {
    if cells == 0 || cells > 3 {
        return Err(DtbError::UnsupportedCellCount {
            property,
            value: cells,
        });
    }
    let mut value = 0u64;
    for index in 0..cells as usize {
        let cell = read_be_u32_slice(data, offset + index * 4, limit)? as u64;
        value = (value << 32) | cell;
    }
    Ok(value)
}

fn parse_reg(
    data: &[u8],
    value_start: usize,
    value_end: usize,
    address_cells: u32,
    size_cells: u32,
    kind: RiscvMemoryRegionKind,
    out: &mut [RiscvMemoryRegion],
    count: &mut usize,
) -> Result<(), DtbError> {
    if address_cells == 0 || address_cells > 2 || size_cells == 0 || size_cells > 2 {
        return Err(DtbError::UnsupportedCellCount {
            property: "reg",
            value: address_cells.max(size_cells),
        });
    }

    let entry_size = (address_cells + size_cells) as usize * 4;
    let value_len = value_end - value_start;
    if value_len == 0 || value_len % entry_size != 0 {
        return Err(DtbError::MalformedProperty {
            offset: value_start,
        });
    }

    let mut entry_offset = value_start;
    while entry_offset < value_end {
        let base = read_cells(data, entry_offset, address_cells, value_end, "reg")?;
        let size = read_cells(
            data,
            entry_offset + address_cells as usize * 4,
            size_cells,
            value_end,
            "reg",
        )?;
        if size == 0 {
            return Err(DtbError::ZeroSizedMemoryRegion { index: *count });
        }
        if base.checked_add(size).is_none() {
            return Err(DtbError::InvalidMemoryReservation {
                address: base,
                size,
            });
        }
        if *count >= out.len() {
            return Err(DtbError::TooManyMemoryRegions);
        }
        out[*count] = RiscvMemoryRegion { base, size, kind };
        *count += 1;
        entry_offset += entry_size;
    }
    Ok(())
}

fn parse_platform_reg(
    data: &[u8],
    value_start: usize,
    value_end: usize,
    address_cells: u32,
    size_cells: u32,
    out: &mut [RiscvPlatformRegion],
    count: &mut usize,
) -> Result<(), DtbError> {
    if address_cells == 0 || size_cells == 0 {
        return Ok(());
    }
    if address_cells > 3 || size_cells > 3 {
        return Err(DtbError::UnsupportedCellCount {
            property: "reg",
            value: address_cells.max(size_cells),
        });
    }
    let value_len = value_end - value_start;
    if value_len == 0 {
        return Ok(());
    }
    let mut effective_size_cells = size_cells;
    let mut entry_size = (address_cells + effective_size_cells) as usize * 4;
    if value_len % entry_size != 0
        && address_cells == 3
        && value_len == ((address_cells + 1) * 4) as usize
    {
        effective_size_cells = 1;
        entry_size = (address_cells + effective_size_cells) as usize * 4;
    }
    if value_len % entry_size != 0 {
        return Err(DtbError::MalformedProperty {
            offset: value_start,
        });
    }

    let mut entry_offset = value_start;
    while entry_offset < value_end {
        let base = read_cells(data, entry_offset, address_cells, value_end, "reg")?;
        let size = read_cells(
            data,
            entry_offset + address_cells as usize * 4,
            effective_size_cells,
            value_end,
            "reg",
        )?;
        if size == 0 {
            return Err(DtbError::ZeroSizedMemoryRegion { index: *count });
        }
        if base.checked_add(size).is_none() {
            return Err(DtbError::InvalidMemoryReservation {
                address: base,
                size,
            });
        }
        if *count >= out.len() {
            return Err(DtbError::TooManyMemoryRegions);
        }
        out[*count] = RiscvPlatformRegion { base, size };
        *count += 1;
        entry_offset += entry_size;
    }
    Ok(())
}

unsafe fn read_be_u32(base: *const u8, offset: usize) -> u32 {
    u32::from_be(ptr::read_unaligned(base.add(offset) as *const u32))
}

unsafe fn read_be_u64(base: *const u8, offset: usize) -> u64 {
    u64::from_be(ptr::read_unaligned(base.add(offset) as *const u64))
}

fn validate_reservation_map(
    dtb: *const u8,
    offset: u32,
    total_size: usize,
) -> Result<(), DtbError> {
    let mut entry_offset = offset as usize;
    loop {
        if entry_offset > total_size || total_size - entry_offset < 16 {
            return Err(DtbError::OutOfBounds {
                field: "mem_rsvmap",
                offset: entry_offset as u32,
                length: 16,
                total_size: total_size as u32,
            });
        }

        let address = unsafe { read_be_u64(dtb, entry_offset) };
        let size = unsafe { read_be_u64(dtb, entry_offset + 8) };
        if address == 0 && size == 0 {
            return Ok(());
        }
        if address.checked_add(size).is_none() {
            return Err(DtbError::InvalidMemoryReservation { address, size });
        }
        entry_offset += 16;
    }
}

fn validate_offset(offset: u32, total_size: usize, field: &'static str) -> Result<(), DtbError> {
    if offset < FDT_HEADER_SIZE as u32 || offset as usize > total_size {
        return Err(DtbError::InvalidOffset { field, offset });
    }
    Ok(())
}

fn validate_range(
    offset: u32,
    length: u32,
    total_size: usize,
    field: &'static str,
) -> Result<(), DtbError> {
    let Some(end) = (offset as usize).checked_add(length as usize) else {
        return Err(DtbError::OutOfBounds {
            field,
            offset,
            length,
            total_size: total_size as u32,
        });
    };
    if end > total_size {
        return Err(DtbError::OutOfBounds {
            field,
            offset,
            length,
            total_size: total_size as u32,
        });
    }
    Ok(())
}

fn initialize_memory_allocator(
    info: &RiscvBootInfo,
    dtb: *const u8,
    regions: &[RiscvMemoryRegion],
    count: usize,
) {
    let mut boot_regions = [MemoryRegion {
        base: 0,
        size: 0,
        kind: MemoryKind::Null,
    }; MAX_BOOT_ALLOC_REGIONS];
    for index in 0..count {
        boot_regions[index] = regions[index].as_boot_region();
    }

    let mut protected = [None; MAX_PROTECTED_RANGES];
    protected[0] = Some((dtb as u64, info.dtb_len() as u64));
    crate::memory::boot_alloc::set_protected_ranges(&protected);
    super::serial::_print(format_args!("[strat9] initializing boot allocator\r\n"));
    crate::memory::boot_alloc::init_boot_allocator(&boot_regions[..count]);
    super::serial::_print(format_args!("[strat9] boot allocator ready\r\n"));

    let total_ram = boot_regions[..count]
        .iter()
        .filter(|region| matches!(region.kind, MemoryKind::Free | MemoryKind::Reclaim))
        .map(|region| region.base.saturating_add(region.size))
        .max()
        .unwrap_or(0);
    {
        let mut boot_allocator = crate::memory::boot_alloc::get_boot_allocator().lock();
        crate::memory::frame::init_metadata_array(total_ram, &mut boot_allocator);
    }
    super::serial::_print(format_args!("[strat9] frame metadata ready\r\n"));
    crate::memory::buddy::init_buddy_allocator(&boot_regions[..count]);
    super::serial::_print(format_args!("[strat9] buddy allocator ready\r\n"));

    let mut mapper = super::paging::Sv39Mapper::new();
    let mut mapped_pages = 0usize;
    for region in &boot_regions[..count] {
        if matches!(region.kind, MemoryKind::Free | MemoryKind::Reclaim) {
            match mapper.map_ram(region.base, region.size) {
                Ok(pages) => mapped_pages += pages,
                Err(error) => super::serial::_print(format_args!(
                    "[strat9] Sv39 map failed for {:#x}: {:?}\r\n",
                    region.base, error
                )),
            }
        }
    }
    super::serial::_print(format_args!(
        "[strat9] Sv39 tables ready: root={:#x} mapped={} pages\r\n",
        mapper.root_physical_address(),
        mapped_pages
    ));

    let mut platform_regions = [RiscvPlatformRegion::EMPTY; MAX_DTB_PLATFORM_REGIONS];
    let platform_count = match info.platform_regions(&mut platform_regions) {
        Ok(count) => count,
        Err(error) => {
            super::serial::_print(format_args!(
                "[strat9] platform discovery failed: {:?}\r\n",
                error
            ));
            0
        }
    };
    let mut platform_ok = platform_count != 0;
    for region in &platform_regions[..platform_count] {
        if let Err(error) = mapper.map_mmio(region.base, region.size) {
            super::serial::_print(format_args!(
                "[strat9] Sv39 MMIO map failed for {:#x}: {:?}\r\n",
                region.base, error
            ));
            platform_ok = false;
        }
    }
    super::serial::_print(format_args!(
        "[strat9] platform regions: {}\r\n",
        platform_count
    ));

    if let Some(token) = crate::sync::IrqDisabledToken::verify() {
        match crate::memory::buddy::alloc(&token, 0) {
            Ok(frame) => {
                let address = frame.start_address.as_u64();
                crate::memory::buddy::free(&token, frame, 0);
                super::serial::_print(format_args!(
                    "[strat9] buddy alloc/free ok: {address:#x}\r\n"
                ));
            }
            Err(error) => {
                super::serial::_print(format_args!("[strat9] buddy alloc failed: {:?}\r\n", error))
            }
        }
    }

    if platform_ok {
        super::serial::_print(format_args!("[strat9] activating Sv39\r\n"));
        unsafe {
            mapper.activate();
            crate::memory::paging::mark_riscv_paging_active();
        }
        super::serial::_print(format_args!("[strat9] Sv39 paging active\r\n"));
        match info.plic_base() {
            Some(base) => match super::plic::init(base, info.hart_id()) {
                Ok(()) => {
                    super::serial::_print(format_args!("[strat9] PLIC ready: {:#x}\r\n", base))
                }
                Err(error) => {
                    super::serial::_print(format_args!("[strat9] PLIC unavailable: {}\r\n", error))
                }
            },
            None => super::serial::_print(format_args!(
                "[strat9] PLIC unavailable: DTB node missing\r\n"
            )),
        }
        match info.pci_base() {
            Some(base) => match super::pci::init(base) {
                Ok(()) => {
                    let mut devices = [super::pci::PciDeviceInfo::EMPTY; 32];
                    let count = super::pci::enumerate(&mut devices);
                    super::serial::_print(format_args!(
                        "[strat9] PCI ECAM ready: {:#x} devices={}\r\n",
                        base, count
                    ));
                }
                Err(error) => super::serial::_print(format_args!(
                    "[strat9] PCI ECAM unavailable: {}\r\n",
                    error
                )),
            },
            None => super::serial::_print(format_args!(
                "[strat9] PCI ECAM unavailable: DTB node missing\r\n"
            )),
        }
        let mut virtio_devices = [RiscvVirtioMmioDevice::EMPTY; MAX_DTB_VIRTIO_MMIO_DEVICES];
        let virtio_device_count = match info.virtio_mmio_devices(&mut virtio_devices) {
            Ok(count) => count,
            Err(error) => {
                super::serial::_print(format_args!(
                    "[strat9] VirtIO-MMIO discovery failed: {:?}\r\n",
                    error
                ));
                0
            }
        };
        let mut virtio_transports =
            [super::virtio_mmio::MmioDeviceInfo::EMPTY; MAX_DTB_VIRTIO_MMIO_DEVICES];
        let virtio_transport_count = super::virtio_mmio::discover(
            &virtio_devices[..virtio_device_count],
            &mut virtio_transports,
        );
        super::serial::_print(format_args!(
            "[strat9] VirtIO-MMIO ready: nodes={} devices={}\r\n",
            virtio_device_count, virtio_transport_count
        ));

        match info.timebase_frequency() {
            Some(frequency) => {
                match super::timer::init(frequency, info.has_isa_extension("sstc")) {
                    Ok(frequency) => super::serial::_print(format_args!(
                        "[strat9] SBI timer ready: {} Hz\r\n",
                        frequency
                    )),
                    Err(error) => super::serial::_print(format_args!(
                        "[strat9] SBI timer unavailable: {}\r\n",
                        error
                    )),
                }
            }
            None => super::serial::_print(format_args!(
                "[strat9] SBI timer unavailable: DTB timebase-frequency missing\r\n"
            )),
        }
        scheduler_smoke_init();
    }
}

fn scheduler_smoke_init() {
    unsafe { crate::memory::address_space::init_kernel_address_space() };
    let _ = crate::memory::kernel_address_space();
    crate::process::init_scheduler();
    super::serial::_print(format_args!("[strat9] scheduler init ok\r\n"));
}

fn park() -> ! {
    loop {
        super::hlt();
    }
}

#[no_mangle]
pub unsafe extern "C" fn riscv_boot_entry(hart_id: usize, dtb: *const u8) -> ! {
    if hart_id != 0 {
        park();
    }

    super::percpu::init_boot_cpu(hart_id as u32);
    super::serial::init();
    super::serial::_print(format_args!(
        "[strat9] percpu ready: {}\r\n",
        super::percpu::current_cpu_index()
    ));
    unsafe { riscv_context_self_test() };
    super::serial::_print(format_args!("[strat9] context switch ok\r\n"));
    super::trap::init();
    super::serial::_print(format_args!("\r\n[strat9] RISC-V OpenSBI entry\r\n"));
    super::serial::_print(format_args!(
        "[strat9] hart={} dtb=0x{:x}\r\n",
        hart_id, dtb as usize
    ));

    match RiscvBootInfo::from_handoff(hart_id, dtb) {
        Ok(info) => {
            super::serial::_print(format_args!(
                "[strat9] DTB valid: {} bytes, version {}\r\n",
                info.dtb_len(),
                info.version()
            ));
            let mut regions = [RiscvMemoryRegion::EMPTY; MAX_DTB_MEMORY_REGIONS];
            match info.memory_regions(&mut regions) {
                Ok(count) => match RiscvBootInfo::validate_memory_regions(&regions[..count]) {
                    Ok(()) => {
                        super::serial::_print(format_args!(
                            "[strat9] memory: {} valid regions\r\n",
                            count
                        ));
                        initialize_memory_allocator(&info, dtb, &regions, count);
                    }
                    Err(error) => super::serial::_print(format_args!(
                        "[strat9] memory map rejected: {:?}\r\n",
                        error
                    )),
                },
                Err(error) => super::serial::_print(format_args!(
                    "[strat9] memory discovery failed: {:?}\r\n",
                    error
                )),
            }
        }
        Err(error) => {
            super::serial::_print(format_args!("[strat9] DTB rejected: {:?}\r\n", error));
        }
    }

    park();
}
