use core::{ptr, slice};

pub const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_HEADER_SIZE: usize = 40;
const FDT_MIN_VERSION: u32 = 16;
const FDT_MAX_VERSION: u32 = 17;
const MAX_DTB_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_DTB_MEMORY_REGIONS: usize = 128;
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

                    let name_len = read_be_u32_slice(data, cursor, struct_end)? as usize;
                    cursor += 4;
                    let name_start = cursor;
                    let name_end =
                        name_start
                            .checked_add(name_len)
                            .ok_or(DtbError::MalformedStructure {
                                offset: name_start,
                                token,
                            })?;
                    if name_len == 0 || name_end > struct_end || data[name_end - 1] != 0 {
                        return Err(DtbError::MalformedProperty { offset: name_start });
                    }

                    let name = core::str::from_utf8(&data[name_start..name_end - 1])
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
                    cursor = align4(name_end);
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
    Ok(u32::from_be([
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
    if cells == 0 || cells > 2 {
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

fn park() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub unsafe extern "C" fn riscv_boot_entry(hart_id: usize, dtb: *const u8) -> ! {
    if hart_id != 0 {
        park();
    }

    super::serial::init();
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
                    Ok(()) => super::serial::_print(format_args!(
                        "[strat9] memory: {} valid regions\r\n",
                        count
                    )),
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
