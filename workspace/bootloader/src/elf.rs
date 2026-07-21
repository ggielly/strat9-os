const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const PT_LOAD: u32 = 1;

const KERNEL_PHYS_BASE: u64 = 0x100_000;
const HIGHER_HALF_THRESHOLD: u64 = 0x8000_0000_0000;

#[derive(Copy, Clone)]
pub struct Segment {
    pub phys_addr: u64,
    pub virt_addr: u64,
    pub mem_size: u64,
    pub file_size: u64,
    pub flags: u32,
}

pub struct Elf64Info {
    pub entry: u64,
    pub segments: [Segment; 16],
    pub segment_count: usize,
    pub phys_end: u64,
}

pub fn parse_elf64(data: &[u8]) -> Result<Elf64Info, &'static str> {
    if data.len() < 64 {
        return Err("ELF header too small");
    }
    if data[0] != 0x7f || data[1] != b'E' || data[2] != b'L' || data[3] != b'F' {
        return Err("Invalid ELF magic");
    }
    if data[EI_CLASS] != ELFCLASS64 {
        return Err("Not ELF64");
    }
    if data[EI_DATA] != ELFDATA2LSB {
        return Err("Not little-endian");
    }

    let entry = read_u64_le(data, 0x18);
    let phoff = read_u64_le(data, 0x20) as usize;
    let phentsize = read_u16_le(data, 0x36) as usize;
    let phnum = read_u16_le(data, 0x38) as usize;

    if phentsize < 56 {
        return Err("Program header entry too small");
    }
    if phnum > 16 {
        return Err("Too many program headers");
    }

    let mut info = Elf64Info {
        entry,
        segments: [Segment { phys_addr: 0, virt_addr: 0, mem_size: 0, file_size: 0, flags: 0 }; 16],
        segment_count: 0,
        phys_end: 0,
    };

    for i in 0..phnum {
        let offset = phoff.checked_add(i * phentsize).ok_or("overflow")?;
        if offset + phentsize > data.len() {
            return Err("out of bounds");
        }

        let p_type = read_u32_le(data, offset);
        let p_flags = read_u32_le(data, offset + 0x04);
        let p_offset = read_u64_le(data, offset + 0x08);
        let p_vaddr = read_u64_le(data, offset + 0x10);
        let p_paddr = read_u64_le(data, offset + 0x18);
        let p_filesz = read_u64_le(data, offset + 0x20);
        let p_memsz = read_u64_le(data, offset + 0x28);

        if p_type != PT_LOAD || p_memsz == 0 || p_filesz == 0 {
            continue;
        }

        // Remap higher-half addresses to physical
        let phys_offset = if p_paddr >= HIGHER_HALF_THRESHOLD {
            KERNEL_PHYS_BASE + (p_paddr - 0xFFFF_FFFF_8000_0000)
        } else {
            p_paddr
        };

        // Safety: only copy if dest is in low memory (identity-mapped)
        let copy_size = p_filesz as usize;
        if phys_offset >= 0x1000 && phys_offset < 0x1000_0000
            && (p_offset as usize) + copy_size <= data.len()
        {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data.as_ptr().add(p_offset as usize),
                    phys_offset as *mut u8,
                    copy_size,
                );
            }
        }

        let seg_end = phys_offset + p_filesz;
        if seg_end > info.phys_end {
            info.phys_end = seg_end;
        }

        info.segments[info.segment_count] = Segment {
            phys_addr: phys_offset,
            virt_addr: p_vaddr,
            mem_size: p_memsz,
            file_size: p_filesz,
            flags: p_flags,
        };
        info.segment_count += 1;
    }

    if info.segment_count == 0 {
        return Err("No PT_LOAD segments found");
    }

    Ok(info)
}

fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ])
}
