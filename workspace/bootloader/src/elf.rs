//! Minimal ELF64 parser for loading the kernel.
//!
//! Following Phil Opp's approach: parse the ELF headers, extract entry point
//! and PT_LOAD segments, then load them into physical memory.

/// ELF64 constants
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const PT_LOAD: u32 = 1;

/// Parsed ELF64 information
pub struct Elf64Info {
    /// Kernel entry point (virtual address)
    pub entry: u64,
    /// Array of (physical_addr, virtual_addr, mem_size) for each PT_LOAD segment
    pub segments: [(u64, u64, u64); 16],
    /// Number of valid segments
    pub segment_count: usize,
}

/// Parse an ELF64 binary and extract load information.
///
/// Returns the entry point and list of PT_LOAD segments with their
/// physical addresses (for copying) and memory sizes (for BSS zeroing).
pub fn parse_elf64(data: &[u8]) -> Result<Elf64Info, &'static str> {
    // Check ELF magic
    if data.len() < 16 {
        return Err("ELF too small");
    }
    if data[0] != 0x7f || data[1] != b'E' || data[2] != b'L' || data[3] != b'F' {
        return Err("Invalid ELF magic");
    }

    // Check ELF class (64-bit) and endianness (little-endian)
    if data[EI_CLASS] != ELFCLASS64 {
        return Err("Not ELF64");
    }
    if data[EI_DATA] != ELFDATA2LSB {
        return Err("Not little-endian");
    }

    // ELF64 header layout
    // e_entry: offset 0x18, 8 bytes
    // e_phoff: offset 0x20, 8 bytes
    // e_phentsize: offset 0x36, 2 bytes
    // e_phnum: offset 0x38, 2 bytes
    if data.len() < 0x40 {
        return Err("ELF header too small");
    }

    let entry = read_u64_le(data, 0x18);
    let phoff = read_u64_le(data, 0x20) as usize;
    let phentsize = read_u16_le(data, 0x36) as usize;
    let phnum = read_u16_le(data, 0x38) as usize;

    if phnum > 16 {
        return Err("Too many program headers");
    }

    let mut info = Elf64Info {
        entry,
        segments: [(0, 0, 0); 16],
        segment_count: 0,
    };

    // Parse program headers
    for i in 0..phnum {
        let offset = phoff + i * phentsize;
        if offset + phentsize > data.len() {
            return Err("Program header out of bounds");
        }

        let p_type = read_u32_le(data, offset);
        let p_offset = read_u64_le(data, offset + 0x08);
        let p_vaddr = read_u64_le(data, offset + 0x10);
        let p_paddr = read_u64_le(data, offset + 0x18);
        let p_filesz = read_u64_le(data, offset + 0x20);
        let p_memsz = read_u64_le(data, offset + 0x28);

        if p_type != PT_LOAD {
            continue;
        }

        if p_memsz == 0 {
            continue;
        }

        // Load segment data into physical memory at p_paddr
        let dst = p_paddr as *mut u8;
        let src = data.as_ptr().add(p_offset as usize);
        let copy_size = p_filesz.min(p_memsz) as usize;

        if p_offset as usize + copy_size > data.len() {
            return Err("Segment data out of bounds");
        }

        unsafe {
            // Copy the segment data
            core::ptr::copy_nonoverlapping(src, dst, copy_size);
            // Zero-fill BSS (memsz > filesz)
            if p_memsz > p_filesz {
                let bss_start = dst.add(copy_size);
                let bss_size = (p_memsz - p_filesz) as usize;
                core::ptr::write_bytes(bss_start, 0, bss_size);
            }
        }

        info.segments[info.segment_count] = (p_paddr, p_vaddr, p_memsz);
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
