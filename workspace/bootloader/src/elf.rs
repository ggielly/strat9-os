const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const PT_LOAD: u32 = 1;
const EM_X86_64: u16 = 62;

const KERNEL_PHYS_BASE: u64 = 0x100_000;
const KERNEL_VIRT_BASE: u64 = 0xFFFF_FFFF_8000_0000;
const HIGHER_HALF_BASE: u64 = 0xFFFF_8000_0000_0000;
/// Extra physical space after file data for BSS. The higher-half virtual
/// mapping inflates p_memsz (up to 2 GiB), but only a small fraction is
/// actual BSS data. This limit bounds physical allocation; refuse if the
/// real BSS exceeds it.
const BSS_MAP_EXTRA: u64 = 64 * 1024 * 1024; // 64 MiB

#[derive(Copy, Clone)]
pub struct Segment {
    pub phys_addr: u64,
    pub virt_addr: u64,
    pub file_offset: u64,
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

    let e_machine = read_u16_le(data, 0x12)?;
    if e_machine != EM_X86_64 {
        return Err("Not x86-64 ELF");
    }

    let entry = read_u64_le(data, 0x18)?;
    let phoff = read_u64_le(data, 0x20)?;
    let phentsize = read_u16_le(data, 0x36)? as usize;
    let phnum = read_u16_le(data, 0x38)? as usize;

    if phentsize < 56 {
        return Err("Program header entry too small");
    }
    if phnum > 16 {
        return Err("Too many program headers");
    }

    // Validate phoff fits in usize and PH table is within the file
    let phoff_usize = usize::try_from(phoff).map_err(|_| "phoff overflow")?;
    let ph_table_end = phoff_usize
        .checked_add(phentsize.checked_mul(phnum).ok_or("PH table size overflow")?)
        .ok_or("PH table end overflow")?;
    if ph_table_end > data.len() {
        return Err("PH table extends beyond file");
    }

    let mut info = Elf64Info {
        entry,
        segments: [Segment {
            phys_addr: 0,
            virt_addr: 0,
            file_offset: 0,
            mem_size: 0,
            file_size: 0,
            flags: 0,
        }; 16],
        segment_count: 0,
        phys_end: 0,
    };

    for i in 0..phnum {
        let offset = phoff_usize
            .checked_add(i.checked_mul(phentsize).ok_or("PH offset overflow")?)
            .ok_or("PH offset overflow")?;
        if offset + phentsize > data.len() {
            return Err("PH extends beyond file");
        }

        let p_type = read_u32_le(data, offset)?;
        let p_flags = read_u32_le(data, offset + 0x04)?;
        let p_offset = read_u64_le(data, offset + 0x08)?;
        let p_vaddr = read_u64_le(data, offset + 0x10)?;
        let p_paddr = read_u64_le(data, offset + 0x18)?;
        let p_filesz = read_u64_le(data, offset + 0x20)?;
        let p_memsz = read_u64_le(data, offset + 0x28)?;

        if p_type != PT_LOAD || p_memsz == 0 {
            continue;
        }

        // ELF spec: p_filesz must not exceed p_memsz
        if p_filesz > p_memsz {
            return Err("PT_LOAD: p_filesz > p_memsz");
        }

        // Compute physical load address.
        // For higher-half virtual addresses, remap to KERNEL_PHYS_BASE.
        let phys_addr = if p_vaddr >= HIGHER_HALF_BASE {
            let offset_in_high = p_vaddr
                .checked_sub(KERNEL_VIRT_BASE)
                .ok_or("higher-half vaddr below KERNEL_VIRT_BASE")?;
            KERNEL_PHYS_BASE
                .checked_add(offset_in_high)
                .ok_or("physical address overflow")?
        } else {
            // Use p_paddr directly for non-higher-half segments
            p_paddr
        };

        // Validate file offset + filesz within the ELF data
        let file_off = usize::try_from(p_offset).map_err(|_| "p_offset overflow")?;
        let file_sz = usize::try_from(p_filesz).map_err(|_| "p_filesz overflow")?;
        let file_end = file_off.checked_add(file_sz).ok_or("file end overflow")?;
        if file_end > data.len() {
            return Err("PT_LOAD: file data extends beyond ELF");
        }

        // Compute BSS size. Higher-half ELFs have p_memsz spanning the
        // entire virtual range (potentially 2 GiB), but actual BSS data is
        // tiny. Clamp to BSS_MAP_EXTRA for physical allocation.
        let bss_full = p_memsz
            .checked_sub(p_filesz)
            .ok_or("BSS underflow (impossible after filesz <= memsz check)")?;
        let bss_len = bss_full.min(BSS_MAP_EXTRA) as usize;

        // Validate physical destination: entire segment must fit in low memory.
        // phys_addr + file_sz + bss_len must be < 0x1000_0000 (16 MiB).
        let data_end = phys_addr
            .checked_add(p_filesz)
            .ok_or("phys data end overflow")?;
        let bss_end = data_end
            .checked_add(bss_full.min(BSS_MAP_EXTRA))
            .ok_or("phys seg end overflow")?;
        if phys_addr < 0x1000 || bss_end > 0x1000_0000 {
            return Err("PT_LOAD: physical address out of safe low-memory range");
        }

        // Compute mapped memory size for this segment (filesz + BSS, clamped)
        let mapped_memsz = p_filesz
            .checked_add(bss_full.min(BSS_MAP_EXTRA))
            .ok_or("mapped_memsz overflow")?;

        // Check for overlap between loaded segments' virtual address ranges.
        // Use only initialized data (p_filesz), skipping pure-BSS segments
        // (filesz == 0) since they cannot conflict with file content and
        // commonly share the tail of a data segment (.bss placed at the end
        // of .data/.bss is a separate PT_LOAD with filesz == 0).
        if p_filesz > 0 {
            let vstart = p_vaddr;
            let vend = p_vaddr.checked_add(p_filesz).ok_or("vend overflow")?;
            for j in 0..info.segment_count {
                let prev = &info.segments[j];
                if prev.file_size == 0 {
                    continue;
                }
                let pstart = prev.virt_addr;
                let pend = prev
                    .virt_addr
                    .checked_add(prev.file_size)
                    .ok_or("prev vend overflow")?;
                if vstart < pend && vend > pstart {
                    return Err("PT_LOAD: segments overlap");
                }
            }
        }

        // Copy initialized data from ELF file into physical memory
        if file_sz > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data.as_ptr().add(file_off),
                    phys_addr as *mut u8,
                    file_sz,
                );
            }
        }

        // Zero BSS region
        if bss_len > 0 {
            unsafe {
                core::ptr::write_bytes(data_end as *mut u8, 0, bss_len);
            }
        }

        if bss_end > info.phys_end {
            info.phys_end = bss_end;
        }

        info.segments[info.segment_count] = Segment {
            phys_addr,
            virt_addr: p_vaddr,
            file_offset: p_offset,
            mem_size: mapped_memsz,
            file_size: p_filesz,
            flags: p_flags,
        };
        info.segment_count += 1;
    }

    if info.segment_count == 0 {
        return Err("No PT_LOAD segments found");
    }

    // Validate that the entry point falls within a loaded, executable segment
    let entry_in_segment = |seg: &Segment| -> bool {
        seg.flags & 0x1 != 0
            && entry >= seg.virt_addr
            && entry < seg.virt_addr.saturating_add(seg.mem_size)
    };
    if !info.segments[..info.segment_count]
        .iter()
        .any(entry_in_segment)
    {
        return Err("entry point not in any loaded executable segment");
    }

    Ok(info)
}

fn read_u16_le(data: &[u8], offset: usize) -> Result<u16, &'static str> {
    let end = offset.checked_add(2).ok_or("u16 read overflow")?;
    if end > data.len() {
        return Err("u16 read out of bounds");
    }
    Ok(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32, &'static str> {
    let end = offset.checked_add(4).ok_or("u32 read overflow")?;
    if end > data.len() {
        return Err("u32 read out of bounds");
    }
    Ok(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

fn read_u64_le(data: &[u8], offset: usize) -> Result<u64, &'static str> {
    let end = offset.checked_add(8).ok_or("u64 read overflow")?;
    if end > data.len() {
        return Err("u64 read out of bounds");
    }
    Ok(u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]))
}
