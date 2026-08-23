const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const PT_LOAD: u32 = 1;

// Program header flags (p_flags)
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;

const KERNEL_PHYS_BASE: u64 = 0x100_000;
const KERNEL_VIRT_BASE: u64 = 0xFFFF_FFFF_8000_0000;
/// Higher-half addresses at or above this threshold are rebased to physical.
const HIGHER_HALF_THRESHOLD: u64 = 0x8000_0000_0000;
/// Maximum physical span accepted for the kernel image. Both the rebase of
/// higher-half `p_paddr` values and the per-segment copy checks are bounded
/// by this window, so a crafted ELF can never target memory outside it.
pub const MAX_KERNEL_PHYS: u64 = 0x1000_0000; // 16 MiB
/// Extra space after file data to map BSS. The BSS segment's p_memsz
/// covers the entire higher-half virtual range (2 GB), which is far too
/// large. We only need enough physical pages for the actual statics.
const BSS_MAP_EXTRA: u64 = 8 * 1024 * 1024; // 8 MiB

#[derive(Copy, Clone)]
pub struct Segment {
    pub phys_addr: u64,
    pub virt_addr: u64,
    pub mem_size: u64,
    pub file_size: u64,
    /// Physical bytes to map for this segment: file data plus the capped
    /// BSS tail (`min(p_memsz - p_filesz, BSS_MAP_EXTRA)`).
    pub map_size: u64,
    pub flags: u32,
}

impl Segment {
    /// Page protections for this segment: writable and/or executable.
    /// Everything defaults to read-only (W^X is enforced per segment).
    pub fn writable(&self) -> bool {
        self.flags & PF_W != 0
    }

    pub fn executable(&self) -> bool {
        self.flags & PF_X != 0
    }
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
        segments: [Segment {
            phys_addr: 0,
            virt_addr: 0,
            mem_size: 0,
            file_size: 0,
            map_size: 0,
            flags: 0,
        }; 16],
        segment_count: 0,
        phys_end: 0,
    };

    for i in 0..phnum {
        let offset = phoff.checked_add(i * phentsize).ok_or("overflow")?;
        let hdr_end = offset.checked_add(phentsize).ok_or("overflow")?;
        if hdr_end > data.len() {
            return Err("out of bounds");
        }

        let p_type = read_u32_le(data, offset);
        let p_flags = read_u32_le(data, offset + 0x04);
        let p_offset = read_u64_le(data, offset + 0x08);
        let p_vaddr = read_u64_le(data, offset + 0x10);
        let p_paddr = read_u64_le(data, offset + 0x18);
        let p_filesz = read_u64_le(data, offset + 0x20);
        let p_memsz = read_u64_le(data, offset + 0x28);

        // Zero-memsz segments carry nothing; skip them. Segments with
        // p_filesz == 0 (BSS-only) are kept: they must be mapped writable
        // and their physical span accounted for.
        if p_type != PT_LOAD || p_memsz == 0 {
            continue;
        }

        // Remap higher-half addresses to physical. Only the exact kernel
        // window [KERNEL_VIRT_BASE, KERNEL_VIRT_BASE + MAX_KERNEL_PHYS) may
        // be rebased: anything else is rejected instead of wrapping around.
        let phys_offset = if p_paddr >= HIGHER_HALF_THRESHOLD {
            let off = p_paddr
                .checked_sub(KERNEL_VIRT_BASE)
                .ok_or("segment address below kernel virtual base")?;
            if off >= MAX_KERNEL_PHYS {
                return Err("segment address outside supported kernel window");
            }
            KERNEL_PHYS_BASE + off
        } else {
            p_paddr
        };

        // Destination must be in low memory: it is identity-mapped by the
        // firmware and covered by the page tables we build. Anything else is
        // a fatal error rather than a silently skipped (i.e. missing) segment.
        let copy_size = p_filesz;
        if phys_offset < 0x1000 {
            return Err("segment physical address below 4 KiB");
        }
        let seg_phys_end = phys_offset
            .checked_add(copy_size)
            .ok_or("segment size overflow")?;
        if seg_phys_end > KERNEL_PHYS_BASE + MAX_KERNEL_PHYS {
            return Err("kernel too large: segment ends above the supported window");
        }
        let src_end = p_offset.checked_add(copy_size).ok_or("offset overflow")?;
        if src_end > data.len() as u64 {
            return Err("program header points outside the ELF file");
        }
        // Physical span to account/map beyond the file data: the real
        // BSS tail (p_memsz - p_filesz), capped at BSS_MAP_EXTRA. Some
        // linkers emit pathological p_memsz values (up to the whole 2 GB
        // higher-half range); the cap keeps those loadable.
        let bss_tail = p_memsz
            .saturating_sub(p_filesz)
            .min(BSS_MAP_EXTRA);
        let seg_map_end = seg_phys_end
            .checked_add(bss_tail)
            .ok_or("segment size overflow")?;
        if seg_map_end > KERNEL_PHYS_BASE + MAX_KERNEL_PHYS {
            return Err("kernel too large: BSS extends above the supported window");
        }

        if copy_size > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data.as_ptr().add(p_offset as usize),
                    phys_offset as *mut u8,
                    copy_size as usize,
                );
            }
        }

        let seg_end = seg_map_end;
        if seg_end > info.phys_end {
            info.phys_end = seg_end;
        }

        info.segments[info.segment_count] = Segment {
            phys_addr: phys_offset,
            virt_addr: p_vaddr,
            mem_size: p_memsz,
            file_size: p_filesz,
            map_size: seg_map_end - phys_offset,
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
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}
