use crate::memory_map::{page_allocation_size, PhysicalRange};

const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const PT_LOAD: u32 = 1;

const KERNEL_PHYS_BASE: u64 = 0x100_000;
const KERNEL_VIRT_BASE: u64 = 0xFFFF_FFFF_8000_0000;
const HIGHER_HALF_THRESHOLD: u64 = 0x8000_0000_0000;
/// Preserve the existing BSS mapping budget in this allocation fix. Replacing
/// this compatibility margin with p_memsz handling is a separate change (R09).
const BSS_MAP_EXTRA: u64 = 8 * 1024 * 1024; // 8 MiB

#[derive(Copy, Clone)]
pub struct Segment {
    pub phys_addr: u64,
    pub virt_addr: u64,
    pub mem_size: u64,
    pub file_size: u64,
    pub file_offset: u64,
    pub flags: u32,
}

pub struct Elf64Info {
    pub entry: u64,
    pub segments: [Segment; 16],
    pub segment_count: usize,
    pub phys_base: u64,
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
            file_offset: 0,
            flags: 0,
        }; 16],
        segment_count: 0,
        phys_base: u64::MAX,
        phys_end: 0,
    };

    for i in 0..phnum {
        let offset = phoff.checked_add(i * phentsize).ok_or("overflow")?;
        let header_end = offset
            .checked_add(phentsize)
            .ok_or("program header overflow")?;
        if header_end > data.len() {
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
            p_paddr
                .checked_sub(KERNEL_VIRT_BASE)
                .and_then(|offset| KERNEL_PHYS_BASE.checked_add(offset))
                .ok_or("unsupported kernel physical address")?
        } else {
            p_paddr
        };

        // Parsing must not write physical memory: validate the complete plan
        // before the caller reserves its contiguous destination with UEFI.
        let file_end = p_offset
            .checked_add(p_filesz)
            .ok_or("segment file range overflow")?;
        if file_end > data.len() as u64 || p_filesz > p_memsz {
            return Err("invalid kernel segment file range");
        }
        if phys_offset < 0x1000 || phys_offset >= 0x1000_0000 {
            return Err("unsupported kernel physical address");
        }

        let seg_end = phys_offset
            .checked_add(p_filesz)
            .and_then(|end| end.checked_add(BSS_MAP_EXTRA))
            .ok_or("kernel image range overflow")?;
        info.phys_base = info.phys_base.min(phys_offset);
        if seg_end > info.phys_end {
            info.phys_end = seg_end;
        }

        info.segments[info.segment_count] = Segment {
            phys_addr: phys_offset,
            virt_addr: p_vaddr,
            mem_size: p_memsz,
            file_size: p_filesz,
            file_offset: p_offset,
            flags: p_flags,
        };
        info.segment_count += 1;
    }

    if info.segment_count == 0 {
        return Err("No PT_LOAD segments found");
    }

    // The existing mapper maps one contiguous image at KERNEL_VIRT_BASE.
    // Verify that moving the physical allocation preserves that layout.
    if info.phys_base % 4096 != 0 {
        return Err("kernel physical base is not page aligned");
    }
    for segment in &info.segments[..info.segment_count] {
        let expected = KERNEL_VIRT_BASE
            .checked_add(segment.phys_addr - info.phys_base)
            .ok_or("kernel virtual address overflow")?;
        if segment.virt_addr != expected {
            return Err("kernel requires a non-contiguous virtual layout");
        }
    }

    Ok(info)
}

impl Elf64Info {
    pub fn image_size(&self) -> u64 {
        self.phys_end - self.phys_base
    }

    /// Copy into a UEFI-owned allocation, then rebase the physical handoff.
    ///
    /// # Safety
    /// The destination must be an exclusively owned, writable page allocation,
    /// must not overlap `data`, and must outlive the kernel's use of this image.
    pub unsafe fn load_into(
        &mut self,
        data: &[u8],
        destination: PhysicalRange,
    ) -> Result<(), &'static str> {
        let image_size = self.image_size();
        if destination.base == 0
            || destination.base % 4096 != 0
            || destination.size < page_allocation_size(image_size)?
        {
            return Err("kernel allocation too small or unaligned");
        }
        destination.end()?;
        // Validate all ranges before the first copy, including callers that
        // supply different file bytes from the ones used to construct the plan.
        for segment in &self.segments[..self.segment_count] {
            let offset = segment
                .phys_addr
                .checked_sub(self.phys_base)
                .ok_or("kernel segment below image base")?;
            let end = offset
                .checked_add(segment.file_size)
                .ok_or("kernel segment overflow")?;
            let file_end = segment
                .file_offset
                .checked_add(segment.file_size)
                .ok_or("kernel file range overflow")?;
            if end > image_size || file_end > data.len() as u64 {
                return Err("kernel segment outside allocation or file");
            }
        }
        for segment in &mut self.segments[..self.segment_count] {
            let address = destination.base + (segment.phys_addr - self.phys_base);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data.as_ptr().add(segment.file_offset as usize),
                    address as *mut u8,
                    segment.file_size as usize,
                );
            }
            segment.phys_addr = address;
        }
        self.phys_base = destination.base;
        self.phys_end = destination.base + image_size;
        Ok(())
    }
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
