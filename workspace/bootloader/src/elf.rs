use crate::memory_map::{page_allocation_size, PhysicalRange, PAGE_SIZE};

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const KERNEL_PHYS_BASE: u64 = 0x10_0000;
pub const KERNEL_VIRT_BASE: u64 = 0xFFFF_FFFF_8000_0000;
// The current higher-half mapper supplies one page directory (1 GiB).
pub const MAX_KERNEL_IMAGE_SIZE: u64 = 1 << 30;
const MAX_SEGMENTS: usize = 16;

#[derive(Copy, Clone, Debug)]
pub struct Segment {
    pub phys_addr: u64,
    pub virt_addr: u64,
    pub mem_size: u64,
    pub file_size: u64,
    pub file_offset: u64,
    pub flags: u32,
}

#[derive(Debug)]
pub struct Elf64Info {
    pub entry: u64,
    pub segments: [Segment; MAX_SEGMENTS],
    pub segment_count: usize,
    pub phys_base: u64,
    pub phys_end: u64,
}

/// Validate a static x86-64 kernel completely, without touching physical memory.
pub fn parse_elf64(data: &[u8]) -> Result<Elf64Info, &'static str> {
    if data.len() < 64 || &data[..4] != b"\x7fELF" {
        return Err("invalid ELF header");
    }
    if data[4] != 2 || data[5] != 1 {
        return Err("kernel must be ELF64 little-endian");
    }
    if data[6] != 1 || read_u32_le(data, 20) != 1 {
        return Err("unsupported ELF version");
    }
    if read_u16_le(data, 16) != 2 || read_u16_le(data, 18) != 62 {
        return Err("kernel must be an x86-64 ET_EXEC image");
    }
    if read_u16_le(data, 52) != 64 || read_u16_le(data, 54) != 56 {
        return Err("unsupported ELF header sizes");
    }
    let phoff =
        usize::try_from(read_u64_le(data, 32)).map_err(|_| "program header offset overflow")?;
    let phnum = read_u16_le(data, 56) as usize;
    if phnum == 0 || phnum > MAX_SEGMENTS || phoff < 64 {
        return Err("invalid program header table");
    }
    let phend = phnum
        .checked_mul(56)
        .and_then(|size| phoff.checked_add(size))
        .ok_or("program header table overflow")?;
    if phend > data.len() {
        return Err("truncated program header table");
    }

    let mut info = Elf64Info {
        entry: read_u64_le(data, 24),
        segments: [Segment {
            phys_addr: 0,
            virt_addr: 0,
            mem_size: 0,
            file_size: 0,
            file_offset: 0,
            flags: 0,
        }; MAX_SEGMENTS],
        segment_count: 0,
        phys_base: 0,
        phys_end: 0,
    };
    let mut previous_virt_end = KERNEL_VIRT_BASE;
    let mut executable_entry = false;
    for index in 0..phnum {
        let offset = phoff + index * 56; // Entire table checked above.
        let p_type = read_u32_le(data, offset);
        if matches!(p_type, 2 | 3 | 5 | 7) {
            return Err("dynamic linking, interpreter or TLS is unsupported for the kernel");
        }
        if p_type != PT_LOAD {
            continue;
        }
        let flags = read_u32_le(data, offset + 4);
        let file_offset = read_u64_le(data, offset + 8);
        let virt_addr = read_u64_le(data, offset + 16);
        let physical = read_u64_le(data, offset + 24);
        let file_size = read_u64_le(data, offset + 32);
        let mem_size = read_u64_le(data, offset + 40);
        let align = read_u64_le(data, offset + 48);
        if file_size > mem_size {
            return Err("ELF file size exceeds segment memory size");
        }
        if mem_size == 0 {
            continue;
        }
        if flags & !7 != 0 {
            return Err("unsupported ELF segment flags");
        }
        if align > 1 && (!align.is_power_of_two() || virt_addr % align != file_offset % align) {
            return Err("invalid ELF segment alignment");
        }
        if virt_addr % PAGE_SIZE != file_offset % PAGE_SIZE {
            return Err("ELF segment file and virtual page offsets differ");
        }
        let virt_end = virt_addr
            .checked_add(mem_size)
            .ok_or("ELF virtual range overflow")?;
        if virt_addr < previous_virt_end {
            return Err("ELF load segments overlap or are out of order");
        }
        if virt_end > KERNEL_VIRT_BASE + MAX_KERNEL_IMAGE_SIZE {
            return Err("ELF exceeds the supported kernel virtual window");
        }
        // A pure BSS has no source bytes; its nominal file offset may be beyond EOF.
        if file_size != 0 {
            let file_end = file_offset
                .checked_add(file_size)
                .ok_or("ELF file range overflow")?;
            if file_end > data.len() as u64 {
                return Err("truncated ELF load segment");
            }
        }
        let phys_addr = if physical >= KERNEL_VIRT_BASE {
            KERNEL_PHYS_BASE
                .checked_add(physical - KERNEL_VIRT_BASE)
                .ok_or("ELF physical address overflow")?
        } else {
            physical
        };
        let phys_end = phys_addr
            .checked_add(mem_size)
            .ok_or("ELF physical range overflow")?;
        if info.segment_count == 0 {
            if virt_addr != KERNEL_VIRT_BASE || phys_addr == 0 || phys_addr % PAGE_SIZE != 0 {
                return Err("unsupported kernel image base");
            }
            info.phys_base = phys_addr;
        }
        let expected_phys = info
            .phys_base
            .checked_add(virt_addr - KERNEL_VIRT_BASE)
            .ok_or("ELF physical layout overflow")?;
        if phys_addr != expected_phys {
            return Err("ELF physical and virtual layouts disagree");
        }
        // Entry must point to actual instructions, not an executable zero-fill tail.
        if flags & PF_X != 0 && info.entry >= virt_addr && info.entry - virt_addr < file_size {
            executable_entry = true;
        }
        info.segments[info.segment_count] = Segment {
            phys_addr,
            virt_addr,
            mem_size,
            file_size,
            file_offset,
            flags,
        };
        info.segment_count += 1;
        info.phys_end = phys_end;
        previous_virt_end = virt_end;
    }
    if info.segment_count == 0 || !executable_entry {
        return Err("ELF entry is outside file-backed executable segments");
    }
    Ok(info)
}

impl Elf64Info {
    pub fn image_size(&self) -> u64 {
        self.phys_end - self.phys_base
    }

    /// Exact zero-fill tail of the final PT_LOAD (the linker emits a separate BSS).
    /// All earlier zero-fill tails are still cleared independently by load_into.
    pub fn bss_range(&self) -> (u64, u64) {
        let last = &self.segments[self.segment_count - 1];
        if last.mem_size == last.file_size {
            (0, 0)
        } else {
            (
                last.virt_addr + last.file_size,
                last.mem_size - last.file_size,
            )
        }
    }

    /// Reserve the destination with UEFI before calling this function.
    ///
    /// # Safety
    /// The destination must be exclusively owned writable memory, disjoint from
    /// data, and remain reserved while the kernel uses it. The plan must come from
    /// parse_elf64 and must not have been modified by the caller.
    pub unsafe fn load_into(
        &mut self,
        data: &[u8],
        destination: PhysicalRange,
    ) -> Result<(), &'static str> {
        let image_size = self.image_size();
        let allocated_size = page_allocation_size(image_size)?;
        if destination.base == 0
            || destination.base % PAGE_SIZE != 0
            || destination.size < allocated_size
            || destination.size > isize::MAX as u64
        {
            return Err("invalid kernel allocation");
        }
        destination.end()?;
        // Validate all sources and destinations before the first write, even when
        // passed different bytes than those used to parse the image.
        for segment in &self.segments[..self.segment_count] {
            let offset = segment
                .phys_addr
                .checked_sub(self.phys_base)
                .ok_or("kernel segment below allocation")?;
            let end = offset
                .checked_add(segment.mem_size)
                .ok_or("kernel segment overflow")?;
            if end > image_size || segment.file_size > segment.mem_size {
                return Err("kernel segment outside allocation");
            }
            if segment.file_size != 0 {
                let file_end = segment
                    .file_offset
                    .checked_add(segment.file_size)
                    .ok_or("kernel file range overflow")?;
                if file_end > data.len() as u64 {
                    return Err("kernel segment outside file");
                }
            }
        }
        // Clear the actual p_memsz extent, gaps and page padding. This also handles
        // pure BSS segments, including ones larger than the former 8 MiB margin.
        unsafe { core::ptr::write_bytes(destination.base as *mut u8, 0, allocated_size as usize) };
        for segment in &mut self.segments[..self.segment_count] {
            let address = destination.base + (segment.phys_addr - self.phys_base);
            if segment.file_size != 0 {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        data.as_ptr().add(segment.file_offset as usize),
                        address as *mut u8,
                        segment.file_size as usize,
                    )
                };
            }
            segment.phys_addr = address;
        }
        self.phys_base = destination.base;
        self.phys_end = destination.base + image_size;
        Ok(())
    }
}

fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}
fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}
