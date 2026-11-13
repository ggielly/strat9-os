/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! Kernel image validation and loading for the UEFI bootloader.
//!
//! The generic ELF64 decoding lives in `strat9-elf-core` (shared with the
//! kernel userland loader and the `s9vm` guest loader). This module adds the
//! bootloader's own policy:
//!
//! - the kernel must be an `ET_EXEC` x86-64 image linked at the higher-half
//!   base [`KERNEL_VIRT_BASE`];
//! - its physical layout must follow its virtual layout, page for page;
//! - it must fit the single 1 GiB page directory the higher-half mapper builds;
//! - the entry point must point at file-backed instructions, not at a
//!   zero-filled BSS tail.

use crate::memory_map::{page_allocation_size, PhysicalRange, PAGE_SIZE};
use strat9_elf_core::{ElfError, Header, PF_MASK, PF_X, PT_DYNAMIC, PT_INTERP, PT_TLS};

const PT_SHLIB: u32 = 5;
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
    let header = Header::parse(data).map_err(ElfError::message)?;
    if !header.is_exec() {
        return Err("kernel must be an x86-64 ET_EXEC image");
    }
    let phnum = header.e_phnum as usize;
    if phnum == 0 || phnum > MAX_SEGMENTS {
        return Err("invalid program header table");
    }

    let mut info = Elf64Info {
        entry: header.e_entry,
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
    for phdr in header.program_headers(data) {
        if matches!(phdr.p_type, PT_DYNAMIC | PT_INTERP | PT_TLS | PT_SHLIB) {
            return Err("dynamic linking, interpreter or TLS is unsupported for the kernel");
        }
        if !phdr.is_load() {
            continue;
        }
        // A segment of zero memory size carries nothing: skip it before the
        // format validation so a pure empty entry cannot fail the load.
        if phdr.p_memsz == 0 {
            continue;
        }
        let segment = phdr
            .load_segment(data.len())
            .map_err(ElfError::message)?
            .ok_or("invalid loadable segment")?;
        if phdr.p_align > 1 && phdr.p_vaddr % phdr.p_align != phdr.p_offset % phdr.p_align {
            return Err("invalid ELF segment alignment");
        }
        if segment.flags & !PF_MASK != 0 {
            return Err("unsupported ELF segment flags");
        }
        if segment.flags & (1 | 2) == (1 | 2) {
            return Err("writable executable ELF segment is unsupported");
        }
        let virt_addr = segment.vaddr;
        let virt_end = segment.end_vaddr();
        if virt_addr < previous_virt_end {
            return Err("ELF load segments overlap or are out of order");
        }
        if info.segment_count != 0
            && virt_addr / PAGE_SIZE == (previous_virt_end - 1) / PAGE_SIZE
            && segment.flags != info.segments[info.segment_count - 1].flags
        {
            return Err("ELF segments with different permissions share a page");
        }
        if virt_end > KERNEL_VIRT_BASE + MAX_KERNEL_IMAGE_SIZE {
            return Err("ELF exceeds the supported kernel virtual window");
        }
        let physical = phdr.p_paddr;
        let phys_addr = if physical >= KERNEL_VIRT_BASE {
            KERNEL_PHYS_BASE
                .checked_add(physical - KERNEL_VIRT_BASE)
                .ok_or("ELF physical address overflow")?
        } else {
            physical
        };
        let phys_end = phys_addr
            .checked_add(segment.memsz)
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
        if segment.flags & PF_X != 0
            && info.entry >= virt_addr
            && info.entry - virt_addr < segment.filesz
        {
            executable_entry = true;
        }
        info.segments[info.segment_count] = Segment {
            phys_addr,
            virt_addr,
            mem_size: segment.memsz,
            file_size: segment.filesz,
            file_offset: segment.file_offset,
            flags: segment.flags,
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
