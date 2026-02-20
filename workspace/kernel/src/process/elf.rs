//! ELF64 loader for Strat9-OS.
//!
//! Parses ELF64 headers and loads PT_LOAD segments into a user address space,
//! then creates a kernel task that trampolines into Ring 3 via IRETQ.
//!
//! Supports :
//!   - ET_EXEC
//!   - ET_DYN (PIE/static-PIE)
//!   - ELF64 little-endian x86_64 binaries.

use alloc::{sync::Arc, vec::Vec};
use x86_64::{
    structures::paging::{Mapper, Page, Size4KiB},
    VirtAddr,
};

use crate::{
    capability::{Capability, CapabilityTable},
    memory::address_space::{AddressSpace, VmaFlags, VmaPageSize, VmaType},
    process::{
        task::{CpuContext, KernelStack, SyncUnsafeCell, Task},
        TaskId, TaskPriority, TaskState,
    },
};

// ---------------------------------------------------------------------------
// ELF64 constants
// ---------------------------------------------------------------------------

const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EV_CURRENT: u32 = 1;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const DT_NULL: i64 = 0;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_SYMENT: i64 = 11;
const DT_JMPREL: i64 = 23;
const DT_PLTRELSZ: i64 = 2;
const DT_PLTREL: i64 = 20;
const DT_RELACOUNT: i64 = 0x6fff_fff9;
const DT_RELR: i64 = 36;
const DT_RELRSZ: i64 = 35;
const DT_RELRENT: i64 = 37;
const R_X86_64_RELATIVE: u32 = 8;
const R_X86_64_64: u32 = 1;
const R_X86_64_GLOB_DAT: u32 = 6;
const R_X86_64_JUMP_SLOT: u32 = 7;

/// Maximum virtual address we accept for user-space mappings.
pub const USER_ADDR_MAX: u64 = 0x0000_8000_0000_0000;
/// Preferred base when placing ET_DYN (PIE) images.
const PIE_BASE_ADDR: u64 = 0x0000_0001_0000_0000;

/// User stack location (below the non-canonical gap).
pub const USER_STACK_BASE: u64 = 0x0000_7FFF_F000_0000;
/// Number of 4 KiB pages for the user stack (16 pages = 64 KiB).
pub const USER_STACK_PAGES: usize = 16;
/// Top of the user stack (stack grows down).
pub const USER_STACK_TOP: u64 = USER_STACK_BASE + (USER_STACK_PAGES as u64) * 4096;

/// Result of loading an ELF image into an address space.
#[derive(Debug, Clone, Copy)]
pub struct LoadedElfInfo {
    /// Entry point to jump to (ld.so entry if PT_INTERP, otherwise program entry).
    pub runtime_entry: u64,
    /// Program entry point from the main executable after relocation.
    pub program_entry: u64,
    /// Relocated virtual address of the main executable program header table.
    pub phdr_vaddr: u64,
    /// Program header entry size.
    pub phent: u16,
    /// Program header count.
    pub phnum: u16,
    /// Dynamic loader base address when PT_INTERP is present.
    pub interp_base: Option<u64>,
}

// ---------------------------------------------------------------------------
// ELF64 header structures
// ---------------------------------------------------------------------------

/// ELF64 file header (64 bytes).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct Elf64Header {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

/// ELF64 program header (56 bytes).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct Elf64Dyn {
    d_tag: i64,
    d_val: u64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct Elf64Rela {
    r_offset: u64,
    r_info: u64,
    r_addend: i64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct Elf64Sym {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse and validate the ELF64 file header from raw bytes.
fn parse_header(data: &[u8]) -> Result<Elf64Header, &'static str> {
    if data.len() < core::mem::size_of::<Elf64Header>() {
        return Err("ELF data too small for header");
    }

    // SAFETY: data is large enough and Elf64Header is repr(C, packed) with no
    // alignment requirements beyond 1.
    let header: Elf64Header =
        unsafe { core::ptr::read_unaligned(data.as_ptr() as *const Elf64Header) };

    // Validate magic
    if header.e_ident[0..4] != ELF_MAGIC {
        return Err("Bad ELF magic");
    }

    // Class: 64-bit
    if header.e_ident[4] != ELFCLASS64 {
        return Err("Not ELF64");
    }

    // Data: little-endian
    if header.e_ident[5] != ELFDATA2LSB {
        return Err("Not little-endian ELF");
    }

    // Machine: x86_64
    if header.e_machine != EM_X86_64 {
        return Err("Not x86_64 ELF");
    }

    // Type: executable or shared object (PIE/static PIE executable image)
    if header.e_type != ET_EXEC && header.e_type != ET_DYN {
        return Err("Unsupported ELF type (expected ET_EXEC or ET_DYN)");
    }

    // ELF version
    if header.e_version != EV_CURRENT {
        return Err("Unsupported ELF version");
    }

    // Entry point must be canonical user space (for ET_DYN this is relative and
    // validated again after relocation). ET_EXEC must be non-zero.
    if header.e_entry >= USER_ADDR_MAX {
        return Err("Entry point outside user address range");
    }
    if header.e_type == ET_EXEC && header.e_entry == 0 {
        return Err("ET_EXEC has null entry");
    }

    // Sanity check program headers
    if header.e_phentsize as usize != core::mem::size_of::<Elf64Phdr>() {
        return Err("Unexpected phentsize");
    }

    let ph_end = (header.e_phoff as usize)
        .checked_add((header.e_phnum as usize) * (header.e_phentsize as usize))
        .ok_or("Program header table overflows")?;
    if ph_end > data.len() {
        return Err("Program headers extend past file");
    }

    Ok(header)
}

/// Iterate over program headers in the ELF.
fn program_headers<'a>(
    data: &'a [u8],
    header: &Elf64Header,
) -> impl Iterator<Item = Elf64Phdr> + 'a {
    let phoff = header.e_phoff as usize;
    let phsize = header.e_phentsize as usize;
    let phnum = header.e_phnum as usize;

    (0..phnum).map(move |i| {
        let offset = phoff + i * phsize;
        // SAFETY: parse_header already validated that all program headers fit
        // within `data`, and Elf64Phdr is packed (align 1).
        unsafe { core::ptr::read_unaligned(data.as_ptr().add(offset) as *const Elf64Phdr) }
    })
}

fn parse_interp_path<'a>(
    elf_data: &'a [u8],
    phdrs: &[Elf64Phdr],
) -> Result<Option<&'a str>, &'static str> {
    let Some(interp) = phdrs.iter().find(|ph| ph.p_type == PT_INTERP) else {
        return Ok(None);
    };
    if interp.p_filesz == 0 {
        return Err("PT_INTERP has empty path");
    }
    let start = interp.p_offset as usize;
    let end = start
        .checked_add(interp.p_filesz as usize)
        .ok_or("PT_INTERP range overflow")?;
    if end > elf_data.len() {
        return Err("PT_INTERP extends past file");
    }
    let raw = &elf_data[start..end];
    let nul = raw
        .iter()
        .position(|&b| b == 0)
        .ok_or("PT_INTERP path is not NUL terminated")?;
    let s = core::str::from_utf8(&raw[..nul]).map_err(|_| "PT_INTERP path is not UTF-8")?;
    if s.is_empty() {
        return Err("PT_INTERP path is empty");
    }
    Ok(Some(s))
}

fn find_relocated_phdr_vaddr(
    header: &Elf64Header,
    phdrs: &[Elf64Phdr],
    load_bias: u64,
) -> Result<u64, &'static str> {
    let phoff = header.e_phoff;
    for ph in phdrs {
        if ph.p_type != PT_LOAD || ph.p_filesz == 0 {
            continue;
        }
        let file_start = ph.p_offset;
        let file_end = ph
            .p_offset
            .checked_add(ph.p_filesz)
            .ok_or("PHDR location overflow")?;
        if phoff >= file_start && phoff < file_end {
            let delta = phoff - file_start;
            let vaddr = ph
                .p_vaddr
                .checked_add(delta)
                .and_then(|v| v.checked_add(load_bias))
                .ok_or("Relocated PHDR address overflow")?;
            if vaddr >= USER_ADDR_MAX {
                return Err("Relocated PHDR outside user address space");
            }
            return Ok(vaddr);
        }
    }
    Err("Program headers are not covered by a PT_LOAD segment")
}

fn read_elf_from_vfs(path: &str) -> Result<Vec<u8>, &'static str> {
    const MAX_ELF_SIZE: usize = 64 * 1024 * 1024;
    let fd =
        crate::vfs::open(path, crate::vfs::OpenFlags::READ).map_err(|_| "PT_INTERP open failed")?;
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = match crate::vfs::read(fd, &mut buf) {
            Ok(n) => n,
            Err(_) => {
                let _ = crate::vfs::close(fd);
                return Err("PT_INTERP read failed");
            }
        };
        if n == 0 {
            break;
        }
        if out.len().saturating_add(n) > MAX_ELF_SIZE {
            let _ = crate::vfs::close(fd);
            return Err("PT_INTERP file too large");
        }
        out.extend_from_slice(&buf[..n]);
    }
    let _ = crate::vfs::close(fd);
    if out.is_empty() {
        return Err("PT_INTERP file is empty");
    }
    Ok(out)
}

/// Compute total mapped bounds for all PT_LOAD segments.
fn compute_load_bounds(phdrs: &[Elf64Phdr]) -> Result<(u64, u64), &'static str> {
    let mut min_vaddr = u64::MAX;
    let mut max_vaddr = 0u64;
    let mut saw_load = false;

    for phdr in phdrs {
        if phdr.p_type != PT_LOAD {
            continue;
        }
        if phdr.p_memsz == 0 {
            continue;
        }
        saw_load = true;

        if phdr.p_memsz < phdr.p_filesz {
            return Err("PT_LOAD memsz < filesz");
        }

        // ELF requires p_vaddr % page == p_offset % page for PT_LOAD.
        if ((phdr.p_vaddr ^ phdr.p_offset) & 0xFFF) != 0 {
            return Err("PT_LOAD alignment mismatch (vaddr/offset)");
        }

        let seg_end = phdr
            .p_vaddr
            .checked_add(phdr.p_memsz)
            .ok_or("PT_LOAD vaddr+memsz overflow")?;
        if seg_end > USER_ADDR_MAX {
            return Err("PT_LOAD exceeds user address space");
        }

        let seg_start_page = phdr.p_vaddr & !0xFFF;
        let seg_end_page = (seg_end + 0xFFF) & !0xFFF;
        min_vaddr = min_vaddr.min(seg_start_page);
        max_vaddr = max_vaddr.max(seg_end_page);
    }

    if !saw_load {
        return Err("ELF has no PT_LOAD segments");
    }
    Ok((min_vaddr, max_vaddr))
}

/// Compute load bias and relocated entry for ET_EXEC / ET_DYN.
fn compute_load_bias_and_entry(
    user_as: &AddressSpace,
    header: &Elf64Header,
    phdrs: &[Elf64Phdr],
) -> Result<(u64, u64), &'static str> {
    let (min_vaddr, max_vaddr) = compute_load_bounds(phdrs)?;
    let span = max_vaddr
        .checked_sub(min_vaddr)
        .ok_or("Invalid PT_LOAD bounds")?;

    let load_bias = if header.e_type == ET_EXEC {
        0
    } else {
        let n_pages = (span as usize).div_ceil(4096);
        let load_base = user_as
            .find_free_vma_range(PIE_BASE_ADDR, n_pages, VmaPageSize::Small)
            .or_else(|| {
                user_as.find_free_vma_range(0x0000_0000_1000_0000, n_pages, VmaPageSize::Small)
            })
            .ok_or("No virtual range for ET_DYN image")?;
        load_base
            .checked_sub(min_vaddr)
            .ok_or("ET_DYN load bias underflow")?
    };

    let relocated_end = max_vaddr
        .checked_add(load_bias)
        .ok_or("Relocated PT_LOAD range overflow")?;
    if relocated_end > USER_ADDR_MAX {
        return Err("Relocated PT_LOAD range exceeds user space");
    }

    let relocated_entry = header
        .e_entry
        .checked_add(load_bias)
        .ok_or("Relocated entry overflow")?;
    if relocated_entry == 0 || relocated_entry >= USER_ADDR_MAX {
        return Err("Relocated entry outside user space");
    }

    Ok((load_bias, relocated_entry))
}

fn apply_segment_permissions(
    user_as: &AddressSpace,
    page_start: u64,
    page_count: usize,
    flags: VmaFlags,
) -> Result<(), &'static str> {
    use x86_64::registers::control::Cr3;

    let pte_flags = flags.to_page_flags();
    // SAFETY: loader owns this AddressSpace during image construction.
    let mut mapper = unsafe { user_as.mapper() };
    for i in 0..page_count {
        let vaddr = page_start
            .checked_add((i as u64) * 4096)
            .ok_or("Permission update address overflow")?;
        let page = Page::<Size4KiB>::from_start_address(VirtAddr::new(vaddr))
            .map_err(|_| "Invalid page while updating segment flags")?;
        // SAFETY: the page is already mapped by map_region for this segment.
        let _ = unsafe {
            mapper
                .update_flags(page, pte_flags)
                .map_err(|_| "Failed to update segment page flags")?
        };
        // We ignore flush here and do a targeted flush decision below.
    }

    // During ELF loading we update a freshly-created user address space that is
    // not active on other CPUs.  Cross-CPU shootdowns here only add boot-time
    // latency and can timeout while APs are not yet servicing IPIs.
    // If this address space is currently active on this CPU, local invalidation
    // is enough for the loader path.
    let (current_cr3, _) = Cr3::read();
    if current_cr3.start_address() == user_as.cr3() {
        let end = page_start + (page_count as u64) * 4096;
        let mut v = page_start;
        while v < end {
            unsafe {
                core::arch::asm!("invlpg [{}]", in(reg) v, options(nostack, preserves_flags));
            }
            v += 4096;
        }
    }

    Ok(())
}

fn read_user_mapped_bytes(
    user_as: &AddressSpace,
    mut vaddr: u64,
    out: &mut [u8],
) -> Result<(), &'static str> {
    let end = vaddr
        .checked_add(out.len() as u64)
        .ok_or("Read range overflow")?;
    if end > USER_ADDR_MAX {
        return Err("Read range outside user space");
    }
    let mut copied = 0usize;
    while copied < out.len() {
        let page_off = (vaddr & 0xFFF) as usize;
        let chunk = core::cmp::min(out.len() - copied, 4096 - page_off);
        let phys = user_as
            .translate(VirtAddr::new(vaddr))
            .ok_or("Failed to translate mapped user bytes")?;
        let src = crate::memory::phys_to_virt(phys.as_u64()) as *const u8;
        // SAFETY: src points to mapped physical memory via HHDM.
        unsafe { core::ptr::copy_nonoverlapping(src, out.as_mut_ptr().add(copied), chunk) };
        copied += chunk;
        vaddr = vaddr
            .checked_add(chunk as u64)
            .ok_or("Virtual address overflow while reading mapped bytes")?;
    }
    Ok(())
}

fn write_user_mapped_bytes(
    user_as: &AddressSpace,
    mut vaddr: u64,
    src: &[u8],
) -> Result<(), &'static str> {
    let end = vaddr
        .checked_add(src.len() as u64)
        .ok_or("Write range overflow")?;
    if end > USER_ADDR_MAX {
        return Err("Write range outside user space");
    }
    let mut written = 0usize;
    while written < src.len() {
        let page_off = (vaddr & 0xFFF) as usize;
        let chunk = core::cmp::min(src.len() - written, 4096 - page_off);
        let phys = user_as
            .translate(VirtAddr::new(vaddr))
            .ok_or("Failed to translate relocation target")?;
        let dst = crate::memory::phys_to_virt(phys.as_u64()) as *mut u8;
        // SAFETY: destination points to mapped user frame through HHDM.
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr().add(written), dst, chunk) };
        written += chunk;
        vaddr = vaddr
            .checked_add(chunk as u64)
            .ok_or("Virtual address overflow while writing mapped bytes")?;
    }
    Ok(())
}

fn read_user_u64(user_as: &AddressSpace, vaddr: u64) -> Result<u64, &'static str> {
    let mut raw = [0u8; 8];
    read_user_mapped_bytes(user_as, vaddr, &mut raw)?;
    Ok(u64::from_le_bytes(raw))
}

fn write_user_u64(user_as: &AddressSpace, vaddr: u64, value: u64) -> Result<(), &'static str> {
    write_user_mapped_bytes(user_as, vaddr, &value.to_le_bytes())
}

fn apply_relr_relocations(
    user_as: &AddressSpace,
    load_bias: u64,
    relr_base: u64,
    relr_size: usize,
    relr_ent: usize,
) -> Result<usize, &'static str> {
    if relr_size == 0 {
        return Ok(0);
    }
    if relr_ent != core::mem::size_of::<u64>() {
        return Err("Unsupported DT_RELRENT size");
    }
    if relr_size % relr_ent != 0 {
        return Err("DT_RELR table size is not aligned");
    }

    let count = relr_size / relr_ent;
    let mut applied = 0usize;
    let mut where_addr = 0u64;

    for i in 0..count {
        let entry_addr = relr_base
            .checked_add((i * relr_ent) as u64)
            .ok_or("DT_RELR walk overflow")?;
        let entry = read_user_u64(user_as, entry_addr)?;

        if (entry & 1) == 0 {
            where_addr = load_bias
                .checked_add(entry)
                .ok_or("DT_RELR absolute relocation overflow")?;
            if where_addr >= USER_ADDR_MAX {
                return Err("DT_RELR target outside user space");
            }
            let cur = read_user_u64(user_as, where_addr)?;
            write_user_u64(
                user_as,
                where_addr,
                cur.checked_add(load_bias)
                    .ok_or("DT_RELR relocated value overflow")?,
            )?;
            where_addr = where_addr
                .checked_add(8)
                .ok_or("DT_RELR where pointer overflow")?;
            applied += 1;
        } else {
            let mut bitmap = entry >> 1;
            for bit in 0..63u64 {
                if (bitmap & 1) != 0 {
                    let slot = where_addr
                        .checked_add(bit * 8)
                        .ok_or("DT_RELR bitmap target overflow")?;
                    if slot >= USER_ADDR_MAX {
                        return Err("DT_RELR bitmap target outside user space");
                    }
                    let cur = read_user_u64(user_as, slot)?;
                    write_user_u64(
                        user_as,
                        slot,
                        cur.checked_add(load_bias)
                            .ok_or("DT_RELR bitmap relocated value overflow")?,
                    )?;
                    applied += 1;
                }
                bitmap >>= 1;
                if bitmap == 0 {
                    break;
                }
            }
            where_addr = where_addr
                .checked_add(63 * 8)
                .ok_or("DT_RELR where advance overflow")?;
        }
    }
    Ok(applied)
}

fn apply_dynamic_relocations(
    user_as: &AddressSpace,
    phdrs: &[Elf64Phdr],
    elf_type: u16,
    load_bias: u64,
) -> Result<(), &'static str> {
    if elf_type != ET_DYN {
        return Ok(());
    }

    let dynamic = phdrs.iter().find(|ph| ph.p_type == PT_DYNAMIC);
    let Some(dynamic_ph) = dynamic else {
        return Ok(());
    };
    if dynamic_ph.p_filesz == 0 {
        return Ok(());
    }

    let dyn_addr = dynamic_ph
        .p_vaddr
        .checked_add(load_bias)
        .ok_or("PT_DYNAMIC relocated address overflow")?;
    let dyn_count = (dynamic_ph.p_filesz as usize) / core::mem::size_of::<Elf64Dyn>();

    let mut rela_addr: Option<u64> = None;
    let mut rela_size: usize = 0;
    let mut rela_ent: usize = core::mem::size_of::<Elf64Rela>();
    let mut jmprel_addr: Option<u64> = None;
    let mut jmprel_size: usize = 0;
    let mut pltrel_kind: Option<u64> = None;
    let mut symtab_addr: Option<u64> = None;
    let mut sym_ent: usize = core::mem::size_of::<Elf64Sym>();
    let mut strtab_addr: Option<u64> = None;
    let mut rela_count_hint: Option<usize> = None;
    let mut relr_addr: Option<u64> = None;
    let mut relr_size: usize = 0;
    let mut relr_ent: usize = 0;

    for i in 0..dyn_count {
        let entry_addr = dyn_addr
            .checked_add((i * core::mem::size_of::<Elf64Dyn>()) as u64)
            .ok_or("PT_DYNAMIC walk overflow")?;
        let mut raw = [0u8; core::mem::size_of::<Elf64Dyn>()];
        read_user_mapped_bytes(user_as, entry_addr, &mut raw)?;
        // SAFETY: raw has exact size of Elf64Dyn; read_unaligned handles packing.
        let dyn_entry = unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const Elf64Dyn) };

        match dyn_entry.d_tag {
            DT_NULL => break,
            DT_RELA => {
                rela_addr = Some(
                    dyn_entry
                        .d_val
                        .checked_add(load_bias)
                        .ok_or("DT_RELA relocated address overflow")?,
                )
            }
            DT_RELASZ => rela_size = dyn_entry.d_val as usize,
            DT_RELAENT => rela_ent = dyn_entry.d_val as usize,
            DT_RELACOUNT => rela_count_hint = Some(dyn_entry.d_val as usize),
            DT_JMPREL => {
                jmprel_addr = Some(
                    dyn_entry
                        .d_val
                        .checked_add(load_bias)
                        .ok_or("DT_JMPREL relocated address overflow")?,
                )
            }
            DT_PLTRELSZ => jmprel_size = dyn_entry.d_val as usize,
            DT_PLTREL => pltrel_kind = Some(dyn_entry.d_val),
            DT_SYMTAB => {
                symtab_addr = Some(
                    dyn_entry
                        .d_val
                        .checked_add(load_bias)
                        .ok_or("DT_SYMTAB relocated address overflow")?,
                )
            }
            DT_SYMENT => sym_ent = dyn_entry.d_val as usize,
            DT_STRTAB => {
                strtab_addr = Some(
                    dyn_entry
                        .d_val
                        .checked_add(load_bias)
                        .ok_or("DT_STRTAB relocated address overflow")?,
                )
            }
            DT_RELR => {
                relr_addr = Some(
                    dyn_entry
                        .d_val
                        .checked_add(load_bias)
                        .ok_or("DT_RELR relocated address overflow")?,
                )
            }
            DT_RELRSZ => relr_size = dyn_entry.d_val as usize,
            DT_RELRENT => relr_ent = dyn_entry.d_val as usize,
            _ => {}
        }
    }

    let mut relr_applied = 0usize;
    if let Some(relr_base) = relr_addr {
        relr_applied = apply_relr_relocations(user_as, load_bias, relr_base, relr_size, relr_ent)?;
    } else if relr_size != 0 || relr_ent != 0 {
        return Err("DT_RELR metadata present without DT_RELR base");
    }
    if rela_ent != core::mem::size_of::<Elf64Rela>() {
        return Err("Unsupported DT_RELAENT size");
    }
    if sym_ent != core::mem::size_of::<Elf64Sym>() {
        return Err("Unsupported DT_SYMENT size");
    }
    if pltrel_kind.is_some() && pltrel_kind != Some(DT_RELA as u64) {
        return Err("Only DT_PLTREL=DT_RELA is supported");
    }

    let resolve_symbol = |sym_idx: u32| -> Result<u64, &'static str> {
        if sym_idx == 0 {
            return Ok(0);
        }
        let symtab = symtab_addr.ok_or("Missing DT_SYMTAB for symbol relocations")?;
        let _ = strtab_addr.ok_or("Missing DT_STRTAB for symbol relocations")?;
        let sym_addr = symtab
            .checked_add((sym_idx as u64) * (sym_ent as u64))
            .ok_or("Symbol table address overflow")?;
        let mut raw = [0u8; core::mem::size_of::<Elf64Sym>()];
        read_user_mapped_bytes(user_as, sym_addr, &mut raw)?;
        // SAFETY: raw has exact size of Elf64Sym.
        let sym = unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const Elf64Sym) };
        if sym.st_shndx == 0 {
            return Err("Undefined symbol relocation not supported");
        }
        sym.st_value
            .checked_add(load_bias)
            .ok_or("Symbol value relocation overflow")
    };

    let apply_rela_table = |table_base: u64,
                            table_size: usize,
                            count_hint: Option<usize>|
     -> Result<usize, &'static str> {
        if table_size == 0 {
            return Ok(0);
        }
        let mut count = table_size / rela_ent;
        if let Some(hint) = count_hint {
            count = core::cmp::min(count, hint);
        }
        let mut applied = 0usize;
        for i in 0..count {
            let rela_addr_i = table_base
                .checked_add((i * rela_ent) as u64)
                .ok_or("Rela table overflow")?;
            let mut raw = [0u8; core::mem::size_of::<Elf64Rela>()];
            read_user_mapped_bytes(user_as, rela_addr_i, &mut raw)?;
            // SAFETY: raw has exact size of Elf64Rela.
            let rela = unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const Elf64Rela) };

            let r_type = (rela.r_info & 0xffff_ffff) as u32;
            let r_sym = (rela.r_info >> 32) as u32;
            let target = rela
                .r_offset
                .checked_add(load_bias)
                .ok_or("Relocation target overflow")?;
            if target >= USER_ADDR_MAX {
                return Err("Relocation target outside user space");
            }

            let value = match r_type {
                R_X86_64_RELATIVE => {
                    if r_sym != 0 {
                        return Err("R_X86_64_RELATIVE with non-zero symbol");
                    }
                    (load_bias as i128)
                        .checked_add(rela.r_addend as i128)
                        .ok_or("Relocation value overflow")?
                }
                R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT | R_X86_64_64 => {
                    let sym_val = resolve_symbol(r_sym)? as i128;
                    sym_val
                        .checked_add(rela.r_addend as i128)
                        .ok_or("Relocation value overflow")?
                }
                _ => return Err("Unsupported dynamic relocation type"),
            };
            if value < 0 || value > u64::MAX as i128 {
                return Err("Relocation value out of range");
            }
            write_user_mapped_bytes(user_as, target, &(value as u64).to_le_bytes())?;
            applied += 1;
        }
        Ok(applied)
    };

    let mut total_applied = 0usize;
    if let Some(rela_base) = rela_addr {
        total_applied += apply_rela_table(rela_base, rela_size, rela_count_hint)?;
    }
    if let Some(jmprel_base) = jmprel_addr {
        total_applied += apply_rela_table(jmprel_base, jmprel_size, None)?;
    }

    if total_applied > 0 {
        log::debug!("[elf] Applied {} RELA relocations", total_applied);
    }
    if relr_applied > 0 {
        log::debug!("[elf] Applied {} RELR relocations", relr_applied);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Convert ELF p_flags to VmaFlags.
fn elf_flags_to_vma(p_flags: u32) -> VmaFlags {
    VmaFlags {
        readable: p_flags & PF_R != 0,
        writable: p_flags & PF_W != 0,
        executable: p_flags & PF_X != 0,
        user_accessible: true,
    }
}

/// Load a single PT_LOAD segment into the given address space.
///
/// Allocates physical frames, maps them with appropriate permissions, and
/// copies file data into the mapping. BSS (memsz > filesz) is already
/// zero-filled because `map_region` zeroes newly allocated frames.
fn load_segment(
    user_as: &AddressSpace,
    elf_data: &[u8],
    phdr: &Elf64Phdr,
    load_bias: u64,
) -> Result<(), &'static str> {
    let vaddr = phdr
        .p_vaddr
        .checked_add(load_bias)
        .ok_or("PT_LOAD relocated vaddr overflow")?;
    let memsz = phdr.p_memsz;
    let filesz = phdr.p_filesz;
    let offset = phdr.p_offset;

    // Validate addresses are in user space
    if vaddr >= USER_ADDR_MAX {
        return Err("PT_LOAD vaddr outside user space");
    }
    let end = vaddr
        .checked_add(memsz)
        .ok_or("PT_LOAD vaddr+memsz overflows")?;
    if end > USER_ADDR_MAX {
        return Err("PT_LOAD segment extends past user space");
    }

    // Validate file region
    let file_end = (offset as usize)
        .checked_add(filesz as usize)
        .ok_or("PT_LOAD offset+filesz overflows")?;
    if file_end > elf_data.len() {
        return Err("PT_LOAD file data extends past ELF");
    }

    // Calculate page-aligned mapping
    let page_start = vaddr & !0xFFF;
    let page_end = (end + 0xFFF) & !0xFFF;
    let page_count = ((page_end - page_start) / 4096) as usize;

    // Map writable during copy, then restore final ELF flags.
    let actual_flags = elf_flags_to_vma(phdr.p_flags);
    let load_flags = VmaFlags {
        readable: true,
        writable: true, // Need write access to copy data in
        executable: actual_flags.executable,
        user_accessible: true,
    };

    let vma_type = if actual_flags.executable {
        VmaType::Code
    } else {
        VmaType::Anonymous
    };
    log::debug!(
        "[elf] map PT_LOAD: start={:#x} pages={} filesz={:#x}",
        page_start,
        page_count,
        filesz
    );
    user_as.map_region(
        page_start,
        page_count,
        load_flags,
        vma_type,
        VmaPageSize::Small,
    )?;

    // Copy file data into the mapped pages.
    // We translate each page through the user AS to find its physical frame,
    // then access it via HHDM to write.
    if filesz > 0 {
        let src = &elf_data[offset as usize..file_end];
        let mut copied = 0usize;

        while copied < src.len() {
            let dst_vaddr = vaddr + copied as u64;
            let page_offset = (dst_vaddr & 0xFFF) as usize;
            let chunk = core::cmp::min(src.len() - copied, 4096 - page_offset);

            // Translate user virtual address → physical → HHDM virtual
            let phys = user_as
                .translate(VirtAddr::new(dst_vaddr))
                .ok_or("Failed to translate user page after mapping")?;
            let hhdm_ptr = crate::memory::phys_to_virt(phys.as_u64()) as *mut u8;

            // SAFETY: hhdm_ptr points to a freshly mapped, zeroed frame via HHDM.
            // The source slice is validated above.
            unsafe {
                core::ptr::copy_nonoverlapping(src.as_ptr().add(copied), hhdm_ptr, chunk);
            }

            copied += chunk;
        }
    }

    // Tighten PTE permissions after copy.
    apply_segment_permissions(user_as, page_start, page_count, actual_flags)?;

    log::debug!(
        "  PT_LOAD: {:#x}..{:#x} ({} pages, file {:#x}+{:#x}, flags {:?})",
        page_start,
        page_end,
        page_count,
        offset,
        filesz,
        actual_flags,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Task creation with IRETQ trampoline
// ---------------------------------------------------------------------------

/// Parameters for the Ring 3 trampoline, stored in a static so the
/// extern "C" trampoline function can access them.
struct TrampolineParams {
    entry_point: u64,
    stack_top: u64,
    arg0: u64,
    address_space: Option<Arc<AddressSpace>>,
}

static mut TRAMPOLINE_PARAMS: TrampolineParams = TrampolineParams {
    entry_point: 0,
    stack_top: 0,
    arg0: 0,
    address_space: None,
};

/// Trampoline that switches to user address space and does IRETQ to Ring 3.
extern "C" fn elf_ring3_trampoline() -> ! {
    use crate::arch::x86_64::gdt;

    let (user_rip, user_rsp, user_arg0);

    // SAFETY: Single-threaded setup. The params are written before the task
    // is scheduled. We read and clear them atomically at first execution.
    unsafe {
        let params = &raw mut TRAMPOLINE_PARAMS;
        user_rip = (*params).entry_point;
        user_rsp = (*params).stack_top;
        user_arg0 = (*params).arg0;

        if let Some(ref as_ref) = (*params).address_space {
            as_ref.switch_to();
        }
        // Clear to avoid dangling Arc reference
        (*params).address_space = None;
        (*params).arg0 = 0;
    }

    let user_cs = gdt::user_code_selector().0 as u64;
    let user_ss = gdt::user_data_selector().0 as u64;
    let user_rflags: u64 = 0x202; // IF=1, reserved bit 1 = 1

    // SAFETY: Valid user mappings have been set up. IRETQ switches to Ring 3.
    unsafe {
        core::arch::asm!(
            "push {ss}",
            "push {rsp_val}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            "mov rdi, {arg0}",
            "iretq",
            ss = in(reg) user_ss,
            rsp_val = in(reg) user_rsp,
            rflags = in(reg) user_rflags,
            cs = in(reg) user_cs,
            rip = in(reg) user_rip,
            arg0 = in(reg) user_arg0,
            options(noreturn),
        );
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load an ELF64 binary and schedule it as a Ring 3 user task.
///
/// # Arguments
/// * `elf_data` - Raw ELF file bytes (must remain valid until load completes).
/// * `name` - Name for the task (debugging purposes).
///
/// # Returns
/// `Ok(())` on success, `Err` with a static error message on failure.
pub fn load_and_run_elf(elf_data: &[u8], name: &'static str) -> Result<TaskId, &'static str> {
    load_and_run_elf_with_caps(elf_data, name, &[])
}

pub fn load_and_run_elf_with_caps(
    elf_data: &[u8],
    name: &'static str,
    seed_caps: &[Capability],
) -> Result<TaskId, &'static str> {
    log::info!("[elf] Loading ELF '{}'...", name);

    // Step 1: Parse and validate ELF header
    let header = parse_header(elf_data)?;
    // Step 2: Create user address space
    let user_as = Arc::new(AddressSpace::new_user()?);

    let phdrs: Vec<Elf64Phdr> = program_headers(elf_data, &header).collect();
    let interp_path = parse_interp_path(elf_data, &phdrs)?;
    let (load_bias, entry) = compute_load_bias_and_entry(&user_as, &header, &phdrs)?;

    let phnum = header.e_phnum;
    log::info!(
        "[elf] ELF '{}': type={}, entry={:#x}, bias={:#x}, {} program headers",
        name,
        if header.e_type == ET_DYN {
            "ET_DYN"
        } else {
            "ET_EXEC"
        },
        entry,
        load_bias,
        phnum,
    );

    // Step 3: Load all PT_LOAD segments
    let mut load_count = 0u32;
    for phdr in phdrs.iter() {
        if phdr.p_type == PT_LOAD && phdr.p_memsz != 0 {
            load_segment(&user_as, elf_data, phdr, load_bias)?;
            load_count += 1;
        }
    }
    if interp_path.is_none() {
        apply_dynamic_relocations(&user_as, &phdrs, header.e_type, load_bias)?;
    }

    log::info!("[elf] Loaded {} PT_LOAD segment(s)", load_count);

    let mut runtime_entry = entry;
    if let Some(path) = interp_path {
        let interp_data = read_elf_from_vfs(path)?;
        let interp_header = parse_header(&interp_data)?;
        let interp_phdrs: Vec<Elf64Phdr> = program_headers(&interp_data, &interp_header).collect();
        if parse_interp_path(&interp_data, &interp_phdrs)?.is_some() {
            return Err("Nested PT_INTERP is not supported");
        }
        let (interp_bias, interp_entry) =
            compute_load_bias_and_entry(&user_as, &interp_header, &interp_phdrs)?;
        let mut interp_load_count = 0u32;
        for phdr in interp_phdrs.iter() {
            if phdr.p_type == PT_LOAD && phdr.p_memsz != 0 {
                load_segment(&user_as, &interp_data, phdr, interp_bias)?;
                interp_load_count += 1;
            }
        }
        apply_dynamic_relocations(&user_as, &interp_phdrs, interp_header.e_type, interp_bias)?;
        runtime_entry = interp_entry;
        log::info!(
            "[elf] PT_INTERP '{}' loaded: {} PT_LOAD, entry={:#x}",
            path,
            interp_load_count,
            runtime_entry
        );
    }

    // Step 4: Map user stack
    let stack_flags = VmaFlags {
        readable: true,
        writable: true,
        executable: false,
        user_accessible: true,
    };
    user_as.map_region(
        USER_STACK_BASE,
        USER_STACK_PAGES,
        stack_flags,
        VmaType::Stack,
        VmaPageSize::Small,
    )?;
    log::debug!(
        "[elf] User stack: {:#x}..{:#x} ({} pages)",
        USER_STACK_BASE,
        USER_STACK_TOP,
        USER_STACK_PAGES,
    );

    // Step 5: Set up trampoline params and create kernel task
    // SAFETY: We are in single-threaded init context. The task is not
    // scheduled until after we've finished writing the params.
    unsafe {
        let params = &raw mut TRAMPOLINE_PARAMS;
        (*params).entry_point = runtime_entry;
        (*params).stack_top = USER_STACK_TOP;
        (*params).arg0 = 0;
        (*params).address_space = Some(user_as.clone());
    }

    let kernel_stack = KernelStack::allocate(Task::DEFAULT_STACK_SIZE)?;
    let context = CpuContext::new(elf_ring3_trampoline as *const () as u64, &kernel_stack);

    let task = Arc::new(Task {
        id: TaskId::new(),
        state: SyncUnsafeCell::new(TaskState::Ready),
        priority: TaskPriority::Normal,
        context: SyncUnsafeCell::new(context),
        kernel_stack,
        user_stack: None,
        name,
        capabilities: SyncUnsafeCell::new(CapabilityTable::new()),
        address_space: SyncUnsafeCell::new(user_as),
        fd_table: SyncUnsafeCell::new(crate::vfs::FileDescriptorTable::new()),
        pending_signals: SyncUnsafeCell::new(super::signal::SignalSet::new()),
        blocked_signals: SyncUnsafeCell::new(super::signal::SignalSet::new()),
        signal_actions: SyncUnsafeCell::new([super::signal::SigAction::Default; 64]),
        signal_stack: SyncUnsafeCell::new(None),
        itimers: super::timer::ITimers::new(),
        wake_pending: core::sync::atomic::AtomicBool::new(false),
        wake_deadline_ns: core::sync::atomic::AtomicU64::new(0),
        brk: core::sync::atomic::AtomicU64::new(0),
        mmap_hint: core::sync::atomic::AtomicU64::new(0x0000_0000_6000_0000),
        ticks: core::sync::atomic::AtomicU64::new(0),
    });

    // Seed capabilities into the new task (before scheduling).
    let mut bootstrap_handle: Option<u64> = None;
    if !seed_caps.is_empty() {
        let caps = unsafe { &mut *task.capabilities.get() };
        for cap in seed_caps {
            let id = caps.insert(cap.clone());
            if bootstrap_handle.is_none()
                && cap.resource_type == crate::capability::ResourceType::Volume
            {
                bootstrap_handle = Some(id.as_u64());
            }
        }
    }

    if let Some(h) = bootstrap_handle {
        // Program entry will see this in its first argument register (RDI).
        unsafe {
            (*(&raw mut TRAMPOLINE_PARAMS)).arg0 = h;
        }
    }

    // Bootstrapping: grant Silo Admin capability to the initial userspace task.
    if name == "init" || name == "silo-admin" {
        let _ = crate::silo::grant_silo_admin_to_task(&task);
    }

    let task_id = task.id;
    crate::process::add_task(task);

    log::info!(
        "[elf] Task '{}' created: entry={:#x}, stack_top={:#x}",
        name,
        runtime_entry,
        USER_STACK_TOP,
    );

    Ok(task_id)
}

/// Load an ELF binary into the provided address space.
/// Returns the entry point address.
pub fn load_elf_image(
    elf_data: &[u8],
    user_as: &AddressSpace,
) -> Result<LoadedElfInfo, &'static str> {
    let header = parse_header(elf_data)?;
    let phdrs: Vec<Elf64Phdr> = program_headers(elf_data, &header).collect();
    let interp_path = parse_interp_path(elf_data, &phdrs)?;
    let (load_bias, entry) = compute_load_bias_and_entry(user_as, &header, &phdrs)?;
    let phdr_vaddr = find_relocated_phdr_vaddr(&header, &phdrs, load_bias)?;

    for phdr in phdrs.iter() {
        if phdr.p_type == PT_LOAD && phdr.p_memsz != 0 {
            load_segment(user_as, elf_data, phdr, load_bias)?;
        }
    }
    if interp_path.is_none() {
        apply_dynamic_relocations(user_as, &phdrs, header.e_type, load_bias)?;
    }

    let mut runtime_entry = entry;
    let mut interp_base = None;
    if let Some(path) = interp_path {
        let interp_data = read_elf_from_vfs(path)?;
        let interp_header = parse_header(&interp_data)?;
        let interp_phdrs: Vec<Elf64Phdr> = program_headers(&interp_data, &interp_header).collect();
        if parse_interp_path(&interp_data, &interp_phdrs)?.is_some() {
            return Err("Nested PT_INTERP is not supported");
        }
        let (interp_bias, interp_entry) =
            compute_load_bias_and_entry(user_as, &interp_header, &interp_phdrs)?;
        let (interp_min_vaddr, _) = compute_load_bounds(&interp_phdrs)?;
        for phdr in interp_phdrs.iter() {
            if phdr.p_type == PT_LOAD && phdr.p_memsz != 0 {
                load_segment(user_as, &interp_data, phdr, interp_bias)?;
            }
        }
        apply_dynamic_relocations(user_as, &interp_phdrs, interp_header.e_type, interp_bias)?;
        runtime_entry = interp_entry;
        interp_base = Some(interp_min_vaddr.saturating_add(interp_bias));
    }

    Ok(LoadedElfInfo {
        runtime_entry,
        program_entry: entry,
        phdr_vaddr,
        phent: header.e_phentsize,
        phnum: header.e_phnum,
        interp_base,
    })
}
