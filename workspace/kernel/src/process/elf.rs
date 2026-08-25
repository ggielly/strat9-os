//! ELF64 loader for Strat9-OS.
//!
//! Parses ELF64 headers and loads PT_LOAD segments into a user address space,
//! then creates a kernel task that trampolines into Ring 3 via IRETQ.
//!
//! Supports :
//!   - ET_EXEC
//!   - ET_DYN (PIE/static-PIE)
//!   - ELF64 little-endian x86_64 binaries.
//!
//!
//! Does not support (or need future fix) :
//!
//!   - FIx TODO : allocation heap during ELF loading
//!     program_headers(elf_data, &header).collect() → Vec<Elf64Phdr>, Vec::new() for interp_phdrs, etc. The kernel uses alloc so it's normal, but allocation errors are not handled (no try_collect, no fallible GlobalAlloc).
//!
//!   - ~~Fix TODO : find_free_vma_range : fallback hardcoded 0x1000_0000~~
//!     DONE : the fallback was removed; a failed search now fails the load
//!     with "No virtual range for ET_DYN image".
//!
//! Security:
//!   - User stack has a guard page (user_stack_base() - 4096) that is intentionally
//!     left unmapped.  Stack underflows hit it and page-fault.
//!
use alloc::{sync::Arc, vec::Vec};
use x86_64::{
    structures::paging::{Mapper, Page, Size4KiB},
    VirtAddr,
};

use crate::{
    capability::Capability,
    memory::address_space::{AddressSpace, VmaFlags, VmaPageSize, VmaType},
    process::{
        task::{CpuContext, KernelStack, ResumeKind, SyncUnsafeCell, Task},
        TaskId, TaskPriority, TaskState,
    },
};

macro_rules! elf_trace {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)] {
            crate::e9_println!($($arg)*);
            crate::serial_println!($($arg)*);
        }
    };
}

// ---------------------------------------------------------------------------
// ELF64 constants (relocation & dynamic tags : not covered by xmas-elf)
// ---------------------------------------------------------------------------

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_TLS: u32 = 7;
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
const R_X86_64_COPY: u32 = 5;
const R_X86_64_GLOB_DAT: u32 = 6;
const R_X86_64_JUMP_SLOT: u32 = 7;
const R_X86_64_TPOFF64: u32 = 18;
const R_X86_64_DTPMOD64: u32 = 16;
const R_X86_64_DTPOFF64: u32 = 17;
const R_X86_64_IRELATIVE: u32 = 37;

/// Maximum virtual address we accept for user-space mappings.
pub const USER_ADDR_MAX: u64 = 0x0000_8000_0000_0000;

/// Number of 4 KiB pages for the user stack (16 pages = 64 KiB).
///
/// This is the *default*: the loader accepts a per-process stack size via
/// [`load_and_run_elf_with_stack`] (issue #64).
pub const USER_STACK_PAGES: usize = 16;
/// Lower bound on a per-process user stack (4 pages = 16 KiB): the boot
/// stack layout alone (argv/envp/auxv + guard margins) needs at least one
/// page, and tiny stacks would fault immediately.
pub const USER_STACK_MIN_PAGES: usize = 4;
/// Upper bound on a per-process user stack (2048 pages = 8 MiB), to keep a
/// buggy or hostile caller from exhausting the user address space / frames.
pub const USER_STACK_MAX_PAGES: usize = 2048;
/// Standard user-mode RFLAGS: IF=1, reserved bit 1 set.
const USER_RFLAGS: u64 = 0x202;

/// Get the randomized user stack base address.
fn user_stack_base() -> u64 {
    crate::kaslr::stack_base()
}

/// Get the randomized user stack top address.
fn user_stack_top() -> u64 {
    crate::kaslr::stack_top()
}

/// Get the guard page address below the user stack.
fn user_stack_guard() -> u64 {
    crate::kaslr::stack_guard()
}

/// Get the randomized PIE base address for ELF loading.
fn pie_base() -> u64 {
    crate::kaslr::pie_base()
}

/// Result of loading an ELF image into an address space.
#[derive(Debug, Clone, Copy)]
pub struct LoadedElfInfo {
    pub runtime_entry: u64,
    pub program_entry: u64,
    pub phdr_vaddr: u64,
    pub phent: u16,
    pub phnum: u16,
    pub interp_base: Option<u64>,
    pub tls_vaddr: u64,
    pub tls_filesz: u64,
    pub tls_memsz: u64,
    pub tls_align: u64,
}

// ---------------------------------------------------------------------------
// ELF64 structures for kernel-internal use
// ---------------------------------------------------------------------------

/// Parsed ELF64 file header (copy-friendly, no borrows).
#[derive(Debug, Clone, Copy)]
struct Elf64Header {
    e_type: u16,
    e_entry: u64,
    e_phoff: u64,
    e_phentsize: u16,
    e_phnum: u16,
}

/// Parsed ELF64 program header (copy-friendly, packed for raw byte reading).
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
// Parsing (uses xmas-elf for header validation)
// ---------------------------------------------------------------------------

/// Parse and validate the ELF64 file header from raw bytes.
///
/// Uses `xmas-elf` for magic/class/machine/version validation, then copies
/// the fields we need into a local `Copy` struct.
fn parse_header(data: &[u8]) -> Result<Elf64Header, &'static str> {
    let elf = xmas_elf::ElfFile::new(data).map_err(|e| {
        crate::serial_println!("[elf] xmas_elf::ElfFile::new failed: {:?}", e);
        "Invalid ELF header"
    })?;

    let hdr = elf.header.pt2;

    // Reject non-x86_64 binaries early.
    let machine = hdr.machine().as_machine();
    if machine != xmas_elf::header::Machine::X86_64 {
        crate::serial_println!(
            "[elf] Rejecting binary: machine={:?} (expected X86_64)",
            machine
        );
        return Err("Not an x86_64 ELF binary");
    }

    // Type: executable or shared object (PIE/static PIE)
    let e_type = hdr.type_().0;
    if e_type != ET_EXEC && e_type != ET_DYN {
        crate::serial_println!(
            "[elf] Rejecting binary: e_type={} (expected ET_EXEC={} or ET_DYN={})",
            e_type,
            ET_EXEC,
            ET_DYN
        );
        return Err("Unsupported ELF type (expected ET_EXEC or ET_DYN)");
    }

    let e_entry = hdr.entry_point();
    // Entry point must be canonical user space (for ET_DYN this is relative and
    // validated again after relocation). ET_EXEC with e_entry=0 is handled later.
    if e_entry >= USER_ADDR_MAX {
        return Err("Entry point outside user address range");
    }

    let e_phentsize = hdr.ph_entry_size();
    let e_phoff = hdr.ph_offset();
    let e_phnum = hdr.ph_count();

    // Sanity check program headers.
    // Compare against our packed Elf64Phdr (56 bytes = standard ELF64), not
    // xmas_elf::ProgramHeader which may have padding due to #[repr(C)].
    if e_phentsize as usize != core::mem::size_of::<Elf64Phdr>() {
        crate::serial_println!(
            "[elf] Rejecting binary: e_phentsize={} expected={}",
            e_phentsize,
            core::mem::size_of::<Elf64Phdr>()
        );
        return Err("Unexpected phentsize");
    }

    let ph_end = (e_phoff as usize)
        .checked_add((e_phnum as usize) * (e_phentsize as usize))
        .ok_or("Program header table overflows")?;
    if ph_end > data.len() {
        return Err("Program headers extend past file");
    }

    Ok(Elf64Header {
        e_type,
        e_entry,
        e_phoff,
        e_phentsize,
        e_phnum,
    })
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

/// Parses interp path.
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

/// Performs the find relocated phdr vaddr operation.
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

/// Reads elf from vfs.
fn read_elf_from_vfs(path: &str) -> Result<Vec<u8>, &'static str> {
    const MAX_ELF_SIZE: usize = 64 * 1024 * 1024;
    let resolved_path =
        crate::vfs::resolve_and_check_path_for_current_task(path, true, false, true)
            .map_err(|_| "PT_INTERP execute denied")?;
    let fd = crate::vfs::open(&resolved_path, crate::vfs::OpenFlags::READ)
        .map_err(|_| "PT_INTERP open failed")?;
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];

    // Read the first chunk to validate ELF magic before loading the whole file.
    let n = match crate::vfs::read(fd, &mut buf) {
        Ok(0) => {
            let _ = crate::vfs::close(fd);
            return Err("PT_INTERP file is empty");
        }
        Ok(n) => n,
        Err(_) => {
            let _ = crate::vfs::close(fd);
            return Err("PT_INTERP read failed");
        }
    };
    if n < 4 || buf[..4] != [0x7F, b'E', b'L', b'F'] {
        let _ = crate::vfs::close(fd);
        return Err("PT_INTERP file is not an ELF");
    }
    out.extend_from_slice(&buf[..n]);

    // Continue reading the rest of the file.
    loop {
        let n = match crate::vfs::read(fd, &mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => {
                let _ = crate::vfs::close(fd);
                return Err("PT_INTERP read failed");
            }
        };
        if out.len().saturating_add(n) > MAX_ELF_SIZE {
            let _ = crate::vfs::close(fd);
            return Err("PT_INTERP file too large");
        }
        out.extend_from_slice(&buf[..n]);
    }
    let _ = crate::vfs::close(fd);
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
        // No hardcoded fallback: if the randomized PIE base cannot host the
        // image (address space full), fail the load loudly instead of
        // silently colliding with existing mappings (issue #68).
        let load_base = user_as
            .find_free_vma_range(pie_base(), n_pages, VmaPageSize::Small)
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

    let entry_raw = if header.e_type == ET_EXEC && header.e_entry == 0 {
        let fallback = phdrs
            .iter()
            .find(|ph| ph.p_type == PT_LOAD && ph.p_memsz != 0 && (ph.p_flags & PF_X) != 0)
            .map(|ph| ph.p_vaddr)
            .ok_or("ET_EXEC has null entry and no executable PT_LOAD")?;
        log::warn!(
            "[elf] ET_EXEC has null entry, using fallback executable segment vaddr={:#x}",
            fallback
        );
        fallback
    } else {
        header.e_entry
    };

    let relocated_entry = entry_raw
        .checked_add(load_bias)
        .ok_or("Relocated entry overflow")?;
    if relocated_entry == 0 || relocated_entry >= USER_ADDR_MAX {
        return Err("Relocated entry outside user space");
    }

    Ok((load_bias, relocated_entry))
}

/// Performs the apply segment permissions operation.
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
        crate::arch::x86_64::tlb::local_range(VirtAddr::new(page_start), VirtAddr::new(end));
    }

    Ok(())
}

/// Reads user mapped bytes.
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
    // SMAP: temporarily disable supervisor-mode access prevention while
    // reading from user-space pages through the HHDM.
    crate::arch::x86_64::stac();
    while copied < out.len() {
        let page_off = (vaddr & 0xFFF) as usize;
        let chunk = core::cmp::min(out.len() - copied, 4096 - page_off);
        let phys = user_as
            .translate(VirtAddr::new(vaddr))
            .ok_or("Failed to translate mapped user bytes")?;
        let paddr = phys.as_u64();
        if paddr == 0 {
            crate::arch::x86_64::clac();
            return Err("Translated physical address is null");
        }
        let src = crate::memory::phys_to_virt(paddr) as *const u8;
        if src.is_null() {
            crate::arch::x86_64::clac();
            return Err("HHDM-mapped source is null");
        }
        // SAFETY: src points to mapped physical memory via HHDM.
        // The address was just validated non-null, and the translate()
        // call guarantees the virtual address is backed by a valid frame.
        unsafe { core::ptr::copy_nonoverlapping(src, out.as_mut_ptr().add(copied), chunk) };
        copied += chunk;
        vaddr = vaddr
            .checked_add(chunk as u64)
            .ok_or("Virtual address overflow while reading mapped bytes")?;
    }
    crate::arch::x86_64::clac();
    Ok(())
}

/// Writes user mapped bytes.
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
    // SMAP: temporarily disable supervisor-mode access prevention while
    // writing to user-space pages through the HHDM.
    crate::arch::x86_64::stac();
    while written < src.len() {
        let page_off = (vaddr & 0xFFF) as usize;
        let chunk = core::cmp::min(src.len() - written, 4096 - page_off);
        let phys = user_as
            .translate(VirtAddr::new(vaddr))
            .ok_or("Failed to translate relocation target")?;
        let paddr = phys.as_u64();
        if paddr == 0 {
            crate::arch::x86_64::clac();
            return Err("Translated physical address is null");
        }
        let dst = crate::memory::phys_to_virt(paddr) as *mut u8;
        if dst.is_null() {
            crate::arch::x86_64::clac();
            return Err("HHDM-mapped destination is null");
        }
        // SAFETY: destination points to mapped user frame through HHDM.
        // The address was just validated non-null, and the translate()
        // call guarantees the virtual address is backed by a valid frame.
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr().add(written), dst, chunk) };
        written += chunk;
        vaddr = vaddr
            .checked_add(chunk as u64)
            .ok_or("Virtual address overflow while writing mapped bytes")?;
    }
    crate::arch::x86_64::clac();
    Ok(())
}

/// Reads user u64.
fn read_user_u64(user_as: &AddressSpace, vaddr: u64) -> Result<u64, &'static str> {
    let mut raw = [0u8; 8];
    read_user_mapped_bytes(user_as, vaddr, &mut raw)?;
    Ok(u64::from_le_bytes(raw))
}

/// Writes user u64.
fn write_user_u64(user_as: &AddressSpace, vaddr: u64, value: u64) -> Result<(), &'static str> {
    write_user_mapped_bytes(user_as, vaddr, &value.to_le_bytes())
}

/// Calls a user-space IFUNC resolver function and returns its result.
///
/// The resolver is located at `resolver_vaddr` in the user address space.
/// All RELATIVE relocations for this binary must have been applied first so
/// that the resolver's own calls/addresses are correct.
fn call_ifunc_resolver(user_as: &AddressSpace, resolver_vaddr: u64) -> Result<u64, &'static str> {
    if resolver_vaddr >= USER_ADDR_MAX {
        return Err("IFUNC resolver address outside user space");
    }
    let phys = user_as
        .translate(VirtAddr::new(resolver_vaddr))
        .ok_or("IFUNC resolver page not mapped")?;
    let hhdm_ptr = crate::memory::phys_to_virt(phys.as_u64());
    // SAFETY: hhdm_ptr points to a user page containing executable code.
    // The resolver is a simple function that returns a u64; it must not
    // access kernel state.  All RELATIVE relocations for this binary have
    // already been applied, so the resolver's own target addresses are valid.
    let resolver: extern "C" fn() -> u64 = unsafe { core::mem::transmute(hhdm_ptr as *const ()) };
    Ok(resolver())
}

/// Performs the apply relr relocations operation.
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
            if where_addr == 0 {
                return Err("DT_RELR bitmap entry before initial address entry");
            }
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
                .checked_add(64 * 8)
                .ok_or("DT_RELR where advance overflow")?;
        }
    }
    Ok(applied)
}

/// Performs the apply dynamic relocations operation.
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
    let dyn_file_size = dynamic_ph.p_filesz as usize;
    let dyn_count = dyn_file_size / core::mem::size_of::<Elf64Dyn>();
    // Read the entire .dynamic section at once to avoid O(n) page-table walks.
    let mut dyn_buf = alloc::vec![0u8; dyn_file_size];
    read_user_mapped_bytes(user_as, dyn_addr, &mut dyn_buf)?;
    let dyn_slice: &[Elf64Dyn] =
        unsafe { core::slice::from_raw_parts(dyn_buf.as_ptr() as *const Elf64Dyn, dyn_count) };

    let mut rela_addr: Option<u64> = None;
    let mut rela_size: usize = 0;
    let mut rela_ent: usize = core::mem::size_of::<Elf64Rela>();
    let mut jmprel_addr: Option<u64> = None;
    let mut jmprel_size: usize = 0;
    let mut pltrel_kind: Option<u64> = None;
    let mut symtab_addr: Option<u64> = None;
    let mut sym_ent: usize = core::mem::size_of::<Elf64Sym>();
    let _strtab_addr: Option<u64> = None;
    let mut rela_count_hint: Option<usize> = None;
    let mut relr_addr: Option<u64> = None;
    let mut relr_size: usize = 0;
    let mut relr_ent: usize = 0;

    for i in 0..dyn_count {
        let dyn_entry = &dyn_slice[i];

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
                let _ = dyn_entry
                    .d_val
                    .checked_add(load_bias)
                    .ok_or("DT_STRTAB relocated address overflow")?;
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

    let read_sym_entry = |sym_idx: u32| -> Result<Elf64Sym, &'static str> {
        let symtab = symtab_addr.ok_or("Missing DT_SYMTAB for symbol relocations")?;
        let sym_addr = symtab
            .checked_add((sym_idx as u64) * (sym_ent as u64))
            .ok_or("Symbol table address overflow")?;
        let mut raw = [0u8; core::mem::size_of::<Elf64Sym>()];
        read_user_mapped_bytes(user_as, sym_addr, &mut raw)?;
        Ok(unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const Elf64Sym) })
    };

    let resolve_sym =
        |sym_idx: u32, with_bias: bool, check_def: bool| -> Result<u64, &'static str> {
            if sym_idx == 0 {
                return Ok(0);
            }
            let sym = read_sym_entry(sym_idx)?;
            if check_def && sym.st_shndx == 0 {
                return Err("Undefined symbol relocation not supported");
            }
            if with_bias {
                sym.st_value
                    .checked_add(load_bias)
                    .ok_or("Symbol value relocation overflow")
            } else {
                Ok(sym.st_value)
            }
        };

    let resolve_size = |sym_idx: u32| -> Result<u64, &'static str> {
        if sym_idx == 0 {
            return Ok(0);
        }
        let sym = read_sym_entry(sym_idx)?;
        Ok(sym.st_size)
    };

    // Variant II TLS: tp = tls_base + aligned_memsz.  We need the aligned
    // memsz for TPOFF64/DTPOFF64 calculations.
    let tls_aligned_memsz: i128 = phdrs
        .iter()
        .find(|ph| ph.p_type == PT_TLS)
        .map(|tls| {
            let memsz = tls.p_memsz;
            let align = tls.p_align.max(1);
            let aligned = (memsz + align - 1) & !(align - 1);
            aligned as i128
        })
        .unwrap_or(0);

    let apply_rela_table = |table_base: u64,
                            table_size: usize,
                            count_hint: Option<usize>|
     -> Result<usize, &'static str> {
        if table_size == 0 {
            return Ok(0);
        }
        // Use the table size as the authoritative entry count.  DT_RELACOUNT is
        // a *hint* from the linker that may undercount; honouring it with min()
        // silently drops valid relocations.  We only validate the hint as a
        // sanity bound (if provided).
        let count = table_size / rela_ent;
        if let Some(hint) = count_hint {
            if hint > count {
                return Err("DT_RELACOUNT exceeds actual RELA table size");
            }
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
                    let sym_val = resolve_sym(r_sym, true, true)? as i128;
                    sym_val
                        .checked_add(rela.r_addend as i128)
                        .ok_or("Relocation value overflow")?
                }
                R_X86_64_COPY => {
                    let sym_val = resolve_sym(r_sym, true, true)?;
                    if sym_val == 0 {
                        continue;
                    }
                    let sym_sz = resolve_size(r_sym)?;
                    if sym_sz > 0 && sym_val < USER_ADDR_MAX {
                        let mut tmp = [0u8; 256];
                        let mut off = 0u64;
                        while off < sym_sz {
                            let chunk = core::cmp::min(256, (sym_sz - off) as usize);
                            let src = sym_val.checked_add(off).ok_or("COPY source overflow")?;
                            let dst = target.checked_add(off).ok_or("COPY target overflow")?;
                            read_user_mapped_bytes(user_as, src, &mut tmp[..chunk])?;
                            write_user_mapped_bytes(user_as, dst, &tmp[..chunk])?;
                            off += chunk as u64;
                        }
                    }
                    applied += 1;
                    continue;
                }
                R_X86_64_TPOFF64 => {
                    let sym_val = if r_sym != 0 {
                        resolve_sym(r_sym, false, false)? as i128
                    } else {
                        0i128
                    };
                    // Variant II: tp = tls_base + aligned_memsz, so offset from tp is
                    // (sym.st_value - aligned_memsz + r_addend).  Use i128 to avoid
                    // underflow when sym_val < aligned_memsz.
                    sym_val
                        .checked_sub(tls_aligned_memsz)
                        .and_then(|v| v.checked_add(rela.r_addend as i128))
                        .ok_or("TPOFF64 value overflow")?
                }
                R_X86_64_DTPMOD64 => {
                    // For single-binary loading (no dynamic linker), the module ID is always 1.
                    1i128
                }
                R_X86_64_DTPOFF64 => {
                    // DTV-relative offset: same as TPOFF64 for single-binary loading.
                    let sym_val = if r_sym != 0 {
                        resolve_sym(r_sym, false, false)? as i128
                    } else {
                        0i128
                    };
                    sym_val
                        .checked_sub(tls_aligned_memsz)
                        .and_then(|v| v.checked_add(rela.r_addend as i128))
                        .ok_or("DTPOFF64 value overflow")?
                }
                R_X86_64_IRELATIVE => {
                    // IRELATIVE: the target is a resolver function that must be
                    // *called* to obtain the final value.  All RELATIVE
                    // relocations for this binary have already been applied, so
                    // the resolver's own addresses are correct.
                    let resolver_vaddr = (load_bias as i128)
                        .checked_add(rela.r_addend as i128)
                        .ok_or("IRELATIVE resolver address overflow")?;
                    if resolver_vaddr < 0 || resolver_vaddr as u64 >= USER_ADDR_MAX {
                        return Err("IRELATIVE resolver outside user space");
                    }
                    let resolved = call_ifunc_resolver(user_as, resolver_vaddr as u64)?;
                    resolved as i128
                }
                _ => {
                    log::warn!("[elf] Unsupported relocation type {}", r_type);
                    continue;
                }
            };
            if value < 0 || value > u64::MAX as i128 {
                return Err("Relocation value out of range");
            }
            let val_u64 = value as u64;
            // Read back before write for diagnosis
            if applied < 5 {
                let r_addend_copy = rela.r_addend; // copy packed field to local
                let mut before = [0u8; 8];
                let _ = read_user_mapped_bytes(user_as, target, &mut before);
                let before_val = u64::from_le_bytes(before);
                crate::e9_println!(
                    "[reloc] [{i}] r_type={} target={:#x} r_addend={:#x} value={:#x} before={:#x}",
                    r_type,
                    target,
                    r_addend_copy,
                    val_u64,
                    before_val
                );
            }
            write_user_mapped_bytes(user_as, target, &val_u64.to_le_bytes())?;
            // Read back after write for diagnosis
            if applied < 5 {
                let mut after = [0u8; 8];
                let _ = read_user_mapped_bytes(user_as, target, &mut after);
                let after_val = u64::from_le_bytes(after);
                crate::e9_println!(
                    "[reloc] [{i}] after_write={:#x} (expected={:#x})",
                    after_val,
                    val_u64
                );
            }
            // Catch any relocation that writes a kernel-range address into user space.
            if val_u64 >= 0xffff_8000_0000_0000 {
                let r_addend_copy = rela.r_addend;
                crate::e9_println!(
                    "[reloc-KERNEL-ADDR] [{i}] r_type={} target={:#x} r_addend={:#x} val={:#x} bias={:#x}",
                    r_type, target, r_addend_copy, val_u64, load_bias
                );
            }
            applied += 1;
        }
        Ok(applied)
    };

    let mut total_applied = 0usize;
    crate::e9_println!(
        "[reloc] apply_dynamic_relocations: bias={:#x} rela_addr={:?} rela_size={} rela_count={:?}",
        load_bias,
        rela_addr,
        rela_size,
        rela_count_hint
    );
    if let Some(rela_base) = rela_addr {
        total_applied += apply_rela_table(rela_base, rela_size, rela_count_hint)?;
    }
    if let Some(jmprel_base) = jmprel_addr {
        total_applied += apply_rela_table(jmprel_base, jmprel_size, None)?;
    }

    if total_applied > 0 {
        crate::e9_println!(
            "[reloc] applied {} RELA relocations (bias={:#x})",
            total_applied,
            load_bias
        );
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
    // Batch-translate all pages at once to avoid page-table walks per-chunk.
    if filesz > 0 {
        let src = &elf_data[offset as usize..file_end];
        let mut copied = 0usize;

        // Collect physical addresses for all pages in the range.
        let n_vaddrs = ((page_end - page_start) / 4096) as usize;
        let mut phys_pages = alloc::vec::Vec::with_capacity(n_vaddrs);
        for i in 0..n_vaddrs {
            let vaddr = page_start + (i as u64) * 4096;
            let phys = user_as
                .translate(VirtAddr::new(vaddr))
                .ok_or("Failed to translate user page after mapping")?;
            phys_pages.push(phys);
        }

        while copied < src.len() {
            let dst_vaddr = vaddr + copied as u64;
            let page_idx = ((dst_vaddr - page_start) / 4096) as usize;
            let page_offset = (dst_vaddr & 0xFFF) as usize;
            let chunk = core::cmp::min(src.len() - copied, 4096 - page_offset);

            let phys = phys_pages[page_idx];
            let hhdm_ptr = crate::memory::phys_to_virt(phys.as_u64()) as *mut u8;
            // SAFETY: hhdm_ptr points to a freshly mapped, zeroed frame via HHDM.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src.as_ptr().add(copied),
                    hhdm_ptr.add(page_offset),
                    chunk,
                );
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
/// Trampoline that switches to user address space and does IRETQ to Ring 3.
///
/// Parameters (entry point, stack top, arg0, address space) are read from the
/// *current task* so that each ELF task carries its own copy.  This makes the
/// trampoline safe under SMP: two tasks can run their trampolines concurrently
/// on different CPUs without any shared mutable state.
extern "C" fn elf_ring3_trampoline() -> ! {
    use crate::arch::x86_64::gdt;
    use core::sync::atomic::Ordering;

    elf_trace!("[trace][elf] ring3_trampoline before current_task");
    let Some(task) = crate::process::scheduler::current_task_clone_spin_debug("ring3_trampoline")
    else {
        crate::e9_println!("[elf] ring3_trampoline: no current task, aborting");
        crate::serial_println!("[elf] ring3_trampoline: no current task, aborting");
        loop {
            x86_64::instructions::hlt();
        }
    };
    elf_trace!(
        "[trace][elf] ring3_trampoline enter tid={} name={}",
        task.id.as_u64(),
        task.name
    );
    task.set_resume_kind(crate::process::task::ResumeKind::IretFrame);

    let user_rip = task.trampoline_entry.load(Ordering::Acquire);
    let user_rsp = task.trampoline_stack_top.load(Ordering::Acquire);
    let user_arg0 = task.trampoline_arg0.load(Ordering::Acquire);
    elf_trace!(
        "[trace][elf] ring3_trampoline args tid={} rip={:#x} rsp={:#x} arg0={:#x}",
        task.id.as_u64(),
        user_rip,
        user_rsp,
        user_arg0
    );

    // Probe: read GOT entries via HHDM before switching to user AS.
    // This is the last kernel-owned moment before user execution begins.
    // If values here are wrong, the bug is in load/relocation, not in
    // something that happens after this point.
    #[cfg(debug_assertions)]
    {
        // SAFETY: Kernel still holds the boot/kernel CR3. HHDM is valid.
        unsafe {
            let as_ref = task.process.address_space_arc();
            let task_name: &str = &task.name;
            for test_off in [0x12920u64, 0x12928u64, 0x12930u64] {
                let vaddr = 0x100000000u64.wrapping_add(test_off);
                if let Some(phys) = as_ref.translate(VirtAddr::new(vaddr)) {
                    let ptr = crate::memory::phys_to_virt(phys.as_u64()) as *const u64;
                    let val = core::ptr::read_unaligned(ptr);
                    elf_trace!(
                        "[trampoline-got] tid={} name={} GOT[{:#x}]=phys={:#x} val={:#x}",
                        task.id.as_u64(),
                        task_name,
                        vaddr,
                        phys.as_u64(),
                        val
                    );
                } else {
                    elf_trace!(
                        "[trampoline-got] tid={} name={} GOT[{:#x}]=<not mapped>",
                        task.id.as_u64(),
                        task_name,
                        vaddr
                    );
                }
            }
        }
    }

    // Switch to the user address space stored in the task.
    // SAFETY: The address space was set up during task creation and is valid.
    unsafe {
        let as_ref = task.process.address_space_arc();
        as_ref.switch_to();
    }
    elf_trace!(
        "[trace][elf] ring3_trampoline switch_to done tid={}",
        task.id.as_u64()
    );

    let user_cs = gdt::user_code_selector().0 as u64;
    let user_ss = gdt::user_data_selector().0 as u64;
    let user_rflags: u64 = USER_RFLAGS;
    elf_trace!(
        "[trace][elf] ring3_trampoline iret tid={} cs={:#x} ss={:#x} rflags={:#x}",
        task.id.as_u64(),
        user_cs,
        user_ss,
        user_rflags
    );

    // ----- Pre-iret LAPIC timer diagnostic -----
    // Verify that the APIC timer is actually running on this CPU before we
    // enter Ring 3 (if it is not, no timer tick = no heartbeat = silent hang).
    unsafe {
        let lvt = crate::arch::x86_64::apic::read_reg(crate::arch::x86_64::apic::REG_LVT_TIMER);
        let init_cnt =
            crate::arch::x86_64::apic::read_reg(crate::arch::x86_64::apic::REG_TIMER_INIT);
        let _cur_cnt =
            crate::arch::x86_64::apic::read_reg(crate::arch::x86_64::apic::REG_TIMER_CURRENT);
        let _rflags_now: u64;
        core::arch::asm!("pushfq; pop {}", out(reg) _rflags_now, options(nostack));
        elf_trace!(
            "[trace][elf] pre-iret LAPIC: LVT={:#x} init={} cur={} IF={}",
            lvt,
            init_cnt,
            _cur_cnt,
            (_rflags_now >> 9) & 1
        );
        if lvt & (1 << 16) != 0 {
            elf_trace!(
                "[trace][elf] WARNING: LAPIC timer is MASKED (bit 16 set) : no ticks will fire!"
            );
        }
        if init_cnt == 0 {
            elf_trace!("[trace][elf] WARNING: LAPIC timer init_count=0 : timer not started!");
        }
    }

    crate::arch::x86_64::ring3_diag::validate_ring3_state(
        user_rip,
        user_rsp,
        user_cs as u16,
        user_ss as u16,
    );

    elf_trace!(
        "[elf] PRE-IRETQ tid={} rip={:#x} rsp={:#x} rflags={:#x}",
        task.id.as_u64(),
        user_rip,
        user_rsp,
        user_rflags
    );

    // E9 probe: validate_ring3_state passed, entering asm block.
    // If '0' is visible but not '1', the compiler inserted code between
    // the two that crashed (unlikely, but this rules it out).
    elf_trace!(
        "E9[0] pre-asm rip={:#x} rsp={:#x} cs={:#x} ss={:#x}",
        user_rip,
        user_rsp,
        user_cs,
        user_ss,
    );

    // SAFETY: Valid user mappings have been set up. IRETQ switches to Ring 3.
    //
    // Interrupts must be masked in the final kernel instructions before
    // `swapgs ; iretq`. Otherwise a timer IRQ can land after `swapgs` but
    // before `iretq`, with `CS=0x8` and `GS=user`, and the first `gs:[..]`
    // access in the handler faults in the swapgs->iretq window.

    // Each `out 0xe9, al` writes an ASCII character to QEMU's E9 port.
    // Debug builds include probes 1-4 for diagnosing IRETQ failures;
    // release builds omit them to avoid port I/O overhead.
    #[cfg(debug_assertions)]
    unsafe {
        core::arch::asm!(
            // Close the IRQ window before touching GS. `iretq` restores IF=1
            // from the user RFLAGS frame, so user mode still starts with
            // interrupts enabled.
            "cli",

            //  Probe 1: entering the asm block
            "push rax",
            "mov al, 0x31",     // '1'
            "out 0xe9, al",
            "pop rax",

            //  Build the iretq frame
            // Order required by IRETQ (popped in reverse order):
            //   [RSP+32] SS
            //   [RSP+24] user RSP
            //   [RSP+16] RFLAGS
            //   [RSP+8]  CS
            //   [RSP+0]  RIP  <--- RSP here after the 5 pushes
            "push {ss}",
            "push {rsp_val}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",

            //  Probe 2: frame iretq complete
            "push rax",
            "mov al, 0x32",     // '2'
            "out 0xe9, al",
            "pop rax",

            //  Pre-fault the user code page
            // Touch the first byte at user_rip to trigger a demand page fault
            // while GS is still the kernel per-CPU block. Without this, the
            // iretq instruction itself can fault in the SWAPGS->Ring3 window,
            // producing a SWAPGS-WINDOW page fault (CS=Ring0 but GS=user).
            "mov rax, {rip}",
            "movzx rax, byte ptr [rax]",

            //  Load arg0 into RDI
            "mov rdi, {arg0}",

            //  Probe 3: RDI loaded, just before SWAPGS
            "push rax",
            "mov al, 0x33",     // '3'
            "out 0xe9, al",
            "pop rax",

            //  SWAPGS: GS.base kernel <-> GS.base user
            "swapgs",

            //  Probe 4: SWAPGS succeeded, IRETQ imminent
            "push rax",
            "mov al, 0x34",     // '4'
            "out 0xe9, al",
            "pop rax",

            //  IRETQ: point of no return
            "iretq",

            ss      = in(reg) user_ss,
            rsp_val = in(reg) user_rsp,
            rflags  = in(reg) user_rflags,
            cs      = in(reg) user_cs,
            rip     = in(reg) user_rip,
            arg0    = in(reg) user_arg0,
            options(noreturn),
        );
    }

    #[cfg(not(debug_assertions))]
    unsafe {
        core::arch::asm!(
            "cli",

            //  Build the iretq frame
            "push {ss}",
            "push {rsp_val}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",

            //  Pre-fault the user code page
            "mov rax, {rip}",
            "movzx rax, byte ptr [rax]",

            //  Load arg0 into RDI
            "mov rdi, {arg0}",

            //  SWAPGS: GS.base kernel <-> GS.base user
            "swapgs",

            //  IRETQ: point of no return
            "iretq",

            ss      = in(reg) user_ss,
            rsp_val = in(reg) user_rsp,
            rflags  = in(reg) user_rflags,
            cs      = in(reg) user_cs,
            rip     = in(reg) user_rip,
            arg0    = in(reg) user_arg0,
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
/// * `elf_data` : raw ELF file bytes (must remain valid until load completes).
/// * `name` : name for the task (debugging purposes).
///
/// # Returns
/// `Ok(())` on success, `Err` with a static error message on failure.
pub fn load_and_run_elf(elf_data: &[u8], name: &'static str) -> Result<TaskId, &'static str> {
    load_and_run_elf_with_caps(elf_data, name, &[])
}

/// Load an ELF64 binary with command-line arguments and schedule it as a Ring 3 task.
///
/// `extra_args` maps to `argv[1..]`; `argv[0]` is always `name`.
pub fn load_and_run_elf_with_args(
    elf_data: &[u8],
    name: &'static str,
    extra_args: &[&str],
) -> Result<TaskId, &'static str> {
    let task = load_elf_task_inner(elf_data, name, extra_args, &[], USER_STACK_PAGES)?;
    let task_id = task.id;
    crate::process::add_task(task);
    Ok(task_id)
}

/// Load an ELF64 binary with an explicit per-process user stack size.
///
/// `stack_pages` is expressed in 4 KiB pages and clamped to
/// [`USER_STACK_MIN_PAGES`]..=[`USER_STACK_MAX_PAGES`] (issue #64).
pub fn load_and_run_elf_with_stack(
    elf_data: &[u8],
    name: &'static str,
    extra_args: &[&str],
    seed_caps: &[Capability],
    stack_pages: usize,
) -> Result<TaskId, &'static str> {
    let task = load_elf_task_inner(elf_data, name, extra_args, seed_caps, stack_pages)?;
    let task_id = task.id;
    crate::process::add_task(task);
    Ok(task_id)
}

/// Thin public wrapper that keeps the existing API stable.
pub fn load_elf_task_with_caps(
    elf_data: &[u8],
    name: &'static str,
    seed_caps: &[Capability],
) -> Result<Arc<Task>, &'static str> {
    load_elf_task_inner(elf_data, name, &[], seed_caps, USER_STACK_PAGES)
}

/// Performs the load and run elf with caps operation.
pub fn load_and_run_elf_with_caps(
    elf_data: &[u8],
    name: &'static str,
    seed_caps: &[Capability],
) -> Result<TaskId, &'static str> {
    crate::e9_println!(
        "[trace][elf] load_and_run_elf enter name={} size={}",
        name,
        elf_data.len()
    );
    let task = load_elf_task_inner(elf_data, name, &[], seed_caps, USER_STACK_PAGES)?;
    let task_id = task.id;
    let runtime_entry = task
        .trampoline_entry
        .load(core::sync::atomic::Ordering::Acquire);
    let boot_stack_top = task
        .trampoline_stack_top
        .load(core::sync::atomic::Ordering::Acquire);
    crate::e9_println!(
        "[trace][elf] load_and_run_elf add_task begin tid={} entry={:#x}",
        task_id.as_u64(),
        runtime_entry
    );
    crate::process::add_task(task);
    crate::e9_println!(
        "[trace][elf] load_and_run_elf add_task done tid={}",
        task_id.as_u64()
    );

    log::info!(
        "[elf] Task '{}' created: entry={:#x}, stack_top={:#x}",
        name,
        runtime_entry,
        boot_stack_top,
    );

    Ok(task_id)
}

const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_RANDOM: u64 = 25;

fn generate_aux_random_seed() -> [u8; 16] {
    let mut seed = [0u8; 16];
    crate::entropy::fill_random(&mut seed);
    seed
}

/// Performs the push auxv operation.
fn push_auxv(user_as: &AddressSpace, sp: &mut u64, tag: u64, val: u64) -> Result<(), &'static str> {
    *sp -= 8;
    write_user_u64(user_as, *sp, val)?;
    *sp -= 8;
    write_user_u64(user_as, *sp, tag)?;
    Ok(())
}

/// Performs the setup boot user stack operation.
/// Sets up the initial user-space stack for a freshly loaded ELF task.
///
/// Stack layout (low addr at bottom = first word read by `_start`):
/// ```
/// [sp+0]             argc
/// [sp+8]             argv[0] ptr  (program name)
/// [sp+8*(2..=argc)]  argv[1..] ptrs  (extra_args)
/// [sp+8*(argc+1)]    NULL  (argv terminator)
/// [sp+8*(argc+2)]    NULL  (envp terminator)
/// ...                auxv pairs
/// ```
fn setup_boot_user_stack(
    user_as: &AddressSpace,
    name: &str,
    extra_args: &[&str],
    phdr_vaddr: u64,
    phent: u16,
    phnum: u16,
    program_entry: u64,
    interp_base: Option<u64>,
    stack_base: u64,
    stack_top: u64,
) -> Result<u64, &'static str> {
    let mut sp = stack_top;

    // Write argv[0] = program name (null-terminated)
    let name_nul_len = (name.len() + 1) as u64;
    sp -= name_nul_len;
    if sp < stack_base {
        return Err("User stack overflow during boot stack setup");
    }
    let argv0_ptr = sp;
    write_user_mapped_bytes(user_as, sp, name.as_bytes())?;
    write_user_mapped_bytes(user_as, sp + name.len() as u64, &[0])?;

    // Write extra arg strings and record their user-space pointers
    let mut extra_ptrs: alloc::vec::Vec<u64> = alloc::vec::Vec::with_capacity(extra_args.len());
    for &arg in extra_args.iter() {
        let arg_nul_len = (arg.len() + 1) as u64;
        sp -= arg_nul_len;
        if sp < stack_base {
            return Err("User stack overflow during boot stack setup");
        }
        extra_ptrs.push(sp);
        write_user_mapped_bytes(user_as, sp, arg.as_bytes())?;
        write_user_mapped_bytes(user_as, sp + arg.len() as u64, &[0])?;
    }

    sp &= !0xF;
    sp -= 16;
    if sp < stack_base {
        return Err("User stack overflow during boot stack setup");
    }
    let random_ptr = sp;
    let random_seed = generate_aux_random_seed();
    write_user_mapped_bytes(user_as, sp, &random_seed)?;
    let auxv_pairs = if interp_base.is_some() { 8u64 } else { 7u64 };
    // argc(1) + argv[0..=N](1+N) + argv_NULL(1) + envp_NULL(1) + auxv(pairs*2)
    let stack_words = 4u64 + extra_args.len() as u64 + auxv_pairs * 2;
    let align_pad = (0u64.wrapping_sub(stack_words * 8)) & 0xF;
    sp -= align_pad;

    // Auxv (written high-to-low since push_auxv decrements sp)
    push_auxv(user_as, &mut sp, 0, 0)?; // AT_NULL
    push_auxv(user_as, &mut sp, AT_RANDOM, random_ptr)?;
    push_auxv(user_as, &mut sp, AT_ENTRY, program_entry)?;
    if let Some(base) = interp_base {
        push_auxv(user_as, &mut sp, AT_BASE, base)?;
    }
    push_auxv(user_as, &mut sp, AT_PAGESZ, 4096)?;
    push_auxv(user_as, &mut sp, AT_PHNUM, phnum as u64)?;
    push_auxv(user_as, &mut sp, AT_PHENT, phent as u64)?;
    push_auxv(user_as, &mut sp, AT_PHDR, phdr_vaddr)?;

    // envp NULL terminator
    sp -= 8;
    write_user_u64(user_as, sp, 0)?;

    // argv NULL terminator
    sp -= 8;
    write_user_u64(user_as, sp, 0)?;

    // Extra argv pointers in reverse (last arg highest in stack, first arg lowest)
    for &ptr in extra_ptrs.iter().rev() {
        sp -= 8;
        write_user_u64(user_as, sp, ptr)?;
    }

    // argv[0] = program name
    sp -= 8;
    write_user_u64(user_as, sp, argv0_ptr)?;

    // argc = 1 (name) + extra_args
    sp -= 8;
    write_user_u64(user_as, sp, 1u64 + extra_args.len() as u64)?;

    debug_assert_eq!(sp & 0xF, 0);
    Ok(sp)
}

/// Internal ELF task builder used by all public loading APIs.
/// `extra_args` are written to the user stack as argv[1..] after the program name.
fn load_elf_task_inner(
    elf_data: &[u8],
    name: &'static str,
    extra_args: &[&str],
    seed_caps: &[Capability],
    stack_pages: usize,
) -> Result<Arc<Task>, &'static str> {
    if !(USER_STACK_MIN_PAGES..=USER_STACK_MAX_PAGES).contains(&stack_pages) {
        return Err("User stack size out of range");
    }
    crate::e9_println!(
        "[trace][elf] load_elf_task enter name={} size={}",
        name,
        elf_data.len()
    );
    log::info!("[elf] Loading ELF '{}'...", name);

    // Step 1: Parse and validate ELF header
    crate::e9_println!("[trace][elf] load_elf_task parse_header begin");
    let header = match parse_header(elf_data) {
        Ok(h) => h,
        Err(e) => {
            crate::serial_println!("[elf] parse_header FAILED for '{}': {}", name, e);
            return Err(e);
        }
    };
    crate::e9_println!(
        "[trace][elf] load_elf_task parse_header ok type={}",
        if header.e_type == ET_DYN {
            "ET_DYN"
        } else {
            "ET_EXEC"
        }
    );
    // Step 2: Create user address space
    crate::e9_println!("[trace][elf] load_elf_task user_as begin");
    let user_as = Arc::new(AddressSpace::new_user()?);
    crate::e9_println!("[trace][elf] load_elf_task user_as done");

    let phdrs: Vec<Elf64Phdr> = program_headers(elf_data, &header).collect();
    let interp_path = parse_interp_path(elf_data, &phdrs)?;
    let (load_bias, entry) = compute_load_bias_and_entry(&user_as, &header, &phdrs)?;
    let phdr_vaddr = find_relocated_phdr_vaddr(&header, &phdrs, load_bias)?;

    let phnum = header.e_phnum;
    crate::e9_println!(
        "[trace][elf] load_elf_task layout entry={:#x} bias={:#x} phdrs={}",
        entry,
        load_bias,
        phnum
    );
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

    crate::e9_println!(
        "[trace][elf] load_elf_task segments_done count={} has_interp={}",
        load_count,
        interp_path.is_some()
    );
    log::info!("[elf] Loaded {} PT_LOAD segment(s)", load_count);

    let mut runtime_entry = entry;
    let mut interp_base: Option<u64> = None;
    if let Some(path) = interp_path {
        let interp_data = read_elf_from_vfs(path)?;
        let interp_header = parse_header(&interp_data)?;
        let interp_phdrs: Vec<Elf64Phdr> = program_headers(&interp_data, &interp_header).collect();
        if parse_interp_path(&interp_data, &interp_phdrs)?.is_some() {
            return Err("Nested PT_INTERP is not supported");
        }
        let (interp_bias, interp_entry) =
            compute_load_bias_and_entry(&user_as, &interp_header, &interp_phdrs)?;
        let (interp_min_vaddr, _) = compute_load_bounds(&interp_phdrs)?;
        let mut interp_load_count = 0u32;
        for phdr in interp_phdrs.iter() {
            if phdr.p_type == PT_LOAD && phdr.p_memsz != 0 {
                load_segment(&user_as, &interp_data, phdr, interp_bias)?;
                interp_load_count += 1;
            }
        }
        apply_dynamic_relocations(&user_as, &interp_phdrs, interp_header.e_type, interp_bias)?;
        runtime_entry = interp_entry;
        interp_base = Some(interp_min_vaddr.saturating_add(interp_bias));
        log::info!(
            "[elf] PT_INTERP '{}' loaded: {} PT_LOAD, entry={:#x}",
            path,
            interp_load_count,
            runtime_entry
        );
    }

    // TLS setup (Variant II: data at negative offsets from FS:0)
    let mut user_fs_base_val = 0u64;
    if let Some(tls) = phdrs.iter().find(|p| p.p_type == PT_TLS) {
        let tls_memsz = tls.p_memsz;
        let tls_filesz = tls.p_filesz;
        let tls_align = core::cmp::max(tls.p_align, 8).next_power_of_two();
        let aligned_memsz = (tls_memsz + tls_align - 1) & !(tls_align - 1);
        let total_size = aligned_memsz + 8;
        let n_tls_pages = ((total_size + 4095) / 4096) as usize;
        let tls_flags = VmaFlags {
            readable: true,
            writable: true,
            executable: false,
            user_accessible: true,
        };
        let tls_base = user_as
            .find_free_vma_range(0x7FFF_E000_0000, n_tls_pages, VmaPageSize::Small)
            .ok_or("No space for TLS block")?;
        user_as.map_region(
            tls_base,
            n_tls_pages,
            tls_flags,
            VmaType::Anonymous,
            VmaPageSize::Small,
        )?;
        if tls_filesz > 0 {
            let src_off = tls.p_offset as usize;
            let src_end = src_off
                .checked_add(tls_filesz as usize)
                .ok_or("PT_TLS offset+filesz overflows")?;
            if src_end > elf_data.len() {
                return Err("PT_TLS file data extends past ELF");
            }
            write_user_mapped_bytes(&user_as, tls_base, &elf_data[src_off..src_end])?;
        }
        let tp = tls_base + aligned_memsz;
        write_user_u64(&user_as, tp, tp)?;
        user_fs_base_val = tp;
    }

    // Step 4: Map user stack
    // Per-process ASLR (issue #62): on top of the boot-time KASLR offset, each
    // image draws its own page-aligned jitter so two processes never share
    // identical stack addresses. The stack size is configurable per process
    // (issue #64). A single guard page below the stack is left unmapped :
    // underflow faults instead of silently corrupting neighbours.
    let stack_base = crate::kaslr::stack_base_with_jitter(crate::kaslr::draw_stack_jitter());
    let stack_top = crate::kaslr::stack_top_for(stack_base, stack_pages);
    let stack_flags = VmaFlags {
        readable: true,
        writable: true,
        executable: false,
        user_accessible: true,
    };
    user_as.map_region(
        stack_base,
        stack_pages,
        stack_flags,
        VmaType::Stack,
        VmaPageSize::Small,
    )?;
    // Guard page: a single unmapped page below the stack.  Any stack
    // underflow (push past the bottom) hits this and faults.  The page
    // is intentionally left unmapped : no VMA, no PTE.
    log::debug!(
        "[elf] User stack: {:#x}..{:#x} ({} pages), guard at {:#x}",
        stack_base,
        stack_top,
        stack_pages,
        user_stack_guard(),
    );

    let boot_sp = setup_boot_user_stack(
        &user_as,
        name,
        extra_args,
        phdr_vaddr,
        header.e_phentsize,
        header.e_phnum,
        entry,
        interp_base,
        stack_base,
        stack_top,
    )?;

    // Step 5: Create kernel task : trampoline params are stored inside the task
    // itself so that concurrent SMP execution of multiple trampolines is safe.
    crate::e9_println!(
        "[trace][elf] load_elf_task kstack_begin size={}",
        Task::DEFAULT_STACK_SIZE
    );
    let kernel_stack = KernelStack::allocate(Task::DEFAULT_STACK_SIZE)?;
    crate::e9_println!(
        "[trace][elf] load_elf_task kstack_done virt={:#x} top={:#x}",
        kernel_stack.virt_base.as_u64(),
        kernel_stack.virt_base.as_u64() + kernel_stack.size as u64
    );
    let context = CpuContext::new(elf_ring3_trampoline as *const () as u64, &kernel_stack);
    let (pid, tid, tgid) = Task::allocate_process_ids();
    let fpu_state = crate::process::task::ExtendedState::new();
    let xcr0_mask = fpu_state.xcr0_mask;

    let task = Arc::new(Task {
        id: TaskId::new(),
        pid,
        tid,
        tgid,
        pgid: core::sync::atomic::AtomicU32::new(pid),
        sid: core::sync::atomic::AtomicU32::new(pid),
        uid: core::sync::atomic::AtomicU32::new(0),
        euid: core::sync::atomic::AtomicU32::new(0),
        gid: core::sync::atomic::AtomicU32::new(0),
        egid: core::sync::atomic::AtomicU32::new(0),
        state: core::sync::atomic::AtomicU8::new(TaskState::Ready as u8),
        priority: TaskPriority::Normal,
        context: SyncUnsafeCell::new(context),
        resume_kind: SyncUnsafeCell::new(ResumeKind::RetFrame),
        interrupt_rsp: core::sync::atomic::AtomicU64::new(0),
        kernel_stack,
        user_stack: Some(crate::process::task::UserStack {
            virt_base: x86_64::VirtAddr::new(stack_base),
            size: stack_pages * 4096,
        }),
        name,
        process: Arc::new(crate::process::process::Process::new(pid, user_as)),
        pending_signals: super::signal::SignalSet::new(),
        blocked_signals: super::signal::SignalSet::new(),
        irq_signal_delivery_blocked: core::sync::atomic::AtomicBool::new(false),
        signal_stack: SyncUnsafeCell::new(None),
        itimers: super::timer::ITimers::new(),
        wake_pending: core::sync::atomic::AtomicBool::new(false),
        wake_deadline_ns: core::sync::atomic::AtomicU64::new(0),
        trampoline_entry: core::sync::atomic::AtomicU64::new(runtime_entry),
        trampoline_stack_top: core::sync::atomic::AtomicU64::new(boot_sp),
        trampoline_arg0: core::sync::atomic::AtomicU64::new(0),
        ticks: core::sync::atomic::AtomicU64::new(0),
        sched_policy: crate::process::task::SyncUnsafeCell::new(Task::default_sched_policy(
            TaskPriority::Normal,
        )),
        home_cpu: core::sync::atomic::AtomicUsize::new(usize::MAX),
        vruntime: core::sync::atomic::AtomicU64::new(0),
        fair_rq_generation: core::sync::atomic::AtomicU64::new(0),
        fair_on_rq: core::sync::atomic::AtomicBool::new(false),
        clear_child_tid: core::sync::atomic::AtomicU64::new(0),
        robust_list_head: core::sync::atomic::AtomicU64::new(0),
        robust_list_len: core::sync::atomic::AtomicUsize::new(0),
        user_fs_base: core::sync::atomic::AtomicU64::new(user_fs_base_val),
        fpu_state: crate::process::task::SyncUnsafeCell::new(fpu_state),
        xcr0_mask: core::sync::atomic::AtomicU64::new(xcr0_mask),
        rt_link: intrusive_collections::LinkedListLink::new(),
    });

    crate::e9_println!(
        "[trace][elf] load_elf_task task_built tid={} pid={} entry={:#x} sp={:#x}",
        task.id.as_u64(),
        task.pid,
        runtime_entry,
        boot_sp
    );
    // Seed capabilities into the new task (before scheduling).
    let mut bootstrap_handle: Option<u64> = None;
    if !seed_caps.is_empty() {
        let caps = unsafe { &mut *task.process.capabilities.get() };
        for cap in seed_caps {
            let id = caps.insert(cap.clone());
            if bootstrap_handle.is_none()
                && cap.resource_type == crate::capability::ResourceType::Volume
            {
                bootstrap_handle = Some(id.as_u64());
            }
        }
    }

    // Setup stdin/stdout/stderr (fd 0/1/2) pointing to /dev/console
    // SAFETY: task is not yet scheduled, exclusive access to fd_table
    {
        let fd_table = unsafe { &mut *task.process.fd_table.get() };
        crate::vfs::console_scheme::setup_stdio(fd_table);
    }

    if let Some(h) = bootstrap_handle {
        // Program entry will see this in its first argument register (RDI).
        task.trampoline_arg0
            .store(h, core::sync::atomic::Ordering::Release);
    }

    task.seed_interrupt_frame(crate::syscall::SyscallFrame {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        rbp: 0,
        rbx: 0,
        r11: USER_RFLAGS,
        r10: 0,
        r9: 0,
        r8: 0,
        rsi: 0,
        rdi: task
            .trampoline_arg0
            .load(core::sync::atomic::Ordering::Acquire),
        rdx: 0,
        rcx: runtime_entry,
        rax: 0,
        iret_rip: runtime_entry,
        iret_cs: crate::arch::x86_64::gdt::user_code_selector().0 as u64,
        iret_rflags: USER_RFLAGS,
        iret_rsp: boot_sp,
        iret_ss: crate::arch::x86_64::gdt::user_data_selector().0 as u64,
    });

    {
        let arc_data_ptr = alloc::sync::Arc::as_ptr(&task) as usize;
        let fpu_ptr = task.fpu_state.get() as usize;
        if let Some(cur) = crate::process::scheduler::current_task_clone() {
            let cur_data_ptr = alloc::sync::Arc::as_ptr(&cur) as usize;
            let cur_strong = alloc::sync::Arc::strong_count(&cur);
            log::info!(
                "[elf] Task '{}' prepared: entry={:#x}, stack_top={:#x} \
                 new_arc={:#x} new_fpu={:#x} cur_arc={:#x} cur_strong={}",
                name,
                runtime_entry,
                boot_sp,
                arc_data_ptr,
                fpu_ptr,
                cur_data_ptr,
                cur_strong,
            );
        } else {
            log::info!(
                "[elf] Task '{}' prepared: entry={:#x}, stack_top={:#x} \
                 new_arc={:#x} new_fpu={:#x} (no current task)",
                name,
                runtime_entry,
                boot_sp,
                arc_data_ptr,
                fpu_ptr,
            );
        }
    }

    Ok(task)
}

/// Load an ELF binary into the provided address space.
/// Returns the entry point address.
pub fn load_elf_image(
    elf_data: &[u8],
    user_as: &AddressSpace,
) -> Result<LoadedElfInfo, &'static str> {
    let header = match parse_header(elf_data) {
        Ok(h) => h,
        Err(e) => {
            crate::serial_println!("[elf] load_elf_image parse_header FAILED: {}", e);
            return Err(e);
        }
    };
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

    let (tls_vaddr, tls_filesz, tls_memsz, tls_align) =
        if let Some(tls) = phdrs.iter().find(|ph| ph.p_type == PT_TLS) {
            let align = core::cmp::max(tls.p_align, 1).next_power_of_two();
            (
                tls.p_vaddr.saturating_add(load_bias),
                tls.p_filesz,
                tls.p_memsz,
                align,
            )
        } else {
            (0, 0, 0, 1)
        };

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
        tls_vaddr,
        tls_filesz,
        tls_memsz,
        tls_align,
    })
}

/// Reads user mapped bytes pub.
pub fn read_user_mapped_bytes_pub(
    user_as: &AddressSpace,
    vaddr: u64,
    out: &mut [u8],
) -> Result<(), &'static str> {
    read_user_mapped_bytes(user_as, vaddr, out)
}

/// Writes user mapped bytes pub.
pub fn write_user_mapped_bytes_pub(
    user_as: &AddressSpace,
    vaddr: u64,
    src: &[u8],
) -> Result<(), &'static str> {
    write_user_mapped_bytes(user_as, vaddr, src)
}

/// Writes user u64 pub.
pub fn write_user_u64_pub(
    user_as: &AddressSpace,
    vaddr: u64,
    value: u64,
) -> Result<(), &'static str> {
    write_user_u64(user_as, vaddr, value)
}
