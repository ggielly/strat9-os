//! Minimal ELF64 loader for Strat9-OS.
//!
//! Parses ELF64 headers and loads PT_LOAD segments into a user address space,
//! then creates a kernel task that trampolines into Ring 3 via IRETQ.
//!
//! Supports ET_EXEC and ET_DYN (PIE/static-PIE) ELF64 little-endian x86_64
//! binaries.

use alloc::sync::Arc;
use x86_64::{
    structures::paging::{Mapper, Page, Size4KiB},
    VirtAddr,
};

use crate::{
    capability::{Capability, CapabilityTable},
    memory::address_space::{AddressSpace, VmaFlags, VmaType},
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
const DT_RELACOUNT: i64 = 0x6fff_fff9;
const R_X86_64_RELATIVE: u32 = 8;

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
    // validated again after relocation).
    if header.e_entry >= USER_ADDR_MAX {
        return Err("Entry point outside user address range");
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
            .find_free_vma_range(PIE_BASE_ADDR, n_pages)
            .or_else(|| user_as.find_free_vma_range(0x0000_0000_1000_0000, n_pages))
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
        let flush = unsafe {
            mapper
                .update_flags(page, pte_flags)
                .map_err(|_| "Failed to update segment page flags")?
        };
        flush.flush();
    }
    Ok(())
}

fn read_user_mapped_bytes(
    user_as: &AddressSpace,
    mut vaddr: u64,
    out: &mut [u8],
) -> Result<(), &'static str> {
    let mut copied = 0usize;
    while copied < out.len() {
        let page_off = (vaddr & 0xFFF) as usize;
        let chunk = core::cmp::min(out.len() - copied, 4096 - page_off);
        let phys = user_as
            .translate(VirtAddr::new(vaddr))
            .ok_or("Failed to translate mapped user bytes")?;
        let src = (crate::memory::phys_to_virt(phys.as_u64()) as *const u8).wrapping_add(page_off);
        // SAFETY: src points to mapped physical memory via HHDM.
        unsafe { core::ptr::copy_nonoverlapping(src, out.as_mut_ptr().add(copied), chunk) };
        copied += chunk;
        vaddr = vaddr
            .checked_add(chunk as u64)
            .ok_or("Virtual address overflow while reading mapped bytes")?;
    }
    Ok(())
}

fn write_user_u64(user_as: &AddressSpace, vaddr: u64, value: u64) -> Result<(), &'static str> {
    let phys = user_as
        .translate(VirtAddr::new(vaddr))
        .ok_or("Failed to translate relocation target")?;
    let dst = crate::memory::phys_to_virt(phys.as_u64()) as *mut u8;
    let bytes = value.to_le_bytes();
    // SAFETY: destination points to mapped user frame through HHDM.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, 8) };
    Ok(())
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
    let mut rela_count_hint: Option<usize> = None;

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
            _ => {}
        }
    }

    let Some(rela_base) = rela_addr else {
        return Ok(());
    };
    if rela_ent != core::mem::size_of::<Elf64Rela>() {
        return Err("Unsupported DT_RELAENT size");
    }
    if rela_size == 0 {
        return Ok(());
    }

    let mut rela_count = rela_size / rela_ent;
    if let Some(hint) = rela_count_hint {
        rela_count = core::cmp::min(rela_count, hint);
    }

    for i in 0..rela_count {
        let rela_addr_i = rela_base
            .checked_add((i * rela_ent) as u64)
            .ok_or("Rela table overflow")?;
        let mut raw = [0u8; core::mem::size_of::<Elf64Rela>()];
        read_user_mapped_bytes(user_as, rela_addr_i, &mut raw)?;
        // SAFETY: raw has exact size of Elf64Rela.
        let rela = unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const Elf64Rela) };

        let r_type = (rela.r_info & 0xffff_ffff) as u32;
        let r_sym = (rela.r_info >> 32) as u32;
        if r_type != R_X86_64_RELATIVE {
            return Err("Unsupported dynamic relocation type");
        }
        if r_sym != 0 {
            return Err("R_X86_64_RELATIVE with non-zero symbol");
        }

        let target = rela
            .r_offset
            .checked_add(load_bias)
            .ok_or("Relocation target overflow")?;
        let value = (load_bias as i128)
            .checked_add(rela.r_addend as i128)
            .ok_or("Relocation value overflow")?;
        if value < 0 || value > u64::MAX as i128 {
            return Err("Relocation value out of range");
        }
        write_user_u64(user_as, target, value as u64)?;
    }

    log::debug!("[elf] Applied {} RELA relocations", rela_count);
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
    user_as.map_region(page_start, page_count, load_flags, vma_type)?;

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
    address_space: Option<Arc<AddressSpace>>,
}

static mut TRAMPOLINE_PARAMS: TrampolineParams = TrampolineParams {
    entry_point: 0,
    stack_top: 0,
    address_space: None,
};

/// Trampoline that switches to user address space and does IRETQ to Ring 3.
extern "C" fn elf_ring3_trampoline() -> ! {
    use crate::arch::x86_64::gdt;

    let (user_rip, user_rsp);

    // SAFETY: Single-threaded setup. The params are written before the task
    // is scheduled. We read and clear them atomically at first execution.
    unsafe {
        let params = &raw mut TRAMPOLINE_PARAMS;
        user_rip = (*params).entry_point;
        user_rsp = (*params).stack_top;

        if let Some(ref as_ref) = (*params).address_space {
            as_ref.switch_to();
        }
        // Clear to avoid dangling Arc reference
        (*params).address_space = None;
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
            "iretq",
            ss = in(reg) user_ss,
            rsp_val = in(reg) user_rsp,
            rflags = in(reg) user_rflags,
            cs = in(reg) user_cs,
            rip = in(reg) user_rip,
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

    let phdrs: alloc::vec::Vec<Elf64Phdr> = program_headers(elf_data, &header).collect();
    if phdrs.iter().any(|ph| ph.p_type == PT_INTERP) {
        return Err("PT_INTERP not supported yet (dynamic linker required)");
    }
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
    apply_dynamic_relocations(&user_as, &phdrs, header.e_type, load_bias)?;

    log::info!("[elf] Loaded {} PT_LOAD segment(s)", load_count);

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
        (*params).entry_point = entry;
        (*params).stack_top = USER_STACK_TOP;
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
        address_space: user_as,
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
    let mut bootstrap_handle: u64 = 0;
    if !seed_caps.is_empty() {
        let caps = unsafe { &mut *task.capabilities.get() };
        for cap in seed_caps {
            let id = caps.insert(cap.clone());
            if bootstrap_handle == 0 && cap.resource_type == crate::capability::ResourceType::Volume
            {
                bootstrap_handle = id.as_u64();
            }
        }
    }

    if bootstrap_handle != 0 {
        let ctx = unsafe { &mut *task.context.get() };
        unsafe {
            // CpuContext stack layout: r15, r14, r13, r12, rbp, rbx, ret
            let frame = ctx.saved_rsp as *mut u64;
            *frame.add(2) = bootstrap_handle;
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
        entry,
        USER_STACK_TOP,
    );

    Ok(task_id)
}

/// Load an ELF binary into the provided address space.
/// Returns the entry point address.
pub fn load_elf_image(
    elf_data: &[u8],
    user_as: &AddressSpace,
) -> Result<u64, &'static str> {
    let header = parse_header(elf_data)?;
    let phdrs: alloc::vec::Vec<Elf64Phdr> = program_headers(elf_data, &header).collect();
    if phdrs.iter().any(|ph| ph.p_type == PT_INTERP) {
        return Err("PT_INTERP not supported yet (dynamic linker required)");
    }
    let (load_bias, entry) = compute_load_bias_and_entry(user_as, &header, &phdrs)?;

    for phdr in phdrs.iter() {
        if phdr.p_type == PT_LOAD && phdr.p_memsz != 0 {
            load_segment(user_as, elf_data, phdr, load_bias)?;
        }
    }
    apply_dynamic_relocations(user_as, &phdrs, header.e_type, load_bias)?;
    Ok(entry)
}
