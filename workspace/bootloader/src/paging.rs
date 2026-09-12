pub use crate::boot_plan::INITIAL_ALLOCATION_LIMIT as INITIAL_PHYS_LIMIT;
use crate::{
    boot_plan::{DirectMapPlan, GIB},
    memory_map::{page_allocation_size, PageFrameCursor, PhysicalRange},
};

pub const FRAMEBUFFER_BASE: u64 = 0xFFFF_DEAD_0000_0000;
pub const ENVIRONMENT_BASE: u64 = 0xFFFF_BEEF_0000_0000;

const PAGE_SIZE: u64 = 0x1000;
const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;

/// Higher-half direct map of physical RAM (HHDM). Must match the value
/// passed to the kernel in `KernelArgs::hhdm_offset` : the kernel does
/// phys_to_virt(phys) = phys + hhdm_offset for ALL physical memory access.
///
/// PML4[510] window (0xFFFFFF0000000000..0xFFFFFF7FFFFFFFFF, 512 GB):
/// distinct from PML4[511] (kernel image slot), PML4[445] (framebuffer)
/// and PML4[381] (environment). The kernel image lives at
/// 0xFFFFFFFF80000000 = PML4[511].PDP[510] : using 0xFFFFFFFF80000000 as
/// the HHDM offset would collide with the kernel-image mapping.
pub const HHDM_OFFSET: u64 = 0xFFFF_FF00_0000_0000;
/// 2 MiB huge-page size used for the HHDM map.
const HUGE_PAGE: u64 = 0x20_0000;

pub const PHYS_OFFSET: u64 = 0;

/// Exact allocation budget for the current mapping topology. Kernel mappings
/// occupy one PD; framebuffer/environment keep their existing layout for now.
pub fn page_table_pages(
    kernel_size: u64,
    framebuffer_size: u64,
    env_size: u64,
    direct_map: DirectMapPlan,
) -> Result<u64, &'static str> {
    let kernel_pages = page_allocation_size(kernel_size)? / PAGE_SIZE;
    if kernel_pages > 512 * 512 {
        return Err("kernel exceeds the supported page-directory window");
    }
    let mut pages = 5 + 2 * (direct_map.end() / GIB) + (kernel_pages + 511) / 512;
    for size in [framebuffer_size, env_size] {
        if size != 0 {
            pages += 2 + (page_allocation_size(size)? / PAGE_SIZE).min(512);
        }
    }
    Ok(pages)
}

/// The caller must own `table_area` exclusively and keep every frame reserved
/// for as long as these tables are active. BootMemory supplies that allocation.
pub unsafe fn create_page_tables(
    kernel_phys: u64,
    kernel_size: u64,
    _framebuffer_phys: u64,
    _framebuffer_size: u64,
    _env_phys: u64,
    _env_size: u64,
    table_area: PhysicalRange,
    direct_map: DirectMapPlan,
) -> Result<u64, &'static str> {
    let required_pages = page_table_pages(kernel_size, _framebuffer_size, _env_size, direct_map)?;
    if table_area.size < required_pages * PAGE_SIZE
        || table_area.end()? > INITIAL_PHYS_LIMIT
        || !direct_map.covers(table_area)
        || kernel_phys == 0
        || kernel_phys % PAGE_SIZE != 0
        || !direct_map.covers(PhysicalRange {
            base: kernel_phys,
            size: page_allocation_size(kernel_size)?,
        })
    {
        return Err("invalid page-table allocation");
    }
    let mut cursor = PageFrameCursor::new(table_area)?;
    let mut alloc_frame = || -> Result<u64, &'static str> {
        let addr = cursor.next_frame()?;
        // SAFETY: the bounded cursor only yields pages in the owned arena.
        unsafe { core::ptr::write_bytes(addr as *mut u8, 0, PAGE_SIZE as usize) };
        Ok(addr)
    };

    let pml4 = alloc_frame()? as *mut u64;

    // Identical coverage for identity and HHDM, using baseline 2 MiB leaves.
    // No PDPTE is a 1 GiB leaf. PS is bit 7; the huge-page PAT bit is bit 12.
    // Cover all allocatable firmware RAM and the complete EFI image, even above
    // 8 GiB, so the instructions after the CR3 write remain executable.
    unsafe {
        for slot in [0, ((HHDM_OFFSET >> 39) & 0x1FF) as usize] {
            let pdp = alloc_frame()? as *mut u64;
            *pml4.add(slot) = pdp as u64 | PRESENT | WRITABLE;
            for gb in 0..direct_map.end() / GIB {
                let pd = alloc_frame()? as *mut u64;
                *pdp.add(gb as usize) = pd as u64 | PRESENT | WRITABLE;
                for index in 0..512u64 {
                    let physical = gb * GIB + index * HUGE_PAGE;
                    *pd.add(index as usize) = physical | PRESENT | WRITABLE | (1 << 7);
                }
            }
        }
    }

    // Higher-half kernel: PML4[511] => PDP[510] => PD => PT (4KB pages)
    unsafe {
        let pdp = alloc_frame()? as *mut u64;
        *pml4.add(511) = pdp as u64 | PRESENT | WRITABLE;

        let pd = alloc_frame()? as *mut u64;
        *pdp.add(510) = pd as u64 | PRESENT | WRITABLE;

        let pages_needed = ((kernel_size + PAGE_SIZE - 1) / PAGE_SIZE) as usize;
        let mut phys = kernel_phys;

        for pt_idx in 0..(pages_needed + 511) / 512 {
            let pt = alloc_frame()? as *mut u64;

            for entry in 0..512usize {
                let page_num = pt_idx * 512 + entry;
                if page_num >= pages_needed {
                    break;
                }
                *pt.add(entry) = phys | PRESENT | WRITABLE;
                phys += PAGE_SIZE;
            }

            *pd.add(pt_idx) = pt as u64 | PRESENT | WRITABLE;
        }
    }

    // Framebuffer
    if _framebuffer_phys != 0 && _framebuffer_size > 0 {
        unsafe {
            let pdp = alloc_frame()? as *mut u64;
            let pml4_idx = ((FRAMEBUFFER_BASE >> 39) & 0x1FF) as usize;
            *pml4.add(pml4_idx) = pdp as u64 | PRESENT | WRITABLE;

            let pd = alloc_frame()? as *mut u64;
            let pdp_idx = ((FRAMEBUFFER_BASE >> 30) & 0x1FF) as usize;
            *pdp.add(pdp_idx) = pd as u64 | PRESENT | WRITABLE;

            let mut mapped: u64 = 0;
            let mut pd_idx: usize = 0;
            let pages = (_framebuffer_size + PAGE_SIZE - 1) / PAGE_SIZE;

            for _page in 0..pages {
                if pd_idx >= 512 {
                    break;
                }
                let pt = alloc_frame()? as *mut u64;
                let pt_phys = _framebuffer_phys + mapped;
                // S1: Write-Combining via PTE PAT bit -> IA32_PAT entry 4.
                *pt.add(0) = pt_phys | PRESENT | WRITABLE | (1 << 7);
                *pd.add(pd_idx) = pt as u64 | PRESENT | WRITABLE;
                pd_idx += 1;
                mapped += PAGE_SIZE;
            }
        }
    }

    // Environment
    if _env_phys != 0 && _env_size > 0 {
        unsafe {
            let pdp = alloc_frame()? as *mut u64;
            let pml4_idx = ((ENVIRONMENT_BASE >> 39) & 0x1FF) as usize;
            *pml4.add(pml4_idx) = pdp as u64 | PRESENT | WRITABLE;

            let pd = alloc_frame()? as *mut u64;
            let pdp_idx = ((ENVIRONMENT_BASE >> 30) & 0x1FF) as usize;
            *pdp.add(pdp_idx) = pd as u64 | PRESENT | WRITABLE;

            let pages = (_env_size + PAGE_SIZE - 1) / PAGE_SIZE;
            let mut pt_idx: usize = 0;

            for page in 0..pages {
                if pt_idx >= 512 {
                    break;
                }
                let pt = alloc_frame()? as *mut u64;
                let pt_phys = _env_phys + page * PAGE_SIZE;
                *pt.add(0) = pt_phys | PRESENT | WRITABLE;
                let pd_idx = ((ENVIRONMENT_BASE >> 21) & 0x1FF) as usize;
                *pd.add(pd_idx) = pt as u64 | PRESENT | WRITABLE;
                pt_idx += 1;
            }
        }
    }

    Ok(pml4 as u64)
}

/// Enter with validated CPU features and a mapped EFI image. There are no stack
/// accesses or calls after CR3 changes; the last jump enters the kernel stub.
#[inline(never)]
pub unsafe fn context_switch(pml4_phys: u64, stack_top: u64, entry: u64, args: u64) -> ! {
    unsafe {
        core::arch::asm!(
            "cli",
            "cld",
            // Force each input into a distinct register that does NOT overlap
            // with our destination scratch registers (rbx, r8, r9, r10).
            // Using in("reg") ties the operand to a specific register; the
            // asm body must reference that register directly, not via {name}.
            "mov rbx, rax",
            "mov r8,  rdx",
            "mov r9,  rcx",
            "mov r10, rsi",
            "xor rbp, rbp",
            // Clear EM/TS, set MP/NE/WP; paging and protected mode stay enabled.
            "mov rax, cr0",
            "and rax, -13",
            "or rax, 0x10022",
            "mov cr0, rax",
            // Select PCID zero before disabling PCIDE, and invalidate inherited
            // global translations by clearing PGE. LA57/CET were rejected earlier.
            "mov rax, cr4",
            "bt rax, 17",
            "jnc 2f",
            "mov rdx, cr3",
            "and rdx, -4096",
            "mov cr3, rdx",
            "2:",
            "and rax, -131201", // ~(PCIDE | PGE)
            "or rax, 0x600", // OSFXSR | OSXMMEXCPT
            "mov cr4, rax",
            // Enable IA32_EFER.NXE (bit 11) so NX page bits are enforced.
            "mov ecx, 0xC0000080",          // IA32_EFER
            "rdmsr",
            "or eax, 1 << 11",              // NXE (LME already set: we run in long mode)
            "wrmsr",
            // S1: program IA32_PAT entry 4 to Write-Combining (0x01).
            // Default PAT = 0x0007040600070406 (entry4 = WB); entry 4 spans
            // bits 35:32, i.e. the low nibble of EDX. Only PTEs carrying the
            // PAT bit (framebuffer mapping) use this entry.
            "mov ecx, 0x277",               // IA32_PAT
            "rdmsr",
            "and edx, 0xFFFFFFF0",
            "or edx, 0x00000001",
            "wrmsr",
            // Now use the scratch registers (safe from rdmsr/wrmsr clobbers).
            "mov rsp, r8",
            "and rsp, -16",
            "mov rdi, r10",
            "mov cr3, rbx",
            "jmp r9",
            in("rax") pml4_phys,
            in("rdx") stack_top,
            in("rcx") entry,
            in("rsi") args,
            options(noreturn)
        );
    }
}
