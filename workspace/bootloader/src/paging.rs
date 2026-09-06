pub const FRAMEBUFFER_BASE: u64 = 0xFFFF_DEAD_0000_0000;
pub const ENVIRONMENT_BASE: u64 = 0xFFFF_BEEF_0000_0000;

const PAGE_SIZE: u64 = 0x1000;
const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;

/// Higher-half direct map of physical RAM (HHDM). Must match the value
/// passed to the kernel in `KernelArgs::hhdm_offset` — the kernel does
/// phys_to_virt(phys) = phys + hhdm_offset for ALL physical memory access.
///
/// PML4[510] window (0xFFFFFF0000000000..0xFFFFFF7FFFFFFFFF, 512 GB):
/// distinct from PML4[511] (kernel image slot), PML4[445] (framebuffer)
/// and PML4[381] (environment). The kernel image lives at
/// 0xFFFFFFFF80000000 = PML4[511].PDP[510] — using 0xFFFFFFFF80000000 as
/// the HHDM offset would collide with the kernel-image mapping.
pub const HHDM_OFFSET: u64 = 0xFFFF_FF00_0000_0000;
/// Upper bound of RAM covered by the HHDM (and identity) map.
const HHDM_COVER_GB: u64 = 8;
/// 2 MiB huge-page size used for the HHDM map.
const HUGE_PAGE: u64 = 0x20_0000;

pub const PHYS_OFFSET: u64 = 0;

/// Bump allocator for page table frames
static mut NEXT_FRAME: u64 = 0;
/// Start of the page-table area (set by `create_page_tables`), for map reservation.
static mut PT_AREA_START: u64 = 0;
/// End of the page-table area (last allocated frame + 1 page).
static mut PT_AREA_END: u64 = 0;

/// Physical range [start, end) occupied by the bootloader's page tables,
/// for the memory-map reservation in `efi_main`.
pub unsafe fn page_table_area() -> (u64, u64) {
    (
        core::ptr::addr_of!(PT_AREA_START).read(),
        core::ptr::addr_of!(PT_AREA_END).read(),
    )
}

unsafe fn alloc_frame() -> u64 {
    let addr = unsafe { NEXT_FRAME };
    if unsafe { PT_AREA_START } == 0 {
        unsafe { PT_AREA_START = addr };
    }
    unsafe {
        NEXT_FRAME += PAGE_SIZE;
        PT_AREA_END = NEXT_FRAME;
    }
    unsafe {
        core::ptr::write_bytes(addr as *mut u8, 0, PAGE_SIZE as usize);
    }
    addr
}

pub unsafe fn create_page_tables(
    kernel_phys: u64,
    kernel_phys_end: u64,
    kernel_size: u64,
    _framebuffer_phys: u64,
    _framebuffer_size: u64,
    _env_phys: u64,
    _env_size: u64,
) -> u64 {
    // Start allocator after kernel + large safety margin
    // Need ~8 page tables per 2MB of kernel, kernel is ~13MB = ~52 page tables = ~208KB
    unsafe {
        NEXT_FRAME = (kernel_phys_end + 0x40_0000) & !0xFFF;
    } // +4MB margin

    let pml4 = alloc_frame() as *mut u64;

    // Identity map: 0..8GB using 1GB huge pages
    unsafe {
        let pdp = alloc_frame() as *mut u64;
        *pml4.add(0) = pdp as u64 | PRESENT | WRITABLE;

        // 1 GiB huge pages: the PDPE PS bit (bit 7) MUST be set or the entry
        // is treated as a page-directory pointer and the walk faults.
        // Note: bit 7 also selects PAT entry 4 (programmed to WC by
        // context_switch); that is harmless here — only the framebuffer
        // mapping uses WC in practice, and this matches the original
        // graphics-branch design.
        for i in 0..8u64 {
            *pdp.add(i as usize) = (i * 0x4000_0000) | PRESENT | WRITABLE | (1 << 7);
        }

        // HHDM: same physical RAM mapped at HHDM_OFFSET (PML4[256]).
        // The kernel computes every physical-memory access as phys +
        // hhdm_offset, so ALL RAM must be reachable through this window —
        // not just the kernel image. 2 MiB huge pages (PS bit on PDE).
        let hhdm_pml4_idx = ((HHDM_OFFSET >> 39) & 0x1FF) as usize; // 256
        let hhdm_pdp = alloc_frame() as *mut u64;
        *pml4.add(hhdm_pml4_idx) = hhdm_pdp as u64 | PRESENT | WRITABLE;

        let mut huge_idx: usize = 0;
        'hhdm: for gb in 0..HHDM_COVER_GB {
            let pd = alloc_frame() as *mut u64;
            *hhdm_pdp.add(gb as usize) = pd as u64 | PRESENT | WRITABLE;
            for i in 0..512u64 {
                if huge_idx >= (HHDM_COVER_GB * 512) as usize {
                    break 'hhdm;
                }
                let phys = (gb * 0x4000_0000) + i * HUGE_PAGE;
                // NOTE: PS bit (1<<7) selects a 2MiB page AND PAT entry 4.
                // context_switch reprograms PAT entry 4 to Write-Combining
                // for the framebuffer — HHDM pages must stay WB, so the PAT
                // bit must be cleared here despite the huge page. On PDEs,
                // PS(bit7)=1 alone makes it a huge page; the PAT bit lives
                // in bit 12 (PCD position) for PDE entries. Bit 7 = PS only.
                *pd.add(i as usize) = phys | PRESENT | WRITABLE | (1 << 7);
                huge_idx += 1;
            }
        }
    }

    // Higher-half kernel: PML4[511] => PDP[510] => PD => PT (4KB pages)
    unsafe {
        let pdp = alloc_frame() as *mut u64;
        *pml4.add(511) = pdp as u64 | PRESENT | WRITABLE;

        let pd = alloc_frame() as *mut u64;
        *pdp.add(510) = pd as u64 | PRESENT | WRITABLE;

        let pages_needed = ((kernel_size + PAGE_SIZE - 1) / PAGE_SIZE) as usize;
        let mut phys = kernel_phys;

        for pt_idx in 0..(pages_needed + 511) / 512 {
            let pt = alloc_frame() as *mut u64;

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
            let pdp = alloc_frame() as *mut u64;
            let pml4_idx = ((FRAMEBUFFER_BASE >> 39) & 0x1FF) as usize;
            *pml4.add(pml4_idx) = pdp as u64 | PRESENT | WRITABLE;

            let pd = alloc_frame() as *mut u64;
            let pdp_idx = ((FRAMEBUFFER_BASE >> 30) & 0x1FF) as usize;
            *pdp.add(pdp_idx) = pd as u64 | PRESENT | WRITABLE;

            let mut mapped: u64 = 0;
            let mut pd_idx: usize = 0;
            let pages = (_framebuffer_size + PAGE_SIZE - 1) / PAGE_SIZE;

            for _page in 0..pages {
                if pd_idx >= 512 {
                    break;
                }
                let pt = alloc_frame() as *mut u64;
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
            let pdp = alloc_frame() as *mut u64;
            let pml4_idx = ((ENVIRONMENT_BASE >> 39) & 0x1FF) as usize;
            *pml4.add(pml4_idx) = pdp as u64 | PRESENT | WRITABLE;

            let pd = alloc_frame() as *mut u64;
            let pdp_idx = ((ENVIRONMENT_BASE >> 30) & 0x1FF) as usize;
            *pdp.add(pdp_idx) = pd as u64 | PRESENT | WRITABLE;

            let pages = (_env_size + PAGE_SIZE - 1) / PAGE_SIZE;
            let mut pt_idx: usize = 0;

            for page in 0..pages {
                if pt_idx >= 512 {
                    break;
                }
                let pt = alloc_frame() as *mut u64;
                let pt_phys = _env_phys + page * PAGE_SIZE;
                *pt.add(0) = pt_phys | PRESENT | WRITABLE;
                let pd_idx = ((ENVIRONMENT_BASE >> 21) & 0x1FF) as usize;
                *pd.add(pd_idx) = pt as u64 | PRESENT | WRITABLE;
                pt_idx += 1;
            }
        }
    }

    pml4 as u64
}

pub unsafe fn context_switch(pml4_phys: u64, stack_top: u64, entry: u64, args: u64) -> ! {
    unsafe {
        core::arch::asm!(
            // Force each input into a distinct register that does NOT overlap
            // with our destination scratch registers (rbx, r8, r9, r10).
            // Using in("reg") ties the operand to a specific register; the
            // asm body must reference that register directly, not via {name}.
            "mov rbx, rax",
            "mov r8,  rdx",
            "mov r9,  rcx",
            "mov r10, rsi",
            "xor rbp, rbp",
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
            "mov cr3, rbx",
            "mov rsp, r8",
            "and rsp, -16",
            "mov rdi, r10",
            "jmp r9",
            in("rax") pml4_phys,
            in("rdx") stack_top,
            in("rcx") entry,
            in("rsi") args,
            options(noreturn)
        );
    }
}
