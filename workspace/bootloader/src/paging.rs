pub const FRAMEBUFFER_BASE: u64 = 0xFFFF_DEAD_0000_0000;
pub const ENVIRONMENT_BASE: u64 = 0xFFFF_BEEF_0000_0000;

const PAGE_SIZE: u64 = 0x1000;
const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;

pub const PHYS_OFFSET: u64 = 0;

/// Bump allocator for page table frames
static mut NEXT_FRAME: u64 = 0;

unsafe fn alloc_frame() -> u64 {
    let addr = unsafe { NEXT_FRAME };
    unsafe {
        NEXT_FRAME += PAGE_SIZE;
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

        // S1: identity map keeps WB — the PTE PAT bit is reserved for the
        // framebuffer mapping (PAT entry 4 = Write-Combining).
        for i in 0..8u64 {
            *pdp.add(i as usize) = (i * 0x4000_0000) | PRESENT | WRITABLE;
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
            "mov cr3, {pml4}",
            "mov rsp, {stack}",
            "and rsp, -16",
            "mov rdi, {args}",
            "jmp {entry}",
            pml4 = in(reg) pml4_phys,
            stack = in(reg) stack_top,
            entry = in(reg) entry,
            args = in(reg) args,
            options(noreturn)
        );
    }
}
