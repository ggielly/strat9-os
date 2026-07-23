pub const FRAMEBUFFER_BASE: u64 = 0xFFFF_DEAD_0000_0000;
pub const ENVIRONMENT_BASE: u64 = 0xFFFF_BEEF_0000_0000;

const PAGE_SIZE: u64 = 0x1000;
const PAGE_SIZE_2M: u64 = 0x200_000;
const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const PAGE_SIZE_BIT: u64 = 1 << 7;  // PS bit: 2MB large page in PD entry
const NO_EXECUTE: u64 = 1 << 63;

pub const PHYS_OFFSET: u64 = 0;

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
    unsafe {
        NEXT_FRAME = (kernel_phys_end + 0x10_0000) & !0xFFF;
    }

    let pml4 = alloc_frame() as *mut u64;

    // Identity map: 0..8GB using 1GB huge pages (WRITABLE, not EXECUTABLE)
    unsafe {
        let pdp = alloc_frame() as *mut u64;
        *pml4.add(0) = pdp as u64 | PRESENT | WRITABLE | NO_EXECUTE;

        for i in 0..8u64 {
            *pdp.add(i as usize) = (i * 0x4000_0000) | PRESENT | WRITABLE | (1 << 7) | NO_EXECUTE;
        }
    }

    // Higher-half kernel: PML4[511] => PDP[510] => PD => PT
    // Kernel pages are EXECUTABLE but not WRITABLE (W^X)
    unsafe {
        let pdp = alloc_frame() as *mut u64;
        *pml4.add(511) = pdp as u64 | PRESENT | WRITABLE;

        let pd = alloc_frame() as *mut u64;
        *pdp.add(510) = pd as u64 | PRESENT | WRITABLE;

        let total_pages = ((kernel_size + 0x100_0000) / PAGE_SIZE) as usize;
        let mut phys = kernel_phys;

        for pt_idx in 0..(total_pages + 511) / 512 {
            let pt = alloc_frame() as *mut u64;

            for entry in 0..512usize {
                let page_num = pt_idx * 512 + entry;
                if page_num >= total_pages {
                    break;
                }
                let target_phys = phys;
                // EXECUTABLE (no NX), not WRITABLE (W^X)
                *pt.add(entry) = target_phys | PRESENT;
                phys += PAGE_SIZE;
            }

            *pd.add(pt_idx) = pt as u64 | PRESENT | WRITABLE;
        }
    }

    // Framebuffer (WRITABLE, not EXECUTABLE) using 2MB large pages
    // This wastes zero page table memory — each PD entry maps 2MB directly.
    // A 8MB framebuffer needs only 4 PD entries instead of 4 PTs (16KB).
    if _framebuffer_phys != 0 && _framebuffer_size > 0 {
        unsafe {
            let pdp = alloc_frame() as *mut u64;
            let pml4_idx = ((FRAMEBUFFER_BASE >> 39) & 0x1FF) as usize;
            *pml4.add(pml4_idx) = pdp as u64 | PRESENT | WRITABLE | NO_EXECUTE;

            let pd = alloc_frame() as *mut u64;
            let pdp_idx = ((FRAMEBUFFER_BASE >> 30) & 0x1FF) as usize;
            *pdp.add(pdp_idx) = pd as u64 | PRESENT | WRITABLE | NO_EXECUTE;

            let pages_2m = (_framebuffer_size + PAGE_SIZE_2M - 1) / PAGE_SIZE_2M;
            let mut phys = _framebuffer_phys & !(PAGE_SIZE_2M - 1);  // Round down to 2MB
            let mut virt = FRAMEBUFFER_BASE & !(PAGE_SIZE_2M - 1);  // Round down to 2MB

            for _ in 0..pages_2m {
                let pd_idx = ((virt >> 21) & 0x1FF) as usize;
                *pd.add(pd_idx) = phys | PRESENT | WRITABLE | NO_EXECUTE | PAGE_SIZE_BIT;
                phys += PAGE_SIZE_2M;
                virt += PAGE_SIZE_2M;
            }
        }
    }

    // Environment (WRITABLE, not EXECUTABLE)
    if _env_phys != 0 && _env_size > 0 {
        unsafe {
            let pdp = alloc_frame() as *mut u64;
            let pml4_idx = ((ENVIRONMENT_BASE >> 39) & 0x1FF) as usize;
            *pml4.add(pml4_idx) = pdp as u64 | PRESENT | WRITABLE | NO_EXECUTE;

            let pd = alloc_frame() as *mut u64;
            let pdp_idx = ((ENVIRONMENT_BASE >> 30) & 0x1FF) as usize;
            *pdp.add(pdp_idx) = pd as u64 | PRESENT | WRITABLE | NO_EXECUTE;

            let pages = (_env_size + PAGE_SIZE - 1) / PAGE_SIZE;
            let mut current_pt: *mut u64 = core::ptr::null_mut();
            let mut pt_entry: usize = 0;

            for page in 0..pages {
                if pt_entry == 0 {
                    current_pt = alloc_frame() as *mut u64;
                    let virt_addr = ENVIRONMENT_BASE + page * PAGE_SIZE;
                    let pd_idx = ((virt_addr >> 21) & 0x1FF) as usize;
                    *pd.add(pd_idx) = current_pt as u64 | PRESENT | WRITABLE | NO_EXECUTE;
                }
                let pt_phys = _env_phys + page * PAGE_SIZE;
                *current_pt.add(pt_entry) = pt_phys | PRESENT | WRITABLE | NO_EXECUTE;
                pt_entry += 1;
                if pt_entry >= 512 {
                    pt_entry = 0;
                }
            }
        }
    }

    pml4 as u64
}

pub unsafe fn context_switch(pml4_phys: u64, stack_top: u64, entry: u64, args: u64) -> ! {
    unsafe {
        core::arch::asm!(
            "xor rbp, rbp",
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
