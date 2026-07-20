//! Page table setup for the kernel.
//!
//! Creates page tables with:
//! - Identity mapping (first 4GB, 2MB pages)
//! - Higher-half kernel at 0xFFFFFFFF80000000
//! - Framebuffer at 0xFFFF_DEAD_0000_0000 (BOOTBOOT-inspired fixed address)
//!
//! Virtual memory layout:
//!   0xFFFF_DEAD_0000_0000  → Framebuffer (DEAD)
//!   0xFFFF_BEEF_0000_0000  → Environment string (BEEF)
//!   0xFFFFFFFF_8000_0000  → Kernel code/data
//!   0x0000_0000_0000_0000  → Identity map (first 4GB)

use x86_64::structures::paging::*;
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::PhysAddr;

/// Fixed virtual addresses (BOOTBOOT-inspired)
///
/// The framebuffer is mapped here so the kernel can access it
/// without knowing the physical address. Like BOOTBOOT's 0xFFFFFFFFFC000000.
pub const FRAMEBUFFER_BASE: u64 = 0xFFFF_DEAD_0000_0000;

/// Environment string (key=value config) mapped here.
pub const ENVIRONMENT_BASE: u64 = 0xFFFF_BEEF_0000_0000;

/// Page size constants
const PAGE_SIZE: u64 = 0x1000; // 4KB
const LARGE_PAGE_SIZE: u64 = 0x200_000; // 2MB

/// Physical memory offset (0 for UEFI since it identity-maps)
pub const PHYS_OFFSET: u64 = 0;

/// A simple bump allocator for physical frames during boot.
struct BootFrameAllocator {
    next: u64,
}

impl BootFrameAllocator {
    const fn new(start: u64) -> Self {
        Self { next: start }
    }

    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let addr = self.next;
        self.next += PAGE_SIZE;
        Some(PhysFrame::containing_address(PhysAddr::new(addr)))
    }
}

static mut BOOT_ALLOCATOR: BootFrameAllocator = BootFrameAllocator::new(0);

/// # Safety
/// The start address must point to valid, unused physical memory.
pub unsafe fn init_allocator(start: u64) {
    unsafe {
        BOOT_ALLOCATOR = BootFrameAllocator::new(start);
    }
}

fn alloc_frame() -> PhysFrame {
    unsafe { BOOT_ALLOCATOR.allocate_frame().expect("Out of boot memory") }
}

/// Create page tables for the kernel.
///
/// # Safety
/// Must be called after ExitBootServices with valid kernel physical addresses.
pub unsafe fn create_page_tables(
    kernel_phys: u64,
    kernel_size: u64,
    framebuffer_phys: u64,
    framebuffer_size: u64,
) -> u64 {
    // Start allocating frames after 2MB (safe area)
    init_allocator(0x200_000);

    // Allocate PML4
    let pml4_frame = alloc_frame();
    let pml4 = frame_to_mut(pml4_frame);

    // Zero out PML4
    for entry in pml4.iter_mut() {
        *entry = PageTableEntry::new();
    }

    // ========================================================================
    // Identity map: first 4GB using 2MB large pages
    // PML4[0] → PDP → 8 PDs (each with 512 x 2MB pages)
    // ========================================================================
    {
        let pdp_frame = alloc_frame();
        let pdp = frame_to_mut(pdp_frame);
        for entry in pdp.iter_mut() {
            *entry = PageTableEntry::new();
        }

        pml4[0].set_addr(pdp_frame.start_address(), PageTableFlags::PRESENT | PageTableFlags::WRITABLE);

        // Create 8 PDs (8 * 512 * 2MB = 8GB)
        for pdp_idx in 0..8u64 {
            let pd_frame = alloc_frame();
            let pd = frame_to_mut(pd_frame);

            for pd_idx_inner in 0..512u64 {
                let phys = pdp_idx * 0x4000_0000 + pd_idx_inner * LARGE_PAGE_SIZE;
                pd[pd_idx_inner as usize].set_addr(
                    PhysAddr::new(phys),
                    PageTableFlags::PRESENT
                        | PageTableFlags::WRITABLE
                        | PageTableFlags::HUGE_PAGE,
                );
            }

            pdp[pdp_idx as usize].set_addr(
                pd_frame.start_address(),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            );
        }
    }

    // ========================================================================
    // Higher-half: PML4[511] → PDP → PD/PT
    // ========================================================================
    {
        let pdp_frame = alloc_frame();
        let pdp = frame_to_mut(pdp_frame);
        for entry in pdp.iter_mut() {
            *entry = PageTableEntry::new();
        }

        pml4[511].set_addr(
            pdp_frame.start_address(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );

        // --- Kernel: PDP[510] → at 0xFFFFFFFF_80000000 ---
        {
            let pd_frame = alloc_frame();
            let pd = frame_to_mut(pd_frame);

            let mut phys = kernel_phys;

            for pd_idx in 0..512u64 {
                let pt_frame = alloc_frame();
                let pt = frame_to_mut(pt_frame);

                for pt_idx in 0..512u64 {
                    if phys >= kernel_phys + kernel_size {
                        // Past kernel, identity map the rest in this 1GB region
                        let page_phys = pd_idx * LARGE_PAGE_SIZE + pt_idx * PAGE_SIZE;
                        pt[pt_idx as usize].set_addr(
                            PhysAddr::new(page_phys),
                            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                        );
                    } else {
                        pt[pt_idx as usize].set_addr(
                            PhysAddr::new(phys),
                            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                        );
                        phys += PAGE_SIZE;
                    }
                }

                pd[pd_idx as usize].set_addr(
                    pt_frame.start_address(),
                    PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                );
            }

            pdp[510].set_addr(
                pd_frame.start_address(),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            );
        }

        // --- Framebuffer: PDP[0xDEAD_0000_0000 >> 30 & 511] ---
        // 0xFFFF_DEAD_0000_0000: PML4[511], PDP[0x1AD = 429]
        if framebuffer_phys != 0 && framebuffer_size > 0 {
            let pdp_idx = ((FRAMEBUFFER_BASE >> 30) & 0x1FF) as usize;

            let pd_frame = alloc_frame();
            let pd = frame_to_mut(pd_frame);

            // Map framebuffer using 2MB large pages (sufficient for FB)
            let mut mapped: u64 = 0;
            let mut pd_idx_inner: usize = 0;

            while mapped < framebuffer_size && pd_idx_inner < 512 {
                let page_phys = framebuffer_phys + mapped;
                // Only works if framebuffer is 2MB aligned; if not, we'd need 4KB pages
                // For simplicity, assume 2MB alignment (typical for GOP)
                if page_phys % LARGE_PAGE_SIZE == 0 {
                    pd[pd_idx_inner].set_addr(
                        PhysAddr::new(page_phys),
                        PageTableFlags::PRESENT
                            | PageTableFlags::WRITABLE
                            | PageTableFlags::HUGE_PAGE,
                    );
                    mapped += LARGE_PAGE_SIZE;
                } else {
                    // Fallback: use 4KB pages for this 2MB region
                    let pt_frame = alloc_frame();
                    let pt = frame_to_mut(pt_frame);

                    let mut pt_phys = page_phys;
                    for pt_idx in 0..512u64 {
                        if mapped >= framebuffer_size {
                            pt[pt_idx as usize].set_addr(
                                PhysAddr::new(pt_phys),
                                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                            );
                        } else {
                            pt[pt_idx as usize].set_addr(
                                PhysAddr::new(pt_phys),
                                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                            );
                            pt_phys += PAGE_SIZE;
                            mapped += PAGE_SIZE;
                        }
                    }

                    pd[pd_idx_inner].set_addr(
                        pt_frame.start_address(),
                        PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                    );
                }
                pd_idx_inner += 1;
            }

            pdp[pdp_idx].set_addr(
                pd_frame.start_address(),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            );
        }

        // --- Environment: PDP[0xBEEF_0000_0000 >> 30 & 511] ---
        // 0xFFFF_BEEF_0000_0000: PML4[511], PDP[0x1AF = 431]
        {
            // We'll map a single 4KB page for the environment string
            let pdp_idx = ((ENVIRONMENT_BASE >> 30) & 0x1FF) as usize;

            // Need PD → PT for a single page
            let pd_frame = alloc_frame();
            let pd = frame_to_mut(pd_frame);

            let pt_frame = alloc_frame();
            let pt = frame_to_mut(pt_frame);

            // The actual content will be written by main.rs after ExitBootServices
            // For now, we just need the page table structure in place
            // Map to physical address 0 (will be fixed up later)
            pt[0].set_addr(
                PhysAddr::new(0), // placeholder, will be remapped
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            );

            let pd_idx = ((ENVIRONMENT_BASE >> 21) & 0x1FF) as usize;
            pd[pd_idx].set_addr(
                pt_frame.start_address(),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            );

            pdp[pdp_idx].set_addr(
                pd_frame.start_address(),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            );
        }
    }

    pml4_frame.start_address().as_u64()
}

/// Context switch to the kernel.
///
/// # Safety
/// All arguments must be valid.
pub unsafe fn context_switch(
    pml4_phys: u64,
    stack_top: u64,
    entry: u64,
    args: u64,
) -> ! {
    unsafe {
        core::arch::asm!(
            "xor rbp, rbp",
            "mov cr3, {pml4}",
            "mov rsp, {stack}",
            "push 0",
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

/// # Safety
/// The frame must be allocated and not aliased.
unsafe fn frame_to_mut(frame: PhysFrame) -> &'static mut PageTable {
    unsafe {
        let virt = frame.start_address().as_u64() + PHYS_OFFSET;
        &mut *(virt as *mut PageTable)
    }
}
