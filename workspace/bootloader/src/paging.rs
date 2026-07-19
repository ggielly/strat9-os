//! Page table setup for the kernel.
//!
//! Creates page tables with:
//! - Identity mapping (first 4GB, 2MB pages)
//! - Higher-half kernel at 0xFFFFFFFF80000000
//!
//! Following Phil Opp's approach: allocate physical frames, build PML4 → PDP → PD → PT.

use x86_64::structures::paging::*;
use x86_64::{PhysAddr, VirtAddr};

/// Higher-half kernel virtual base address (matches kernel linker script)
const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// Physical memory offset (HHDM) - disabled for UEFI (identity-mapped)
const HHDM_OFFSET: u64 = 0;

/// Page size constants
const PAGE_SIZE: u64 = 0x1000; // 4KB
const LARGE_PAGE_SIZE: u64 = 0x200_000; // 2MB

/// Direct mapping of physical memory into virtual space.
/// UEFI already identity-maps, so we keep the same layout.
pub const PHYS_OFFSET: u64 = HHDM_OFFSET;

/// A simple bump allocator for physical frames during boot.
/// This runs after ExitBootServices, so we use raw pointer arithmetic.
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

// Global allocator instance (used during boot only)
static mut BOOT_ALLOCATOR: BootFrameAllocator = BootFrameAllocator::new(0);

/// Initialize the boot frame allocator with a start address.
///
/// Must be called before any page table allocation.
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
///
/// # Layout
/// - Identity map: PML4[0] → first 4GB via 2MB pages
/// - Higher-half: PML4[511] → kernel at 0xFFFFFFFF80000000 via 4KB pages
pub unsafe fn create_page_tables(
    kernel_phys: u64,
    kernel_size: u64,
) -> u64 {
    // Start allocating frames after 2MB (safe area, avoids real mode IVT and our own code)
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
    // PML4[0] → PDP → 512 PD entries (each 2MB)
    // ========================================================================
    {
        let pdp_frame = alloc_frame();
        let pdp = frame_to_mut(pdp_frame);
        for entry in pdp.iter_mut() {
            *entry = PageTableEntry::new();
        }

        // Link PML4[0] to PDP
        pml4[0].set_addr(pdp_frame.start_address(), PageTableFlags::PRESENT | PageTableFlags::WRITABLE);

        // Create 8 PDs (8 * 512 * 2MB = 8GB, covers typical systems)
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
    // Higher-half kernel: PML4[511] → PDP → PD → PT
    // Maps kernel at virtual 0xFFFFFFFF80000000
    // ========================================================================
    {
        // PML4[511] maps to the last 512GB entry
        // The kernel is at -2GB, which is PML4[511], PDP[510]
        let pdp_frame = alloc_frame();
        let pdp = frame_to_mut(pdp_frame);
        for entry in pdp.iter_mut() {
            *entry = PageTableEntry::new();
        }

        // Link PML4[511] to PDP
        pml4[511].set_addr(
            pdp_frame.start_address(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );

        // PDP[510] covers virtual address range 0xFFFFFFFF_80000000..0xFFFFFFFF_C0000000 (1GB)
        let pd_frame = alloc_frame();
        let pd = frame_to_mut(pd_frame);

        // Map kernel using 4KB pages for precise control
        let pages_needed = (kernel_size + PAGE_SIZE - 1) / PAGE_SIZE;
        let mut phys = kernel_phys;

        for pd_idx in 0..512u64 {
            let pt_frame = alloc_frame();
            let pt = frame_to_mut(pt_frame);

            for pt_idx in 0..512u64 {
                if phys >= kernel_phys + kernel_size * PAGE_SIZE {
                    // Past kernel, identity map the rest
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

    pml4_frame.start_address().as_u64()
}

/// Context switch to the kernel.
///
/// Loads the new page table, sets up the stack, and jumps to the kernel entry point.
/// Follows Phil Opp's exact pattern.
///
/// # Safety
/// - `pml4_phys` must be a valid PML4 physical address
/// - `stack_top` must be a valid stack pointer
/// - `entry` must be a valid kernel entry point
/// - `args` must point to a valid KernelArgs structure
pub unsafe fn context_switch(
    pml4_phys: u64,
    stack_top: u64,
    entry: u64,
    args: u64,
) -> ! {
    unsafe {
        core::arch::asm!(
            "xor rbp, rbp",         // Clear frame pointer (for stack unwinding)
            "mov cr3, {pml4}",      // Load kernel page tables
            "mov rsp, {stack}",     // Set up kernel stack
            "push 0",               // Alignment dummy
            "mov rdi, {args}",      // First argument: KernelArgs pointer (System V ABI)
            "jmp {entry}",          // Jump to kernel entry point
            pml4 = in(reg) pml4_phys,
            stack = in(reg) stack_top,
            entry = in(reg) entry,
            args = in(reg) args,
            options(noreturn)
        );
    }
}

/// Convert a PhysFrame to a mutable page table reference.
///
/// # Safety
/// The frame must be allocated and not aliased.
unsafe fn frame_to_mut(frame: PhysFrame) -> &'static mut PageTable {
    unsafe {
        let virt = frame.start_address().as_u64() + PHYS_OFFSET;
        &mut *(virt as *mut PageTable)
    }
}
