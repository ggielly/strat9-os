use x86_64::structures::paging::*;
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::PhysAddr;

pub const FRAMEBUFFER_BASE: u64 = 0xFFFF_DEAD_0000_0000;
pub const ENVIRONMENT_BASE: u64 = 0xFFFF_BEEF_0000_0000;

const PAGE_SIZE: u64 = 0x1000;
const LARGE_PAGE_SIZE: u64 = 0x200_000;

pub const PHYS_OFFSET: u64 = 0;

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

unsafe fn init_allocator(start: u64) {
    BOOT_ALLOCATOR = BootFrameAllocator::new(start);
}

fn alloc_frame() -> PhysFrame {
    unsafe { BOOT_ALLOCATOR.allocate_frame().expect("Out of boot memory") }
}

fn alloc_zeroed_frame() -> (PhysFrame, &'static mut PageTable) {
    let frame = alloc_frame();
    let table = unsafe { frame_to_mut(frame) };
    for entry in table.iter_mut() {
        *entry = PageTableEntry::new();
    }
    (frame, table)
}

pub unsafe fn create_page_tables(
    kernel_phys: u64,
    kernel_phys_end: u64,
    kernel_size: u64,
    framebuffer_phys: u64,
    framebuffer_size: u64,
    env_phys: u64,
    env_size: u64,
) -> u64 {
    let alloc_start = (kernel_phys_end + 0xFFF) & !0xFFF;
    init_allocator(alloc_start);

    let (pml4_frame, pml4) = alloc_zeroed_frame();

    // Identity map: PML4[0..8] → 8× 1GB windows via 2MB large pages
    for pdp_idx in 0..8u64 {
        let (pdp_frame, pdp) = alloc_zeroed_frame();
        pml4[pdp_idx as usize].set_addr(
            pdp_frame.start_address(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );

        for pd_idx_inner in 0..512u64 {
            let phys = pdp_idx * 0x4000_0000 + pd_idx_inner * LARGE_PAGE_SIZE;
            pdp[pd_idx_inner as usize].set_addr(
                PhysAddr::new(phys),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE
                    | PageTableFlags::HUGE_PAGE | PageTableFlags::NO_EXECUTE,
            );
        }
    }

    // Higher-half kernel: PML4[511] → PDP[510]
    {
        let (pdp_frame, pdp) = alloc_zeroed_frame();
        pml4[511].set_addr(
            pdp_frame.start_address(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );

        let kernel_large_pages = ((kernel_size + LARGE_PAGE_SIZE - 1) / LARGE_PAGE_SIZE).max(1);
        let (pd_frame, pd) = alloc_zeroed_frame();

        for pd_idx_inner in 0..kernel_large_pages {
            let (pt_frame, pt) = alloc_zeroed_frame();

            for pt_idx in 0..512u64 {
                let offset = pd_idx_inner * 512 * PAGE_SIZE + pt_idx * PAGE_SIZE;
                if offset >= kernel_size {
                    break;
                }
                let phys = kernel_phys + offset;
                pt[pt_idx as usize].set_addr(
                    PhysAddr::new(phys),
                    PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                );
            }

            pd[pd_idx_inner as usize].set_addr(
                pt_frame.start_address(),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            );
        }

        pdp[510].set_addr(
            pd_frame.start_address(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );
    }

    // Framebuffer: PML4[445] → PDP[180]
    if framebuffer_phys != 0 && framebuffer_size > 0 {
        let (fb_pdp_frame, fb_pdp) = alloc_zeroed_frame();
        pml4[445].set_addr(
            fb_pdp_frame.start_address(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );

        let (pd_frame, pd) = alloc_zeroed_frame();

        let mut mapped: u64 = 0;
        let mut pd_idx_inner: usize = 0;

        while mapped < framebuffer_size && pd_idx_inner < 512 {
            let page_phys = framebuffer_phys + mapped;

            if page_phys % LARGE_PAGE_SIZE == 0 {
                pd[pd_idx_inner].set_addr(
                    PhysAddr::new(page_phys),
                    PageTableFlags::PRESENT | PageTableFlags::WRITABLE
                        | PageTableFlags::HUGE_PAGE | PageTableFlags::NO_EXECUTE
                        | PageTableFlags::WRITE_THROUGH,
                );
                mapped += LARGE_PAGE_SIZE;
            } else {
                let (pt_frame, pt) = alloc_zeroed_frame();

                let mut pt_phys = page_phys;
                let mut pt_mapped: u64 = 0;

                for pt_idx in 0..512u64 {
                    if mapped + pt_mapped >= framebuffer_size {
                        break;
                    }
                    pt[pt_idx as usize].set_addr(
                        PhysAddr::new(pt_phys),
                        PageTableFlags::PRESENT | PageTableFlags::WRITABLE
                            | PageTableFlags::NO_EXECUTE | PageTableFlags::WRITE_THROUGH,
                    );
                    pt_phys += PAGE_SIZE;
                    pt_mapped += PAGE_SIZE;
                }

                mapped += pt_mapped;

                pd[pd_idx_inner].set_addr(
                    pt_frame.start_address(),
                    PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                );
            }
            pd_idx_inner += 1;
        }

        fb_pdp[180].set_addr(
            pd_frame.start_address(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );
    }

    // Environment: PML4[381] → PDP[444]
    if env_phys != 0 && env_size > 0 {
        let (env_pdp_frame, env_pdp) = alloc_zeroed_frame();
        pml4[381].set_addr(
            env_pdp_frame.start_address(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );

        let (pd_frame, pd) = alloc_zeroed_frame();

        let mut mapped: u64 = 0;
        let mut pd_idx_inner: usize = 0;

        while mapped < env_size && pd_idx_inner < 512 {
            let (pt_frame, pt) = alloc_zeroed_frame();

            let mut pt_phys = env_phys + mapped;
            let mut pt_mapped: u64 = 0;

            for pt_idx in 0..512u64 {
                if mapped + pt_mapped >= env_size {
                    break;
                }
                pt[pt_idx as usize].set_addr(
                    PhysAddr::new(pt_phys),
                    PageTableFlags::PRESENT | PageTableFlags::WRITABLE
                        | PageTableFlags::NO_EXECUTE,
                );
                pt_phys += PAGE_SIZE;
                pt_mapped += PAGE_SIZE;
            }

            mapped += pt_mapped;

            pd[pd_idx_inner].set_addr(
                pt_frame.start_address(),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            );
            pd_idx_inner += 1;
        }

        env_pdp[444].set_addr(
            pd_frame.start_address(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );
    }

    pml4_frame.start_address().as_u64()
}

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

unsafe fn frame_to_mut(frame: PhysFrame) -> &'static mut PageTable {
    unsafe {
        let virt = frame.start_address().as_u64() + PHYS_OFFSET;
        &mut *(virt as *mut PageTable)
    }
}
