use x86_64::{
    structures::paging::{page_table::PageTableEntry, *},
    PhysAddr,
};

pub const FRAMEBUFFER_BASE: u64 = 0xFFFF_DEAD_0000_0000;
pub const ENVIRONMENT_BASE: u64 = 0xFFFF_BEEF_0000_0000;

const PAGE_SIZE: u64 = 0x1000;

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

unsafe fn frame_to_mut(frame: PhysFrame) -> &'static mut PageTable {
    unsafe {
        let virt = frame.start_address().as_u64() + PHYS_OFFSET;
        &mut *(virt as *mut PageTable)
    }
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
    let alloc_start = (kernel_phys_end + 0x10_0000) & !0xFFF;
    init_allocator(alloc_start);

    let pml4_frame = alloc_frame();
    let pml4 = frame_to_mut(pml4_frame);

    // Identity map: 0..8GB using 2MB huge pages
    let pdp_frame = alloc_frame();
    let pdp = frame_to_mut(pdp_frame);
    pml4[0].set_addr(
        pdp_frame.start_address(),
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
    );
    for i in 0..8u64 {
        pdp[i as usize].set_addr(
            PhysAddr::new(i * 0x4000_0000),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::HUGE_PAGE,
        );
    }

    // Higher-half kernel: PML4[511] => PDP[510] => PD => PT
    {
        let pdp_frame = alloc_frame();
        let pdp = frame_to_mut(pdp_frame);
        pml4[511].set_addr(
            pdp_frame.start_address(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );

        let pd_frame = alloc_frame();
        let pd = frame_to_mut(pd_frame);
        pdp[510].set_addr(
            pd_frame.start_address(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );

        let pages_needed = ((kernel_size + PAGE_SIZE - 1) / PAGE_SIZE) as usize;
        let mut phys = kernel_phys;

        for pt_idx in 0..(pages_needed + 511) / 512 {
            let pt_frame = alloc_frame();
            let pt = frame_to_mut(pt_frame);

            for entry in 0..512usize {
                let page_num = pt_idx * 512 + entry;
                if page_num >= pages_needed {
                    break;
                }
                pt[entry].set_addr(
                    PhysAddr::new(phys),
                    PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                );
                phys += PAGE_SIZE;
            }

            pd[pt_idx].set_addr(
                pt_frame.start_address(),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            );
        }
    }

    pml4_frame.start_address().as_u64()
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
