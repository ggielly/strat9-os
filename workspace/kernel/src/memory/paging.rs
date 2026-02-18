//! Virtual Memory Management (Paging) for Strat9-OS
//!
//! Uses the `x86_64` crate's `OffsetPageTable` which is designed for the HHDM
//! (Higher Half Direct Map) pattern — exactly what Limine provides.
//!
//! Provides map/unmap/translate operations on the active page table.

use x86_64::{
    registers::control::Cr3,
    structures::paging::{
        FrameAllocator as X86FrameAllocator, Mapper, OffsetPageTable, Page, PageTable,
        PageTableFlags, PhysFrame as X86PhysFrame, Size4KiB, Translate,
    },
    PhysAddr, VirtAddr,
};

use crate::memory::FrameAllocator;

/// Wrapper around our buddy allocator implementing the x86_64 crate's FrameAllocator trait.
///
/// This is used by `OffsetPageTable` when it needs to allocate intermediate page tables.
pub struct BuddyFrameAllocator;

// SAFETY: allocate_frame returns valid, unused, 4KiB-aligned physical frames
// from the buddy allocator.
unsafe impl X86FrameAllocator<Size4KiB> for BuddyFrameAllocator {
    fn allocate_frame(&mut self) -> Option<X86PhysFrame<Size4KiB>> {
        let lock = crate::memory::get_allocator();
        let mut guard = lock.lock();
        let allocator = guard.as_mut()?;
        let frame = allocator.alloc_frame().ok()?;
        X86PhysFrame::from_start_address(frame.start_address).ok()
    }
}

/// The kernel page mapper using HHDM offset translation.
static mut MAPPER: Option<OffsetPageTable<'static>> = None;

/// Physical address of the kernel's level-4 page table (set at init, never changes).
static mut KERNEL_CR3: PhysAddr = PhysAddr::new_truncate(0);

/// Initialize the paging subsystem.
///
/// Reads the active CR3 (level-4 page table) and creates an `OffsetPageTable`
/// mapper using the HHDM offset for physical-to-virtual translation.
///
/// Must be called after the buddy allocator and HHDM offset are initialized.
pub fn init(hhdm_offset: u64) {
    let phys_offset = VirtAddr::new(hhdm_offset);
    let (level_4_frame, _flags) = Cr3::read();
    let level_4_phys = level_4_frame.start_address().as_u64();
    let level_4_virt = phys_offset + level_4_phys;
    let level_4_table_ptr = level_4_virt.as_mut_ptr::<PageTable>();

    // SAFETY: Called once during single-threaded init. The HHDM offset correctly
    // maps all physical RAM to virtual addresses. CR3 points to a valid page table
    // set up by Limine.
    unsafe {
        let kcr3 = &raw mut KERNEL_CR3;
        *kcr3 = level_4_frame.start_address();

        let mapper = &raw mut MAPPER;
        *mapper = Some(OffsetPageTable::new(&mut *level_4_table_ptr, phys_offset));
    }

    log::info!(
        "Paging initialized: CR3={:#x}, HHDM={:#x}, L4 table @ {:#x}",
        level_4_phys,
        hhdm_offset,
        level_4_virt.as_u64(),
    );
}

/// Map a virtual page to a physical frame with the given flags.
///
/// Intermediate page tables are allocated from the buddy allocator as needed.
pub fn map_page(
    page: Page<Size4KiB>,
    frame: X86PhysFrame<Size4KiB>,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    // SAFETY: We trust the caller to provide valid page/frame/flags.
    // The mapper and frame allocator are correctly initialized.
    let mapper = unsafe {
        (*(&raw mut MAPPER))
            .as_mut()
            .ok_or("Paging not initialized")?
    };
    let mut allocator = BuddyFrameAllocator;

    unsafe {
        mapper
            .map_to(page, frame, flags, &mut allocator)
            .map_err(|_| "Failed to map page")?
            .flush();
    }
    Ok(())
}

/// Unmap a virtual page, returning the physical frame it was mapped to.
pub fn unmap_page(page: Page<Size4KiB>) -> Result<X86PhysFrame<Size4KiB>, &'static str> {
    let mapper = unsafe {
        (*(&raw mut MAPPER))
            .as_mut()
            .ok_or("Paging not initialized")?
    };
    let (frame, flush) = mapper.unmap(page).map_err(|_| "Failed to unmap page")?;
    flush.flush();
    Ok(frame)
}

/// Translate a virtual address to its mapped physical address.
///
/// Returns `None` if the address is not mapped.
pub fn translate(addr: VirtAddr) -> Option<PhysAddr> {
    let mapper = unsafe { (*(&raw const MAPPER)).as_ref()? };
    mapper.translate_addr(addr)
}

/// Read the current CR3 value (physical address of the active level-4 page table).
pub fn active_page_table() -> PhysAddr {
    let (frame, _) = Cr3::read();
    frame.start_address()
}

/// Return the physical address of the kernel's level-4 page table.
///
/// This is the CR3 value captured at init time — used by `AddressSpace::new_user()`
/// to clone kernel mappings (PML4 entries 256..512) into new address spaces.
pub fn kernel_l4_phys() -> PhysAddr {
    // SAFETY: Written once during single-threaded init, read-only after that.
    unsafe { *(&raw const KERNEL_CR3) }
}

/// Ensure a physical address is identity-mapped in the HHDM region.
///
/// If the page is not present, it is mapped with Read/Write permissions.
/// This is used to lazily map MMIO or legacy BIOS regions (like ACPI tables)
/// that might have been skipped by the bootloader's initial map.
pub fn ensure_identity_map(phys_addr: u64) {
    let virt_addr = crate::memory::phys_to_virt(phys_addr);
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt_addr));
    let frame = X86PhysFrame::containing_address(PhysAddr::new(phys_addr));

    if translate(VirtAddr::new(virt_addr)).is_none() {
        log::debug!(
            "Identity mapping missing page: {:#x} -> {:#x}",
            phys_addr,
            virt_addr
        );
        // Map as Present | Writable (generic safe default for MMIO/BIOS)
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        if let Err(e) = map_page(page, frame, flags) {
            log::error!("Failed to identity map {:#x}: {}", phys_addr, e);
        }
    }
}
