//! Virtual Memory Management (Paging) for Strat9-OS
//!
//! Uses the `x86_64` crate's `OffsetPageTable` which is designed for the HHDM
//! (Higher Half Direct Map) pattern : exactly what Limine provides.
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

use crate::{
    memory::frame::{FrameAllocOptions, FramePurpose},
    sync::SpinLock,
};

/// Wrapper around the buddy allocator implementing the x86_64 crate's `FrameAllocator` trait.
///
/// Used by `OffsetPageTable` when it needs a new intermediate page-table node
/// (PML4 / PDPT / PD / PT).
///
/// # Safety invariant: page-table frames MUST be zeroed
///
/// The x86_64 CPU page-table walker reads all 512 entries of every
/// intermediate node it traverses, regardless of which entries are "in use".
/// If a newly allocated page-table frame contains stale bytes (left behind by
/// the slab allocator or a previous allocation), any non-zero entry is decoded
/// as a valid PTE pointing to an arbitrary physical address.  The first fetch
/// from such an address becomes the new RIP after the Ring 3 transition —
/// explaining why RIP is non-deterministic across boots.
///
/// `BuddyFrameAllocator` enforces zeroing via `FrameAllocOptions::new()
///  .purpose(FramePurpose::PageTable)` which:
///
///  1. Calls the buddy allocator for a raw order-0 frame.
///  2. CAS-claims the frame via the [`MetaSlot`](crate::memory::MetaSlot) refcount field
///     (`REFCOUNT_UNUSED` → `1`).
///  3. Zeros the 4 KiB with a single `ptr::write_bytes` through the HHDM.
///  4. Sets purpose flags on the [`MetaSlot`](crate::memory::MetaSlot) with `Release` ordering.
///  5. Stores `refcount = 1` with `Release` ordering so any future reader
///     that loads the refcount with `Acquire` observes a fully-initialised frame.
///
/// This matches the Asterinas OSTD pattern (`FrameAllocOptions` + per-frame
/// [`MetaSlot`](crate::memory::MetaSlot) with refcount CAS). Metadata lives in
/// dedicated slots (not in mapped page bytes); see [`get_meta_slot`](crate::memory::get_meta_slot).
pub struct BuddyFrameAllocator;

// SAFETY: `BuddyFrameAllocator::allocate_frame` returns 4KiB-aligned,
// exclusively-owned physical frames.  Exclusive ownership is guaranteed by
// the buddy's own bitmap + free-list discipline.  Frames allocated with
// `FramePurpose::PageTable` are always fully zeroed before being returned.
unsafe impl X86FrameAllocator<Size4KiB> for BuddyFrameAllocator {
    fn allocate_frame(&mut self) -> Option<X86PhysFrame<Size4KiB>> {
        // SAFETY: `BuddyFrameAllocator` is only ever called from within
        // `OffsetPageTable` during page-table operations.  Those occur either
        // during single-threaded early boot, or while the caller holds a lock
        // that disables IRQs (e.g. the scheduler SpinLock, the AddressSpace
        // lock).  IRQs are therefore guaranteed to be disabled.
        let token = unsafe { crate::sync::IrqDisabledToken::token_from_trusted_context() };

        // `PageTable` purpose enforces:
        //  - `zeroed = true` unconditionally (cannot be overridden by callers).
        //  - `FrameMeta::flags` stamped with `KERNEL | ALLOCATED`.
        //  - `FrameMeta::refcount` set to 1 with `Release` ordering after
        //    zeroing, so any `Acquire` load of the refcount observes a clean
        //    frame.
        let frame = FrameAllocOptions::new()
            .purpose(FramePurpose::PageTable)
            .allocate(&token)
            .ok()?;

        X86PhysFrame::from_start_address(frame.start_address).ok()
    }
}

/// Paging initialization flag.
static mut PAGING_READY: bool = false;

/// Physical address of the kernel's level-4 page table (set at init, never changes).
static mut KERNEL_CR3: PhysAddr = PhysAddr::new_truncate(0);

/// Serializes mutations of the canonical kernel page tables.
///
/// The active-CR3 mapping helpers are still caller-synchronized by their own
/// higher-level address-space locks, but kernel-global mappings such as vmalloc
/// must not race while allocating or wiring intermediate page-table levels.
static KERNEL_PT_LOCK: SpinLock<()> = SpinLock::new(());

/// Returns whether initialized.
pub fn is_initialized() -> bool {
    unsafe { *(&raw const PAGING_READY) }
}

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

    // SAFETY: called once during single-threaded init. The HHDM offset correctly
    // maps all physical RAM to virtual addresses. CR3 points to a valid page table
    // set up by Limine.
    unsafe {
        let kcr3 = &raw mut KERNEL_CR3;
        *kcr3 = level_4_frame.start_address();
        let ready = &raw mut PAGING_READY;
        *ready = true;
    }

    log::info!(
        "Paging initialized: CR3={:#x}, HHDM={:#x}, L4 table @ {:#x}",
        level_4_phys,
        hhdm_offset,
        level_4_virt.as_u64(),
    );
}

/// Map all RAM regions from the memory map into the HHDM.
///
/// This ensures that every byte of physical RAM is accessible through the
/// higher-half direct map. Should be called after paging::init.
/// Fix for VMWare Workstation which doesn't identity-map all RAM by default, causing
/// the kernel to crash when it tries to access unmapped RAM (e.g. for the buddy allocator's
/// metadata array). Limine's initial map only covers the first 1GB of RAM, which is not enough
/// for our 2GB test VM. This function lazily maps any missing RAM regions on
/// demand using `ensure_identity_map_range()`, which checks if the region is already mapped
/// before mapping it. This allows the kernel to boot successfully on VMWare Workstation without
/// requiring changes to the bootloader or Limine configuration.
///
pub fn map_all_ram(memory_regions: &[crate::boot::entry::MemoryRegion]) {
    use crate::boot::entry::MemoryKind;

    for region in memory_regions {
        if matches!(region.kind, MemoryKind::Free | MemoryKind::Reclaim) {
            log::debug!(
                "Mapping RAM region to HHDM: phys=0x{:x}..0x{:x}",
                region.base,
                region.base + region.size
            );
            ensure_identity_map_range(region.base, region.size);
        }
    }
}

/// Map a virtual page to a physical frame with the given flags.
///
/// Intermediate page tables are allocated from the buddy allocator as needed.
pub fn map_page(
    page: Page<Size4KiB>,
    frame: X86PhysFrame<Size4KiB>,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    if !is_initialized() {
        return Err("Paging not initialized");
    }
    let phys_offset = VirtAddr::new(crate::memory::hhdm_offset());
    let (level_4_frame, _) = Cr3::read();
    let level_4_virt = phys_offset + level_4_frame.start_address().as_u64();
    // SAFETY: level_4_virt points to the active CR3 PML4 via HHDM.
    let mapper = unsafe { &mut *level_4_virt.as_mut_ptr::<PageTable>() };
    let mut mapper = unsafe { OffsetPageTable::new(mapper, phys_offset) };
    let mut allocator = BuddyFrameAllocator;

    unsafe {
        mapper
            .map_to(page, frame, flags, &mut allocator)
            .map_err(|_| "Failed to map page")?
            .flush();
    }
    Ok(())
}

/// Map a page into the kernel's canonical page tables (not the active CR3).
///
/// This ensures that the mapping is visible from all address spaces, because
/// every user address space clones the kernel half (PML4[256..512]) from the
/// kernel's L4 table at creation time.
///
/// Used by vmalloc so that heap allocations are kernel-global.
/// Intermediate page tables are allocated from the buddy allocator as needed.
pub fn map_page_kernel(
    page: Page<Size4KiB>,
    frame: X86PhysFrame<Size4KiB>,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    if !is_initialized() {
        return Err("Paging not initialized");
    }
    let _guard = KERNEL_PT_LOCK.lock();
    // SAFETY: KERNEL_CR3 is set once during init and never changes.
    let kernel_cr3 = unsafe { *(&raw const KERNEL_CR3) };
    let phys_offset = VirtAddr::new(crate::memory::hhdm_offset());
    let level_4_virt = phys_offset + kernel_cr3.as_u64();
    // SAFETY: level_4_virt points to the kernel's L4 table via HHDM.
    let mapper = unsafe { &mut *level_4_virt.as_mut_ptr::<PageTable>() };
    let mut mapper = unsafe { OffsetPageTable::new(mapper, phys_offset) };
    let mut allocator = BuddyFrameAllocator;

    unsafe {
        mapper
            .map_to(page, frame, flags, &mut allocator)
            .map_err(|_| "Failed to map page (kernel)")?
            .flush();
    }
    Ok(())
}

/// Unmap a page from the active CR3, returning the physical frame.
pub fn unmap_page(page: Page<Size4KiB>) -> Result<X86PhysFrame<Size4KiB>, &'static str> {
    if !is_initialized() {
        return Err("Paging not initialized");
    }
    let phys_offset = VirtAddr::new(crate::memory::hhdm_offset());
    let (level_4_frame, _) = Cr3::read();
    let level_4_virt = phys_offset + level_4_frame.start_address().as_u64();
    // SAFETY: level_4_virt points to the active CR3 PML4 via HHDM.
    let mapper = unsafe { &mut *level_4_virt.as_mut_ptr::<PageTable>() };
    let mut mapper = unsafe { OffsetPageTable::new(mapper, phys_offset) };
    let (frame, flush) = mapper.unmap(page).map_err(|_| "Failed to unmap page")?;
    flush.flush();
    Ok(frame)
}

/// Unmap a page from the kernel's canonical page tables.
///
/// This is the counterpart to `map_page_kernel`. It removes the mapping from
/// the kernel's L4 table so that the page is no longer visible in any address
/// space.
pub fn unmap_page_kernel(page: Page<Size4KiB>) -> Result<X86PhysFrame<Size4KiB>, &'static str> {
    if !is_initialized() {
        return Err("Paging not initialized");
    }
    let _guard = KERNEL_PT_LOCK.lock();
    // SAFETY: KERNEL_CR3 is set once during init and never changes.
    let kernel_cr3 = unsafe { *(&raw const KERNEL_CR3) };
    let phys_offset = VirtAddr::new(crate::memory::hhdm_offset());
    let level_4_virt = phys_offset + kernel_cr3.as_u64();
    // SAFETY: level_4_virt points to the kernel's L4 table via HHDM.
    let mapper = unsafe { &mut *level_4_virt.as_mut_ptr::<PageTable>() };
    let mut mapper = unsafe { OffsetPageTable::new(mapper, phys_offset) };
    let (frame, flush) = mapper
        .unmap(page)
        .map_err(|_| "Failed to unmap page (kernel)")?;
    flush.flush();
    Ok(frame)
}

/// Translate a virtual address to its mapped physical address.
///
/// Returns `None` if the address is not mapped.
pub fn translate(addr: VirtAddr) -> Option<PhysAddr> {
    if !is_initialized() {
        return None;
    }
    let phys_offset = VirtAddr::new(crate::memory::hhdm_offset());
    let (level_4_frame, _) = Cr3::read();
    let level_4_virt = phys_offset + level_4_frame.start_address().as_u64();
    // SAFETY: level_4_virt points to the active CR3 PML4 via HHDM.
    let mapper = unsafe { &mut *level_4_virt.as_mut_ptr::<PageTable>() };
    let mapper = unsafe { OffsetPageTable::new(mapper, phys_offset) };
    mapper.translate_addr(addr)
}

fn translate_via_active_page_tables(addr: VirtAddr) -> Option<PhysAddr> {
    let hhdm = crate::memory::hhdm_offset();
    let (level_4_frame, _) = Cr3::read();

    unsafe {
        let l4_ptr = (level_4_frame.start_address().as_u64() + hhdm) as *const u64;
        let l4e = *l4_ptr.add(((addr.as_u64() >> 39) & 0x1FF) as usize);
        if l4e & 1 == 0 {
            return None;
        }

        let l3_ptr = ((l4e & 0x000F_FFFF_FFFF_F000) + hhdm) as *const u64;
        let l3e = *l3_ptr.add(((addr.as_u64() >> 30) & 0x1FF) as usize);
        if l3e & 1 == 0 {
            return None;
        }
        if l3e & 0x80 != 0 {
            return Some(PhysAddr::new(
                (l3e & 0x000F_FFFF_C000_0000) + (addr.as_u64() & 0x3FFF_FFFF),
            ));
        }

        let l2_ptr = ((l3e & 0x000F_FFFF_FFFF_F000) + hhdm) as *const u64;
        let l2e = *l2_ptr.add(((addr.as_u64() >> 21) & 0x1FF) as usize);
        if l2e & 1 == 0 {
            return None;
        }
        if l2e & 0x80 != 0 {
            return Some(PhysAddr::new(
                (l2e & 0x000F_FFFF_FFE0_0000) + (addr.as_u64() & 0x1F_FFFF),
            ));
        }

        let l1_ptr = ((l2e & 0x000F_FFFF_FFFF_F000) + hhdm) as *const u64;
        let l1e = *l1_ptr.add(((addr.as_u64() >> 12) & 0x1FF) as usize);
        if l1e & 1 == 0 {
            return None;
        }

        Some(PhysAddr::new(
            (l1e & 0x000F_FFFF_FFFF_F000) + (addr.as_u64() & 0xFFF),
        ))
    }
}

/// Returns whether the current page tables map the HHDM view of the whole range.
///
/// This helper is safe before `paging::init()` and is intended for early boot
/// allocators that must only touch memory already reachable through the current
/// firmware-provided direct map.
pub fn is_hhdm_range_mapped_now(phys_base: u64, size: u64) -> bool {
    if size == 0 {
        return true;
    }

    let start = phys_base & !0xFFF;
    let end = phys_base
        .saturating_add(size)
        .saturating_add(0xFFF)
        & !0xFFF;

    let mut phys = start;
    while phys < end {
        let virt = VirtAddr::new(crate::memory::phys_to_virt(phys));
        let Some(mapped) = translate_via_active_page_tables(virt) else {
            return false;
        };
        if mapped.as_u64() != phys {
            return false;
        }
        phys = phys.saturating_add(4096);
    }
    true
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

/// Ensure a physical range is mapped in the HHDM region.
///
/// Builds a single `OffsetPageTable` for the entire range instead of
/// one per page, and emits a single summary log instead of per-page noise.
pub fn ensure_identity_map_range(phys_base: u64, size: u64) {
    if size == 0 || !is_initialized() {
        return;
    }

    let page_size = 4096u64;
    let start = phys_base & !(page_size - 1);
    let end = (phys_base.saturating_add(size).saturating_add(page_size - 1)) & !(page_size - 1);
    if start >= end {
        return;
    }

    let phys_offset = VirtAddr::new(crate::memory::hhdm_offset());
    let (level_4_frame, _) = Cr3::read();
    let level_4_virt = phys_offset + level_4_frame.start_address().as_u64();

    // SAFETY: level_4_virt points to the active CR3 PML4 via HHDM.
    let l4_table = unsafe { &mut *level_4_virt.as_mut_ptr::<PageTable>() };
    let mut mapper = unsafe { OffsetPageTable::new(l4_table, phys_offset) };
    let mut allocator = BuddyFrameAllocator;
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    let mut mapped_count: u64 = 0;
    let mut p = start;
    while p < end {
        let virt = VirtAddr::new(crate::memory::phys_to_virt(p));
        // Only map if not already present.
        if mapper.translate_addr(virt).is_none() {
            let page = Page::<Size4KiB>::containing_address(virt);
            let frame = X86PhysFrame::containing_address(PhysAddr::new(p));
            // SAFETY: frame is a valid physical page; mapper uses HHDM offset.
            match unsafe { mapper.map_to(page, frame, flags, &mut allocator) } {
                Ok(flush) => {
                    flush.flush();
                    mapped_count += 1;
                }
                Err(_) => {
                    log::error!("ensure_identity_map_range: failed to map {:#x}", p);
                }
            }
        }
        p = p.saturating_add(page_size);
    }

    if mapped_count > 0 {
        log::debug!(
            "Identity mapped {} pages: phys {:#x}..{:#x}",
            mapped_count,
            start,
            end,
        );
    }
}
