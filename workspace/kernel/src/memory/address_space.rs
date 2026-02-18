//! Per-process address spaces for Strat9-OS.
//!
//! Each task owns an `AddressSpace` backed by a PML4 page table.
//! Kernel tasks share a single kernel address space. User tasks get a fresh
//! PML4 with the kernel half (entries 256..512) cloned from the kernel's table.
//!
//! x86_64 virtual address space layout:
//! - PML4[0..256]   → User space (per-process, zeroed for new AS)
//! - PML4[256..512] → Kernel space (shared, cloned from kernel L4)

use alloc::{collections::BTreeMap, sync::Arc};

use spin::Once;
use x86_64::{
    registers::control::{Cr3, Cr3Flags},
    structures::paging::{
        FrameAllocator as X86FrameAllocator, Mapper, OffsetPageTable, Page, PageTable,
        PageTableFlags, PhysFrame as X86PhysFrame, Size4KiB, Translate,
    },
    PhysAddr, VirtAddr,
};

use crate::{
    memory::{paging::BuddyFrameAllocator, FrameAllocator},
    sync::SpinLock,
};

/// Flags describing permissions for a virtual memory region.
#[derive(Debug, Clone, Copy)]
pub struct VmaFlags {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub user_accessible: bool,
}

impl VmaFlags {
    /// Convert to x86_64 page table flags.
    pub fn to_page_flags(self) -> PageTableFlags {
        let mut flags = PageTableFlags::PRESENT;
        if self.writable {
            flags |= PageTableFlags::WRITABLE;
        }
        if !self.executable {
            flags |= PageTableFlags::NO_EXECUTE;
        }
        if self.user_accessible {
            flags |= PageTableFlags::USER_ACCESSIBLE;
        }
        flags
    }
}

/// Type/purpose of a virtual memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmaType {
    /// Zero-filled anonymous memory (heap, mmap).
    Anonymous,
    /// Stack region (grows downward).
    Stack,
    /// Code/text segment (typically RX).
    Code,
    /// Kernel-internal mapping.
    Kernel,
}

/// A tracked virtual memory region within an address space.
#[derive(Debug, Clone)]
pub struct VirtualMemoryRegion {
    /// Start virtual address (page-aligned).
    pub start: u64,
    /// Number of 4KiB pages in this region.
    pub page_count: usize,
    /// Access permissions.
    pub flags: VmaFlags,
    /// Purpose of this region.
    pub vma_type: VmaType,
}

/// A per-process address space backed by a PML4 page table.
///
/// Kernel tasks share a single `AddressSpace` (the kernel AS).
/// User tasks each get their own, with kernel entries (PML4[256..512]) cloned
/// so that the kernel is always mapped regardless of which AS is active.
pub struct AddressSpace {
    /// Physical address of the PML4 table (loaded into CR3).
    cr3_phys: PhysAddr,
    /// Virtual address of the PML4 table (via HHDM, for reading/modifying).
    l4_table_virt: VirtAddr,
    /// Whether this is the kernel address space (never freed).
    is_kernel: bool,
    /// Tracked virtual memory regions (key = start address).
    regions: SpinLock<BTreeMap<u64, VirtualMemoryRegion>>,
}

// SAFETY: AddressSpace is protected by the scheduler lock and per-task ownership.
// The PML4 table is accessed through HHDM virtual addresses which are valid on all CPUs.
unsafe impl Send for AddressSpace {}
unsafe impl Sync for AddressSpace {}

impl AddressSpace {
    /// Create the kernel address space by wrapping the current (boot) CR3.
    ///
    /// # Safety
    /// Must be called exactly once, during single-threaded init, after paging is initialized.
    pub unsafe fn new_kernel() -> Self {
        let (level_4_frame, _flags) = Cr3::read();
        let cr3_phys = level_4_frame.start_address();
        let l4_table_virt = VirtAddr::new(crate::memory::phys_to_virt(cr3_phys.as_u64()));

        log::info!(
            "Kernel address space initialized: CR3={:#x}",
            cr3_phys.as_u64()
        );

        AddressSpace {
            cr3_phys,
            l4_table_virt,
            is_kernel: true,
            regions: SpinLock::new(BTreeMap::new()),
        }
    }

    /// Create a new user address space with the kernel half cloned.
    ///
    /// Allocates a fresh PML4 frame, zeroes it, then copies entries 256..512
    /// from the kernel PML4. This shares the kernel's L3/L2/L1 subtrees so
    /// kernel mapping changes propagate automatically.
    pub fn new_user() -> Result<Self, &'static str> {
        // Allocate a frame for the new PML4 table.
        let new_l4_phys = {
            let lock = crate::memory::get_allocator();
            let mut guard = lock.lock();
            let allocator = guard.as_mut().ok_or("Allocator not initialized")?;
            let frame = allocator
                .alloc_frame()
                .map_err(|_| "Failed to allocate PML4 frame")?;
            frame.start_address
        };

        let new_l4_virt = VirtAddr::new(crate::memory::phys_to_virt(new_l4_phys.as_u64()));

        // Zero the entire table first (clears user-half entries 0..256).
        // SAFETY: new_l4_virt points to a freshly allocated, HHDM-mapped frame.
        unsafe {
            core::ptr::write_bytes(new_l4_virt.as_mut_ptr::<u8>(), 0, 4096);
        }

        // Clone kernel entries (PML4[256..512]) from the kernel's L4 table.
        let kernel_l4_phys = crate::memory::paging::kernel_l4_phys();
        let kernel_l4_virt = VirtAddr::new(crate::memory::phys_to_virt(kernel_l4_phys.as_u64()));

        // SAFETY: Both pointers are valid HHDM-mapped page tables. We only read
        // from the kernel table and write to the freshly allocated table.
        unsafe {
            let kernel_l4 = &*(kernel_l4_virt.as_ptr::<PageTable>());
            let new_l4 = &mut *(new_l4_virt.as_mut_ptr::<PageTable>());
            for i in 256..512 {
                new_l4[i] = kernel_l4[i].clone();
            }
        }

        log::debug!(
            "User address space created: CR3={:#x} (kernel entries cloned from {:#x})",
            new_l4_phys.as_u64(),
            kernel_l4_phys.as_u64()
        );

        Ok(AddressSpace {
            cr3_phys: new_l4_phys,
            l4_table_virt: new_l4_virt,
            is_kernel: false,
            regions: SpinLock::new(BTreeMap::new()),
        })
    }

    /// Construct a temporary `OffsetPageTable` mapper for this address space.
    ///
    /// # Safety
    /// The caller must ensure exclusive access to the page tables (e.g. via
    /// the scheduler lock or single-threaded context).
    unsafe fn mapper(&self) -> OffsetPageTable<'_> {
        let phys_offset = VirtAddr::new(crate::memory::hhdm_offset());
        // SAFETY: l4_table_virt is the HHDM-mapped address of our PML4.
        // The caller guarantees exclusive access.
        unsafe {
            OffsetPageTable::new(
                &mut *self.l4_table_virt.as_mut_ptr::<PageTable>(),
                phys_offset,
            )
        }
    }

    /// Map a contiguous region of pages backed by newly allocated physical frames.
    ///
    /// Frames are allocated from the buddy allocator and zero-filled.
    /// The region is tracked in the VMA list.
    pub fn map_region(
        &self,
        start: u64,
        page_count: usize,
        flags: VmaFlags,
        vma_type: VmaType,
    ) -> Result<(), &'static str> {
        let page_flags = flags.to_page_flags();
        let mut frame_allocator = BuddyFrameAllocator;

        // SAFETY: We have logical ownership of this address space.
        let mut mapper = unsafe { self.mapper() };

        for i in 0..page_count {
            let page_addr = start + (i as u64) * 4096;
            let page = Page::<Size4KiB>::from_start_address(VirtAddr::new(page_addr))
                .map_err(|_| "Page address not aligned")?;

            // Allocate a physical frame.
            let frame = frame_allocator
                .allocate_frame()
                .ok_or("Failed to allocate frame for mapping")?;

            // Zero the frame before mapping.
            // SAFETY: The frame is freshly allocated and we access it via HHDM.
            unsafe {
                let frame_virt = crate::memory::phys_to_virt(frame.start_address().as_u64());
                core::ptr::write_bytes(frame_virt as *mut u8, 0, 4096);
            }

            // Map the page to the frame.
            // SAFETY: The frame is valid and unused; flags are caller-specified.
            unsafe {
                mapper
                    .map_to(page, frame, page_flags, &mut frame_allocator)
                    .map_err(|_| "Failed to map page")?
                    .flush();
            }
        }

        // Track the region.
        let region = VirtualMemoryRegion {
            start,
            page_count,
            flags,
            vma_type,
        };
        self.regions.lock().insert(start, region);

        log::trace!(
            "Mapped region: {:#x}..{:#x} ({} pages, {:?})",
            start,
            start + (page_count as u64) * 4096,
            page_count,
            vma_type
        );

        Ok(())
    }

    /// Unmap a previously mapped region and free the backing frames.
    pub fn unmap_region(&self, start: u64, page_count: usize) -> Result<(), &'static str> {
        // SAFETY: We have logical ownership of this address space.
        let mut mapper = unsafe { self.mapper() };

        for i in 0..page_count {
            let page_addr = start + (i as u64) * 4096;
            let page = Page::<Size4KiB>::from_start_address(VirtAddr::new(page_addr))
                .map_err(|_| "Page address not aligned")?;

            let (frame, flush) = mapper.unmap(page).map_err(|_| "Failed to unmap page")?;
            flush.flush();

            // Free the physical frame back to the buddy allocator.
            let phys_frame = crate::memory::PhysFrame {
                start_address: frame.start_address(),
            };
            let lock = crate::memory::get_allocator();
            let mut guard = lock.lock();
            if let Some(allocator) = guard.as_mut() {
                allocator.free(phys_frame, 0);
            }
        }

        // Remove from VMA tracking.
        self.regions.lock().remove(&start);

        log::trace!(
            "Unmapped region: {:#x}..{:#x} ({} pages)",
            start,
            start + (page_count as u64) * 4096,
            page_count
        );

        Ok(())
    }

    /// Translate a virtual address to its mapped physical address.
    pub fn translate(&self, vaddr: VirtAddr) -> Option<PhysAddr> {
        // SAFETY: Read-only access to the page tables.
        let mapper = unsafe { self.mapper() };
        mapper.translate_addr(vaddr)
    }

    /// Get the physical address of this address space's PML4 table.
    pub fn cr3(&self) -> PhysAddr {
        self.cr3_phys
    }

    /// Switch the CPU to this address space by writing CR3.
    ///
    /// Skips the write if CR3 already points to this address space (avoids
    /// unnecessary TLB flush).
    ///
    /// # Safety
    /// The caller must ensure this address space's page tables are valid and
    /// that the kernel half is correctly mapped.
    pub unsafe fn switch_to(&self) {
        let (current_frame, _) = Cr3::read();
        if current_frame.start_address() == self.cr3_phys {
            return; // Already active — skip to avoid TLB flush.
        }

        // SAFETY: cr3_phys points to a valid, 4KiB-aligned PML4 table with
        // the kernel half correctly populated.
        unsafe {
            let frame =
                X86PhysFrame::from_start_address(self.cr3_phys).expect("CR3 address not aligned");
            Cr3::write(frame, Cr3Flags::empty());
        }
    }

    /// Whether this is the kernel address space.
    pub fn is_kernel(&self) -> bool {
        self.is_kernel
    }

    /// Unmap all tracked user regions (best-effort).
    ///
    /// This frees user frames and clears the VMA list. Kernel mappings are untouched.
    pub fn unmap_all_user_regions(&self) {
        if self.is_kernel {
            return;
        }

        let regions: alloc::vec::Vec<(u64, usize)> = {
            let guard = self.regions.lock();
            guard.values().map(|r| (r.start, r.page_count)).collect()
        };

        for (start, pages) in regions {
            let _ = self.unmap_region(start, pages);
        }
    }

    fn free_user_page_tables(&self) {
        if self.is_kernel {
            return;
        }

        // SAFETY: We have logical ownership of this address space during drop.
        let l4 = unsafe { &mut *self.l4_table_virt.as_mut_ptr::<PageTable>() };

        for i in 0..256 {
            if !l4[i].flags().contains(PageTableFlags::PRESENT) {
                continue;
            }
            let l3_frame = match l4[i].frame() {
                Ok(f) => f,
                Err(_) => {
                    l4[i].set_unused();
                    continue;
                }
            };

            free_l3_table(l3_frame);
            l4[i].set_unused();
        }
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        if self.is_kernel {
            return; // Never free the kernel address space.
        }

        // Best-effort cleanup of user mappings.
        self.unmap_all_user_regions();
        self.free_user_page_tables();

        // Free the PML4 frame itself.
        // NOTE: Recursive freeing of intermediate page tables (L3/L2/L1) that
        // belong exclusively to the user half is deferred to P2.
        let phys_frame = crate::memory::PhysFrame {
            start_address: self.cr3_phys,
        };
        let lock = crate::memory::get_allocator();
        let mut guard = lock.lock();
        if let Some(allocator) = guard.as_mut() {
            allocator.free(phys_frame, 0);
        }

        log::debug!(
            "User address space dropped: CR3={:#x}",
            self.cr3_phys.as_u64()
        );
    }
}

// ---------------------------------------------------------------------------
// Page table cleanup helpers (user half only)
// ---------------------------------------------------------------------------

fn free_frame(phys: PhysAddr) {
    let phys_frame = crate::memory::PhysFrame {
        start_address: phys,
    };
    let lock = crate::memory::get_allocator();
    let mut guard = lock.lock();
    if let Some(allocator) = guard.as_mut() {
        allocator.free(phys_frame, 0);
    }
}

fn free_l1_table(frame: X86PhysFrame<Size4KiB>) {
    let l1_virt = VirtAddr::new(crate::memory::phys_to_virt(frame.start_address().as_u64()));
    // SAFETY: l1_virt points to a valid page table frame in HHDM.
    let l1 = unsafe { &mut *l1_virt.as_mut_ptr::<PageTable>() };
    for entry in l1.iter_mut() {
        if entry.flags().contains(PageTableFlags::PRESENT) {
            // Mapped frames are already freed via unmap_all_user_regions.
            entry.set_unused();
        }
    }
    free_frame(frame.start_address());
}

fn free_l2_table(frame: X86PhysFrame<Size4KiB>) {
    let l2_virt = VirtAddr::new(crate::memory::phys_to_virt(frame.start_address().as_u64()));
    let l2 = unsafe { &mut *l2_virt.as_mut_ptr::<PageTable>() };
    for entry in l2.iter_mut() {
        if !entry.flags().contains(PageTableFlags::PRESENT) {
            continue;
        }
        if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            // 2 MiB pages are not expected in user space today.
            entry.set_unused();
            continue;
        }
        if let Ok(l1_frame) = entry.frame() {
            free_l1_table(l1_frame);
        }
        entry.set_unused();
    }
    free_frame(frame.start_address());
}

fn free_l3_table(frame: X86PhysFrame<Size4KiB>) {
    let l3_virt = VirtAddr::new(crate::memory::phys_to_virt(frame.start_address().as_u64()));
    let l3 = unsafe { &mut *l3_virt.as_mut_ptr::<PageTable>() };
    for entry in l3.iter_mut() {
        if !entry.flags().contains(PageTableFlags::PRESENT) {
            continue;
        }
        if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            // 1 GiB pages are not expected in user space today.
            entry.set_unused();
            continue;
        }
        if let Ok(l2_frame) = entry.frame() {
            free_l2_table(l2_frame);
        }
        entry.set_unused();
    }
    free_frame(frame.start_address());
}

// ---------------------------------------------------------------------------
// Kernel address space singleton
// ---------------------------------------------------------------------------

static KERNEL_ADDRESS_SPACE: Once<Arc<AddressSpace>> = Once::new();

/// Initialize the kernel address space singleton.
///
/// Must be called once during boot, after paging is initialized, before the
/// scheduler creates any tasks.
///
/// # Safety
/// Must be called in single-threaded init context.
pub unsafe fn init_kernel_address_space() {
    KERNEL_ADDRESS_SPACE.call_once(|| {
        // SAFETY: Called once, single-threaded, paging initialized.
        Arc::new(unsafe { AddressSpace::new_kernel() })
    });
}

/// Get a reference to the kernel address space.
///
/// Panics if called before `init_kernel_address_space()`.
pub fn kernel_address_space() -> &'static Arc<AddressSpace> {
    KERNEL_ADDRESS_SPACE
        .get()
        .expect("Kernel address space not initialized")
}
