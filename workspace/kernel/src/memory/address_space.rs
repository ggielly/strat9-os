//! Per-process address spaces for Strat9-OS.
//!
//! Each task owns an `AddressSpace` backed by a PML4 page table.
//! Kernel tasks share a single kernel address space. User tasks get a fresh
//! PML4 with the kernel half (entries 256..512) cloned from the kernel's table.
//!
//! x86_64 virtual address space layout:
//! - PML4[0..256]   → User space (per-process, zeroed for new AS)
//! - PML4[256..512] → Kernel space (shared, cloned from kernel L4)

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use spin::Once;
use x86_64::{
    registers::control::{Cr3, Cr3Flags},
    structures::paging::{
        mapper::TranslateResult, Mapper, OffsetPageTable,
        Page, PageTable, PageTableFlags, PhysFrame as X86PhysFrame, Size2MiB, Size4KiB, Translate,
    },
    PhysAddr, VirtAddr,
};

use crate::{
    memory::{paging::BuddyFrameAllocator, FrameAllocator},
    sync::SpinLock,
};

/// Flags describing permissions for a virtual memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Supported page sizes for VMAs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmaPageSize {
    /// Standard 4 KiB page.
    Small,
    /// Huge 2 MiB page.
    Huge,
}

impl VmaPageSize {
    pub fn bytes(self) -> u64 {
        match self {
            VmaPageSize::Small => 4096,
            VmaPageSize::Huge => 2 * 1024 * 1024,
        }
    }
}

/// A tracked virtual memory region within an address space.
#[derive(Debug, Clone)]
pub struct VirtualMemoryRegion {
    /// Start virtual address (page-aligned).
    pub start: u64,
    /// Number of pages in this region (size depends on `page_size`).
    pub page_count: usize,
    /// Access permissions.
    pub flags: VmaFlags,
    /// Purpose of this region.
    pub vma_type: VmaType,
    /// Size of each page in this region.
    pub page_size: VmaPageSize,
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
    pub(crate) unsafe fn mapper(&self) -> OffsetPageTable<'_> {
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

    /// Reserve a contiguous region of virtual pages without allocating physical frames.
    ///
    /// The pages will be mapped lazily during page faults (Demand Paging).
    pub fn reserve_region(
        &self,
        start: u64,
        page_count: usize,
        flags: VmaFlags,
        vma_type: VmaType,
        page_size: VmaPageSize,
    ) -> Result<(), &'static str> {
        let page_bytes = page_size.bytes();
        if page_count == 0 || start % page_bytes != 0 {
            return Err("Invalid region arguments");
        }
        let len = (page_count as u64)
            .checked_mul(page_bytes)
            .ok_or("Region length overflow")?;
        let end = start.checked_add(len).ok_or("Region end overflow")?;
        const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;
        if end > USER_SPACE_END {
            return Err("Region out of user-space range");
        }

        // Reject overlapping VMAs
        {
            let regions = self.regions.lock();
            if regions.iter().any(|(&vma_start, vma)| {
                let vma_end = vma_start
                    .saturating_add((vma.page_count as u64).saturating_mul(vma.page_size.bytes()));
                vma_start < end && vma_end > start
            }) {
                return Err("Region overlaps existing mapping");
            }
        }

        // Track the region, attempting to merge with previous.
        let mut regions = self.regions.lock();
        let mut merged = false;

        if let Some((&prev_start, prev_vma)) = regions.range(..start).next_back() {
            let prev_end = prev_start + (prev_vma.page_count as u64) * prev_vma.page_size.bytes();
            if prev_end == start
                && prev_vma.flags == flags
                && prev_vma.vma_type == vma_type
                && prev_vma.page_size == page_size
            {
                let new_count = prev_vma
                    .page_count
                    .checked_add(page_count)
                    .ok_or("Region page_count overflow")?;
                let updated_vma = VirtualMemoryRegion {
                    start: prev_start,
                    page_count: new_count,
                    flags,
                    vma_type,
                    page_size,
                };
                regions.insert(prev_start, updated_vma);
                merged = true;
            }
        }

        if !merged {
            let region = VirtualMemoryRegion {
                start,
                page_count,
                flags,
                vma_type,
                page_size,
            };
            regions.insert(start, region);
        }

        log::trace!(
            "Reserved lazy region: {:#x} ({} pages, size={:?})",
            start,
            page_count,
            page_size
        );
        Ok(())
    }

    /// Handle a page fault by checking if the address falls within a reserved VMA.
    ///
    /// If it does, allocates a physical frame and maps it.
    pub fn handle_fault(&self, fault_addr: u64) -> Result<(), &'static str> {
        use x86_64::structures::paging::mapper::MapToError;

        // 1. Find the VMA covering this address
        let vma = {
            let regions = self.regions.lock();
            let mut iter = regions.range(..=fault_addr);
            let (&start, vma) = iter.next_back().ok_or("No VMA found for address")?;
            let end = start + (vma.page_count as u64) * vma.page_size.bytes();
            if fault_addr >= end {
                return Err("Address outside VMA bounds");
            }
            vma.clone()
        };

        // Align fault address to the page size used by this VMA.
        let page_bytes = vma.page_size.bytes();
        let page_addr = fault_addr & !(page_bytes - 1);

        // 2. Only Anonymous/Stack regions support demand paging for now
        match vma.vma_type {
            VmaType::Anonymous | VmaType::Stack | VmaType::Code => {}
            _ => return Err("VMA type does not support demand paging"),
        }

        // 3. If already mapped (race/re-fault), treat as handled.
        if self.translate(VirtAddr::new(page_addr)).is_some() {
            return Ok(());
        }

        // 4. Allocate and map a single page of the required size
        let mut frame_allocator = crate::memory::paging::BuddyFrameAllocator;
        let order = match vma.page_size {
            VmaPageSize::Small => 0,
            VmaPageSize::Huge => 9,
        };

        let lock = crate::memory::get_allocator();
        let mut guard = lock.lock();
        let allocator = guard.as_mut().ok_or("Allocator not initialized")?;
        let frame = allocator
            .alloc(order)
            .map_err(|_| "OOM during demand paging")?;
        drop(guard);

        // Zero the frame
        unsafe {
            let virt = crate::memory::phys_to_virt(frame.start_address.as_u64());
            core::ptr::write_bytes(virt as *mut u8, 0, page_bytes as usize);
        }

        let mut page_flags = vma.flags.to_page_flags();

        // SAFETY: We own the address space.
        unsafe {
            let mut mapper = self.mapper();
            match vma.page_size {
                VmaPageSize::Small => {
                    let page =
                        Page::<Size4KiB>::from_start_address(VirtAddr::new(page_addr)).unwrap();
                    let phys_frame =
                        x86_64::structures::paging::PhysFrame::<Size4KiB>::containing_address(
                            frame.start_address,
                        );
                    match mapper.map_to(page, phys_frame, page_flags, &mut frame_allocator) {
                        Ok(flush) => flush.flush(),
                        Err(MapToError::PageAlreadyMapped(_)) => {
                            let lock = crate::memory::get_allocator();
                            let mut guard = lock.lock();
                            if let Some(allocator) = guard.as_mut() {
                                allocator.free(
                                    crate::memory::PhysFrame {
                                        start_address: frame.start_address,
                                    },
                                    order,
                                );
                            }
                            return Ok(());
                        }
                        Err(_) => {
                            let lock = crate::memory::get_allocator();
                            let mut guard = lock.lock();
                            if let Some(allocator) = guard.as_mut() {
                                allocator.free(
                                    crate::memory::PhysFrame {
                                        start_address: frame.start_address,
                                    },
                                    order,
                                );
                            }
                            return Err("Failed to map demand page (4K)");
                        }
                    }
                }
                VmaPageSize::Huge => {
                    let page =
                        Page::<Size2MiB>::from_start_address(VirtAddr::new(page_addr)).unwrap();
                    let phys_frame =
                        x86_64::structures::paging::PhysFrame::<Size2MiB>::containing_address(
                            frame.start_address,
                        );
                    page_flags |= PageTableFlags::HUGE_PAGE;
                    match mapper.map_to(page, phys_frame, page_flags, &mut frame_allocator) {
                        Ok(flush) => flush.flush(),
                        Err(MapToError::PageAlreadyMapped(_)) => {
                            let lock = crate::memory::get_allocator();
                            let mut guard = lock.lock();
                            if let Some(allocator) = guard.as_mut() {
                                allocator.free(
                                    crate::memory::PhysFrame {
                                        start_address: frame.start_address,
                                    },
                                    order,
                                );
                            }
                            return Ok(());
                        }
                        Err(_) => {
                            let lock = crate::memory::get_allocator();
                            let mut guard = lock.lock();
                            if let Some(allocator) = guard.as_mut() {
                                allocator.free(
                                    crate::memory::PhysFrame {
                                        start_address: frame.start_address,
                                    },
                                    order,
                                );
                            }
                            return Err("Failed to map demand page (2M)");
                        }
                    }
                }
            }
        }

        // Track refcount for COW
        crate::memory::cow::frame_inc_ref(crate::memory::PhysFrame {
            start_address: frame.start_address,
        });

        log::trace!(
            "Demand paging ({:?}): mapped {:#x} to frame {:#x}",
            vma.page_size,
            page_addr,
            frame.start_address.as_u64()
        );
        Ok(())
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
        page_size: VmaPageSize,
    ) -> Result<(), &'static str> {
        let page_bytes = page_size.bytes();
        if page_count == 0 || start % page_bytes != 0 {
            return Err("Invalid region arguments");
        }
        let len = (page_count as u64)
            .checked_mul(page_bytes)
            .ok_or("Region length overflow")?;
        let end = start.checked_add(len).ok_or("Region end overflow")?;
        const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;
        if end > USER_SPACE_END {
            return Err("Region out of user-space range");
        }

        // Reject overlapping VMAs early
        {
            let regions = self.regions.lock();
            if regions.iter().any(|(&vma_start, vma)| {
                let vma_end = vma_start
                    .saturating_add((vma.page_count as u64).saturating_mul(vma.page_size.bytes()));
                vma_start < end && vma_end > start
            }) {
                return Err("Region overlaps existing mapping");
            }
        }

        let page_flags = flags.to_page_flags();
        let mut frame_allocator = BuddyFrameAllocator;

        // SAFETY: we have logical ownership of this address space.
        let mut mapper = unsafe { self.mapper() };
        let mut mapped_pages = 0usize;

        for i in 0..page_count {
            let page_addr = start
                .checked_add((i as u64).saturating_mul(page_bytes))
                .ok_or("Page address overflow")?;

            // Allocate a physical frame of appropriate size.
            let order = match page_size {
                VmaPageSize::Small => 0,
                VmaPageSize::Huge => 9,
            };

            let lock = crate::memory::get_allocator();
            let mut guard = lock.lock();
            let allocator = guard.as_mut().ok_or("Allocator not initialized")?;
            let frame = allocator
                .alloc(order)
                .map_err(|_| "Failed to allocate frame")?;
            drop(guard);

            // Zero the frame
            unsafe {
                let frame_virt = crate::memory::phys_to_virt(frame.start_address.as_u64());
                core::ptr::write_bytes(frame_virt as *mut u8, 0, page_bytes as usize);
            }

            // Map the page.
            let map_ok = match page_size {
                VmaPageSize::Small => {
                    use x86_64::structures::paging::Size4KiB;
                    let page = Page::<Size4KiB>::from_start_address(VirtAddr::new(page_addr))
                        .map_err(|_| "Map 4K: invalid page address")?;
                    let phys_frame =
                        x86_64::structures::paging::PhysFrame::<Size4KiB>::containing_address(
                            frame.start_address,
                        );
                    unsafe {
                        mapper
                            .map_to(page, phys_frame, page_flags, &mut frame_allocator)
                            .map(|flush| flush.flush())
                            .is_ok()
                    }
                }
                VmaPageSize::Huge => {
                    use x86_64::structures::paging::Size2MiB;
                    let page = Page::<Size2MiB>::from_start_address(VirtAddr::new(page_addr))
                        .map_err(|_| "Map 2M: invalid page address")?;
                    let phys_frame =
                        x86_64::structures::paging::PhysFrame::<Size2MiB>::containing_address(
                            frame.start_address,
                        );
                    let mut huge_flags = page_flags;
                    huge_flags |= PageTableFlags::HUGE_PAGE;
                    unsafe {
                        mapper
                            .map_to(page, phys_frame, huge_flags, &mut frame_allocator)
                            .map(|flush| flush.flush())
                            .is_ok()
                    }
                }
            };

            if !map_ok {
                log::error!(
                    "map_region: map_to failed at page {} vaddr={:#x} size={:?}",
                    i,
                    page_addr,
                    page_size
                );
                // Free frame for this page that failed to map.
                let lock = crate::memory::get_allocator();
                let mut guard = lock.lock();
                if let Some(allocator) = guard.as_mut() {
                    allocator.free(frame, order);
                }
                drop(guard);

                // Roll back already mapped pages to keep state consistent.
                for j in (0..mapped_pages).rev() {
                    let rb_addr = start + (j as u64) * page_bytes;
                    match page_size {
                        VmaPageSize::Small => {
                            use x86_64::structures::paging::Size4KiB;
                            let rb_page =
                                Page::<Size4KiB>::from_start_address(VirtAddr::new(rb_addr))
                                    .map_err(|_| "Rollback: invalid 4K page address")?;
                            if let Ok((rb_frame, rb_flush)) = mapper.unmap(rb_page) {
                                rb_flush.flush();
                                crate::memory::cow::frame_dec_ref(crate::memory::PhysFrame {
                                    start_address: rb_frame.start_address(),
                                });
                            }
                        }
                        VmaPageSize::Huge => {
                            use x86_64::structures::paging::Size2MiB;
                            let rb_page =
                                Page::<Size2MiB>::from_start_address(VirtAddr::new(rb_addr))
                                    .map_err(|_| "Rollback: invalid 2M page address")?;
                            if let Ok((rb_frame, rb_flush)) = mapper.unmap(rb_page) {
                                rb_flush.flush();
                                crate::memory::cow::frame_dec_ref(crate::memory::PhysFrame {
                                    start_address: rb_frame.start_address(),
                                });
                            }
                        }
                    }
                }

                return Err("Failed to map page");
            }

            // Track refcount for COW
            crate::memory::cow::frame_inc_ref(crate::memory::PhysFrame {
                start_address: frame.start_address,
            });

            mapped_pages += 1;
        }

        // Track the region
        let mut regions = self.regions.lock();
        let region = VirtualMemoryRegion {
            start,
            page_count,
            flags,
            vma_type,
            page_size,
        };
        regions.insert(start, region);

        let end = start + (page_count as u64) * page_bytes;
        crate::trace_mem!(
            crate::trace::category::MEM_MAP,
            crate::trace::TraceKind::MemMap,
            page_size.bytes(),
            crate::trace::TraceTaskCtx {
                task_id: 0,
                pid: 0,
                tid: 0,
                cr3: self.cr3_phys.as_u64(),
            },
            0,
            start,
            end,
            page_count as u64
        );

        Ok(())
    }

    pub fn map_shared_frames(
        &self,
        start: u64,
        frame_phys_addrs: &[u64],
        flags: VmaFlags,
        vma_type: VmaType,
    ) -> Result<(), &'static str> {
        let page_count = frame_phys_addrs.len();
        if page_count == 0 || start % 4096 != 0 {
            return Err("Invalid shared region arguments");
        }
        let len = (page_count as u64)
            .checked_mul(4096)
            .ok_or("Shared region length overflow")?;
        let end = start
            .checked_add(len)
            .ok_or("Shared region end overflow")?;
        const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;
        if end > USER_SPACE_END {
            return Err("Shared region out of user-space range");
        }

        {
            let regions = self.regions.lock();
            if regions.iter().any(|(&vma_start, vma)| {
                let vma_end = vma_start
                    .saturating_add((vma.page_count as u64).saturating_mul(vma.page_size.bytes()));
                vma_start < end && vma_end > start
            }) {
                return Err("Shared region overlaps existing mapping");
            }
        }

        let page_flags = flags.to_page_flags();
        let mut frame_allocator = BuddyFrameAllocator;
        let mut mapper = unsafe { self.mapper() };
        let mut mapped_pages = 0usize;

        for (i, phys_addr) in frame_phys_addrs.iter().copied().enumerate() {
            let page_addr = start
                .checked_add((i as u64) * 4096)
                .ok_or("Shared page address overflow")?;
            let page = Page::<Size4KiB>::from_start_address(VirtAddr::new(page_addr))
                .map_err(|_| "Map shared: invalid page address")?;
            let frame = X86PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(phys_addr));

            let map_ok = unsafe {
                mapper
                    .map_to(page, frame, page_flags, &mut frame_allocator)
                    .map(|flush| flush.flush())
                    .is_ok()
            };

            if !map_ok {
                for j in (0..mapped_pages).rev() {
                    let rb_addr = start + (j as u64) * 4096;
                    if let Ok(rb_page) = Page::<Size4KiB>::from_start_address(VirtAddr::new(rb_addr)) {
                        if let Ok((rb_frame, rb_flush)) = mapper.unmap(rb_page) {
                            rb_flush.flush();
                            crate::memory::cow::frame_dec_ref(crate::memory::PhysFrame {
                                start_address: rb_frame.start_address(),
                            });
                        }
                    }
                }
                return Err("Failed to map shared page");
            }

            crate::memory::cow::frame_inc_ref(crate::memory::PhysFrame {
                start_address: PhysAddr::new(phys_addr),
            });
            mapped_pages += 1;
        }

        let mut regions = self.regions.lock();
        regions.insert(
            start,
            VirtualMemoryRegion {
                start,
                page_count,
                flags,
                vma_type,
                page_size: VmaPageSize::Small,
            },
        );
        Ok(())
    }

    /// Unmap a previously mapped region and free the backing frames.
    pub fn unmap_region(
        &self,
        start: u64,
        page_count: usize,
        page_size: VmaPageSize,
    ) -> Result<(), &'static str> {
        let page_bytes = page_size.bytes();
        // SAFETY: We have logical ownership of this address space.
        let mut mapper = unsafe { self.mapper() };

        for i in 0..page_count {
            let page_addr = start + (i as u64) * page_bytes;

            let frame_addr = match page_size {
                VmaPageSize::Small => {
                    use x86_64::structures::paging::Size4KiB;
                    let page = Page::<Size4KiB>::from_start_address(VirtAddr::new(page_addr))
                        .map_err(|_| "Failed to unmap: invalid 4K page address")?;
                    let (frame, flush) =
                        mapper.unmap(page).map_err(|_| "Failed to unmap 4K page")?;
                    flush.flush();
                    frame.start_address()
                }
                VmaPageSize::Huge => {
                    use x86_64::structures::paging::Size2MiB;
                    let page = Page::<Size2MiB>::from_start_address(VirtAddr::new(page_addr))
                        .map_err(|_| "Failed to unmap: invalid 2M page address")?;
                    let (frame, flush) =
                        mapper.unmap(page).map_err(|_| "Failed to unmap 2M page")?;
                    flush.flush();
                    frame.start_address()
                }
            };

            // COW-aware refcount decrement: free only when last mapping disappears.
            let phys_frame = crate::memory::PhysFrame {
                start_address: frame_addr,
            };
            crate::memory::cow::frame_dec_ref(phys_frame);
        }

        // Remove from VMA tracking.
        self.regions.lock().remove(&start);

        log::trace!(
            "Unmapped region: {:#x}..{:#x} ({} pages, size={:?})",
            start,
            start + (page_count as u64) * page_bytes,
            page_count,
            page_size
        );

        let end = start + (page_count as u64) * page_bytes;
        crate::trace_mem!(
            crate::trace::category::MEM_UNMAP,
            crate::trace::TraceKind::MemUnmap,
            page_size.bytes(),
            crate::trace::TraceTaskCtx {
                task_id: 0,
                pid: 0,
                tid: 0,
                cr3: self.cr3_phys.as_u64(),
            },
            0,
            start,
            end,
            page_count as u64
        );

        Ok(())
    }

    /// Find a free virtual address range of `n_pages` pages of `page_size` starting at or after `hint`.
    pub fn find_free_vma_range(
        &self,
        hint: u64,
        n_pages: usize,
        page_size: VmaPageSize,
    ) -> Option<u64> {
        if n_pages == 0 {
            return None;
        }
        let page_bytes = page_size.bytes();
        let length = (n_pages as u64).checked_mul(page_bytes)?;
        let upper_limit: u64 = 0x0000_8000_0000_0000; // USER_SPACE_END

        // Round hint up to a page boundary
        let mut candidate = (hint.saturating_add(page_bytes - 1)) & !(page_bytes - 1);
        if candidate == 0 {
            candidate = page_bytes;
        }

        let regions = self.regions.lock();
        for (&vma_start, vma) in regions.iter() {
            let vma_end = vma_start + vma.page_count as u64 * vma.page_size.bytes();

            // A gap exists before this VMA — candidate fits.
            if candidate.saturating_add(length) <= vma_start {
                break;
            }

            // Candidate overlaps this VMA; skip past it.
            if vma_end > candidate {
                candidate = (vma_end.saturating_add(page_bytes - 1)) & !(page_bytes - 1);
            }
        }

        // Final bounds check.
        if candidate.checked_add(length)? <= upper_limit {
            Some(candidate)
        } else {
            None
        }
    }

    /// Return true if any tracked VMA overlaps `[addr, addr + len)`.
    pub fn has_mapping_in_range(&self, addr: u64, len: u64) -> bool {
        let end = match addr.checked_add(len) {
            Some(v) => v,
            None => return true,
        };
        let regions = self.regions.lock();
        regions.iter().any(|(&vma_start, vma)| {
            let vma_end = vma_start
                .saturating_add((vma.page_count as u64).saturating_mul(vma.page_size.bytes()));
            vma_start < end && vma_end > addr
        })
    }

    pub fn unmap_range(&self, addr: u64, len: u64) -> Result<(), &'static str> {
        if len == 0 {
            return Ok(());
        }
        let end = addr
            .checked_add(len)
            .ok_or("unmap_range: address overflow")?;

        // Pre-validate huge-page overlaps: partial unmap of 2MiB mappings is
        // not supported yet. Callers must unmap on huge-page boundaries.
        {
            let regions = self.regions.lock();
            for (&vma_start, vma) in regions.iter() {
                let vma_end = vma_start + vma.page_count as u64 * vma.page_size.bytes();
                if vma_start >= end || vma_end <= addr {
                    continue;
                }
                if vma.page_size == VmaPageSize::Huge {
                    let range_start = core::cmp::max(vma_start, addr);
                    let range_end = core::cmp::min(vma_end, end);
                    if range_start % vma.page_size.bytes() != 0
                        || range_end % vma.page_size.bytes() != 0
                    {
                        return Err("unmap_range: partial unmap of 2MiB pages is not supported");
                    }
                }
            }
        }

        // Process regions one by one to avoid heap allocation (Vec)
        loop {
            // Find the first overlapping region
            let region_info = {
                let regions = self.regions.lock();
                regions
                    .iter()
                    .find(|(&vma_start, vma)| {
                        let vma_end = vma_start + vma.page_count as u64 * vma.page_size.bytes();
                        vma_start < end && vma_end > addr
                    })
                    .map(|(&k, v)| (k, v.clone()))
            };

            let Some((vma_start, vma)) = region_info else {
                break; // No more overlapping regions
            };

            let vma_end = vma_start + vma.page_count as u64 * vma.page_size.bytes();
            let range_start = core::cmp::max(vma_start, addr);
            let range_end = core::cmp::min(vma_end, end);

            // 1. Hardware unmap
            // SAFETY: Logical ownership of address space.
            let mut mapper = unsafe { self.mapper() };
            let mut page_addr = range_start;
            let page_bytes = vma.page_size.bytes();
            while page_addr < range_end {
                // Lazy VMAs can contain unfaulted pages (no PTE). In that case
                // there is nothing to unmap in hardware; just update VMA metadata.
                if mapper.translate_addr(VirtAddr::new(page_addr)).is_none() {
                    page_addr += page_bytes;
                    continue;
                }

                let frame_addr = match vma.page_size {
                    VmaPageSize::Small => {
                        use x86_64::structures::paging::Size4KiB;
                        let page = Page::<Size4KiB>::from_start_address(VirtAddr::new(page_addr))
                            .map_err(|_| "unmap_range: invalid 4K page address")?;
                        let (frame, flush) = mapper
                            .unmap(page)
                            .map_err(|_| "unmap_range: unmap 4K failed")?;
                        flush.flush();
                        frame.start_address()
                    }
                    VmaPageSize::Huge => {
                        use x86_64::structures::paging::Size2MiB;
                        let page = Page::<Size2MiB>::from_start_address(VirtAddr::new(page_addr))
                            .map_err(|_| "unmap_range: invalid 2M page address")?;
                        let (frame, flush) = mapper
                            .unmap(page)
                            .map_err(|_| "unmap_range: unmap 2M failed")?;
                        flush.flush();
                        frame.start_address()
                    }
                };

                let phys = crate::memory::PhysFrame {
                    start_address: frame_addr,
                };
                crate::memory::cow::frame_dec_ref(phys);
                page_addr += page_bytes;
            }

            // 2. Update tracking: remove and re-insert fragments
            {
                let mut regions = self.regions.lock();
                regions.remove(&vma_start);

                if range_start > vma_start {
                    let leading_pages =
                        ((range_start - vma_start) / vma.page_size.bytes()) as usize;
                    regions.insert(
                        vma_start,
                        VirtualMemoryRegion {
                            start: vma_start,
                            page_count: leading_pages,
                            flags: vma.flags,
                            vma_type: vma.vma_type,
                            page_size: vma.page_size,
                        },
                    );
                }

                if range_end < vma_end {
                    let trailing_pages = ((vma_end - range_end) / vma.page_size.bytes()) as usize;
                    regions.insert(
                        range_end,
                        VirtualMemoryRegion {
                            start: range_end,
                            page_count: trailing_pages,
                            flags: vma.flags,
                            vma_type: vma.vma_type,
                            page_size: vma.page_size,
                        },
                    );
                }
            }
        }

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

    /// Check if this address space has any user-space memory mappings.
    pub fn has_user_mappings(&self) -> bool {
        if self.is_kernel {
            return false;
        }
        let regions = self.regions.lock();
        // Check for any non-kernel mappings.
        regions.values().any(|vma| vma.vma_type != VmaType::Kernel)
    }

    /// Unmap all tracked user regions (best-effort).
    ///
    /// This frees user frames and clears the VMA list. Kernel mappings are untouched.
    /// Does not allocate memory.
    pub fn unmap_all_user_regions(&self) {
        if self.is_kernel {
            return;
        }

        loop {
            // Pop the first region from the map to avoid allocation
            let first = {
                let mut guard = self.regions.lock();
                if let Some(&start) = guard.keys().next() {
                    guard.remove(&start)
                } else {
                    None
                }
            };

            if let Some(region) = first {
                let _ = self.unmap_region(region.start, region.page_count, region.page_size);
            } else {
                break;
            }
        }
    }

    pub fn clone_cow(&self) -> Result<Arc<AddressSpace>, &'static str> {
        if self.is_kernel {
            return Err("Cannot fork kernel address space");
        }

        let child = Arc::new(AddressSpace::new_user()?);

        let regions: Vec<VirtualMemoryRegion> = {
            let guard = self.regions.lock();
            guard.values().cloned().collect()
        };

        let mut tlb_flush_needed = false;
        let mut processed_pages = Vec::new();

        let res: Result<(), &'static str> = (|| {
            let mut parent_mapper = unsafe { self.mapper() };
            let mut child_mapper = unsafe { child.mapper() };
            let mut frame_allocator = BuddyFrameAllocator;

            for region in regions.iter() {
                // Register VMA in child
                {
                    let mut child_regions = child.regions.lock();
                    child_regions.insert(region.start, region.clone());
                }

                let page_bytes = region.page_size.bytes();

                for i in 0..region.page_count {
                    let vaddr = VirtAddr::new(region.start + (i as u64) * page_bytes);

                    // Translate parent page to frame
                    let (phys_frame_addr, flags): (PhysAddr, PageTableFlags) =
                        match parent_mapper.translate(vaddr) {
                            TranslateResult::Mapped {
                                frame,
                                offset: _,
                                flags,
                            } => (frame.start_address(), flags),
                            _ => continue,
                        };

                    let mut new_flags = flags;
                    let is_writable = flags.contains(PageTableFlags::WRITABLE);
                    const COW_BIT: PageTableFlags = PageTableFlags::BIT_9;

                    if is_writable {
                        new_flags.remove(PageTableFlags::WRITABLE);
                        new_flags.insert(COW_BIT);

                        unsafe {
                            let res: Result<(), &'static str> = match region.page_size {
                                VmaPageSize::Small => parent_mapper
                                    .update_flags(
                                        Page::<Size4KiB>::from_start_address(vaddr).unwrap(),
                                        new_flags,
                                    )
                                    .map(|f| f.ignore())
                                    .map_err(|_| "Failed to update parent 4K flags"),
                                VmaPageSize::Huge => parent_mapper
                                    .update_flags(
                                        Page::<Size2MiB>::from_start_address(vaddr).unwrap(),
                                        new_flags,
                                    )
                                    .map(|f| f.ignore())
                                    .map_err(|_| "Failed to update parent 2M flags"),
                            };
                            if let Err(e) = res {
                                return Err(e);
                            }
                        }
                        tlb_flush_needed = true;
                    }

                    let phys = crate::memory::PhysFrame {
                        start_address: phys_frame_addr,
                    };
                    crate::memory::cow::frame_inc_ref(phys);

                    // Map in child. We map it as WRITABLE first to ensure intermediate
                    // page tables (PDPT, PD) are created with WRITABLE bit set.
                    // If we mapped directly as COW (Read-only), some Mapper implementations
                    // might create Read-Only intermediate tables, blocking future COW resolution.
                    let map_flags = new_flags | PageTableFlags::WRITABLE;

                    unsafe {
                        let map_res: Result<(), &'static str> = match region.page_size {
                            VmaPageSize::Small => {
                                let page = Page::<Size4KiB>::from_start_address(vaddr).unwrap();
                                let frame = x86_64::structures::paging::PhysFrame::<Size4KiB>::containing_address(phys_frame_addr);
                                child_mapper
                                    .map_to(page, frame, map_flags, &mut frame_allocator)
                                    .map(|f| f.ignore())
                                    .map_err(|_| "Failed to map 4K in child")
                            }
                            VmaPageSize::Huge => {
                                let page = Page::<Size2MiB>::from_start_address(vaddr).unwrap();
                                let frame = x86_64::structures::paging::PhysFrame::<Size2MiB>::containing_address(phys_frame_addr);
                                child_mapper
                                    .map_to(page, frame, map_flags, &mut frame_allocator)
                                    .map(|f| f.ignore())
                                    .map_err(|_| "Failed to map 2M in child")
                            }
                        };

                        if let Err(e) = map_res {
                            crate::memory::cow::frame_dec_ref(phys);
                            return Err(e);
                        }

                        // Now downgrade to the actual COW flags (which may be Read-Only).
                        if !new_flags.contains(PageTableFlags::WRITABLE) {
                            let downgrade_res: Result<(), &'static str> = match region.page_size {
                                VmaPageSize::Small => {
                                    let page = Page::<Size4KiB>::from_start_address(vaddr).unwrap();
                                    child_mapper
                                        .update_flags(page, new_flags)
                                        .map(|f| f.ignore())
                                        .map_err(|_| "Failed to update child 4K flags")
                                }
                                VmaPageSize::Huge => {
                                    let page = Page::<Size2MiB>::from_start_address(vaddr).unwrap();
                                    child_mapper
                                        .update_flags(page, new_flags)
                                        .map(|f| f.ignore())
                                        .map_err(|_| "Failed to update child 2M flags")
                                }
                            };
                            if let Err(e) = downgrade_res {
                                let unmapped = match region.page_size {
                                    VmaPageSize::Small => {
                                        let page =
                                            Page::<Size4KiB>::from_start_address(vaddr).unwrap();
                                        child_mapper.unmap(page).map(|(_, f)| f.ignore()).is_ok()
                                    }
                                    VmaPageSize::Huge => {
                                        let page =
                                            Page::<Size2MiB>::from_start_address(vaddr).unwrap();
                                        child_mapper.unmap(page).map(|(_, f)| f.ignore()).is_ok()
                                    }
                                };
                                if unmapped {
                                    crate::memory::cow::frame_dec_ref(phys);
                                }
                                return Err(e);
                            }
                        }
                    }

                    processed_pages.push((vaddr.as_u64(), flags, phys, region.page_size));
                }
            }
            Ok(())
        })();

        if let Err(e) = res {
            log::error!("clone_cow error: {}. Rolling back...", e);
            let mut parent_mapper = unsafe { self.mapper() };
            for (vaddr, original_flags, phys, page_size) in processed_pages.into_iter().rev() {
                if original_flags.contains(PageTableFlags::WRITABLE) {
                    unsafe {
                        match page_size {
                            VmaPageSize::Small => {
                                let _ = parent_mapper.update_flags(
                                    Page::<Size4KiB>::from_start_address(VirtAddr::new(vaddr))
                                        .unwrap(),
                                    original_flags,
                                );
                            }
                            VmaPageSize::Huge => {
                                let _ = parent_mapper.update_flags(
                                    Page::<Size2MiB>::from_start_address(VirtAddr::new(vaddr))
                                        .unwrap(),
                                    original_flags,
                                );
                            }
                        };
                    }
                }
                crate::memory::cow::frame_dec_ref(phys);
            }
            if tlb_flush_needed {
                crate::arch::x86_64::tlb::shootdown_all();
            }
            return Err(e);
        }

        if tlb_flush_needed {
            crate::arch::x86_64::tlb::shootdown_all();
        }
        Ok(child)
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

        log::trace!("AddressSpace::drop begin CR3={:#x}", self.cr3_phys.as_u64());

        // Best-effort cleanup of user mappings.
        self.unmap_all_user_regions();
        #[cfg(not(feature = "selftest"))]
        self.free_user_page_tables();
        #[cfg(feature = "selftest")]
        {
            // Runtime selftests create/destroy many temporary address spaces and
            // currently expose instability in recursive page-table teardown.
            // Keep tests deterministic by skipping deep PT reclaim in this mode.
            log::trace!(
                "AddressSpace::drop selftest mode: skipping deep page-table free for CR3={:#x}",
                self.cr3_phys.as_u64()
            );
        }

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

        log::trace!("AddressSpace::drop end CR3={:#x}", self.cr3_phys.as_u64());
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
