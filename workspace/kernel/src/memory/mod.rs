// Memory management module

pub mod address_space;
pub mod boot_alloc;
pub mod buddy;
pub mod cow;
pub mod frame;
pub mod heap;
pub mod paging;
pub mod userslice;
pub mod zone;

use crate::{boot::entry::MemoryRegion, sync::IrqDisabledToken};
use core::sync::atomic::{AtomicU64, Ordering};

/// Higher Half Direct Map offset.
/// Set by Limine entry (non-zero) or left at 0 for BIOS/identity-mapped boot.
/// All physical-to-virtual conversions must add this offset.
static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Store the HHDM offset (call once, early in boot)
pub fn set_hhdm_offset(offset: u64) {
    HHDM_OFFSET.store(offset, Ordering::Relaxed);
}

/// Get the current HHDM offset
pub fn hhdm_offset() -> u64 {
    HHDM_OFFSET.load(Ordering::Relaxed)
}

/// Convert a physical address to a virtual address using the HHDM offset
#[inline]
pub fn phys_to_virt(phys: u64) -> u64 {
    phys.wrapping_add(HHDM_OFFSET.load(Ordering::Relaxed))
}

/// Convert a virtual address back to a physical address (reverse of phys_to_virt)
#[inline]
pub fn virt_to_phys(virt: u64) -> u64 {
    virt.wrapping_sub(HHDM_OFFSET.load(Ordering::Relaxed))
}

/// Initialize the memory management subsystem
pub fn init_memory_manager(memory_regions: &[MemoryRegion]) {
    buddy::init_buddy_allocator(memory_regions);
    // Race/corruption diagnostic: register slab lock for E9 LOCK-A/LOCK-R traces.
    heap::debug_register_slab_trace();
}

/// Initialize copy-on-write metadata.
pub fn init_cow_subsystem(_memory_regions: &[MemoryRegion]) {}

// Re-exports
pub use crate::sync::with_irqs_disabled;
pub use address_space::{kernel_address_space, AddressSpace, VmaFlags, VmaPageSize, VmaType};
pub use buddy::get_allocator;
pub use frame::{AllocError, FrameAllocOptions, FrameAllocator, FramePurpose, PhysFrame};
pub use userslice::{UserSliceError, UserSliceRead, UserSliceReadWrite, UserSliceWrite};

/// Allocate `2^order` contiguous physical frames (raw, no zeroing).
///
/// Prefer `FrameAllocOptions::new().allocate(token)` for order-0 allocations
/// where zeroing or metadata stamping is needed (page tables, anonymous pages).
/// This raw path is kept for multi-page / DMA bulk allocations where the caller
/// manages zeroing explicitly.
#[inline]
pub fn allocate_frames(token: &IrqDisabledToken, order: u8) -> Result<PhysFrame, AllocError> {
    buddy::alloc(token, order)
}

/// Free `2^order` contiguous physical frames.
///
/// Requires an `IrqDisabledToken` proving that IRQs are disabled on the calling CPU.
#[inline]
pub fn free_frames(token: &IrqDisabledToken, frame: PhysFrame, order: u8) {
    buddy::free(token, frame, order);
}

/// Allocate a single **zeroed** physical frame with `KernelData` purpose.
///
/// This is the standard allocation path for all kernel-internal frames.  It
/// uses `FrameAllocOptions::new()` (zeroed = true, purpose = KernelData) and
/// performs the UNUSED → 0 → 1 refcount CAS (Asterinas OSTD pattern).
///
/// For page-table node allocation use `BuddyFrameAllocator` (via paging.rs)
/// or `FrameAllocOptions::new().purpose(FramePurpose::PageTable).allocate()`.
/// For user-space frames use `FrameAllocOptions::new().purpose(FramePurpose::UserData)`.
#[inline]
pub fn allocate_frame(token: &IrqDisabledToken) -> Result<PhysFrame, AllocError> {
    FrameAllocOptions::new().allocate(token)
}

/// Free a single physical frame.
#[inline]
pub fn free_frame(token: &IrqDisabledToken, frame: PhysFrame) {
    free_frames(token, frame, 0);
}

/// Allocate a zeroed 4 KiB frame suitable for DMA operations.
///
/// Disables IRQs internally.  The frame is zeroed before being returned
/// (guaranteed by `FrameAllocOptions::new()` — zeroed = true by default).
pub fn allocate_dma_frame() -> Option<PhysFrame> {
    with_irqs_disabled(|token| {
        // `FrameAllocOptions::new()` defaults to zeroed = true; no manual
        // `write_bytes` call is needed here any more.
        FrameAllocOptions::new()
            .purpose(FramePurpose::KernelData)
            .allocate(token)
            .ok()
    })
}
