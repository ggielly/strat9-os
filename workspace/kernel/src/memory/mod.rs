// Memory management module

pub mod address_space;
pub mod buddy;
pub mod cow;
pub mod frame;
pub mod heap;
pub mod paging;
pub mod userslice;
pub mod zone;

use crate::boot::entry::MemoryRegion;
use alloc::{boxed::Box, vec::Vec};
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
    init_cow_metadata(memory_regions);
}

fn init_cow_metadata(memory_regions: &[MemoryRegion]) {
    use crate::boot::entry::MemoryKind;

    let max_end = memory_regions
        .iter()
        .filter(|r| matches!(r.kind, MemoryKind::Free | MemoryKind::Reclaim))
        .map(|r| r.base.saturating_add(r.size))
        .max()
        .unwrap_or(0);

    if max_end == 0 {
        log::warn!("COW metadata not initialized: no usable memory regions");
        return;
    }

    let max_pfn = ((max_end.saturating_add(4095)) / 4096) as usize;
    let mut metas = Vec::with_capacity(max_pfn);
    for _ in 0..max_pfn {
        metas.push(cow::FrameMeta::new());
    }

    let boxed = metas.into_boxed_slice();
    let ptr = Box::into_raw(boxed) as *mut cow::FrameMeta;

    // SAFETY: `ptr` points to a leaked boxed slice of exactly `max_pfn` entries.
    unsafe {
        cow::init_frame_metadata(max_pfn, ptr);
    }
}

// Re-exports
pub use address_space::{kernel_address_space, AddressSpace, VmaFlags, VmaPageSize, VmaType};
pub use buddy::get_allocator;
pub use frame::{AllocError, FrameAllocator, PhysFrame};
pub use userslice::{UserSliceError, UserSliceRead, UserSliceReadWrite, UserSliceWrite};

/// Allocate a zeroed 4KB frame suitable for DMA operations
pub fn allocate_dma_frame() -> Option<PhysFrame> {
    let mut allocator = get_allocator().lock();
    let frame = allocator.as_mut()?.alloc_frame().ok()?;
    // Zero the frame
    let virt = phys_to_virt(frame.start_address.as_u64()) as *mut u8;
    unsafe {
        core::ptr::write_bytes(virt, 0, 4096);
    }
    Some(frame)
}

// TODO: Implement slab allocator
