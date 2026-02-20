// Memory management module

pub mod address_space;
pub mod buddy;
pub mod cow;
pub mod frame;
pub mod heap;
pub mod paging;
pub mod userslice;
pub mod zone;

use crate::entry::MemoryRegion;
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
}

// Re-exports
pub use address_space::{kernel_address_space, AddressSpace, VmaFlags, VmaType};
pub use buddy::get_allocator;
pub use frame::{AllocError, FrameAllocator, PhysFrame};
pub use userslice::{UserSliceError, UserSliceRead, UserSliceReadWrite, UserSliceWrite};

// TODO: Implement slab allocator
