#![no_std]

/// Error type for DMA allocation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaAllocError;

#[derive(Clone, Copy)]
pub struct DmaRegion {
    pub phys: u64,
    pub virt: *mut u8,
    pub size: usize,
}

// SAFETY: DmaRegion contains only a physical address, a raw pointer, and a size.
// It is safe to send across threads because the underlying DMA memory is
// accessed only through the allocator's synchronization guarantees.
unsafe impl Send for DmaRegion {}
// SAFETY: DmaRegion is safe to share between threads for the same reasons
// as Send above; concurrent access is controlled by the allocator.
unsafe impl Sync for DmaRegion {}

impl DmaRegion {
    pub const ZERO: Self = Self {
        phys: 0,
        virt: core::ptr::null_mut(),
        size: 0,
    };

    pub fn is_null(&self) -> bool {
        self.virt.is_null()
    }
}

pub trait DmaAllocator {
    fn alloc_dma(&self, size: usize) -> Result<DmaRegion, DmaAllocError>;
    /// # Safety
    ///
    /// The caller must ensure that `region` was previously allocated by this
    /// allocator and has not already been freed.
    unsafe fn free_dma(&self, region: DmaRegion);
}
