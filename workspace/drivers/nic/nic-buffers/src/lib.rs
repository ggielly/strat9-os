#![no_std]

/// Error type for DMA allocation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaAllocError;

#[derive(Clone, Copy)]
pub struct DmaRegion {
    /// Physical base address (CPU side, and device side when not translated).
    pub phys: u64,
    /// IOVA assigned by the device's IOMMU domain, or 0 when untranslated.
    pub iova: u64,
    /// Owning IOMMU domain id, or 0 when untranslated.
    pub domain_id: u16,
    pub virt: *mut u8,
    pub size: usize,
}

// SAFETY: DmaRegion contains only numeric addresses, a raw pointer, and a
// size.  It is safe to send across threads because the underlying DMA memory
// is accessed only through the allocator's synchronization guarantees.
unsafe impl Send for DmaRegion {}
// SAFETY: DmaRegion is safe to share between threads for the same reasons
// as Send above; concurrent access is controlled by the allocator.
unsafe impl Sync for DmaRegion {}

impl DmaRegion {
    pub const ZERO: Self = Self {
        phys: 0,
        iova: 0,
        domain_id: 0,
        virt: core::ptr::null_mut(),
        size: 0,
    };

    /// Returns whether null.
    pub fn is_null(&self) -> bool {
        self.virt.is_null()
    }

    /// Address the device must program for this region.
    ///
    /// This is the IOVA when the region is mapped into an IOMMU domain, and
    /// the physical address otherwise.
    pub fn device_addr(&self) -> u64 {
        if self.iova != 0 {
            self.iova
        } else {
            self.phys
        }
    }

    /// True when the region is mapped into an IOMMU domain.
    pub fn is_translated(&self) -> bool {
        self.iova != 0
    }
}

pub trait DmaAllocator {
    /// Allocates dma.
    fn alloc_dma(&self, size: usize) -> Result<DmaRegion, DmaAllocError>;
    /// # Safety
    ///
    /// The caller must ensure that `region` was previously allocated by this
    /// allocator and has not already been freed.
    unsafe fn free_dma(&self, region: DmaRegion);
}
