#![no_std]

#[derive(Clone, Copy)]
pub struct DmaRegion {
    pub phys: u64,
    pub virt: *mut u8,
    pub size: usize,
}

unsafe impl Send for DmaRegion {}
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
    fn alloc_dma(&self, size: usize) -> Result<DmaRegion, ()>;
    unsafe fn free_dma(&self, region: DmaRegion);
}
