use core::sync::atomic::{AtomicUsize, Ordering};

pub struct MmioRegion {
    base: AtomicUsize,
    size: usize,
}

impl MmioRegion {
    /// Creates a new instance.
    pub const fn new() -> Self {
        Self {
            base: AtomicUsize::new(0),
            size: 0,
        }
    }

    /// Performs the init operation.
    pub fn init(&mut self, base: usize, size: usize) {
        self.base.store(base, Ordering::Release);
        self.size = size;
    }

    /// Performs the base operation.
    pub fn base(&self) -> usize {
        self.base.load(Ordering::Acquire)
    }

    /// Returns whether valid.
    pub fn is_valid(&self) -> bool {
        self.base() != 0
    }

    /// Performs the checked addr operation.
    fn checked_addr(&self, offset: usize, width: usize) -> usize {
        let base = self.base();
        assert!(base != 0);
        let end = offset.checked_add(width).expect("mmio offset overflow");
        assert!(end <= self.size);
        base.checked_add(offset).expect("mmio address overflow")
    }

    /// Performs the read8 operation.
    pub fn read8(&self, offset: usize) -> u8 {
        let addr = self.checked_addr(offset, core::mem::size_of::<u8>());
        // SAFETY: caller guarantees this address is a valid MMIO region
        unsafe { core::ptr::read_volatile(addr as *const u8) }
    }

    /// Performs the read16 operation.
    pub fn read16(&self, offset: usize) -> u16 {
        let addr = self.checked_addr(offset, core::mem::size_of::<u16>());
        // SAFETY: caller guarantees this address is a valid MMIO region
        unsafe { core::ptr::read_volatile(addr as *const u16) }
    }

    /// Performs the read32 operation.
    pub fn read32(&self, offset: usize) -> u32 {
        let addr = self.checked_addr(offset, core::mem::size_of::<u32>());
        // SAFETY: caller guarantees this address is a valid MMIO region
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }

    /// Performs the read64 operation.
    pub fn read64(&self, offset: usize) -> u64 {
        let addr = self.checked_addr(offset, core::mem::size_of::<u64>());
        // SAFETY: caller guarantees this address is a valid MMIO region
        unsafe { core::ptr::read_volatile(addr as *const u64) }
    }

    /// Performs the write8 operation.
    pub fn write8(&self, offset: usize, val: u8) {
        let addr = self.checked_addr(offset, core::mem::size_of::<u8>());
        // SAFETY: caller guarantees this address is a valid MMIO region
        unsafe { core::ptr::write_volatile(addr as *mut u8, val) }
    }

    /// Performs the write16 operation.
    pub fn write16(&self, offset: usize, val: u16) {
        let addr = self.checked_addr(offset, core::mem::size_of::<u16>());
        // SAFETY: caller guarantees this address is a valid MMIO region
        unsafe { core::ptr::write_volatile(addr as *mut u16, val) }
    }

    /// Performs the write32 operation.
    pub fn write32(&self, offset: usize, val: u32) {
        let addr = self.checked_addr(offset, core::mem::size_of::<u32>());
        // SAFETY: caller guarantees this address is a valid MMIO region
        unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
    }

    /// Performs the write64 operation.
    pub fn write64(&self, offset: usize, val: u64) {
        let addr = self.checked_addr(offset, core::mem::size_of::<u64>());
        // SAFETY: caller guarantees this address is a valid MMIO region
        unsafe { core::ptr::write_volatile(addr as *mut u64, val) }
    }

    /// Sets bits32.
    pub fn set_bits32(&self, offset: usize, bits: u32) {
        let val = self.read32(offset);
        self.write32(offset, val | bits);
    }

    /// Performs the clear bits32 operation.
    pub fn clear_bits32(&self, offset: usize, bits: u32) {
        let val = self.read32(offset);
        self.write32(offset, val & !bits);
    }

    /// Performs the modify32 operation.
    pub fn modify32(&self, offset: usize, clear: u32, set: u32) {
        let val = self.read32(offset);
        self.write32(offset, (val & !clear) | set);
    }

    /// Reads field32.
    pub fn read_field32(&self, offset: usize, mask: u32, shift: u32) -> u32 {
        (self.read32(offset) & mask) >> shift
    }

    /// Writes field32.
    pub fn write_field32(&self, offset: usize, mask: u32, shift: u32, value: u32) {
        self.modify32(offset, mask, (value << shift) & mask);
    }
}

// SAFETY: MmioRegion contains only an atomic base address and a size.
// Access to the MMIO region itself requires the caller to ensure
// the mapping is valid and not concurrently mutated.
unsafe impl Send for MmioRegion {}
unsafe impl Sync for MmioRegion {}

/// Performs the memory barrier operation.
pub fn memory_barrier() {
    core::sync::atomic::fence(Ordering::SeqCst);
}
