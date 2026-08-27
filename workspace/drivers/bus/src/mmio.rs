use core::sync::atomic::Ordering;

pub struct MmioRegion {
    base: usize,
    size: usize,
}

impl MmioRegion {
    /// Creates a new instance.
    pub const fn new() -> Self {
        Self { base: 0, size: 0 }
    }

    /// Performs the init operation.
    pub fn init(&mut self, base: usize, size: usize) {
        self.base = base;
        self.size = size;
    }

    /// Performs the base operation.
    pub fn base(&self) -> usize {
        self.base
    }

    /// Returns whether valid.
    pub fn is_valid(&self) -> bool {
        self.base != 0
    }

    /// Bounds + alignment check for a would-be access of `width` bytes at
    /// `offset`, without performing it.
    ///
    /// Drivers exposing user-controllable offsets (e.g. `/bus/<drv>/reg/<hex>`)
    /// must call this before touching MMIO so an out-of-range request fails
    /// with a clean error instead of tripping the panic backstop in
    /// [`Self::checked_addr`] and taking the kernel down.
    pub fn contains(&self, offset: usize, width: usize) -> bool {
        if width == 0 {
            return false;
        }
        match offset.checked_add(width) {
            Some(end) => self.base != 0 && end <= self.size && offset % width == 0,
            None => false,
        }
    }
    /// Validate a caller-supplied 32-bit register offset (bounds + natural
    /// alignment), mapping failures to [`BusError::InvalidAddress`] instead
    /// of tripping the panic backstop inside the accessors.
    pub fn check_user_offset(&self, offset: usize) -> Result<(), crate::BusError> {
        if self.contains(offset, core::mem::size_of::<u32>()) {
            Ok(())
        } else {
            Err(crate::BusError::InvalidAddress)
        }
    }

    /// Performs the checked addr operation.
    ///
    /// Enforces region bounds AND natural alignment for the access width:
    /// `read_volatile`/`write_volatile` on a misaligned pointer is UB on
    /// several supported architectures (strict-alignment ARM/MIPS), not
    /// just a slow access.
    fn checked_addr(&self, offset: usize, width: usize) -> usize {
        let base = self.base();
        assert!(base != 0, "mmio access on uninitialized MmioRegion");
        let end = offset.checked_add(width).expect("mmio offset overflow");
        assert!(
            end <= self.size,
            "mmio access out of bounds (offset={:#x}, width={}, size={:#x})",
            offset,
            width,
            self.size
        );
        assert!(
            offset % width == 0,
            "misaligned mmio access (offset={:#x}, width={})",
            offset,
            width
        );
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
    ///
    /// `value` is masked to the field width *before* shifting so that a
    /// caller passing an unshifted field value can never trigger a shift
    /// overflow (`value` may be up to u32::MAX when `shift > 0`). Bits of
    /// `value` outside the field width are ignored by contract.
    pub fn write_field32(&self, offset: usize, mask: u32, shift: u32, value: u32) {
        let width_mask = mask >> shift;
        let field = ((value & width_mask) << shift) & mask;
        self.modify32(offset, mask, field);
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
