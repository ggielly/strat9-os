// Memory zone management for buddy allocator

use x86_64::PhysAddr;

/// Memory zone types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ZoneType {
    /// DMA zone: 0-16MB (for legacy ISA DMA)
    DMA = 0,
    /// Normal zone: 16MB-896MB (for most allocations)
    Normal = 1,
    /// HighMem zone: > 896MB (for high memory)
    HighMem = 2,
}

impl ZoneType {
    /// Number of zones supported in Phase 1
    pub const COUNT: usize = 3;
}

/// Maximum buddy order (0-11 for 4KB to 8MB blocks)
pub const MAX_ORDER: usize = 11;

/// Bitmap used by buddy coalescing logic.
///
/// The storage is provided externally (stolen from early boot free pages)
/// and addressed through HHDM.
#[derive(Debug, Clone, Copy)]
pub struct BuddyBitmap {
    pub data: *mut u8,
    pub num_bits: usize,
}

impl BuddyBitmap {
    /// Empty bitmap for const initialization.
    pub const fn empty() -> Self {
        Self {
            data: core::ptr::null_mut(),
            num_bits: 0,
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_null() || self.num_bits == 0
    }

    /// Toggle a bit and return its new value.
    #[inline]
    pub fn toggle(&self, idx: usize) -> bool {
        debug_assert!(idx < self.num_bits);
        let byte_idx = idx >> 3;
        let mask = 1u8 << (idx & 7);
        unsafe {
            let byte = self.data.add(byte_idx);
            let new_val = *byte ^ mask;
            *byte = new_val;
            (new_val & mask) != 0
        }
    }

    #[inline]
    pub fn test(&self, idx: usize) -> bool {
        if idx >= self.num_bits || self.is_empty() {
            return false;
        }
        let byte_idx = idx >> 3;
        let mask = 1u8 << (idx & 7);
        unsafe { (*self.data.add(byte_idx) & mask) != 0 }
    }

    #[inline]
    pub fn set(&self, idx: usize) {
        debug_assert!(idx < self.num_bits);
        let byte_idx = idx >> 3;
        let mask = 1u8 << (idx & 7);
        unsafe {
            *self.data.add(byte_idx) |= mask;
        }
    }

    #[inline]
    pub fn clear(&self, idx: usize) {
        debug_assert!(idx < self.num_bits);
        let byte_idx = idx >> 3;
        let mask = 1u8 << (idx & 7);
        unsafe {
            *self.data.add(byte_idx) &= !mask;
        }
    }
}

/// Memory zone with buddy allocator free lists
pub struct Zone {
    /// Zone type
    pub zone_type: ZoneType,

    /// Base physical address of this zone
    pub base: PhysAddr,

    /// Total number of managed pages in this zone.
    pub page_count: usize,

    /// Total address span covered by this zone metadata, in pages.
    ///
    /// Unlike `page_count`, this includes holes and is used to size bitmaps.
    pub span_pages: usize,

    /// Number of allocated pages
    pub allocated: usize,

    /// Free lists for each order (0-11), intrusive list head as physical addr.
    /// 0 means empty.
    pub free_lists: [u64; MAX_ORDER + 1],

    /// Per-order buddy pair bitmaps (Linux-style parity map).
    pub buddy_bitmaps: [BuddyBitmap; MAX_ORDER + 1],

    /// Optional debug bitmap: 1 bit per page = allocated.
    #[cfg(debug_assertions)]
    pub alloc_bitmap: BuddyBitmap,
}

impl Zone {
    /// Create a new empty zone
    pub const fn new(zone_type: ZoneType) -> Self {
        Zone {
            zone_type,
            base: PhysAddr::new(0),
            page_count: 0,
            span_pages: 0,
            allocated: 0,
            free_lists: [0; MAX_ORDER + 1],
            buddy_bitmaps: [BuddyBitmap::empty(); MAX_ORDER + 1],
            #[cfg(debug_assertions)]
            alloc_bitmap: BuddyBitmap::empty(),
        }
    }

    /// Check if an address is within this zone
    pub fn contains_address(&self, addr: PhysAddr) -> bool {
        let zone_start = self.base.as_u64();
        let zone_end = zone_start + (self.span_pages as u64 * 4096);
        let addr_val = addr.as_u64();
        addr_val >= zone_start && addr_val < zone_end
    }

    /// Get number of available (free) pages
    pub fn available_pages(&self) -> usize {
        self.page_count.saturating_sub(self.allocated)
    }
}

// SAFETY: access is protected by the allocator lock.
unsafe impl Send for BuddyBitmap {}
