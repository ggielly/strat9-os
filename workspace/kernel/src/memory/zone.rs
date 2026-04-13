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

/// Maximum number of discontiguous physical segments tracked per zone.
///
/// VMware and some firmware expose fragmented RAM maps with many holes. A
/// single zone therefore contains multiple independently managed buddy segments
/// instead of one monolithic min/max span.
pub const MAX_ZONE_SEGMENTS: usize = 64;

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

    /// Returns whether empty.
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

    /// Performs the test operation.
    #[inline]
    pub fn test(&self, idx: usize) -> bool {
        if idx >= self.num_bits || self.is_empty() {
            return false;
        }
        let byte_idx = idx >> 3;
        let mask = 1u8 << (idx & 7);
        unsafe { (*self.data.add(byte_idx) & mask) != 0 }
    }

    /// Performs the set operation.
    #[inline]
    pub fn set(&self, idx: usize) {
        debug_assert!(idx < self.num_bits);
        let byte_idx = idx >> 3;
        let mask = 1u8 << (idx & 7);
        unsafe {
            *self.data.add(byte_idx) |= mask;
        }
    }

    /// Performs the clear operation.
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

/// One contiguous buddy-managed extent inside a zone.
#[derive(Clone, Copy)]
pub struct ZoneSegment {
    /// Base physical address of this contiguous segment.
    pub base: PhysAddr,

    /// Number of pages managed by this segment.
    pub page_count: usize,

    /// Free lists for each order within this segment.
    pub free_lists: [u64; MAX_ORDER + 1],

    /// Per-order parity bitmaps scoped to this segment only.
    pub buddy_bitmaps: [BuddyBitmap; MAX_ORDER + 1],

    /// Optional debug bitmap: 1 bit per page = allocated.
    #[cfg(debug_assertions)]
    pub alloc_bitmap: BuddyBitmap,
}

impl ZoneSegment {
    /// Empty segment for const initialization.
    pub const fn empty() -> Self {
        Self {
            base: PhysAddr::new(0),
            page_count: 0,
            free_lists: [0; MAX_ORDER + 1],
            buddy_bitmaps: [BuddyBitmap::empty(); MAX_ORDER + 1],
            #[cfg(debug_assertions)]
            alloc_bitmap: BuddyBitmap::empty(),
        }
    }

    /// Returns whether this segment is populated.
    #[inline]
    pub fn is_populated(&self) -> bool {
        self.page_count != 0
    }

    /// Returns whether an address falls within the segment.
    #[inline]
    pub fn contains_address(&self, addr: PhysAddr) -> bool {
        if !self.is_populated() {
            return false;
        }
        let start = self.base.as_u64();
        let end = start + (self.page_count as u64 * 4096);
        let value = addr.as_u64();
        value >= start && value < end
    }

    /// Returns the exclusive end address of the segment.
    #[inline]
    pub fn end_address(&self) -> u64 {
        self.base.as_u64() + (self.page_count as u64 * 4096)
    }

    /// Count the number of free blocks at a given order.
    pub fn free_list_count(&self, order: u8) -> usize {
        let mut count = 0usize;
        let mut phys = self.free_lists[order as usize];
        while phys != 0 {
            count += 1;
            let meta = crate::memory::frame::get_meta(PhysAddr::new(phys));
            phys = if meta.next() == crate::memory::frame::FRAME_META_LINK_NONE {
                0
            } else {
                meta.next()
            };
        }
        count
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
    /// Unlike `page_count`, this includes holes and is kept for diagnostics.
    pub span_pages: usize,

    /// Number of allocated pages
    pub allocated: usize,

    /// Number of populated contiguous segments in this zone.
    pub segment_count: usize,

    /// Independently managed contiguous segments inside this zone.
    pub segments: [ZoneSegment; MAX_ZONE_SEGMENTS],
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
            segment_count: 0,
            segments: [ZoneSegment::empty(); MAX_ZONE_SEGMENTS],
        }
    }

    /// Check if an address is within this zone
    pub fn contains_address(&self, addr: PhysAddr) -> bool {
        self.segments[..self.segment_count]
            .iter()
            .any(|segment| segment.contains_address(addr))
    }

    /// Get number of available (free) pages
    pub fn available_pages(&self) -> usize {
        self.page_count.saturating_sub(self.allocated)
    }

    /// Count the number of free blocks at a given order.
    ///
    /// Walks the buddy free list. Safe because we only read the next link from
    /// the per-frame [`crate::memory::frame::MetaSlot`] (not from mapped page bytes).
    pub fn free_list_count(&self, order: u8) -> usize {
        self.segments[..self.segment_count]
            .iter()
            .map(|segment| segment.free_list_count(order))
            .sum()
    }
}

// SAFETY: access is protected by the allocator lock.
unsafe impl Send for BuddyBitmap {}
