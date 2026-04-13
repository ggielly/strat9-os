// Memory zone management for buddy allocator

use core::{ptr, slice};
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

/// Minimal free-block classes used by the buddy allocator.
///
/// This is intentionally smaller than Linux's full migratetype/pageblock
/// matrix. The current design separates long-lived kernel pages from more
/// reclaimable or relocatable user pages without introducing full migration
/// machinery yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Migratetype {
    /// Default class for kernel data, page tables and other pinned pages.
    Unmovable = 0,
    /// Preferred class for user-space data and frames that can later be moved.
    Movable = 1,
}

impl Migratetype {
    /// Number of migratetypes tracked by the allocator.
    pub const COUNT: usize = 2;

    /// Stable iteration order used by diagnostics.
    pub const ALL: [Self; Self::COUNT] = [Self::Unmovable, Self::Movable];

    /// Returns the free-list index for this migratetype.
    #[inline]
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Returns the donor probing order for an allocation request.
    #[inline]
    pub const fn fallback_order(self) -> [Self; Self::COUNT] {
        match self {
            Self::Unmovable => [Self::Unmovable, Self::Movable],
            Self::Movable => [Self::Movable, Self::Unmovable],
        }
    }
}

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

    /// Free lists for each order within this segment, split by migratetype.
    pub free_lists: [[u64; MAX_ORDER + 1]; Migratetype::COUNT],

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
            free_lists: [[0; MAX_ORDER + 1]; Migratetype::COUNT],
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
        Migratetype::ALL
            .into_iter()
            .map(|migratetype| self.free_list_count_for(order, migratetype))
            .sum()
    }

    /// Count the number of free blocks at a given order and migratetype.
    pub fn free_list_count_for(&self, order: u8, migratetype: Migratetype) -> usize {
        let mut count = 0usize;
        let mut phys = self.free_lists[migratetype.index()][order as usize];
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

    /// Pages reported as usable RAM by the boot memory map for this zone.
    pub present_pages: usize,

    /// Total address span covered by this zone metadata, in pages.
    ///
    /// Unlike `page_count`, this includes holes and is kept for diagnostics.
    pub span_pages: usize,

    /// Number of allocated pages
    pub allocated: usize,

    /// Pages removed from management during boot reservations.
    pub reserved_pages: usize,

    /// Hard reserve kept available for lower zones or emergency paths.
    pub lowmem_reserve_pages: usize,

    /// Watermark below which this zone should be avoided when possible.
    pub watermark_min: usize,

    /// Advisory low watermark for diagnostics and future reclaim hooks.
    pub watermark_low: usize,

    /// Advisory high watermark for diagnostics and future reclaim hooks.
    pub watermark_high: usize,

    /// Number of populated contiguous segments in this zone.
    pub segment_count: usize,

    /// Total number of segment slots reserved for this zone.
    pub segment_capacity: usize,

    /// Independently managed contiguous segments inside this zone.
    pub segments: *mut ZoneSegment,
}

impl Zone {
    /// Create a new empty zone
    pub const fn new(zone_type: ZoneType) -> Self {
        Zone {
            zone_type,
            base: PhysAddr::new(0),
            page_count: 0,
            present_pages: 0,
            span_pages: 0,
            allocated: 0,
            reserved_pages: 0,
            lowmem_reserve_pages: 0,
            watermark_min: 0,
            watermark_low: 0,
            watermark_high: 0,
            segment_count: 0,
            segment_capacity: 0,
            segments: ptr::null_mut(),
        }
    }

    /// Returns the reserved segment storage as a slice.
    #[inline]
    pub fn segments(&self) -> &[ZoneSegment] {
        if self.segment_capacity == 0 || self.segments.is_null() {
            &[]
        } else {
            unsafe { slice::from_raw_parts(self.segments, self.segment_capacity) }
        }
    }

    /// Returns the reserved segment storage as a mutable slice.
    #[inline]
    pub fn segments_mut(&mut self) -> &mut [ZoneSegment] {
        if self.segment_capacity == 0 || self.segments.is_null() {
            &mut []
        } else {
            unsafe { slice::from_raw_parts_mut(self.segments, self.segment_capacity) }
        }
    }

    /// Reset the zone's segment storage metadata.
    #[inline]
    pub fn clear_segments(&mut self) {
        self.segment_count = 0;
        self.segment_capacity = 0;
        self.segments = ptr::null_mut();
    }

    /// Check if an address is within this zone
    pub fn contains_address(&self, addr: PhysAddr) -> bool {
        self.segments()
            .iter()
            .take(self.segment_count)
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
        self.segments()
            .iter()
            .take(self.segment_count)
            .map(|segment| segment.free_list_count(order))
            .sum()
    }

    /// Count the number of free blocks at a given order for one migratetype.
    pub fn free_list_count_for(&self, order: u8, migratetype: Migratetype) -> usize {
        self.segments()
            .iter()
            .take(self.segment_count)
            .map(|segment| segment.free_list_count_for(order, migratetype))
            .sum()
    }

    /// Returns the total free pages by migratetype across all orders.
    pub fn free_pages_by_migratetype(&self) -> [usize; Migratetype::COUNT] {
        let mut totals = [0usize; Migratetype::COUNT];
        for migratetype in Migratetype::ALL {
            let idx = migratetype.index();
            for order in 0..=MAX_ORDER {
                let blocks = self.free_list_count_for(order as u8, migratetype);
                totals[idx] = totals[idx].saturating_add(blocks << order);
            }
        }
        totals
    }

    /// Returns the number of free pages currently available in blocks of at least `order`.
    ///
    /// This is the relevant numerator for fragmentation analysis of an
    /// allocation request at `order`: pages on smaller free lists exist, but
    /// cannot satisfy that request without prior coalescing.
    pub fn free_pages_at_or_above_order(&self, order: u8) -> usize {
        let mut pages = 0usize;
        for current_order in order as usize..=MAX_ORDER {
            pages =
                pages.saturating_add(self.free_list_count(current_order as u8) << current_order);
        }
        pages
    }

    /// Returns a simple fragmentation score for `order`, expressed as a percentage.
    ///
    /// `0` means all currently free pages are still usable for an allocation of
    /// that order. `100` means all free pages are trapped in blocks smaller than
    /// the requested order. `cached_order0_pages` accounts for pages parked in
    /// per-CPU caches, which behave like order-0 fragments until drained.
    pub fn fragmentation_score(&self, order: u8, cached_order0_pages: usize) -> usize {
        if order == 0 {
            return 0;
        }

        let total_free = self.available_pages().saturating_add(cached_order0_pages);
        if total_free == 0 {
            return 0;
        }

        let usable = self.free_pages_at_or_above_order(order);
        let fragmented = total_free.saturating_sub(usable);
        fragmented.saturating_mul(100) / total_free
    }

    /// Returns the largest order that currently has at least one free block.
    pub fn largest_free_order(&self) -> Option<u8> {
        for order in (0..=MAX_ORDER).rev() {
            if self.free_list_count(order as u8) > 0 {
                return Some(order as u8);
            }
        }
        None
    }
}

// SAFETY: access is protected by the allocator lock.
unsafe impl Send for BuddyBitmap {}
// SAFETY: raw segment storage is owned and mutated only under the allocator lock.
unsafe impl Send for Zone {}
