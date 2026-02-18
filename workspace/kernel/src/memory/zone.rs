// Memory zone management for buddy allocator

use crate::memory::frame::PhysFrame;
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

/// A single free block in a buddy allocator free list
#[derive(Debug, Clone, Copy)]
pub struct FreeBlock {
    pub frame: PhysFrame,
    /// Index into global FREE_BLOCKS pool, not a pointer
    pub next: Option<usize>,
}

/// Memory zone with buddy allocator free lists
pub struct Zone {
    /// Zone type
    pub zone_type: ZoneType,

    /// Base physical address of this zone
    pub base: PhysAddr,

    /// Total number of pages in this zone
    pub page_count: usize,

    /// Number of allocated pages
    pub allocated: usize,

    /// Free lists for each order (0-11)
    /// Each free_lists[order] is an index into the global FREE_BLOCKS pool
    pub free_lists: [Option<usize>; MAX_ORDER + 1],
}

impl Zone {
    /// Create a new empty zone
    pub const fn new(zone_type: ZoneType) -> Self {
        Zone {
            zone_type,
            base: PhysAddr::new(0),
            page_count: 0,
            allocated: 0,
            free_lists: [None; MAX_ORDER + 1],
        }
    }

    /// Check if an address is within this zone
    pub fn contains_address(&self, addr: PhysAddr) -> bool {
        let zone_start = self.base.as_u64();
        let zone_end = zone_start + (self.page_count as u64 * 4096);
        let addr_val = addr.as_u64();
        addr_val >= zone_start && addr_val < zone_end
    }

    /// Get number of available (free) pages
    pub fn available_pages(&self) -> usize {
        self.page_count.saturating_sub(self.allocated)
    }
}
