// Buddy allocator implementation

use crate::{
    entry::{MemoryKind, MemoryRegion},
    memory::{
        frame::{AllocError, FrameAllocator, PhysFrame},
        zone::{FreeBlock, Zone, ZoneType, MAX_ORDER},
    },
    serial_println,
    sync::SpinLock,
};
use x86_64::PhysAddr;

const MAX_FREE_BLOCKS: usize = 65536;

static mut FREE_BLOCKS: [Option<FreeBlock>; MAX_FREE_BLOCKS] = [None; MAX_FREE_BLOCKS];
static mut FREE_BLOCKS_USED: usize = 0;
static mut FREE_BLOCKS_FREE_HEAD: Option<usize> = None;
static mut FREE_BLOCKS_FREE_NEXT: [Option<usize>; MAX_FREE_BLOCKS] = [None; MAX_FREE_BLOCKS];

const PAGE_SIZE: u64 = 4096;
const DMA_MAX: u64 = 16 * 1024 * 1024;
const NORMAL_MAX: u64 = 896 * 1024 * 1024;

pub struct BuddyAllocator {
    zones: [Zone; ZoneType::COUNT],
}

// --- Free block pool helpers (free functions to avoid borrow issues) ---

fn pool_alloc(frame: PhysFrame) -> Option<usize> {
    unsafe {
        let idx = if let Some(free_idx) = FREE_BLOCKS_FREE_HEAD {
            FREE_BLOCKS_FREE_HEAD = FREE_BLOCKS_FREE_NEXT[free_idx];
            FREE_BLOCKS_FREE_NEXT[free_idx] = None;
            free_idx
        } else {
            if FREE_BLOCKS_USED >= MAX_FREE_BLOCKS {
                return None;
            }
            let i = FREE_BLOCKS_USED;
            FREE_BLOCKS_USED += 1;
            i
        };
        FREE_BLOCKS[idx] = Some(FreeBlock { frame, next: None });
        Some(idx)
    }
}

fn pool_release(idx: usize) {
    unsafe {
        FREE_BLOCKS[idx] = None;
        FREE_BLOCKS_FREE_NEXT[idx] = FREE_BLOCKS_FREE_HEAD;
        FREE_BLOCKS_FREE_HEAD = Some(idx);
    }
}

fn free_list_push(zone: &mut Zone, frame: PhysFrame, order: u8) {
    let idx = pool_alloc(frame).expect("Free block pool exhausted");
    unsafe {
        FREE_BLOCKS[idx].as_mut().unwrap().next = zone.free_lists[order as usize];
        zone.free_lists[order as usize] = Some(idx);
    }
}

fn free_list_pop(zone: &mut Zone, order: u8) -> Option<PhysFrame> {
    let head_idx = zone.free_lists[order as usize]?;
    unsafe {
        let block = FREE_BLOCKS[head_idx].as_ref().unwrap();
        let frame = block.frame;
        zone.free_lists[order as usize] = block.next;
        pool_release(head_idx);
        Some(frame)
    }
}

fn free_list_remove(zone: &mut Zone, order: u8, target: PhysFrame) -> bool {
    let mut prev_idx: Option<usize> = None;
    let mut current_idx = zone.free_lists[order as usize];
    unsafe {
        while let Some(idx) = current_idx {
            let block = FREE_BLOCKS[idx].as_ref().unwrap();
            if block.frame == target {
                let next = block.next;
                if let Some(prev) = prev_idx {
                    FREE_BLOCKS[prev].as_mut().unwrap().next = next;
                } else {
                    zone.free_lists[order as usize] = next;
                }
                pool_release(idx);
                return true;
            }
            prev_idx = Some(idx);
            current_idx = block.next;
        }
    }
    false
}

impl BuddyAllocator {
    pub const fn new() -> Self {
        BuddyAllocator {
            zones: [
                Zone::new(ZoneType::DMA),
                Zone::new(ZoneType::Normal),
                Zone::new(ZoneType::HighMem),
            ],
        }
    }

    pub fn init(&mut self, memory_regions: &[MemoryRegion]) {
        serial_println!(
            "Buddy allocator: initializing with {} memory regions",
            memory_regions.len()
        );

        for region in memory_regions {
            if let MemoryKind::Free = region.kind {
                serial_println!(
                    "  Free region: base=0x{:x}, size=0x{:x} ({}MB)",
                    region.base,
                    region.size,
                    region.size / (1024 * 1024)
                );
                self.add_region(region.base, region.size);
            }
        }

        for zone in &self.zones {
            serial_println!(
                "  Zone {:?}: {} pages ({} MB)",
                zone.zone_type,
                zone.page_count,
                (zone.page_count * 4096) / (1024 * 1024)
            );
        }
    }

    fn add_region(&mut self, base: u64, size: u64) {
        let mut region_base = base;
        let region_end = base.saturating_add(size);

        while region_base < region_end {
            let zone_idx = Self::zone_index_for_addr(region_base);
            let zone_end = match zone_idx {
                x if x == ZoneType::DMA as usize => DMA_MAX,
                x if x == ZoneType::Normal as usize => NORMAL_MAX,
                _ => region_end,
            };
            let segment_end = region_end.min(zone_end);
            let segment_size = segment_end.saturating_sub(region_base);
            self.add_region_segment(zone_idx, region_base, segment_size);
            region_base = segment_end;
        }
    }

    fn add_region_segment(&mut self, zone_idx: usize, base: u64, size: u64) {
        let base_addr = PhysAddr::new(base);
        let page_count = size as usize / PAGE_SIZE as usize;
        if page_count == 0 {
            return;
        }

        let zone = &mut self.zones[zone_idx];
        if zone.page_count == 0 || base_addr < zone.base {
            zone.base = base_addr;
        }
        zone.page_count += page_count;

        let mut current_addr = base_addr;
        let mut remaining = page_count;
        while remaining > 0 {
            let order = Self::max_order_for_block(current_addr, remaining).min(MAX_ORDER as u8);
            let frames_in_block = 1usize << order;
            let frame =
                PhysFrame::from_start_address(current_addr).expect("Unaligned frame address");
            free_list_push(zone, frame, order);
            current_addr += (frames_in_block as u64) * PAGE_SIZE;
            remaining -= frames_in_block;
        }
    }

    fn max_order_for_block(addr: PhysAddr, frames: usize) -> u8 {
        let mut order = 0u8;
        while order < MAX_ORDER as u8 {
            let next = order + 1;
            let n = 1usize << next;
            let bs = (n as u64) * PAGE_SIZE;
            if n <= frames && addr.is_aligned(bs) {
                order = next;
            } else {
                break;
            }
        }
        order
    }

    fn zone_index_for_addr(addr: u64) -> usize {
        if addr < DMA_MAX {
            ZoneType::DMA as usize
        } else if addr < NORMAL_MAX {
            ZoneType::Normal as usize
        } else {
            ZoneType::HighMem as usize
        }
    }

    fn buddy_for(zone: &Zone, frame: PhysFrame, order: u8) -> Option<PhysFrame> {
        let zs = zone.base.as_u64();
        let ze = zs + (zone.page_count as u64 * PAGE_SIZE);
        let fa = frame.start_address.as_u64();
        if fa < zs || fa >= ze {
            return None;
        }
        let bs = PAGE_SIZE << order;
        let buddy_addr = zs + ((fa - zs) ^ bs);
        if buddy_addr < ze {
            PhysFrame::from_start_address(PhysAddr::new(buddy_addr)).ok()
        } else {
            None
        }
    }

    fn alloc_from_zone(zone: &mut Zone, order: u8) -> Option<PhysFrame> {
        for cur in order..=MAX_ORDER as u8 {
            if let Some(frame) = free_list_pop(zone, cur) {
                let mut so = cur;
                while so > order {
                    so -= 1;
                    let buddy = PhysFrame::from_start_address(
                        frame.start_address + ((1u64 << so) * PAGE_SIZE),
                    )
                    .unwrap();
                    free_list_push(zone, buddy, so);
                }
                zone.allocated += 1usize << order;
                return Some(frame);
            }
        }
        None
    }

    fn free_to_zone(zone: &mut Zone, frame: PhysFrame, order: u8) {
        let mut cf = frame;
        let mut co = order;
        while co < MAX_ORDER as u8 {
            let buddy = match Self::buddy_for(zone, cf, co) {
                Some(b) => b,
                None => break,
            };
            if !free_list_remove(zone, co, buddy) {
                break;
            }
            if buddy.start_address.as_u64() < cf.start_address.as_u64() {
                cf = buddy;
            }
            co += 1;
        }
        free_list_push(zone, cf, co);
        zone.allocated = zone.allocated.saturating_sub(1usize << order);
    }
}

impl FrameAllocator for BuddyAllocator {
    fn alloc(&mut self, order: u8) -> Result<PhysFrame, AllocError> {
        if order > MAX_ORDER as u8 {
            return Err(AllocError::InvalidOrder);
        }
        for zi in [
            ZoneType::Normal as usize,
            ZoneType::HighMem as usize,
            ZoneType::DMA as usize,
        ] {
            let zone = &mut self.zones[zi];
            if let Some(frame) = Self::alloc_from_zone(zone, order) {
                return Ok(frame);
            }
        }
        Err(AllocError::OutOfMemory)
    }

    fn free(&mut self, frame: PhysFrame, order: u8) {
        let zi = Self::zone_index_for_addr(frame.start_address.as_u64());
        let zone = &mut self.zones[zi];
        Self::free_to_zone(zone, frame, order);
    }
}

static BUDDY_ALLOCATOR: SpinLock<Option<BuddyAllocator>> = SpinLock::new(None);

pub fn init_buddy_allocator(memory_regions: &[MemoryRegion]) {
    let mut allocator = BuddyAllocator::new();
    allocator.init(memory_regions);
    *BUDDY_ALLOCATOR.lock() = Some(allocator);
}

pub fn get_allocator() -> &'static SpinLock<Option<BuddyAllocator>> {
    &BUDDY_ALLOCATOR
}

/// Statistics for a single memory zone
#[derive(Debug, Clone, Copy)]
pub struct ZoneStats {
    pub zone_type: ZoneType,
    pub base: u64,
    pub page_count: usize,
    pub allocated: usize,
}

/// Overall memory statistics
#[derive(Debug, Clone)]
pub struct MemoryStats {
    pub total_pages: usize,
    pub allocated_pages: usize,
    pub zones: alloc::vec::Vec<ZoneStats>,
}

impl BuddyAllocator {
    /// Get memory statistics
    pub fn get_stats(&self) -> MemoryStats {
        let mut total_pages = 0;
        let mut allocated_pages = 0;
        let mut zone_stats = alloc::vec::Vec::new();

        for zone in &self.zones {
            total_pages += zone.page_count;
            allocated_pages += zone.allocated;

            zone_stats.push(ZoneStats {
                zone_type: zone.zone_type,
                base: zone.base.as_u64(),
                page_count: zone.page_count,
                allocated: zone.allocated,
            });
        }

        MemoryStats {
            total_pages,
            allocated_pages,
            zones: zone_stats,
        }
    }
}
