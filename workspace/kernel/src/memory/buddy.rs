// Buddy allocator implementation

use crate::{
    boot::entry::{MemoryKind, MemoryRegion},
    memory::{
        frame::{AllocError, FrameAllocator, PhysFrame},
        hhdm_offset, phys_to_virt,
        zone::{BuddyBitmap, Zone, ZoneType, MAX_ORDER},
    },
    serial_println,
    sync::SpinLock,
};
use x86_64::PhysAddr;

const PAGE_SIZE: u64 = 4096;
const DMA_MAX: u64 = 16 * 1024 * 1024;
const NORMAL_MAX: u64 = 896 * 1024 * 1024;

#[cfg(feature = "selftest")]
macro_rules! buddy_dbg {
    ($($arg:tt)*) => {
        serial_println!($($arg)*);
    };
}

#[cfg(not(feature = "selftest"))]
macro_rules! buddy_dbg {
    ($($arg:tt)*) => {};
}

pub struct BuddyAllocator {
    zones: [Zone; ZoneType::COUNT],
    /// Per-zone bitmap pool reserved from free memory: [start, end).
    bitmap_pool: [(u64, u64); ZoneType::COUNT],
}

impl BuddyAllocator {
    pub const fn new() -> Self {
        BuddyAllocator {
            zones: [
                Zone::new(ZoneType::DMA),
                Zone::new(ZoneType::Normal),
                Zone::new(ZoneType::HighMem),
            ],
            bitmap_pool: [(0, 0); ZoneType::COUNT],
        }
    }

    pub fn init(&mut self, memory_regions: &[MemoryRegion]) {
        #[cfg(debug_assertions)]
        debug_assert!(
            hhdm_offset() != u64::MAX,
            "HHDM offset sanity check failed unexpectedly"
        );

        serial_println!(
            "Buddy allocator: initializing with {} memory regions",
            memory_regions.len()
        );
        for (base, size) in Self::protected_module_ranges().into_iter().flatten() {
            buddy_dbg!(
                "  Protected module range: phys=0x{:x}..0x{:x}",
                Self::align_down(base, PAGE_SIZE),
                Self::align_up(base.saturating_add(size), PAGE_SIZE)
            );
        }

        // Pass 1: compute per-zone address span (base + span_pages)
        self.pass_count(memory_regions);

        // Pass 2: steal bitmap storage from free regions and wire bitmap pointers
        self.pass_steal_and_setup_bitmaps(memory_regions);

        // Pass 3: populate free lists from free memory excluding stolen pages
        self.pass_populate(memory_regions);

        for zone in &self.zones {
            serial_println!(
                "  Zone {:?}: managed={} pages span={} pages ({} MB managed)",
                zone.zone_type,
                zone.page_count,
                zone.span_pages,
                (zone.page_count * 4096) / (1024 * 1024)
            );
        }
    }

    fn pass_count(&mut self, memory_regions: &[MemoryRegion]) {
        let mut min_base = [u64::MAX; ZoneType::COUNT];
        let mut max_end = [0u64; ZoneType::COUNT];

        for region in memory_regions {
            for zi in 0..ZoneType::COUNT {
                if let Some((start, end)) = Self::zone_intersection_aligned(region, zi) {
                    if start < min_base[zi] {
                        min_base[zi] = start;
                    }
                    if end > max_end[zi] {
                        max_end[zi] = end;
                    }
                }
            }
        }

        for zi in 0..ZoneType::COUNT {
            let zone = &mut self.zones[zi];
            zone.page_count = 0;
            zone.allocated = 0;
            zone.free_lists = [0; MAX_ORDER + 1];

            if min_base[zi] == u64::MAX || max_end[zi] <= min_base[zi] {
                zone.base = PhysAddr::new(0);
                zone.span_pages = 0;
                continue;
            }

            zone.base = PhysAddr::new(min_base[zi]);
            zone.span_pages = ((max_end[zi] - min_base[zi]) / PAGE_SIZE) as usize;
        }
    }

    fn pass_steal_and_setup_bitmaps(&mut self, memory_regions: &[MemoryRegion]) {
        for zi in 0..ZoneType::COUNT {
            let zone_span = self.zones[zi].span_pages;
            let needed_bytes = Self::bitmap_bytes_for_span(zone_span);
            let needed_pages = needed_bytes.div_ceil(PAGE_SIZE as usize);

            if needed_pages == 0 {
                self.bitmap_pool[zi] = (0, 0);
                self.clear_zone_bitmaps(zi);
                continue;
            }

            let (pool_start, pool_end) =
                self.steal_contiguous_pool(memory_regions, zi, needed_pages as u64);
            self.bitmap_pool[zi] = (pool_start, pool_end);
            buddy_dbg!(
                "  Zone {:?}: bitmap pool phys=0x{:x}..0x{:x} ({} pages)",
                self.zones[zi].zone_type,
                pool_start,
                pool_end,
                needed_pages
            );

            // Zero stolen pages to initialize all bitmaps to 0.
            unsafe {
                core::ptr::write_bytes(
                    phys_to_virt(pool_start) as *mut u8,
                    0,
                    (pool_end - pool_start) as usize,
                );
            }

            self.setup_zone_bitmaps(zi, pool_start, pool_end);
        }
    }

    fn pass_populate(&mut self, memory_regions: &[MemoryRegion]) {
        for region in memory_regions {
            for zi in 0..ZoneType::COUNT {
                let Some((start, end)) = Self::zone_intersection_aligned(region, zi) else {
                    continue;
                };

                let (stolen_start, stolen_end) = self.bitmap_pool[zi];
                if stolen_start == 0
                    || stolen_end == 0
                    || end <= stolen_start
                    || start >= stolen_end
                {
                    self.seed_range_as_free(zi, start, end);
                    continue;
                }

                if start < stolen_start {
                    self.seed_range_as_free(zi, start, stolen_start);
                }
                if stolen_end < end {
                    self.seed_range_as_free(zi, stolen_end, end);
                }
            }
        }
    }

    fn clear_zone_bitmaps(&mut self, zone_idx: usize) {
        let zone = &mut self.zones[zone_idx];
        zone.buddy_bitmaps = [BuddyBitmap::empty(); MAX_ORDER + 1];
        #[cfg(debug_assertions)]
        {
            zone.alloc_bitmap = BuddyBitmap::empty();
        }
    }

    fn setup_zone_bitmaps(&mut self, zone_idx: usize, pool_start: u64, pool_end: u64) {
        let zone = &mut self.zones[zone_idx];
        let mut cursor = pool_start;

        for order in 0..=MAX_ORDER {
            let num_bits = Self::pairs_for_order(zone.span_pages, order as u8);
            let num_bytes = Self::bits_to_bytes(num_bits) as u64;
            if num_bits == 0 {
                zone.buddy_bitmaps[order] = BuddyBitmap::empty();
                continue;
            }
            debug_assert!(cursor + num_bytes <= pool_end);
            zone.buddy_bitmaps[order] = BuddyBitmap {
                data: phys_to_virt(cursor) as *mut u8,
                num_bits,
            };
            cursor += num_bytes;
        }

        #[cfg(debug_assertions)]
        {
            let num_bits = zone.span_pages;
            let num_bytes = Self::bits_to_bytes(num_bits) as u64;
            if num_bits == 0 {
                zone.alloc_bitmap = BuddyBitmap::empty();
            } else {
                debug_assert!(cursor + num_bytes <= pool_end);
                zone.alloc_bitmap = BuddyBitmap {
                    data: phys_to_virt(cursor) as *mut u8,
                    num_bits,
                };
                cursor += num_bytes;
            }
        }

        debug_assert!(cursor <= pool_end);
    }

    fn seed_range_as_free(&mut self, zone_idx: usize, start: u64, end: u64) {
        if start >= end {
            return;
        }
        let zone = &mut self.zones[zone_idx];
        let mut addr = start;
        while addr < end {
            if Self::is_protected_module_page(addr) {
                buddy_dbg!(
                    "  Zone {:?}: skip protected page 0x{:x}",
                    zone.zone_type,
                    addr
                );
                addr += PAGE_SIZE;
                continue;
            }
            Self::insert_free_block(zone, addr, 0);
            zone.page_count += 1;
            addr += PAGE_SIZE;
        }
    }

    fn alloc_from_zone(zone: &mut Zone, order: u8) -> Option<PhysFrame> {
        for cur_order in order..=MAX_ORDER as u8 {
            let Some(frame_phys) = Self::free_list_pop(zone, cur_order) else {
                continue;
            };
            let block_size = PAGE_SIZE << cur_order;
            let block_end = frame_phys.saturating_add(block_size);
            if Self::protected_overlap_end(frame_phys, block_end).is_some() {
                buddy_dbg!(
                    "  Zone {:?}: dropped protected free block 0x{:x}..0x{:x} order={}",
                    zone.zone_type,
                    frame_phys,
                    block_end,
                    cur_order
                );
                continue;
            }

            // One block of this order transitions free -> allocated.
            let _ = Self::toggle_pair(zone, frame_phys, cur_order);

            // Split down to requested order.
            let mut split_order = cur_order;
            while split_order > order {
                split_order -= 1;
                let buddy_phys = frame_phys + ((1u64 << split_order) * PAGE_SIZE);
                Self::free_list_push(zone, buddy_phys, split_order);
                // Pair at split_order becomes (allocated, free).
                let _ = Self::toggle_pair(zone, frame_phys, split_order);
            }

            zone.allocated += 1usize << order;

            #[cfg(debug_assertions)]
            Self::mark_allocated(zone, frame_phys, order, true);

            return PhysFrame::from_start_address(PhysAddr::new(frame_phys)).ok();
        }
        None
    }

    fn free_to_zone(zone: &mut Zone, frame: PhysFrame, order: u8) {
        let frame_phys = frame.start_address.as_u64();
        let block_size = PAGE_SIZE << order;
        let block_end = frame_phys.saturating_add(block_size);

        debug_assert!(order <= MAX_ORDER as u8);
        debug_assert!(frame.start_address.is_aligned(PAGE_SIZE << order));
        debug_assert!(zone.contains_address(frame.start_address));

        if Self::protected_overlap_end(frame_phys, block_end).is_some() {
            buddy_dbg!(
                "  Zone {:?}: drop free overlap-protected 0x{:x}..0x{:x} order={}",
                zone.zone_type,
                frame_phys,
                block_end,
                order
            );
            return;
        }

        #[cfg(debug_assertions)]
        Self::mark_allocated(zone, frame_phys, order, false);

        Self::insert_free_block(zone, frame_phys, order);
        zone.allocated = zone.allocated.saturating_sub(1usize << order);
    }

    /// Linux-style parity-map coalescing insertion.
    fn insert_free_block(zone: &mut Zone, frame_phys: u64, initial_order: u8) {
        let mut current = frame_phys;
        let mut order = initial_order;

        loop {
            let bit_is_set = Self::toggle_pair(zone, current, order);
            if bit_is_set || order == MAX_ORDER as u8 {
                Self::free_list_push(zone, current, order);
                break;
            }

            let Some(buddy) = Self::buddy_phys(zone, current, order) else {
                Self::free_list_push(zone, current, order);
                break;
            };

            let removed = Self::free_list_remove(zone, buddy, order);
            if !removed {
                // Inconsistency fallback: keep allocator consistent.
                debug_assert!(false, "buddy bitmap/list inconsistency while freeing");
                Self::free_list_push(zone, current, order);
                break;
            }

            current = core::cmp::min(current, buddy);
            order += 1;
        }
    }

    #[inline]
    fn page_index(zone: &Zone, phys: u64) -> usize {
        debug_assert!(zone.span_pages > 0);
        let base = zone.base.as_u64();
        debug_assert!(phys >= base);
        debug_assert!((phys - base).is_multiple_of(PAGE_SIZE));
        ((phys - base) / PAGE_SIZE) as usize
    }

    #[inline]
    fn pair_index(zone: &Zone, phys: u64, order: u8) -> usize {
        Self::page_index(zone, phys) >> (order as usize + 1)
    }

    #[inline]
    fn toggle_pair(zone: &mut Zone, phys: u64, order: u8) -> bool {
        let bitmap = zone.buddy_bitmaps[order as usize];
        if bitmap.is_empty() {
            return true;
        }
        let idx = Self::pair_index(zone, phys, order);
        debug_assert!(idx < bitmap.num_bits);
        bitmap.toggle(idx)
    }

    #[inline]
    fn buddy_phys(zone: &Zone, phys: u64, order: u8) -> Option<u64> {
        let base = zone.base.as_u64();
        if phys < base {
            return None;
        }
        let offset = phys - base;
        let block_size = PAGE_SIZE << order;
        let buddy_offset = offset ^ block_size;
        let buddy_page = (buddy_offset / PAGE_SIZE) as usize;
        if buddy_page >= zone.span_pages {
            return None;
        }
        Some(base + buddy_offset)
    }

    #[cfg(debug_assertions)]
    fn mark_allocated(zone: &mut Zone, frame_phys: u64, order: u8, allocated: bool) {
        if zone.alloc_bitmap.is_empty() {
            return;
        }
        let start = Self::page_index(zone, frame_phys);
        let count = 1usize << order;
        for i in 0..count {
            let bit = start + i;
            debug_assert!(bit < zone.alloc_bitmap.num_bits);
            if allocated {
                debug_assert!(!zone.alloc_bitmap.test(bit), "double allocation detected");
                zone.alloc_bitmap.set(bit);
            } else {
                debug_assert!(zone.alloc_bitmap.test(bit), "double free detected");
                zone.alloc_bitmap.clear(bit);
            }
        }
    }

    fn free_list_push(zone: &mut Zone, phys: u64, order: u8) {
        let head = zone.free_lists[order as usize];
        Self::write_free_prev(phys, 0);
        Self::write_free_next(phys, head);
        if head != 0 {
            Self::write_free_prev(head, phys);
        }
        zone.free_lists[order as usize] = phys;
    }

    fn free_list_pop(zone: &mut Zone, order: u8) -> Option<u64> {
        let head = zone.free_lists[order as usize];
        if head == 0 {
            return None;
        }
        let next = Self::read_free_next(head);
        zone.free_lists[order as usize] = next;
        if next != 0 {
            Self::write_free_prev(next, 0);
        }
        Self::write_free_next(head, 0);
        Self::write_free_prev(head, 0);
        Some(head)
    }

    fn free_list_remove(zone: &mut Zone, phys: u64, order: u8) -> bool {
        let prev = Self::read_free_prev(phys);
        let next = Self::read_free_next(phys);

        if prev == 0 {
            if zone.free_lists[order as usize] != phys {
                return false;
            }
            zone.free_lists[order as usize] = next;
        } else {
            Self::write_free_next(prev, next);
        }

        if next != 0 {
            Self::write_free_prev(next, prev);
        }

        Self::write_free_next(phys, 0);
        Self::write_free_prev(phys, 0);
        true
    }

    #[inline]
    fn read_free_next(phys: u64) -> u64 {
        unsafe { *(phys_to_virt(phys) as *const u64) }
    }

    #[inline]
    fn write_free_next(phys: u64, next: u64) {
        unsafe {
            *(phys_to_virt(phys) as *mut u64) = next;
        }
    }

    #[inline]
    fn read_free_prev(phys: u64) -> u64 {
        unsafe { *((phys_to_virt(phys) + 8) as *const u64) }
    }

    #[inline]
    fn write_free_prev(phys: u64, prev: u64) {
        unsafe {
            *((phys_to_virt(phys) + 8) as *mut u64) = prev;
        }
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

    fn zone_bounds(zone_idx: usize) -> (u64, u64) {
        match zone_idx {
            x if x == ZoneType::DMA as usize => (0, DMA_MAX),
            x if x == ZoneType::Normal as usize => (DMA_MAX, NORMAL_MAX),
            _ => (NORMAL_MAX, u64::MAX),
        }
    }

    fn zone_intersection_aligned(region: &MemoryRegion, zone_idx: usize) -> Option<(u64, u64)> {
        if !matches!(region.kind, MemoryKind::Free) {
            return None;
        }

        let region_start = region.base;
        let region_end = region.base.saturating_add(region.size);
        let (zone_start, zone_end) = Self::zone_bounds(zone_idx);

        let start = core::cmp::max(region_start, zone_start);
        let end = core::cmp::min(region_end, zone_end);
        if start >= end {
            return None;
        }

        // Reserve physical address 0 as sentinel/not-usable.
        let start = Self::align_up(core::cmp::max(start, PAGE_SIZE), PAGE_SIZE);
        let end = Self::align_down(end, PAGE_SIZE);
        if start >= end {
            None
        } else {
            Some((start, end))
        }
    }

    fn steal_contiguous_pool(
        &self,
        memory_regions: &[MemoryRegion],
        zone_idx: usize,
        needed_pages: u64,
    ) -> (u64, u64) {
        let needed_bytes = needed_pages * PAGE_SIZE;
        for region in memory_regions {
            let Some((start, end)) = Self::zone_intersection_aligned(region, zone_idx) else {
                continue;
            };
            if end - start < needed_bytes {
                continue;
            }
            let mut candidate = start;
            while candidate + needed_bytes <= end {
                let candidate_end = candidate + needed_bytes;
                if let Some(overlap_end) = Self::protected_overlap_end(candidate, candidate_end) {
                    candidate = Self::align_up(overlap_end, PAGE_SIZE);
                    continue;
                }
                buddy_dbg!(
                    "  Zone {:?}: steal candidate accepted 0x{:x}..0x{:x}",
                    self.zones[zone_idx].zone_type,
                    candidate,
                    candidate_end
                );
                return (candidate, candidate_end);
            }
        }
        panic!(
            "Buddy allocator: cannot reserve {} pages for zone {:?} bitmaps",
            needed_pages, self.zones[zone_idx].zone_type
        );
    }

    fn protected_overlap_end(start: u64, end: u64) -> Option<u64> {
        for (base, size) in Self::protected_module_ranges().into_iter().flatten() {
            if size == 0 {
                continue;
            }
            let pstart = Self::align_down(base, PAGE_SIZE);
            let pend = Self::align_up(base.saturating_add(size), PAGE_SIZE);
            if end <= pstart || start >= pend {
                continue;
            }
            return Some(pend);
        }
        None
    }

    fn is_protected_module_page(phys: u64) -> bool {
        let page = Self::align_down(phys, PAGE_SIZE);
        for (base, size) in Self::protected_module_ranges().into_iter().flatten() {
            if size == 0 {
                continue;
            }
            let pstart = Self::align_down(base, PAGE_SIZE);
            let pend = Self::align_up(base.saturating_add(size), PAGE_SIZE);
            if page >= pstart && page < pend {
                return true;
            }
        }
        false
    }

    fn protected_module_ranges() -> [Option<(u64, u64)>; 10] {
        [
            crate::boot::limine::fs_ext4_module(),
            crate::boot::limine::strate_fs_ramfs_module(),
            crate::boot::limine::init_module(),
            crate::boot::limine::console_admin_module(),
            crate::boot::limine::strate_net_module(),
            crate::boot::limine::dhcp_client_module(),
            crate::boot::limine::ping_module(),
            crate::boot::limine::test_syscalls_module(),
            crate::boot::limine::test_mem_module(),
            crate::boot::limine::test_mem_stressed_module(),
        ]
    }

    #[inline]
    fn pairs_for_order(span_pages: usize, order: u8) -> usize {
        let pair_span = 1usize << (order as usize + 1);
        span_pages.div_ceil(pair_span)
    }

    #[inline]
    fn bits_to_bytes(bits: usize) -> usize {
        bits.div_ceil(8)
    }

    fn bitmap_bytes_for_span(span_pages: usize) -> usize {
        let mut bytes = 0usize;
        for order in 0..=MAX_ORDER as u8 {
            bytes += Self::bits_to_bytes(Self::pairs_for_order(span_pages, order));
        }
        #[cfg(debug_assertions)]
        {
            bytes += Self::bits_to_bytes(span_pages);
        }
        bytes
    }

    #[inline]
    fn align_up(value: u64, align: u64) -> u64 {
        debug_assert!(align.is_power_of_two());
        (value + align - 1) & !(align - 1)
    }

    #[inline]
    fn align_down(value: u64, align: u64) -> u64 {
        debug_assert!(align.is_power_of_two());
        value & !(align - 1)
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
            if let Some(frame) = Self::alloc_from_zone(&mut self.zones[zi], order) {
                return Ok(frame);
            }
        }

        Err(AllocError::OutOfMemory)
    }

    fn free(&mut self, frame: PhysFrame, order: u8) {
        let frame_phys = frame.start_address.as_u64();
        let zi = Self::zone_index_for_addr(frame_phys);
        let zone = &mut self.zones[zi];
        Self::free_to_zone(zone, frame, order);
    }
}

impl BuddyAllocator {
    /// Allocate explicitly from one zone (e.g. DMA-only callers).
    pub fn alloc_zone(&mut self, order: u8, zone: ZoneType) -> Result<PhysFrame, AllocError> {
        if order > MAX_ORDER as u8 {
            return Err(AllocError::InvalidOrder);
        }
        Self::alloc_from_zone(&mut self.zones[zone as usize], order).ok_or(AllocError::OutOfMemory)
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

impl BuddyAllocator {
    /// Fast totals without heap allocation (safe in low-level paths).
    pub fn page_totals(&self) -> (usize, usize) {
        let mut total_pages = 0usize;
        let mut allocated_pages = 0usize;
        for zone in &self.zones {
            total_pages = total_pages.saturating_add(zone.page_count);
            allocated_pages = allocated_pages.saturating_add(zone.allocated);
        }
        (total_pages, allocated_pages)
    }

    /// Snapshot zones without heap allocation.
    /// Returns the number of entries written to `out`.
    pub fn zone_snapshot(&self, out: &mut [(u8, u64, usize, usize)]) -> usize {
        let n = core::cmp::min(out.len(), self.zones.len());
        for (i, zone) in self.zones.iter().take(n).enumerate() {
            out[i] = (
                zone.zone_type as u8,
                zone.base.as_u64(),
                zone.page_count,
                zone.allocated,
            );
        }
        n
    }
}
