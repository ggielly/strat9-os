// Buddy allocator implementation
//
// Refcount sentinel invariant (OSTD-style, fully enforced):
//
//   free-list frame => refcount == REFCOUNT_UNUSED  (u32::MAX)
//   live frame      => refcount >= 1
//
// `mark_block_free()` stamps REFCOUNT_UNUSED on every free path.
// `mark_block_allocated()` leaves refcount untouched (still REFCOUNT_UNUSED)
// so that `FrameAllocOptions::allocate()` can perform a fail-fast
// CAS(REFCOUNT_UNUSED → 1) that catches double-free / free-list corruption
// immediately rather than silently aliasing memory.

use crate::{
    boot::entry::{MemoryKind, MemoryRegion},
    memory::{
        boot_alloc,
        frame::{
            frame_flags, get_meta, AllocError, FrameAllocator, PhysFrame, FRAME_META_LINK_NONE,
        },
        hhdm_offset, phys_to_virt,
        zone::{
            BuddyBitmap, Migratetype, Zone, ZoneSegment, ZoneType, MAX_ORDER, PAGEBLOCK_ORDER,
            PAGEBLOCK_PAGES,
        },
    },
    serial_println,
    sync::{IrqDisabledToken, SpinLock, SpinLockGuard},
};
use core::{
    mem, ptr,
    sync::atomic::{AtomicUsize, Ordering as AtomicOrdering},
};
use x86_64::PhysAddr;

const PAGE_SIZE: u64 = 4096;
const DMA_MAX: u64 = 16 * 1024 * 1024;
const NORMAL_MAX: u64 = 896 * 1024 * 1024;
const LOCAL_CACHE_CAPACITY: usize = 256;
const LOCAL_CACHE_REFILL_ORDER: u8 = 4;
const LOCAL_CACHE_REFILL_FRAMES: usize = 1 << (LOCAL_CACHE_REFILL_ORDER as usize);
const LOCAL_CACHE_FLUSH_BATCH: usize = 64;
const LOCAL_CACHE_SLOTS: usize = Migratetype::COUNT * crate::arch::x86_64::percpu::MAX_CPUS;
const LOCAL_CACHED_ZONE_MIGRATETYPE_SLOTS: usize = Migratetype::COUNT * ZoneType::COUNT;
const COMPACTION_FRAGMENTATION_THRESHOLD: usize = 35;
const COMPACTION_SNAPSHOT_NONE: usize = usize::MAX;
const UNMOVABLE_ZONE_ORDER: [usize; ZoneType::COUNT] = [
    ZoneType::Normal as usize,
    ZoneType::HighMem as usize,
    ZoneType::DMA as usize,
];
const MOVABLE_ZONE_ORDER: [usize; ZoneType::COUNT] = [
    ZoneType::HighMem as usize,
    ZoneType::Normal as usize,
    ZoneType::DMA as usize,
];

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

#[derive(Clone, Copy, Debug)]
struct CompactionCandidate {
    zone_idx: usize,
    zone_type: ZoneType,
    order: u8,
    migratetype: Migratetype,
    pressure: ZonePressure,
    fragmentation_score: usize,
    requested_pages: usize,
    available_pages: usize,
    usable_pages: usize,
    cached_pages: usize,
    pageblock_count: usize,
    matching_pageblocks: usize,
}

impl BuddyAllocator {
    /// Creates a new instance.
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

    /// Performs the init operation.
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

        // Dump memory regions for diagnostic (compare QEMU vs VMware maps)
        for (i, region) in memory_regions.iter().enumerate() {
            let kind_str = match region.kind {
                crate::boot::entry::MemoryKind::Free => "FREE",
                crate::boot::entry::MemoryKind::Reclaim => "RECLAIM",
                crate::boot::entry::MemoryKind::Reserved => "RESERVED",
                crate::boot::entry::MemoryKind::Null => "NULL",
                _ => "UNKNOWN",
            };
            serial_println!(
                "  [buddy] MMAP[{:2}]: phys={:#018x}..{:#018x} size={:#x} ({})",
                i,
                region.base,
                region.base.saturating_add(region.size),
                region.size,
                kind_str
            );
        }

        for (_protected_base, _protected_size) in
            Self::protected_module_ranges().into_iter().flatten()
        {
            buddy_dbg!(
                "  Protected module range: phys=0x{:x}..0x{:x}",
                Self::align_down(_protected_base, PAGE_SIZE),
                Self::align_up(_protected_base.saturating_add(_protected_size), PAGE_SIZE)
            );
        }

        // Pass 1: compute per-zone address span (base + span_pages)
        self.pass_count(memory_regions);

        // Diagnostic: log span info for each zone (helps diagnose VMware memory map issues)
        for zone in &self.zones {
            serial_println!(
                "  [buddy] Zone {:?}: base={:#x} span={} pages ({} MB span)",
                zone.zone_type,
                zone.base.as_u64(),
                zone.span_pages,
                (zone.span_pages * 4096) / (1024 * 1024)
            );
        }

        // Pass 2: reserve per-zone bitmap pools using an upper bound derived
        // from the boot allocator's current free extents.
        let mut candidates = [MemoryRegion {
            base: 0,
            size: 0,
            kind: MemoryKind::Reserved,
        }; boot_alloc::MAX_BOOT_ALLOC_REGIONS];
        let candidate_len = boot_alloc::snapshot_free_regions(&mut candidates);
        self.pass_reserve_bitmap_pools(&candidates[..candidate_len]);

        // Pass 3: reserve exact segment storage from the remaining accessible
        // boot memory and then build the final segmented buddy layout from the boot
        // allocator's remaining free ranges after bitmap reservations.
        let mut remaining = [MemoryRegion {
            base: 0,
            size: 0,
            kind: MemoryKind::Reserved,
        }; boot_alloc::MAX_BOOT_ALLOC_REGIONS];
        let remaining_len = boot_alloc::snapshot_free_regions(&mut remaining);
        self.pass_reserve_segment_storage(&remaining[..remaining_len]);
        self.pass_build_segments(&remaining[..remaining_len]);
        self.pass_finalize_zone_accounting();
        self.pass_setup_segment_bitmaps();
        self.pass_populate();

        // Seal the boot allocator: all its remaining free regions are now managed
        // by buddy.  Any later boot_alloc::alloc_stack() call would otherwise
        // double-allocate pages that buddy already tracks in its free lists.
        boot_alloc::seal();

        for zone in &self.zones {
            let hole_pages = zone.span_pages.saturating_sub(zone.page_count);
            let efficiency = if zone.span_pages > 0 {
                (zone.page_count * 100) / zone.span_pages
            } else {
                0
            };
            serial_println!(
                "  [buddy] Zone {:?}: segments={}/{} managed={} present={} reserved={} span={} holes={} min/low/high={}/{}/{} reserve={} ({}% utilized, {} MB managed)",
                zone.zone_type,
                zone.segment_count,
                zone.segment_capacity,
                zone.page_count,
                zone.present_pages,
                zone.reserved_pages,
                zone.span_pages,
                hole_pages,
                zone.watermark_min,
                zone.watermark_low,
                zone.watermark_high,
                zone.lowmem_reserve_pages,
                efficiency,
                (zone.page_count * 4096) / (1024 * 1024)
            );
            if zone.span_pages > 0 && efficiency < 70 {
                serial_println!(
                    "  [buddy] WARNING: Zone {:?} has large holes ({}% wasted). This may indicate VMware memory fragmentation.",
                    zone.zone_type,
                    100 - efficiency
                );
            }
        }
    }

    /// Performs the pass count operation.
    fn pass_count(&mut self, memory_regions: &[MemoryRegion]) {
        let mut min_base = [u64::MAX; ZoneType::COUNT];
        let mut max_end = [0u64; ZoneType::COUNT];
        let mut present_pages = [0usize; ZoneType::COUNT];

        for region in memory_regions {
            for zi in 0..ZoneType::COUNT {
                if let Some((start, end)) = Self::zone_intersection_aligned(region, zi) {
                    present_pages[zi] =
                        present_pages[zi].saturating_add(((end - start) / PAGE_SIZE) as usize);
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
            zone.base = PhysAddr::new(0);
            zone.page_count = 0;
            zone.present_pages = present_pages[zi];
            zone.span_pages = 0;
            zone.allocated = 0;
            zone.reserved_pages = 0;
            zone.lowmem_reserve_pages = 0;
            zone.watermark_min = 0;
            zone.watermark_low = 0;
            zone.watermark_high = 0;
            zone.clear_segments();

            if min_base[zi] == u64::MAX || max_end[zi] <= min_base[zi] {
                continue;
            }

            zone.base = PhysAddr::new(min_base[zi]);
            zone.span_pages = ((max_end[zi] - min_base[zi]) / PAGE_SIZE) as usize;
        }
    }

    /// Reserve per-zone segment tables sized to the actual fragmented layout.
    fn pass_reserve_segment_storage(&mut self, memory_regions: &[MemoryRegion]) {
        let mut segment_counts = [0usize; ZoneType::COUNT];

        for region in memory_regions {
            for (zi, count) in segment_counts.iter_mut().enumerate() {
                if Self::zone_intersection_aligned(region, zi).is_some() {
                    *count = count.saturating_add(1);
                }
            }
        }

        for (zi, &segment_count) in segment_counts.iter().enumerate() {
            let zone = &mut self.zones[zi];
            zone.clear_segments();

            if segment_count == 0 {
                continue;
            }

            let bytes = segment_count.saturating_mul(mem::size_of::<ZoneSegment>());
            let storage_phys =
                boot_alloc::alloc_bytes_accessible(bytes, mem::align_of::<ZoneSegment>())
                    .unwrap_or_else(|| {
                        panic!(
                            "Buddy allocator: unable to reserve {} bytes for {:?} segment table",
                            bytes, zone.zone_type
                        )
                    })
                    .as_u64();
            unsafe {
                ptr::write_bytes(phys_to_virt(storage_phys) as *mut u8, 0, bytes);
            }

            zone.segment_capacity = segment_count;
            zone.segments = phys_to_virt(storage_phys) as *mut ZoneSegment;
        }
    }

    /// Reserve per-zone bitmap pools using a segmentation-safe upper bound.
    fn pass_reserve_bitmap_pools(&mut self, memory_regions: &[MemoryRegion]) {
        for zi in 0..ZoneType::COUNT {
            let managed_pages = memory_regions
                .iter()
                .filter_map(|region| Self::zone_intersection_aligned(region, zi))
                .map(|(start, end)| ((end - start) / PAGE_SIZE) as usize)
                .sum::<usize>();
            let needed_bytes = Self::bitmap_bytes_upper_bound_for_pages(managed_pages);
            let reserved_bytes = Self::align_up(needed_bytes as u64, PAGE_SIZE);

            if reserved_bytes == 0 {
                self.bitmap_pool[zi] = (0, 0);
                continue;
            }

            let pool_start = boot_alloc::alloc_bytes_accessible(needed_bytes, PAGE_SIZE as usize)
                .unwrap_or_else(|| {
                    panic!(
                        "Buddy allocator: unable to reserve {} bytes for zone {:?} bitmaps",
                        needed_bytes, self.zones[zi].zone_type
                    )
                })
                .as_u64();
            let pool_end = pool_start.saturating_add(reserved_bytes);
            self.bitmap_pool[zi] = (pool_start, pool_end);
            buddy_dbg!(
                "  Zone {:?}: bitmap pool phys=0x{:x}..0x{:x} ({} bytes)",
                self.zones[zi].zone_type,
                pool_start,
                pool_end,
                needed_bytes
            );

            // Zero stolen pages to initialize all bitmaps to 0.
            unsafe {
                core::ptr::write_bytes(
                    phys_to_virt(pool_start) as *mut u8,
                    0,
                    (pool_end - pool_start) as usize,
                );
            }
        }
    }

    /// Finalise zone accounting once the managed segment set is known.
    fn pass_finalize_zone_accounting(&mut self) {
        for zone in &mut self.zones {
            zone.reserved_pages = zone.present_pages.saturating_sub(zone.page_count);
            zone.lowmem_reserve_pages =
                Self::lowmem_reserve_target_pages(zone.zone_type, zone.page_count);
            zone.watermark_min = Self::watermark_target_pages(zone.page_count, 256, 16, 2048);

            let delta = Self::watermark_target_pages(zone.page_count, 512, 16, 2048);
            zone.watermark_low = zone
                .watermark_min
                .saturating_add(delta)
                .min(zone.page_count);
            zone.watermark_high = zone
                .watermark_low
                .saturating_add(delta)
                .min(zone.page_count);
        }
    }

    /// Compute a bounded watermark target for a zone.
    fn watermark_target_pages(
        managed_pages: usize,
        divisor: usize,
        floor: usize,
        cap: usize,
    ) -> usize {
        Self::bounded_zone_target(managed_pages, divisor, floor, cap, 8)
    }

    /// Compute a bounded low-memory reserve target.
    fn lowmem_reserve_target_pages(zone_type: ZoneType, managed_pages: usize) -> usize {
        match zone_type {
            ZoneType::DMA => Self::bounded_zone_target(managed_pages, 8, 16, 512, 4),
            ZoneType::Normal => Self::bounded_zone_target(managed_pages, 64, 64, 2048, 8),
            ZoneType::HighMem => 0,
        }
    }

    /// Bound a policy target to something meaningful for the current zone size.
    fn bounded_zone_target(
        managed_pages: usize,
        divisor: usize,
        floor: usize,
        cap: usize,
        max_fraction_divisor: usize,
    ) -> usize {
        if managed_pages == 0 {
            return 0;
        }

        let scaled = core::cmp::max(managed_pages / divisor, floor);
        let capped = core::cmp::min(scaled, cap);
        let max_for_zone = core::cmp::max(1, managed_pages / max_fraction_divisor);
        core::cmp::min(capped, max_for_zone)
    }

    /// Build the final segmented physical layout from remaining boot allocator ranges.
    fn pass_build_segments(&mut self, memory_regions: &[MemoryRegion]) {
        for region in memory_regions {
            for zi in 0..ZoneType::COUNT {
                let Some((start, end)) = Self::zone_intersection_aligned(region, zi) else {
                    continue;
                };
                let zone = &mut self.zones[zi];
                if zone.segment_count >= zone.segment_capacity {
                    panic!(
                        "Buddy allocator: zone {:?} exceeded reserved segment capacity={} while processing phys=0x{:x}..0x{:x}",
                        zone.zone_type,
                        zone.segment_capacity,
                        start,
                        end,
                    );
                }

                let slot = zone.segment_count;
                zone.segments_mut()[slot] = ZoneSegment {
                    base: PhysAddr::new(start),
                    page_count: ((end - start) / PAGE_SIZE) as usize,
                    free_lists: [[0; MAX_ORDER + 1]; Migratetype::COUNT],
                    buddy_bitmaps: [BuddyBitmap::empty(); MAX_ORDER + 1],
                    pageblock_tags: ptr::null_mut(),
                    pageblock_count: 0,
                    #[cfg(debug_assertions)]
                    alloc_bitmap: BuddyBitmap::empty(),
                };
                zone.segment_count = slot + 1;
                zone.page_count = zone
                    .page_count
                    .saturating_add(((end - start) / PAGE_SIZE) as usize);

                buddy_dbg!(
                    "  Zone {:?}: segment phys=0x{:x}..0x{:x} pages={}",
                    zone.zone_type,
                    start,
                    end,
                    ((end - start) / PAGE_SIZE) as usize,
                );
            }
        }
    }

    /// Assign bitmap slices to each populated segment.
    fn pass_setup_segment_bitmaps(&mut self) {
        for zi in 0..ZoneType::COUNT {
            let (pool_start, pool_end) = self.bitmap_pool[zi];
            if pool_start == 0 || pool_end <= pool_start {
                continue;
            }

            let zone = &mut self.zones[zi];
            let default_pageblock_migratetype = Self::default_pageblock_migratetype(zone.zone_type);
            let mut cursor = pool_start;
            let segment_count = zone.segment_count;
            for segment in zone.segments_mut().iter_mut().take(segment_count) {
                let _exact_bitmap_bytes = Self::bitmap_bytes_for_span(segment.page_count);
                for order in 0..=MAX_ORDER {
                    let num_bits = Self::pairs_for_order(segment.page_count, order as u8);
                    let num_bytes = Self::bits_to_bytes(num_bits) as u64;
                    if num_bits == 0 {
                        segment.buddy_bitmaps[order] = BuddyBitmap::empty();
                        continue;
                    }

                    debug_assert!(cursor + num_bytes <= pool_end);
                    segment.buddy_bitmaps[order] = BuddyBitmap {
                        data: phys_to_virt(cursor) as *mut u8,
                        num_bits,
                    };
                    cursor += num_bytes;
                }

                #[cfg(debug_assertions)]
                {
                    let num_bits = segment.page_count;
                    let num_bytes = Self::bits_to_bytes(num_bits) as u64;
                    if num_bits == 0 {
                        segment.alloc_bitmap = BuddyBitmap::empty();
                    } else {
                        debug_assert!(cursor + num_bytes <= pool_end);
                        segment.alloc_bitmap = BuddyBitmap {
                            data: phys_to_virt(cursor) as *mut u8,
                            num_bits,
                        };
                        cursor += num_bytes;
                    }
                }

                let pageblock_count = segment.page_count.div_ceil(PAGEBLOCK_PAGES);
                segment.pageblock_count = pageblock_count;
                if pageblock_count == 0 {
                    segment.pageblock_tags = ptr::null_mut();
                } else {
                    let num_bytes = pageblock_count as u64;
                    debug_assert!(cursor + num_bytes <= pool_end);
                    segment.pageblock_tags = phys_to_virt(cursor) as *mut u8;
                    unsafe {
                        ptr::write_bytes(
                            segment.pageblock_tags,
                            default_pageblock_migratetype as u8,
                            pageblock_count,
                        );
                    }
                    cursor += num_bytes;
                }
            }

            debug_assert!(cursor <= pool_end);
        }
    }

    /// Seed each contiguous segment with greedy block insertion.
    fn pass_populate(&mut self) {
        for zi in 0..ZoneType::COUNT {
            let zone_type = self.zones[zi].zone_type;
            let segment_count = self.zones[zi].segment_count;
            for si in 0..segment_count {
                let (start, end) = {
                    let segments = self.zones[zi].segments();
                    let segment = &segments[si];
                    (segment.base.as_u64(), segment.end_address())
                };
                let segment = &mut self.zones[zi].segments_mut()[si];
                Self::seed_range_as_free(zone_type, segment, start, end);
            }
        }
    }

    /// Seeds a contiguous physical range `[start, end)` as free using greedy block insertion.
    ///
    /// Unlike the previous min/max span design, `segment` is guaranteed to be a
    /// genuinely contiguous free extent. Greedy seeding therefore improves boot
    /// time without ever making holes visible to the buddy topology.
    fn seed_range_as_free(zone_type: ZoneType, segment: &mut ZoneSegment, start: u64, end: u64) {
        let _ = zone_type;
        if start >= end {
            return;
        }
        let mut addr = start;

        'seed: while addr < end {
            if !segment.contains_address(PhysAddr::new(addr)) {
                break;
            }

            if let Some(protected_end) = Self::protected_overlap_end(addr, addr + PAGE_SIZE) {
                buddy_dbg!(
                    "  Zone {:?}: skip protected range 0x{:x}..0x{:x}",
                    zone_type,
                    addr,
                    protected_end
                );
                addr = core::cmp::min(protected_end, end);
                continue;
            }

            let remaining_pages = ((end - addr) / PAGE_SIZE) as usize;
            debug_assert!(remaining_pages != 0);
            let mut order = ((remaining_pages.ilog2()) as u8).min(MAX_ORDER as u8);

            while order > 0 {
                let block_size = PAGE_SIZE << order;
                if addr & (block_size - 1) == 0 {
                    break;
                }
                order -= 1;
            }

            loop {
                let block_size = PAGE_SIZE << order;
                let block_end = addr.saturating_add(block_size);
                if block_end > end {
                    debug_assert!(order != 0);
                    order -= 1;
                    continue;
                }

                if Self::protected_overlap_end(addr, block_end).is_some() {
                    if order == 0 {
                        if let Some(skip_to) = Self::protected_overlap_end(addr, block_end) {
                            buddy_dbg!("  Zone {:?}: skip protected page 0x{:x}", zone_type, addr);
                            addr = core::cmp::min(skip_to, end);
                            continue 'seed;
                        }
                    }
                    order -= 1;
                    continue;
                }

                let migratetype = Self::pageblock_migratetype(
                    segment,
                    addr,
                    Self::default_pageblock_migratetype(zone_type),
                );
                Self::insert_free_block(segment, addr, order, migratetype);
                addr = block_end;
                continue 'seed;
            }
        }
    }

    /// Allocates from zone.
    fn alloc_from_zone(
        zone: &mut Zone,
        zone_idx: usize,
        order: u8,
        migratetype: Migratetype,
        honor_watermarks: bool,
        token: &IrqDisabledToken,
    ) -> Option<PhysFrame> {
        if !Self::zone_allows_allocation(zone, zone_idx, order, honor_watermarks) {
            return None;
        }

        for si in 0..zone.segment_count {
            let frame_phys = {
                let segment = &mut zone.segments_mut()[si];
                Self::alloc_from_segment(segment, order, migratetype, token)
            };
            if let Some(frame_phys) = frame_phys {
                zone.allocated += 1usize << order;
                return PhysFrame::from_start_address(PhysAddr::new(frame_phys)).ok();
            }
        }
        None
    }

    /// Allocate from one contiguous segment.
    fn alloc_from_segment(
        segment: &mut ZoneSegment,
        order: u8,
        requested_migratetype: Migratetype,
        _token: &IrqDisabledToken,
    ) -> Option<u64> {
        for cur_order in order..=MAX_ORDER as u8 {
            for donor_migratetype in requested_migratetype.fallback_order() {
                let Some(frame_phys) = Self::free_list_pop(segment, cur_order, donor_migratetype)
                else {
                    continue;
                };
                debug_assert!(
                    !crate::memory::frame::block_phys_has_poison_guard(frame_phys, cur_order),
                    "buddy: poisoned block on free list (order {})",
                    cur_order
                );
                let block_size = PAGE_SIZE << cur_order;
                let block_end = frame_phys.saturating_add(block_size);
                if Self::protected_overlap_end(frame_phys, block_end).is_some() {
                    panic!(
                        "Buddy allocator inconsistency: free block 0x{:x} order {} overlaps protected memory",
                        frame_phys, cur_order
                    );
                }

                let _ = Self::toggle_pair(segment, frame_phys, cur_order);

                let mut split_order = cur_order;
                while split_order > order {
                    split_order -= 1;
                    Self::retag_pageblock_range(
                        segment,
                        frame_phys,
                        split_order,
                        requested_migratetype,
                    );
                    let buddy_phys = frame_phys + ((1u64 << split_order) * PAGE_SIZE);
                    let buddy_migratetype =
                        Self::pageblock_migratetype(segment, buddy_phys, donor_migratetype);
                    Self::mark_block_free(buddy_phys, split_order, buddy_migratetype);
                    Self::free_list_push(segment, buddy_phys, split_order, buddy_migratetype);
                    let _ = Self::toggle_pair(segment, frame_phys, split_order);
                }
                Self::retag_pageblock_range(segment, frame_phys, order, requested_migratetype);
                Self::mark_block_allocated(frame_phys, order, requested_migratetype);

                #[cfg(debug_assertions)]
                Self::mark_allocated(segment, frame_phys, order, true);

                return Some(frame_phys);
            }
        }
        None
    }

    #[inline]
    fn find_segment_index(zone: &Zone, phys: u64, order: u8) -> Option<usize> {
        zone.segments()
            .iter()
            .take(zone.segment_count)
            .position(|segment| Self::segment_contains_block(segment, phys, order))
    }

    #[inline]
    fn segment_contains_block(segment: &ZoneSegment, phys: u64, order: u8) -> bool {
        if !segment.contains_address(PhysAddr::new(phys)) {
            return false;
        }
        let block_end = phys.saturating_add(PAGE_SIZE << order);
        block_end <= segment.end_address()
    }

    /// Releases to zone.
    fn free_to_zone(zone: &mut Zone, frame: PhysFrame, order: u8, _token: &IrqDisabledToken) {
        let frame_phys = frame.start_address.as_u64();
        let block_size = PAGE_SIZE << order;
        let block_end = frame_phys.saturating_add(block_size);
        let migratetype = Self::block_migratetype(frame_phys);
        let Some(segment_idx) = Self::find_segment_index(zone, frame_phys, order) else {
            panic!(
                "buddy free: frame 0x{:x} order {} does not belong to any segment in zone {:?}",
                frame_phys, order, zone.zone_type,
            );
        };

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
        {
            let segment = &mut zone.segments_mut()[segment_idx];
            Self::mark_allocated(segment, frame_phys, order, false);
        }

        {
            let segment = &mut zone.segments_mut()[segment_idx];
            if order as usize >= PAGEBLOCK_ORDER {
                Self::retag_pageblock_range(segment, frame_phys, order, migratetype);
            }
            let free_migratetype = Self::pageblock_migratetype(segment, frame_phys, migratetype);
            Self::mark_block_free(frame_phys, order, free_migratetype);
            Self::insert_free_block(segment, frame_phys, order, free_migratetype);
        }
        zone.allocated = zone.allocated.saturating_sub(1usize << order);
    }

    /// Drops allocator accounting for a poisoned block without returning it to the free list.
    ///
    /// The block is **not** placed on any free list and its debug-bitmap entries
    /// remain marked as "allocated" : because they genuinely are: the pages are
    /// quarantined and inaccessible.  Clearing them would defeat the double-free
    /// detector for any later attempt to free the same block.
    fn quarantine_poisoned_block_in_zone(
        zone: &mut Zone,
        frame: PhysFrame,
        order: u8,
        _token: &IrqDisabledToken,
    ) {
        let frame_phys = frame.start_address.as_u64();
        let block_size = PAGE_SIZE << order;
        let block_end = frame_phys.saturating_add(block_size);
        let Some(segment_idx) = Self::find_segment_index(zone, frame_phys, order) else {
            panic!(
                "buddy quarantine: frame 0x{:x} order {} does not belong to any segment in zone {:?}",
                frame_phys,
                order,
                zone.zone_type,
            );
        };

        debug_assert!(order <= MAX_ORDER as u8);
        debug_assert!(frame.start_address.is_aligned(PAGE_SIZE << order));
        debug_assert!(zone.contains_address(frame.start_address));
        debug_assert!(Self::segment_contains_block(
            &zone.segments()[segment_idx],
            frame_phys,
            order
        ));

        if Self::protected_overlap_end(frame_phys, block_end).is_some() {
            return;
        }

        // Intentionally NO mark_allocated(false) here : pages stay "allocated"
        // in the debug bitmap because they are quarantined, not freed.

        zone.allocated = zone.allocated.saturating_sub(1usize << order);
        POISON_QUARANTINE_PAGES.fetch_add(1usize << order, AtomicOrdering::Relaxed);
    }

    /// Linux-style parity-map coalescing insertion.
    /// Returns after inserting the (potentially coalesced) block into the appropriate free list, without recursing further.
    /// If the buddy bit is already set or we reach MAX_ORDER, the block is inserted as-is.
    /// Otherwise, the buddy block is removed from its free list and coalesced with the current block, and the process repeats at the next order.
    fn insert_free_block(
        segment: &mut ZoneSegment,
        frame_phys: u64,
        initial_order: u8,
        migratetype: Migratetype,
    ) {
        let mut current = frame_phys;
        let mut order = initial_order;

        loop {
            let bit_is_set = Self::toggle_pair(segment, current, order);
            if bit_is_set || order == MAX_ORDER as u8 {
                Self::mark_block_free(current, order, migratetype);
                Self::free_list_push(segment, current, order, migratetype);
                break;
            }

            let Some(buddy) = Self::buddy_phys(segment, current, order) else {
                Self::mark_block_free(current, order, migratetype);
                Self::free_list_push(segment, current, order, migratetype);
                break;
            };

            if !Self::can_merge_with_buddy(buddy, order, migratetype) {
                Self::mark_block_free(current, order, migratetype);
                Self::free_list_push(segment, current, order, migratetype);
                break;
            }

            let removed = Self::free_list_remove(segment, buddy, order, migratetype);
            if !removed {
                debug_assert!(false, "buddy bitmap/list inconsistency while freeing");
                Self::mark_block_free(current, order, migratetype);
                Self::free_list_push(segment, current, order, migratetype);
                break;
            }

            current = core::cmp::min(current, buddy);
            order += 1;
        }
    }

    /// Performs the page index operation.
    #[inline]
    fn page_index(segment: &ZoneSegment, phys: u64) -> usize {
        debug_assert!(segment.page_count > 0);
        let base = segment.base.as_u64();
        debug_assert!(phys >= base);
        debug_assert!((phys - base).is_multiple_of(PAGE_SIZE));
        ((phys - base) / PAGE_SIZE) as usize
    }

    /// Performs the pair index operation.
    #[inline]
    fn pair_index(segment: &ZoneSegment, phys: u64, order: u8) -> usize {
        Self::page_index(segment, phys) >> (order as usize + 1)
    }

    /// Performs the toggle pair operation.
    #[inline]
    fn toggle_pair(segment: &mut ZoneSegment, phys: u64, order: u8) -> bool {
        let bitmap = segment.buddy_bitmaps[order as usize];
        if bitmap.is_empty() {
            return true;
        }
        let idx = Self::pair_index(segment, phys, order);
        debug_assert!(idx < bitmap.num_bits);
        bitmap.toggle(idx)
    }

    /// Performs the buddy phys operation.
    #[inline]
    fn buddy_phys(segment: &ZoneSegment, phys: u64, order: u8) -> Option<u64> {
        let base = segment.base.as_u64();
        if phys < base {
            return None;
        }
        let offset = phys - base;
        let block_size = PAGE_SIZE << order;
        let buddy_offset = offset ^ block_size;
        let buddy_page = (buddy_offset / PAGE_SIZE) as usize;
        if buddy_page >= segment.page_count {
            return None;
        }
        Some(base + buddy_offset)
    }

    /// Performs the mark allocated operation.
    #[cfg(debug_assertions)]
    fn mark_allocated(segment: &mut ZoneSegment, frame_phys: u64, order: u8, allocated: bool) {
        if segment.alloc_bitmap.is_empty() {
            return;
        }
        let start = Self::page_index(segment, frame_phys);
        let count = 1usize << order;
        for i in 0..count {
            let bit = start + i;
            debug_assert!(bit < segment.alloc_bitmap.num_bits);
            if allocated {
                debug_assert!(
                    !segment.alloc_bitmap.test(bit),
                    "double allocation detected"
                );
                segment.alloc_bitmap.set(bit);
            } else {
                debug_assert!(segment.alloc_bitmap.test(bit), "double free detected");
                segment.alloc_bitmap.clear(bit);
            }
        }
    }

    /// Releases list push.
    fn free_list_push(segment: &mut ZoneSegment, phys: u64, order: u8, migratetype: Migratetype) {
        debug_assert!(
            !crate::memory::frame::block_phys_has_poison_guard(phys, order),
            "buddy: refusing to push poisoned block to free list"
        );
        let head = segment.free_lists[migratetype.index()][order as usize];
        Self::write_free_prev(phys, 0);
        Self::write_free_next(phys, head);
        if head != 0 {
            Self::write_free_prev(head, phys);
        }
        segment.free_lists[migratetype.index()][order as usize] = phys;
    }

    /// Releases list pop.
    fn free_list_pop(
        segment: &mut ZoneSegment,
        order: u8,
        migratetype: Migratetype,
    ) -> Option<u64> {
        let head = segment.free_lists[migratetype.index()][order as usize];
        if head == 0 {
            return None;
        }
        let next = Self::read_free_next(head);
        segment.free_lists[migratetype.index()][order as usize] = next;
        if next != 0 {
            Self::write_free_prev(next, 0);
        }
        Self::write_free_next(head, 0);
        Self::write_free_prev(head, 0);
        Some(head)
    }

    /// Releases list remove.
    fn free_list_remove(
        segment: &mut ZoneSegment,
        phys: u64,
        order: u8,
        migratetype: Migratetype,
    ) -> bool {
        let prev = Self::read_free_prev(phys);
        let next = Self::read_free_next(phys);

        if prev == 0 {
            if segment.free_lists[migratetype.index()][order as usize] != phys {
                return false;
            }
            segment.free_lists[migratetype.index()][order as usize] = next;
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

    /// Reads free next.
    #[inline]
    fn read_free_next(phys: u64) -> u64 {
        let next = get_meta(PhysAddr::new(phys)).next();
        if next == FRAME_META_LINK_NONE {
            0
        } else {
            next
        }
    }

    /// Writes free next.
    #[inline]
    fn write_free_next(phys: u64, next: u64) {
        get_meta(PhysAddr::new(phys)).set_next(if next == 0 {
            FRAME_META_LINK_NONE
        } else {
            next
        });
    }

    /// Reads free prev.
    #[inline]
    fn read_free_prev(phys: u64) -> u64 {
        let prev = get_meta(PhysAddr::new(phys)).prev();
        if prev == FRAME_META_LINK_NONE {
            0
        } else {
            prev
        }
    }

    /// Writes free prev.
    #[inline]
    fn write_free_prev(phys: u64, prev: u64) {
        get_meta(PhysAddr::new(phys)).set_prev(if prev == 0 {
            FRAME_META_LINK_NONE
        } else {
            prev
        });
    }

    /// Performs the zone index for addr operation.
    fn zone_index_for_addr(addr: u64) -> usize {
        if addr < DMA_MAX {
            ZoneType::DMA as usize
        } else if addr < NORMAL_MAX {
            ZoneType::Normal as usize
        } else {
            ZoneType::HighMem as usize
        }
    }

    /// Performs the zone bounds operation.
    fn zone_bounds(zone_idx: usize) -> (u64, u64) {
        match zone_idx {
            x if x == ZoneType::DMA as usize => (0, DMA_MAX),
            x if x == ZoneType::Normal as usize => (DMA_MAX, NORMAL_MAX),
            _ => (NORMAL_MAX, u64::MAX),
        }
    }

    /// Performs the zone intersection aligned operation.
    fn zone_intersection_aligned(region: &MemoryRegion, zone_idx: usize) -> Option<(u64, u64)> {
        if !matches!(region.kind, MemoryKind::Free | MemoryKind::Reclaim) {
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

    /// Performs the protected overlap end operation.
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

    /// Performs the protected module ranges operation.
    fn protected_module_ranges() -> [Option<(u64, u64)>; boot_alloc::MAX_PROTECTED_RANGES] {
        boot_alloc::protected_ranges_snapshot()
    }

    /// Performs the pairs for order operation.
    #[inline]
    fn pairs_for_order(span_pages: usize, order: u8) -> usize {
        let pair_span = 1usize << (order as usize + 1);
        span_pages.div_ceil(pair_span)
    }

    /// Performs the bits to bytes operation.
    #[inline]
    fn bits_to_bytes(bits: usize) -> usize {
        bits.div_ceil(8)
    }

    /// Performs the bitmap bytes for span operation.
    fn bitmap_bytes_for_span(span_pages: usize) -> usize {
        let mut bytes = 0usize;
        for order in 0..=MAX_ORDER as u8 {
            bytes += Self::bits_to_bytes(Self::pairs_for_order(span_pages, order));
        }
        #[cfg(debug_assertions)]
        {
            bytes += Self::bits_to_bytes(span_pages);
        }
        bytes += Self::pageblock_tag_bytes_for_span(span_pages);
        bytes
    }

    /// Upper bound for bitmap storage over any segmentation of `page_count` pages.
    ///
    /// For one page, every order contributes at most one parity bit. Summing that
    /// pessimistic bound across all pages yields a simple safe allocation bound,
    /// even if bitmap-pool reservations split ranges further.
    fn bitmap_bytes_upper_bound_for_pages(page_count: usize) -> usize {
        let mut bits = page_count.saturating_mul(MAX_ORDER + 1);
        #[cfg(debug_assertions)]
        {
            bits = bits.saturating_add(page_count);
        }
        Self::bits_to_bytes(bits)
            .saturating_add(Self::pageblock_tag_bytes_upper_bound_for_pages(page_count))
    }

    /// Exact byte count required for pageblock migratetype tags over one contiguous span.
    #[inline]
    fn pageblock_tag_bytes_for_span(span_pages: usize) -> usize {
        span_pages.div_ceil(PAGEBLOCK_PAGES)
    }

    /// Safe upper bound for pageblock-tag storage across any segmentation of `page_count` pages.
    #[inline]
    fn pageblock_tag_bytes_upper_bound_for_pages(page_count: usize) -> usize {
        page_count
    }

    /// Performs the align up operation.
    #[inline]
    fn align_up(value: u64, align: u64) -> u64 {
        debug_assert!(align.is_power_of_two());
        (value + align - 1) & !(align - 1)
    }

    /// Performs the align down operation.
    #[inline]
    fn align_down(value: u64, align: u64) -> u64 {
        debug_assert!(align.is_power_of_two());
        value & !(align - 1)
    }

    /// Default pageblock migratetype assigned at bootstrap for one zone.
    #[inline]
    fn default_pageblock_migratetype(zone_type: ZoneType) -> Migratetype {
        match zone_type {
            ZoneType::HighMem => Migratetype::Movable,
            ZoneType::DMA | ZoneType::Normal => Migratetype::Unmovable,
        }
    }

    /// Returns the pageblock index covering `phys` inside `segment`.
    #[inline]
    fn pageblock_index(segment: &ZoneSegment, phys: u64) -> usize {
        Self::page_index(segment, phys) / PAGEBLOCK_PAGES
    }

    /// Decode one pageblock tag byte into a migratetype.
    #[inline]
    fn decode_pageblock_tag(tag: u8) -> Migratetype {
        match tag {
            x if x == Migratetype::Movable as u8 => Migratetype::Movable,
            _ => Migratetype::Unmovable,
        }
    }

    /// Returns the current pageblock migratetype for a block start.
    #[inline]
    fn pageblock_migratetype(
        segment: &ZoneSegment,
        phys: u64,
        fallback: Migratetype,
    ) -> Migratetype {
        if segment.pageblock_count == 0 || segment.pageblock_tags.is_null() {
            return fallback;
        }
        let idx = Self::pageblock_index(segment, phys);
        debug_assert!(idx < segment.pageblock_count);
        unsafe { Self::decode_pageblock_tag(*segment.pageblock_tags.add(idx)) }
    }

    /// Retag every pageblock overlapped by the buddy block `[phys, phys + 2^order * PAGE_SIZE)`.
    fn retag_pageblock_range(
        segment: &mut ZoneSegment,
        phys: u64,
        order: u8,
        migratetype: Migratetype,
    ) {
        if segment.pageblock_count == 0 || segment.pageblock_tags.is_null() {
            return;
        }

        let start_page = Self::page_index(segment, phys);
        let end_page_exclusive = start_page.saturating_add(1usize << order);
        let start_idx = start_page / PAGEBLOCK_PAGES;
        let end_idx = end_page_exclusive.saturating_sub(1) / PAGEBLOCK_PAGES;
        debug_assert!(end_idx < segment.pageblock_count);

        for idx in start_idx..=end_idx {
            unsafe {
                *segment.pageblock_tags.add(idx) = migratetype as u8;
            }
        }
    }

    /// Count pageblocks by migratetype for one zone.
    fn zone_pageblock_counts(zone: &Zone) -> [usize; Migratetype::COUNT] {
        let mut counts = [0usize; Migratetype::COUNT];
        for segment in zone.segments().iter().take(zone.segment_count) {
            if segment.pageblock_count == 0 || segment.pageblock_tags.is_null() {
                continue;
            }
            for idx in 0..segment.pageblock_count {
                let migratetype =
                    unsafe { Self::decode_pageblock_tag(*segment.pageblock_tags.add(idx)) };
                counts[migratetype.index()] = counts[migratetype.index()].saturating_add(1);
            }
        }
        counts
    }

    fn zone_effective_free_pages(zone: &Zone, zone_idx: usize) -> usize {
        zone.available_pages()
            .saturating_add(LOCAL_CACHED_ZONE_FRAMES[zone_idx].load(AtomicOrdering::Relaxed))
    }

    /// Returns whether the zone should be considered for the current request.
    fn zone_allows_allocation(
        zone: &Zone,
        zone_idx: usize,
        order: u8,
        honor_watermarks: bool,
    ) -> bool {
        if zone.page_count == 0 {
            return false;
        }

        if !honor_watermarks {
            return true;
        }

        let requested_pages = 1usize << order;
        let floor = zone.watermark_min.saturating_add(zone.lowmem_reserve_pages);
        Self::zone_effective_free_pages(zone, zone_idx) >= requested_pages.saturating_add(floor)
    }

    /// Returns whether a buddy block is free and coalescible with `migratetype`.
    fn can_merge_with_buddy(phys: u64, order: u8, migratetype: Migratetype) -> bool {
        let meta = get_meta(PhysAddr::new(phys));
        let flags = meta.get_flags();
        flags & frame_flags::FREE != 0
            && meta.get_order() == order
            && Self::migratetype_from_flags(flags) == migratetype
            && !crate::memory::frame::block_phys_has_poison_guard(phys, order)
    }

    /// Decode the block migratetype stored in frame metadata flags.
    fn block_migratetype(frame_phys: u64) -> Migratetype {
        Self::migratetype_from_flags(get_meta(PhysAddr::new(frame_phys)).get_flags())
    }

    /// Decode a migratetype from frame flags.
    #[inline]
    fn migratetype_from_flags(flags: u32) -> Migratetype {
        if flags & frame_flags::MOVABLE != 0 {
            Migratetype::Movable
        } else {
            Migratetype::Unmovable
        }
    }

    /// Encode the metadata flags for a free block of the given migratetype.
    #[inline]
    fn free_flags_for(migratetype: Migratetype) -> u32 {
        match migratetype {
            Migratetype::Unmovable => frame_flags::FREE,
            Migratetype::Movable => frame_flags::FREE | frame_flags::MOVABLE,
        }
    }

    /// Encode the metadata flags for an allocated block of the given migratetype.
    #[inline]
    fn allocated_flags_for(migratetype: Migratetype) -> u32 {
        match migratetype {
            Migratetype::Unmovable => frame_flags::ALLOCATED,
            Migratetype::Movable => frame_flags::ALLOCATED | frame_flags::MOVABLE,
        }
    }

    /// Try to allocate from the supplied zone order, first honoring reserves and then bypassing them.
    fn alloc_in_zone_order(
        &mut self,
        order: u8,
        migratetype: Migratetype,
        zone_order: &[usize],
        token: &IrqDisabledToken,
    ) -> Option<PhysFrame> {
        for honor_watermarks in [true, false] {
            for &zi in zone_order {
                if let Some(frame) = Self::alloc_from_zone(
                    &mut self.zones[zi],
                    zi,
                    order,
                    migratetype,
                    honor_watermarks,
                    token,
                ) {
                    return Some(frame);
                }
            }
        }
        None
    }

    /// Returns the preferred zone scan order for one migratetype.
    ///
    /// Unmovable allocations still prefer `Normal` first because the current
    /// kernel hot-touches those pages directly. Movable allocations instead
    /// prefer `HighMem` first to preserve scarce low memory for pinned kernel
    /// structures and emergency paths.
    #[inline]
    fn preferred_zone_order(migratetype: Migratetype) -> &'static [usize; ZoneType::COUNT] {
        match migratetype {
            Migratetype::Unmovable => &UNMOVABLE_ZONE_ORDER,
            Migratetype::Movable => &MOVABLE_ZONE_ORDER,
        }
    }

    #[inline]
    fn zone_pressure_for_free_pages(zone: &Zone, free_pages: usize) -> ZonePressure {
        let reserve_floor = zone.watermark_min.saturating_add(zone.lowmem_reserve_pages);
        let low_floor = zone.watermark_low.saturating_add(zone.lowmem_reserve_pages);
        let high_floor = zone
            .watermark_high
            .saturating_add(zone.lowmem_reserve_pages);

        if free_pages <= reserve_floor {
            ZonePressure::Min
        } else if free_pages <= low_floor {
            ZonePressure::Low
        } else if free_pages <= high_floor {
            ZonePressure::High
        } else {
            ZonePressure::Healthy
        }
    }

    fn compaction_candidate(
        &self,
        order: u8,
        migratetype: Migratetype,
        zone_order: &[usize],
    ) -> Option<CompactionCandidate> {
        if order == 0 {
            return None;
        }

        let requested_pages = 1usize << order;
        let mut best: Option<CompactionCandidate> = None;

        for &zone_idx in zone_order {
            let zone = &self.zones[zone_idx];
            if zone.page_count == 0 {
                continue;
            }

            let cached_pages = LOCAL_CACHED_ZONE_FRAMES[zone_idx].load(AtomicOrdering::Relaxed);
            if cached_pages == 0 {
                continue;
            }

            let effective_free = Self::zone_effective_free_pages(zone, zone_idx);
            let available_pages = effective_free
                .saturating_sub(zone.watermark_min.saturating_add(zone.lowmem_reserve_pages));
            if available_pages < requested_pages {
                continue;
            }

            let usable_pages = zone.free_pages_at_or_above_order(order);
            if usable_pages >= requested_pages {
                continue;
            }

            let fragmentation_score = zone.fragmentation_score(order, cached_pages);
            if fragmentation_score < COMPACTION_FRAGMENTATION_THRESHOLD {
                continue;
            }

            let pageblocks = Self::zone_pageblock_counts(zone);
            let candidate = CompactionCandidate {
                zone_idx,
                zone_type: zone.zone_type,
                order,
                migratetype,
                pressure: Self::zone_pressure_for_free_pages(zone, effective_free),
                fragmentation_score,
                requested_pages,
                available_pages,
                usable_pages,
                cached_pages,
                pageblock_count: pageblocks[Migratetype::Unmovable.index()]
                    .saturating_add(pageblocks[Migratetype::Movable.index()]),
                matching_pageblocks: pageblocks[migratetype.index()],
            };

            let replace = match best {
                None => true,
                Some(current) => {
                    candidate.fragmentation_score > current.fragmentation_score
                        || (candidate.fragmentation_score == current.fragmentation_score
                            && candidate.cached_pages > current.cached_pages)
                        || (candidate.fragmentation_score == current.fragmentation_score
                            && candidate.cached_pages == current.cached_pages
                            && candidate.matching_pageblocks > current.matching_pageblocks)
                }
            };

            if replace {
                best = Some(candidate);
            }
        }

        best
    }

    #[inline]
    fn compaction_drain_budget(candidate: CompactionCandidate) -> usize {
        let pageblock_goal = if candidate.matching_pageblocks != 0 {
            PAGEBLOCK_PAGES
        } else {
            candidate.requested_pages
        };
        let target_pages = core::cmp::max(candidate.requested_pages, pageblock_goal)
            .saturating_mul(2)
            .max(LOCAL_CACHE_FLUSH_BATCH);
        core::cmp::min(target_pages, candidate.cached_pages)
    }

    /// Allocate while the caller already owns the global allocator lock.
    fn alloc_locked_with_migratetype(
        &mut self,
        order: u8,
        migratetype: Migratetype,
        token: &IrqDisabledToken,
    ) -> Result<PhysFrame, AllocError> {
        if order > MAX_ORDER as u8 {
            return Err(AllocError::InvalidOrder);
        }

        let cpu_idx = crate::arch::x86_64::percpu::current_cpu_index();
        if ALLOC_IN_PROGRESS[cpu_idx].swap(true, core::sync::atomic::Ordering::Acquire) {
            panic!("Recursive allocation detected on CPU {}!", cpu_idx);
        }

        let result = self
            .alloc_in_zone_order(
                order,
                migratetype,
                Self::preferred_zone_order(migratetype),
                token,
            )
            .ok_or_else(|| {
                crate::memory::buddy::record_buddy_alloc_fail(order);
                AllocError::OutOfMemory
            });

        ALLOC_IN_PROGRESS[cpu_idx].store(false, core::sync::atomic::Ordering::Release);
        result
    }

    /// Allocate from one explicit zone while the caller already owns the global allocator lock.
    fn alloc_zone_locked(
        &mut self,
        order: u8,
        zone: ZoneType,
        migratetype: Migratetype,
        token: &IrqDisabledToken,
    ) -> Result<PhysFrame, AllocError> {
        if order > MAX_ORDER as u8 {
            return Err(AllocError::InvalidOrder);
        }

        let cpu_idx = crate::arch::x86_64::percpu::current_cpu_index();
        if ALLOC_IN_PROGRESS[cpu_idx].swap(true, core::sync::atomic::Ordering::Acquire) {
            panic!("Recursive allocation detected on CPU {}!", cpu_idx);
        }

        let zone_idx = zone as usize;
        let zone_order = [zone_idx];
        let result = self
            .alloc_in_zone_order(order, migratetype, &zone_order, token)
            .ok_or_else(|| {
                crate::memory::buddy::record_buddy_alloc_fail(order);
                AllocError::OutOfMemory
            });

        ALLOC_IN_PROGRESS[cpu_idx].store(false, core::sync::atomic::Ordering::Release);
        result
    }

    fn mark_block_allocated(frame_phys: u64, order: u8, migratetype: Migratetype) {
        let page_count = 1usize << order;
        for page_idx in 0..page_count {
            let phys = frame_phys + page_idx as u64 * PAGE_SIZE;
            let meta = get_meta(PhysAddr::new(phys));
            // Sentinel must still be intact at this point : if not, the frame
            // was never on the free list (double-alloc or metadata corruption).
            debug_assert_eq!(
                meta.get_refcount(),
                crate::memory::frame::REFCOUNT_UNUSED,
                "buddy: mark_block_allocated on frame {:#x} with unexpected refcount (corruption?)",
                phys,
            );
            meta.set_flags(Self::allocated_flags_for(migratetype));
            meta.set_order(order);
            // Leave refcount as REFCOUNT_UNUSED; FrameAllocOptions::allocate()
            // will perform CAS(REFCOUNT_UNUSED → 1) as the fail-fast handoff.
        }
    }

    fn mark_block_free(frame_phys: u64, order: u8, migratetype: Migratetype) {
        Self::set_block_meta(
            frame_phys,
            order,
            Self::free_flags_for(migratetype),
            crate::memory::frame::REFCOUNT_UNUSED,
        );
    }

    /// Stamp every 4 KiB [`MetaSlot`] in the buddy block (flags, order, free-list links, refcount).
    ///
    /// [`MetaSlot::reset_with_free_list_meta`] runs on **each** page, including non-head pages
    /// of a multi-page block: the whole block returns to the buddy as one unit, so vtable and
    /// guard bits are cleared (except poison preserved per-slot) on every constituent frame.
    fn set_block_meta(frame_phys: u64, order: u8, flags: u32, refcount: u32) {
        let page_count = 1usize << order;
        for page_idx in 0..page_count {
            let phys = frame_phys + page_idx as u64 * PAGE_SIZE;
            let meta = get_meta(PhysAddr::new(phys));
            meta.set_flags(flags);
            meta.set_order(order);
            meta.set_next(FRAME_META_LINK_NONE);
            meta.set_prev(FRAME_META_LINK_NONE);
            meta.set_refcount(refcount);
            meta.reset_with_free_list_meta();
        }
    }
}

static BUDDY_ALLOCATOR: SpinLock<Option<BuddyAllocator>> = SpinLock::new(None);

/// Per-order allocation failure counters.
///
/// `BUDDY_ALLOC_FAIL_COUNTS[order]` counts how many times a request for
/// `order` failed to find a free block at `order` or any higher order.
/// These are incremented in `alloc_from_zone` when the loop exhausts all
/// orders without finding a free block.
///
/// Read via `buddy_alloc_fail_counts_snapshot()` for diagnostics.
static BUDDY_ALLOC_FAIL_COUNTS: [core::sync::atomic::AtomicUsize;
    crate::memory::zone::MAX_ORDER + 1] =
    [const { core::sync::atomic::AtomicUsize::new(0) }; crate::memory::zone::MAX_ORDER + 1];

static COMPACTION_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);
static COMPACTION_SUCCESSES: AtomicUsize = AtomicUsize::new(0);
static COMPACTION_LAST_ORDER: AtomicUsize = AtomicUsize::new(COMPACTION_SNAPSHOT_NONE);
static COMPACTION_LAST_MIGRATETYPE: AtomicUsize = AtomicUsize::new(COMPACTION_SNAPSHOT_NONE);
static COMPACTION_LAST_ZONE: AtomicUsize = AtomicUsize::new(COMPACTION_SNAPSHOT_NONE);
static COMPACTION_LAST_PRESSURE: AtomicUsize = AtomicUsize::new(ZonePressure::SNAPSHOT_COUNT);
static COMPACTION_LAST_FRAGMENTATION: AtomicUsize = AtomicUsize::new(0);
static COMPACTION_LAST_REQUESTED_PAGES: AtomicUsize = AtomicUsize::new(0);
static COMPACTION_LAST_AVAILABLE_PAGES: AtomicUsize = AtomicUsize::new(0);
static COMPACTION_LAST_USABLE_PAGES: AtomicUsize = AtomicUsize::new(0);
static COMPACTION_LAST_CACHED_PAGES: AtomicUsize = AtomicUsize::new(0);
static COMPACTION_LAST_DRAINED_PAGES: AtomicUsize = AtomicUsize::new(0);
static COMPACTION_LAST_PAGEBLOCK_COUNT: AtomicUsize = AtomicUsize::new(0);
static COMPACTION_LAST_MATCHING_PAGEBLOCKS: AtomicUsize = AtomicUsize::new(0);

/// Records a buddy allocation failure for the given order.
///
/// Called from `alloc_from_zone` when no free block is available at any
/// order >= `order`. Increments the per-order counter for diagnostics.
pub(crate) fn record_buddy_alloc_fail(order: u8) {
    let idx = order as usize;
    if idx <= crate::memory::zone::MAX_ORDER {
        BUDDY_ALLOC_FAIL_COUNTS[idx].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Returns the buddy allocation failure counts by order.
///
/// Use this for diagnostics : e.g., to determine whether a heap panic is
/// caused by genuine memory pressure or by high-order fragmentation.
pub fn buddy_alloc_fail_counts_snapshot() -> [usize; crate::memory::zone::MAX_ORDER + 1] {
    let mut out = [0usize; crate::memory::zone::MAX_ORDER + 1];
    for (i, counter) in BUDDY_ALLOC_FAIL_COUNTS.iter().enumerate() {
        out[i] = counter.load(core::sync::atomic::Ordering::Relaxed);
    }
    out
}

fn snapshot_zone_type(value: usize) -> Option<ZoneType> {
    match value {
        x if x == ZoneType::DMA as usize => Some(ZoneType::DMA),
        x if x == ZoneType::Normal as usize => Some(ZoneType::Normal),
        x if x == ZoneType::HighMem as usize => Some(ZoneType::HighMem),
        _ => None,
    }
}

fn snapshot_migratetype(value: usize) -> Option<Migratetype> {
    match value {
        x if x == Migratetype::Unmovable as usize => Some(Migratetype::Unmovable),
        x if x == Migratetype::Movable as usize => Some(Migratetype::Movable),
        _ => None,
    }
}

fn record_compaction_attempt(candidate: CompactionCandidate, drained_pages: usize, success: bool) {
    COMPACTION_ATTEMPTS.fetch_add(1, AtomicOrdering::Relaxed);
    if success {
        COMPACTION_SUCCESSES.fetch_add(1, AtomicOrdering::Relaxed);
    }

    COMPACTION_LAST_ORDER.store(candidate.order as usize, AtomicOrdering::Relaxed);
    COMPACTION_LAST_MIGRATETYPE.store(candidate.migratetype as usize, AtomicOrdering::Relaxed);
    COMPACTION_LAST_ZONE.store(candidate.zone_type as usize, AtomicOrdering::Relaxed);
    COMPACTION_LAST_PRESSURE.store(candidate.pressure.as_snapshot(), AtomicOrdering::Relaxed);
    COMPACTION_LAST_FRAGMENTATION.store(candidate.fragmentation_score, AtomicOrdering::Relaxed);
    COMPACTION_LAST_REQUESTED_PAGES.store(candidate.requested_pages, AtomicOrdering::Relaxed);
    COMPACTION_LAST_AVAILABLE_PAGES.store(candidate.available_pages, AtomicOrdering::Relaxed);
    COMPACTION_LAST_USABLE_PAGES.store(candidate.usable_pages, AtomicOrdering::Relaxed);
    COMPACTION_LAST_CACHED_PAGES.store(candidate.cached_pages, AtomicOrdering::Relaxed);
    COMPACTION_LAST_DRAINED_PAGES.store(drained_pages, AtomicOrdering::Relaxed);
    COMPACTION_LAST_PAGEBLOCK_COUNT.store(candidate.pageblock_count, AtomicOrdering::Relaxed);
    COMPACTION_LAST_MATCHING_PAGEBLOCKS
        .store(candidate.matching_pageblocks, AtomicOrdering::Relaxed);
}

/// Snapshot compaction-assist telemetry without locking the allocator.
pub fn compaction_stats_snapshot() -> CompactionStats {
    let last_order = COMPACTION_LAST_ORDER.load(AtomicOrdering::Relaxed);
    let last_migratetype = COMPACTION_LAST_MIGRATETYPE.load(AtomicOrdering::Relaxed);
    let last_zone = COMPACTION_LAST_ZONE.load(AtomicOrdering::Relaxed);
    let last_pressure = COMPACTION_LAST_PRESSURE.load(AtomicOrdering::Relaxed);

    CompactionStats {
        attempts: COMPACTION_ATTEMPTS.load(AtomicOrdering::Relaxed),
        successes: COMPACTION_SUCCESSES.load(AtomicOrdering::Relaxed),
        last_order: if last_order == COMPACTION_SNAPSHOT_NONE {
            None
        } else {
            Some(last_order as u8)
        },
        last_migratetype: snapshot_migratetype(last_migratetype),
        last_zone: snapshot_zone_type(last_zone),
        last_pressure: ZonePressure::from_snapshot(last_pressure),
        last_fragmentation_score: COMPACTION_LAST_FRAGMENTATION.load(AtomicOrdering::Relaxed),
        last_requested_pages: COMPACTION_LAST_REQUESTED_PAGES.load(AtomicOrdering::Relaxed),
        last_available_pages: COMPACTION_LAST_AVAILABLE_PAGES.load(AtomicOrdering::Relaxed),
        last_usable_pages: COMPACTION_LAST_USABLE_PAGES.load(AtomicOrdering::Relaxed),
        last_cached_pages: COMPACTION_LAST_CACHED_PAGES.load(AtomicOrdering::Relaxed),
        last_drained_pages: COMPACTION_LAST_DRAINED_PAGES.load(AtomicOrdering::Relaxed),
        last_pageblock_count: COMPACTION_LAST_PAGEBLOCK_COUNT.load(AtomicOrdering::Relaxed),
        last_matching_pageblocks: COMPACTION_LAST_MATCHING_PAGEBLOCKS.load(AtomicOrdering::Relaxed),
    }
}

/// Pages permanently withheld from the buddy free lists due to [`meta_guard::POISONED`].
static POISON_QUARANTINE_PAGES: AtomicUsize = AtomicUsize::new(0);

/// Snapshot of pages quarantined (not recycled) because frame metadata reported poison.
pub fn poison_quarantine_pages_snapshot() -> usize {
    POISON_QUARANTINE_PAGES.load(AtomicOrdering::Relaxed)
}

/// Returns the global buddy lock address for deadlock tracing.
pub fn debug_buddy_lock_addr() -> usize {
    &BUDDY_ALLOCATOR as *const _ as usize
}

/// Per-CPU flag to detect recursive allocations (deadlocks from logs/interrupts)
static ALLOC_IN_PROGRESS: [core::sync::atomic::AtomicBool; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; crate::arch::x86_64::percpu::MAX_CPUS];

struct LocalFrameCache {
    len: usize,
    frames: [u64; LOCAL_CACHE_CAPACITY],
}

impl LocalFrameCache {
    const fn new() -> Self {
        Self {
            len: 0,
            frames: [0; LOCAL_CACHE_CAPACITY],
        }
    }

    fn clear(&mut self) {
        self.len = 0;
    }

    fn pop(&mut self) -> Option<PhysFrame> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        Some(PhysFrame {
            start_address: PhysAddr::new(self.frames[self.len]),
        })
    }

    fn push(&mut self, frame: PhysFrame) -> Result<(), PhysFrame> {
        if self.len >= LOCAL_CACHE_CAPACITY {
            return Err(frame);
        }
        self.frames[self.len] = frame.start_address.as_u64();
        self.len += 1;
        Ok(())
    }

    fn pop_many(&mut self, out: &mut [u64]) -> usize {
        let count = core::cmp::min(self.len, out.len());
        for slot in out.iter_mut().take(count) {
            self.len -= 1;
            *slot = self.frames[self.len];
        }
        count
    }

    fn pop_many_for_zone(&mut self, out: &mut [u64], zone_idx: usize) -> usize {
        let mut written = 0usize;
        let mut idx = 0usize;

        while idx < self.len && written < out.len() {
            let phys = self.frames[idx];
            if zone_index_for_phys(phys) != zone_idx {
                idx += 1;
                continue;
            }

            self.len -= 1;
            out[written] = phys;
            written += 1;
            self.frames[idx] = self.frames[self.len];
        }

        written
    }
}

static LOCAL_FRAME_CACHES: [SpinLock<LocalFrameCache>; LOCAL_CACHE_SLOTS] =
    [const { SpinLock::new(LocalFrameCache::new()) }; LOCAL_CACHE_SLOTS];
static LOCAL_CACHED_FRAMES: AtomicUsize = AtomicUsize::new(0);
static LOCAL_CACHED_ZONE_FRAMES: [AtomicUsize; ZoneType::COUNT] =
    [const { AtomicUsize::new(0) }; ZoneType::COUNT];
static LOCAL_CACHED_ZONE_MIGRATETYPE_FRAMES: [AtomicUsize; LOCAL_CACHED_ZONE_MIGRATETYPE_SLOTS] =
    [const { AtomicUsize::new(0) }; LOCAL_CACHED_ZONE_MIGRATETYPE_SLOTS];

type GlobalGuard = SpinLockGuard<'static, Option<BuddyAllocator>>;

struct OnDemandGlobalLock {
    guard: Option<GlobalGuard>,
}

impl OnDemandGlobalLock {
    fn new() -> Self {
        Self { guard: None }
    }

    fn unlock(&mut self) {
        self.guard = None;
    }

    fn with_allocator<R>(
        &mut self,
        f: impl FnOnce(&mut BuddyAllocator, &IrqDisabledToken) -> R,
    ) -> Option<R> {
        let guard = self.guard.get_or_insert_with(|| BUDDY_ALLOCATOR.lock());
        guard.with_mut_and_token(|slot, token| slot.as_mut().map(|allocator| f(allocator, token)))
    }

    fn alloc_with_migratetype(
        &mut self,
        order: u8,
        migratetype: Migratetype,
    ) -> Result<PhysFrame, AllocError> {
        self.with_allocator(|allocator, token| {
            allocator.alloc_locked_with_migratetype(order, migratetype, token)
        })
        .unwrap_or(Err(AllocError::OutOfMemory))
    }

    fn free(&mut self, frame: PhysFrame, order: u8) {
        let _ = self.with_allocator(|allocator, token| allocator.free(frame, order, token));
    }

    fn free_phys_batch(&mut self, phys_batch: &[u64], count: usize) {
        if count == 0 {
            return;
        }
        let _ = self.with_allocator(|allocator, token| {
            for phys in phys_batch.iter().take(count).copied() {
                allocator.free(
                    PhysFrame {
                        start_address: PhysAddr::new(phys),
                    },
                    0,
                    token,
                );
            }
        });
    }
}

#[inline]
fn zone_index_for_phys(phys: u64) -> usize {
    if phys < DMA_MAX {
        ZoneType::DMA as usize
    } else if phys < NORMAL_MAX {
        ZoneType::Normal as usize
    } else {
        ZoneType::HighMem as usize
    }
}

#[inline]
fn local_cache_slot(cpu_idx: usize, migratetype: Migratetype) -> usize {
    migratetype.index() * crate::arch::x86_64::percpu::MAX_CPUS + cpu_idx
}

#[inline]
fn local_cached_zone_migratetype_slot(zone_idx: usize, migratetype: Migratetype) -> usize {
    migratetype.index() * ZoneType::COUNT + zone_idx
}

#[inline]
fn is_cacheable_phys_for(phys: u64, migratetype: Migratetype) -> bool {
    match migratetype {
        Migratetype::Unmovable => zone_index_for_phys(phys) == ZoneType::Normal as usize,
        Migratetype::Movable => zone_index_for_phys(phys) != ZoneType::DMA as usize,
    }
}

#[inline]
fn local_cached_zone_migratetype_count(zone_idx: usize, migratetype: Migratetype) -> usize {
    LOCAL_CACHED_ZONE_MIGRATETYPE_FRAMES[local_cached_zone_migratetype_slot(zone_idx, migratetype)]
        .load(AtomicOrdering::Relaxed)
}

#[inline]
fn local_cached_inc_phys(phys: u64, migratetype: Migratetype) {
    let zone_idx = zone_index_for_phys(phys);
    LOCAL_CACHED_FRAMES.fetch_add(1, AtomicOrdering::Relaxed);
    LOCAL_CACHED_ZONE_FRAMES[zone_idx].fetch_add(1, AtomicOrdering::Relaxed);
    LOCAL_CACHED_ZONE_MIGRATETYPE_FRAMES[local_cached_zone_migratetype_slot(zone_idx, migratetype)]
        .fetch_add(1, AtomicOrdering::Relaxed);
}

#[inline]
fn local_cached_dec_phys(phys: u64, migratetype: Migratetype) {
    let prev_total = LOCAL_CACHED_FRAMES.fetch_sub(1, AtomicOrdering::Relaxed);
    debug_assert!(prev_total > 0);
    let zone = zone_index_for_phys(phys);
    let prev_zone = LOCAL_CACHED_ZONE_FRAMES[zone].fetch_sub(1, AtomicOrdering::Relaxed);
    debug_assert!(prev_zone > 0);
    let prev_zone_type = LOCAL_CACHED_ZONE_MIGRATETYPE_FRAMES
        [local_cached_zone_migratetype_slot(zone, migratetype)]
    .fetch_sub(1, AtomicOrdering::Relaxed);
    debug_assert!(prev_zone_type > 0);
}

fn drain_local_caches_to_global(max_pages: usize, global: &mut OnDemandGlobalLock) -> usize {
    if max_pages == 0 {
        return 0;
    }

    let mut drained = 0usize;
    let mut batch = [0u64; LOCAL_CACHE_FLUSH_BATCH];
    for migratetype in Migratetype::ALL {
        for cpu in 0..crate::arch::x86_64::percpu::MAX_CPUS {
            if drained >= max_pages {
                break;
            }
            let target = core::cmp::min(batch.len(), max_pages.saturating_sub(drained));
            if target == 0 {
                break;
            }

            let popped = {
                let mut cache = LOCAL_FRAME_CACHES[local_cache_slot(cpu, migratetype)].lock();
                cache.pop_many(&mut batch[..target])
            };
            if popped == 0 {
                continue;
            }

            for phys in batch.iter().take(popped).copied() {
                local_cached_dec_phys(phys, migratetype);
            }
            global.free_phys_batch(&batch, popped);

            // Keep lock acquisition on-demand during cross-CPU draining.
            global.unlock();
            drained += popped;
        }
    }

    drained
}

fn drain_local_caches_for_zone(
    max_pages: usize,
    zone_idx: usize,
    primary_migratetype: Migratetype,
    global: &mut OnDemandGlobalLock,
) -> usize {
    if max_pages == 0 {
        return 0;
    }

    let mut drained = 0usize;
    let mut batch = [0u64; LOCAL_CACHE_FLUSH_BATCH];

    for migratetype in primary_migratetype.fallback_order() {
        for cpu in 0..crate::arch::x86_64::percpu::MAX_CPUS {
            if drained >= max_pages {
                return drained;
            }

            let target = core::cmp::min(batch.len(), max_pages.saturating_sub(drained));
            if target == 0 {
                break;
            }

            let popped = {
                let mut cache = LOCAL_FRAME_CACHES[local_cache_slot(cpu, migratetype)].lock();
                cache.pop_many_for_zone(&mut batch[..target], zone_idx)
            };
            if popped == 0 {
                continue;
            }

            for phys in batch.iter().take(popped).copied() {
                local_cached_dec_phys(phys, migratetype);
            }
            global.free_phys_batch(&batch, popped);
            global.unlock();
            drained += popped;
        }
    }

    if drained < max_pages {
        drained = drained.saturating_add(drain_local_caches_to_global(
            max_pages.saturating_sub(drained),
            global,
        ));
    }

    drained
}

/// Initializes buddy allocator.
pub fn init_buddy_allocator(memory_regions: &[MemoryRegion]) {
    for cache in &LOCAL_FRAME_CACHES {
        cache.lock().clear();
    }
    LOCAL_CACHED_FRAMES.store(0, AtomicOrdering::Relaxed);
    for zone_cached in &LOCAL_CACHED_ZONE_FRAMES {
        zone_cached.store(0, AtomicOrdering::Relaxed);
    }
    for zone_cached in &LOCAL_CACHED_ZONE_MIGRATETYPE_FRAMES {
        zone_cached.store(0, AtomicOrdering::Relaxed);
    }

    {
        let mut guard = BUDDY_ALLOCATOR.lock();
        *guard = Some(BuddyAllocator::new());
        guard.with_mut_and_token(|slot, _token| {
            if let Some(allocator) = slot.as_mut() {
                allocator.init(memory_regions);
            }
        });
    }
    // Race/corruption diagnostic: register buddy lock for E9 LOCK-A/LOCK-R traces.
    crate::sync::debug_set_trace_buddy_addr(debug_buddy_lock_addr());
}

/// Returns allocator.
pub fn get_allocator() -> &'static SpinLock<Option<BuddyAllocator>> {
    &BUDDY_ALLOCATOR
}

fn refill_local_cache(
    cpu_idx: usize,
    global: &mut OnDemandGlobalLock,
    migratetype: Migratetype,
) -> Result<PhysFrame, AllocError> {
    // Critical path: refill in batches from the global allocator to amortize lock contention.
    let (base, order) = match global.alloc_with_migratetype(LOCAL_CACHE_REFILL_ORDER, migratetype) {
        Ok(frame) => (frame, LOCAL_CACHE_REFILL_ORDER),
        Err(AllocError::OutOfMemory) => (global.alloc_with_migratetype(0, migratetype)?, 0),
        Err(e) => return Err(e),
    };
    global.unlock();

    let frame_count = 1usize << order;
    let mut overflow = [0u64; LOCAL_CACHE_REFILL_FRAMES];
    let mut overflow_len = 0usize;
    let mut ret = None;

    {
        let mut cache = LOCAL_FRAME_CACHES[local_cache_slot(cpu_idx, migratetype)].lock();
        for idx in 0..frame_count {
            let phys = base.start_address.as_u64() + (idx as u64) * PAGE_SIZE;
            let frame = PhysFrame {
                start_address: PhysAddr::new(phys),
            };
            if !is_cacheable_phys_for(phys, migratetype) {
                overflow[overflow_len] = phys;
                overflow_len += 1;
                continue;
            }
            if ret.is_none() {
                // Re-publish the returned page as an allocated order-0 block.
                // The refcount must stay REFCOUNT_UNUSED so FrameAllocOptions
                // can still claim it via CAS(UNUSED -> 1).
                BuddyAllocator::mark_block_allocated(phys, 0, migratetype);
                ret = Some(frame);
                continue;
            }
            // Pages parked in the local cache are logically free and must
            // therefore carry the free-list sentinel invariant.
            BuddyAllocator::mark_block_free(phys, 0, migratetype);
            if cache.push(frame).is_ok() {
                local_cached_inc_phys(phys, migratetype);
            } else {
                overflow[overflow_len] = phys;
                overflow_len += 1;
            }
        }
    }

    if overflow_len != 0 {
        global.free_phys_batch(&overflow, overflow_len);
    }

    ret.ok_or(AllocError::OutOfMemory)
}

fn steal_from_other_caches(cpu_idx: usize, migratetype: Migratetype) -> Option<PhysFrame> {
    let cpu_count = crate::arch::x86_64::percpu::cpu_count()
        .max(1)
        .min(crate::arch::x86_64::percpu::MAX_CPUS);

    for step in 1..cpu_count {
        let peer = (cpu_idx + step) % cpu_count;
        let mut cache = LOCAL_FRAME_CACHES[local_cache_slot(peer, migratetype)].lock();
        if let Some(frame) = cache.pop() {
            BuddyAllocator::mark_block_allocated(frame.start_address.as_u64(), 0, migratetype);
            local_cached_dec_phys(frame.start_address.as_u64(), migratetype);
            return Some(frame);
        }
    }
    None
}

fn alloc_order0_cached(migratetype: Migratetype) -> Result<PhysFrame, AllocError> {
    let cpu_idx = crate::arch::x86_64::percpu::current_cpu_index();

    {
        let mut cache = LOCAL_FRAME_CACHES[local_cache_slot(cpu_idx, migratetype)].lock();
        if let Some(frame) = cache.pop() {
            BuddyAllocator::mark_block_allocated(frame.start_address.as_u64(), 0, migratetype);
            local_cached_dec_phys(frame.start_address.as_u64(), migratetype);
            return Ok(frame);
        }
    }

    let mut global = OnDemandGlobalLock::new();

    if let Ok(frame) = refill_local_cache(cpu_idx, &mut global, migratetype) {
        return Ok(frame);
    }
    // Critical lock-order rule: never hold global while probing local caches.
    global.unlock();

    if let Some(frame) = steal_from_other_caches(cpu_idx, migratetype) {
        return Ok(frame);
    }

    global.alloc_with_migratetype(0, migratetype)
}

fn free_order0_cached(frame: PhysFrame, migratetype: Migratetype) {
    // NOTE: O(2^order) MetaSlot scan : acceptable here because order is always 0
    // (single-page check) on this hot path.
    if crate::memory::frame::block_phys_has_poison_guard(frame.start_address.as_u64(), 0) {
        let mut global = OnDemandGlobalLock::new();
        global.free(frame, 0);
        return;
    }

    if !is_cacheable_phys_for(frame.start_address.as_u64(), migratetype) {
        let mut global = OnDemandGlobalLock::new();
        global.free(frame, 0);
        return;
    }

    let cpu_idx = crate::arch::x86_64::percpu::current_cpu_index();
    let mut spill = [0u64; LOCAL_CACHE_FLUSH_BATCH];

    let spill_len = {
        let mut cache = LOCAL_FRAME_CACHES[local_cache_slot(cpu_idx, migratetype)].lock();
        if cache.push(frame).is_ok() {
            // Mark free only on the success path: the incoming frame transitions
            // from "caller-allocated" to "cache sentinel" (REFCOUNT_UNUSED).
            BuddyAllocator::mark_block_free(frame.start_address.as_u64(), 0, migratetype);
            local_cached_inc_phys(frame.start_address.as_u64(), migratetype);
            return;
        }

        // Cache full: pop existing frames to spill to buddy, then retry the push.
        let mut spill_len = cache.pop_many(&mut spill);
        for phys in spill.iter().take(spill_len).copied() {
            local_cached_dec_phys(phys, migratetype);
        }

        if cache.push(frame).is_ok() {
            BuddyAllocator::mark_block_free(frame.start_address.as_u64(), 0, migratetype);
            local_cached_inc_phys(frame.start_address.as_u64(), migratetype);
        } else {
            // Still full after spilling : the incoming frame joins the spill batch.
            // It will be marked free by free_phys_batch → free_to_zone.
            spill[spill_len] = frame.start_address.as_u64();
            spill_len += 1;
        }
        spill_len
    };

    if spill_len != 0 {
        let mut global = OnDemandGlobalLock::new();
        global.free_phys_batch(&spill, spill_len);
    }
}

/// Allocate frames with per-CPU caching on order-0 requests.
///
/// `_token` is a compile-time proof that interrupts are disabled on the calling CPU,
/// preventing re-entrant allocation through an interrupt handler on the same lock.
pub fn alloc(_token: &IrqDisabledToken, order: u8) -> Result<PhysFrame, AllocError> {
    alloc_migratetype(_token, order, Migratetype::Unmovable)
}

/// Allocate frames with an explicit migratetype preference.
///
/// Order-0 allocations use a per-CPU cache partitioned by migratetype so the
/// fast path preserves the caller's mobility class.
pub fn alloc_migratetype(
    _token: &IrqDisabledToken,
    order: u8,
    migratetype: Migratetype,
) -> Result<PhysFrame, AllocError> {
    if crate::silo::debug_boot_reg_active() {
        crate::serial_println!(
            "[trace][buddy] alloc enter order={} migratetype={:?} buddy_lock={:#x}",
            order,
            migratetype,
            &BUDDY_ALLOCATOR as *const _ as usize
        );
    }
    if order == 0 {
        alloc_order0_cached(migratetype)
    } else {
        let mut global = OnDemandGlobalLock::new();
        match global.alloc_with_migratetype(order, migratetype) {
            Ok(frame) => Ok(frame),
            Err(AllocError::OutOfMemory) => {
                let candidate = global
                    .with_allocator(|allocator, _token| {
                        allocator.compaction_candidate(
                            order,
                            migratetype,
                            BuddyAllocator::preferred_zone_order(migratetype),
                        )
                    })
                    .flatten();

                if let Some(candidate) = candidate {
                    let budget = BuddyAllocator::compaction_drain_budget(candidate);
                    global.unlock();
                    let drained = drain_local_caches_for_zone(
                        budget,
                        candidate.zone_idx,
                        migratetype,
                        &mut global,
                    );
                    let retry = global.alloc_with_migratetype(order, migratetype);
                    record_compaction_attempt(candidate, drained, retry.is_ok());
                    if retry.is_ok() || drained != 0 {
                        return retry;
                    }
                } else {
                    global.unlock();
                }

                let _ = drain_local_caches_to_global(usize::MAX, &mut global);
                global.alloc_with_migratetype(order, migratetype)
            }
            Err(e) => Err(e),
        }
    }
}

/// Free frames with per-CPU caching on order-0 requests.
///
/// `_token` is a compile-time proof that interrupts are disabled on the calling CPU.
pub fn free(_token: &IrqDisabledToken, frame: PhysFrame, order: u8) {
    let migratetype = BuddyAllocator::block_migratetype(frame.start_address.as_u64());
    if order == 0 {
        free_order0_cached(frame, migratetype);
    } else {
        let mut global = OnDemandGlobalLock::new();
        global.free(frame, order);
    }
}

impl FrameAllocator for BuddyAllocator {
    /// Performs the alloc operation.
    fn alloc(&mut self, order: u8, token: &IrqDisabledToken) -> Result<PhysFrame, AllocError> {
        self.alloc_locked_with_migratetype(order, Migratetype::Unmovable, token)
    }

    /// Performs the free operation.
    fn free(&mut self, frame: PhysFrame, order: u8, token: &IrqDisabledToken) {
        let cpu_idx = crate::arch::x86_64::percpu::current_cpu_index();
        if ALLOC_IN_PROGRESS[cpu_idx].swap(true, core::sync::atomic::Ordering::Acquire) {
            panic!("Recursive deallocation detected on CPU {}!", cpu_idx);
        }

        let frame_phys = frame.start_address.as_u64();
        let zi = Self::zone_index_for_addr(frame_phys);
        let zone = &mut self.zones[zi];
        // NOTE: O(2^order) MetaSlot scan. Acceptable for large-order frees
        // (kernel stacks, vmalloc) which are rare; order-0 path is handled
        // separately in free_order0_cached with a single-page check.
        if crate::memory::frame::block_phys_has_poison_guard(frame_phys, order) {
            Self::quarantine_poisoned_block_in_zone(zone, frame, order, token);
        } else {
            Self::free_to_zone(zone, frame, order, token);
        }

        ALLOC_IN_PROGRESS[cpu_idx].store(false, core::sync::atomic::Ordering::Release);
    }
}

impl BuddyAllocator {
    /// Allocate explicitly from one zone (e.g. DMA-only callers).
    pub fn alloc_zone(
        &mut self,
        order: u8,
        zone: ZoneType,
        token: &IrqDisabledToken,
    ) -> Result<PhysFrame, AllocError> {
        self.alloc_zone_locked(order, zone, Migratetype::Unmovable, token)
    }

    /// Allocate explicitly from one zone with a migratetype hint.
    ///
    /// This keeps the target zone fixed but still selects the preferred
    /// free-list class and fallback donor order from `migratetype`.
    pub fn alloc_zone_migratetype(
        &mut self,
        order: u8,
        zone: ZoneType,
        migratetype: Migratetype,
        token: &IrqDisabledToken,
    ) -> Result<PhysFrame, AllocError> {
        self.alloc_zone_locked(order, zone, migratetype, token)
    }
}

/// Derived pressure state for a zone snapshot.
///
/// Thresholds are evaluated against the zone's effective free pages, including
/// pages parked in order-0 per-CPU caches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZonePressure {
    /// Free pages are above the high watermark.
    Healthy,
    /// Free pages dropped below the high watermark.
    High,
    /// Free pages dropped below the low watermark.
    Low,
    /// Free pages reached the minimum watermark plus reserve floor.
    Min,
}

impl ZonePressure {
    const SNAPSHOT_COUNT: usize = 4;

    #[inline]
    const fn as_snapshot(self) -> usize {
        match self {
            Self::Healthy => 0,
            Self::High => 1,
            Self::Low => 2,
            Self::Min => 3,
        }
    }

    #[inline]
    const fn from_snapshot(value: usize) -> Option<Self> {
        match value {
            0 => Some(Self::Healthy),
            1 => Some(Self::High),
            2 => Some(Self::Low),
            3 => Some(Self::Min),
            _ => None,
        }
    }
}

/// Snapshot statistics for a single memory zone.
///
/// The struct is plain data on purpose so low-level diagnostics and crash paths
/// can snapshot it onto the stack without heap allocation.
#[derive(Debug, Clone, Copy)]
pub struct ZoneStats {
    /// Zone classification.
    pub zone_type: ZoneType,
    /// Lowest physical address covered by the zone span.
    pub base: u64,
    /// Pages currently managed by buddy in this zone.
    pub managed_pages: usize,
    /// Pages reported as usable by the firmware map before reservations.
    pub present_pages: usize,
    /// Outer span in pages, including holes.
    pub spanned_pages: usize,
    /// Pages removed from management during bootstrap.
    pub reserved_pages: usize,
    /// Pages allocated to live callers.
    pub allocated_pages: usize,
    /// Order-0 pages currently parked in per-CPU caches.
    pub cached_pages: usize,
    /// Cached pages parked in unmovable per-CPU caches.
    pub cached_unmovable_pages: usize,
    /// Cached pages parked in movable per-CPU caches.
    pub cached_movable_pages: usize,
    /// Effective free pages, including cached pages.
    pub free_pages: usize,
    /// Free pages tracked in movable free lists.
    pub movable_free_pages: usize,
    /// Free pages tracked in unmovable free lists.
    pub unmovable_free_pages: usize,
    /// Number of populated contiguous segments.
    pub segment_count: usize,
    /// Reserved segment-table capacity.
    pub segment_capacity: usize,
    /// Total number of pageblocks tracked across all segments.
    pub pageblock_count: usize,
    /// Pageblocks currently tagged unmovable.
    pub unmovable_pageblocks: usize,
    /// Pageblocks currently tagged movable.
    pub movable_pageblocks: usize,
    /// Minimum watermark.
    pub watermark_min: usize,
    /// Low watermark.
    pub watermark_low: usize,
    /// High watermark.
    pub watermark_high: usize,
    /// Low-memory reserve kept for lower-priority paths.
    pub lowmem_reserve_pages: usize,
    /// Largest currently available free order.
    pub largest_free_order: Option<u8>,
}

impl ZoneStats {
    /// Empty snapshot entry for stack-allocated arrays.
    pub const fn empty() -> Self {
        Self {
            zone_type: ZoneType::DMA,
            base: 0,
            managed_pages: 0,
            present_pages: 0,
            spanned_pages: 0,
            reserved_pages: 0,
            allocated_pages: 0,
            cached_pages: 0,
            cached_unmovable_pages: 0,
            cached_movable_pages: 0,
            free_pages: 0,
            movable_free_pages: 0,
            unmovable_free_pages: 0,
            segment_count: 0,
            segment_capacity: 0,
            pageblock_count: 0,
            unmovable_pageblocks: 0,
            movable_pageblocks: 0,
            watermark_min: 0,
            watermark_low: 0,
            watermark_high: 0,
            lowmem_reserve_pages: 0,
            largest_free_order: None,
        }
    }

    /// Returns the number of hole pages inside the zone span.
    #[inline]
    pub fn hole_pages(&self) -> usize {
        self.spanned_pages.saturating_sub(self.managed_pages)
    }

    /// Returns the effective reserve floor enforced by policy.
    #[inline]
    pub fn reserve_floor_pages(&self) -> usize {
        self.watermark_min.saturating_add(self.lowmem_reserve_pages)
    }

    /// Returns the free pages remaining after the reserve floor is discounted.
    #[inline]
    pub fn available_after_reserve_pages(&self) -> usize {
        self.free_pages.saturating_sub(self.reserve_floor_pages())
    }

    /// Returns the derived pressure state from the current zone watermarks.
    pub fn pressure(&self) -> ZonePressure {
        let reserve_floor = self.reserve_floor_pages();
        let low_floor = self.watermark_low.saturating_add(self.lowmem_reserve_pages);
        let high_floor = self
            .watermark_high
            .saturating_add(self.lowmem_reserve_pages);

        if self.free_pages <= reserve_floor {
            ZonePressure::Min
        } else if self.free_pages <= low_floor {
            ZonePressure::Low
        } else if self.free_pages <= high_floor {
            ZonePressure::High
        } else {
            ZonePressure::Healthy
        }
    }
}

/// Snapshot of the last fragmentation-driven compaction assist attempt.
///
/// The fields are intentionally plain data so crash dumps and shell commands
/// can read them without locking or heap allocation.
#[derive(Debug, Clone, Copy)]
pub struct CompactionStats {
    /// Number of targeted compaction assists attempted after an allocation miss.
    pub attempts: usize,
    /// Number of attempts that yielded a successful retry.
    pub successes: usize,
    /// Last requested buddy order that triggered a targeted drain.
    pub last_order: Option<u8>,
    /// Mobility class of the last assisted allocation.
    pub last_migratetype: Option<Migratetype>,
    /// Zone selected as the preferred compaction target.
    pub last_zone: Option<ZoneType>,
    /// Pressure state observed on that zone before draining caches.
    pub last_pressure: Option<ZonePressure>,
    /// Fragmentation score that justified the assist path.
    pub last_fragmentation_score: usize,
    /// Pages requested by the original allocation.
    pub last_requested_pages: usize,
    /// Effective free pages left above reserves in the chosen zone.
    pub last_available_pages: usize,
    /// Free pages already available at or above the requested order.
    pub last_usable_pages: usize,
    /// Order-0 pages parked in local caches for the chosen zone.
    pub last_cached_pages: usize,
    /// Pages actually drained from local caches during the last attempt.
    pub last_drained_pages: usize,
    /// Total pageblocks tracked in the selected zone.
    pub last_pageblock_count: usize,
    /// Pageblocks already tagged with the requested migratetype.
    pub last_matching_pageblocks: usize,
}

impl CompactionStats {
    /// Empty snapshot used before any assisted drain happened.
    pub const fn empty() -> Self {
        Self {
            attempts: 0,
            successes: 0,
            last_order: None,
            last_migratetype: None,
            last_zone: None,
            last_pressure: None,
            last_fragmentation_score: 0,
            last_requested_pages: 0,
            last_available_pages: 0,
            last_usable_pages: 0,
            last_cached_pages: 0,
            last_drained_pages: 0,
            last_pageblock_count: 0,
            last_matching_pageblocks: 0,
        }
    }
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
        let cached_pages = LOCAL_CACHED_FRAMES.load(AtomicOrdering::Relaxed);
        allocated_pages = allocated_pages.saturating_sub(cached_pages);
        (total_pages, allocated_pages)
    }

    /// Get a reference to a zone by index.
    pub fn get_zone(&self, idx: usize) -> &Zone {
        &self.zones[idx]
    }

    /// Snapshot zones without heap allocation.
    /// Returns the number of entries written to `out`.
    pub fn zone_snapshot(&self, out: &mut [ZoneStats]) -> usize {
        let n = core::cmp::min(out.len(), self.zones.len());
        for (i, zone) in self.zones.iter().take(n).enumerate() {
            let cached_unmovable = local_cached_zone_migratetype_count(i, Migratetype::Unmovable);
            let cached_movable = local_cached_zone_migratetype_count(i, Migratetype::Movable);
            let cached = cached_unmovable.saturating_add(cached_movable);
            let pageblocks = Self::zone_pageblock_counts(zone);
            let mut free_by_type = zone.free_pages_by_migratetype();
            free_by_type[Migratetype::Unmovable.index()] =
                free_by_type[Migratetype::Unmovable.index()].saturating_add(cached_unmovable);
            free_by_type[Migratetype::Movable.index()] =
                free_by_type[Migratetype::Movable.index()].saturating_add(cached_movable);
            out[i] = ZoneStats {
                zone_type: zone.zone_type,
                base: zone.base.as_u64(),
                managed_pages: zone.page_count,
                present_pages: zone.present_pages,
                spanned_pages: zone.span_pages,
                reserved_pages: zone.reserved_pages,
                allocated_pages: zone.allocated.saturating_sub(cached),
                cached_pages: cached,
                cached_unmovable_pages: cached_unmovable,
                cached_movable_pages: cached_movable,
                free_pages: Self::zone_effective_free_pages(zone, i),
                movable_free_pages: free_by_type[Migratetype::Movable.index()],
                unmovable_free_pages: free_by_type[Migratetype::Unmovable.index()],
                segment_count: zone.segment_count,
                segment_capacity: zone.segment_capacity,
                pageblock_count: pageblocks[Migratetype::Unmovable.index()]
                    .saturating_add(pageblocks[Migratetype::Movable.index()]),
                unmovable_pageblocks: pageblocks[Migratetype::Unmovable.index()],
                movable_pageblocks: pageblocks[Migratetype::Movable.index()],
                watermark_min: zone.watermark_min,
                watermark_low: zone.watermark_low,
                watermark_high: zone.watermark_high,
                lowmem_reserve_pages: zone.lowmem_reserve_pages,
                largest_free_order: zone.largest_free_order(),
            };
        }
        n
    }
}
