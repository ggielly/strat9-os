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
        zone::{BuddyBitmap, Zone, ZoneType, MAX_ORDER},
    },
    serial_println,
    sync::{IrqDisabledToken, SpinLock, SpinLockGuard},
};
use core::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use x86_64::PhysAddr;

const PAGE_SIZE: u64 = 4096;
const DMA_MAX: u64 = 16 * 1024 * 1024;
const NORMAL_MAX: u64 = 896 * 1024 * 1024;
const LOCAL_CACHE_CAPACITY: usize = 256;
const LOCAL_CACHE_REFILL_ORDER: u8 = 4;
const LOCAL_CACHE_REFILL_FRAMES: usize = 1 << (LOCAL_CACHE_REFILL_ORDER as usize);
const LOCAL_CACHE_FLUSH_BATCH: usize = 64;

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

        // Pass 2: reserve bitmap storage via the boot allocator.
        self.pass_boot_alloc_and_setup_bitmaps();

        // Pass 3: populate free lists from the boot allocator's remaining ranges.
        let mut remaining = [MemoryRegion {
            base: 0,
            size: 0,
            kind: MemoryKind::Reserved,
        }; boot_alloc::MAX_BOOT_ALLOC_REGIONS];
        let remaining_len = boot_alloc::snapshot_free_regions(&mut remaining);
        self.pass_populate(&remaining[..remaining_len]);

        // Seal the boot allocator: all its remaining free regions are now managed
        // by buddy.  Any later boot_alloc::alloc_stack() call would otherwise
        // double-allocate pages that buddy already tracks in its free lists.
        boot_alloc::seal();

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

    /// Performs the pass count operation.
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

    /// Performs the pass steal and setup bitmaps operation.
    fn pass_boot_alloc_and_setup_bitmaps(&mut self) {
        for zi in 0..ZoneType::COUNT {
            let zone_span = self.zones[zi].span_pages;
            let needed_bytes = Self::bitmap_bytes_for_span(zone_span);
            let reserved_bytes = Self::align_up(needed_bytes as u64, PAGE_SIZE);

            if reserved_bytes == 0 {
                self.bitmap_pool[zi] = (0, 0);
                self.clear_zone_bitmaps(zi);
                continue;
            }

            let pool_start = boot_alloc::alloc_bytes(needed_bytes, PAGE_SIZE as usize)
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

            self.setup_zone_bitmaps(zi, pool_start, pool_end);
        }
    }

    /// Performs the pass populate operation.
    fn pass_populate(&mut self, memory_regions: &[MemoryRegion]) {
        for region in memory_regions {
            for zi in 0..ZoneType::COUNT {
                let Some((start, end)) = Self::zone_intersection_aligned(region, zi) else {
                    continue;
                };
                self.seed_range_as_free(zi, start, end);
            }
        }
    }

    /// Performs the clear zone bitmaps operation.
    fn clear_zone_bitmaps(&mut self, zone_idx: usize) {
        let zone = &mut self.zones[zone_idx];
        zone.buddy_bitmaps = [BuddyBitmap::empty(); MAX_ORDER + 1];
        #[cfg(debug_assertions)]
        {
            zone.alloc_bitmap = BuddyBitmap::empty();
        }
    }

    /// Performs the setup zone bitmaps operation.
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

    /// Performs the seed range as free operation.
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

    /// Allocates from zone.
    fn alloc_from_zone(zone: &mut Zone, order: u8, _token: &IrqDisabledToken) -> Option<PhysFrame> {
        for cur_order in order..=MAX_ORDER as u8 {
            let Some(frame_phys) = Self::free_list_pop(zone, cur_order) else {
                continue;
            };
            let block_size = PAGE_SIZE << cur_order;
            let block_end = frame_phys.saturating_add(block_size);
            if Self::protected_overlap_end(frame_phys, block_end).is_some() {
                // Inconsistency: a free block overlaps with protected kernel memory.
                // This means seed_range_as_free() was incorrect.
                panic!("Buddy allocator inconsistency: free block 0x{:x} order {} overlaps protected memory", frame_phys, cur_order);
            }

            // One block of this order transitions free -> allocated.
            let _ = Self::toggle_pair(zone, frame_phys, cur_order);

            // Split down to requested order.
            let mut split_order = cur_order;
            while split_order > order {
                split_order -= 1;
                let buddy_phys = frame_phys + ((1u64 << split_order) * PAGE_SIZE);
                Self::mark_block_free(buddy_phys, split_order);
                Self::free_list_push(zone, buddy_phys, split_order);
                // Pair at split_order becomes (allocated, free).
                let _ = Self::toggle_pair(zone, frame_phys, split_order);
            }

            zone.allocated += 1usize << order;
            Self::mark_block_allocated(frame_phys, order);

            #[cfg(debug_assertions)]
            Self::mark_allocated(zone, frame_phys, order, true);

            return PhysFrame::from_start_address(PhysAddr::new(frame_phys)).ok();
        }
        None
    }

    /// Releases to zone.
    fn free_to_zone(zone: &mut Zone, frame: PhysFrame, order: u8, _token: &IrqDisabledToken) {
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

        Self::mark_block_free(frame_phys, order);
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
                Self::mark_block_free(current, order);
                Self::free_list_push(zone, current, order);
                break;
            }

            let Some(buddy) = Self::buddy_phys(zone, current, order) else {
                Self::mark_block_free(current, order);
                Self::free_list_push(zone, current, order);
                break;
            };

            let removed = Self::free_list_remove(zone, buddy, order);
            if !removed {
                // Inconsistency fallback: keep allocator consistent.
                debug_assert!(false, "buddy bitmap/list inconsistency while freeing");
                Self::mark_block_free(current, order);
                Self::free_list_push(zone, current, order);
                break;
            }

            current = core::cmp::min(current, buddy);
            order += 1;
        }
    }

    /// Performs the page index operation.
    #[inline]
    fn page_index(zone: &Zone, phys: u64) -> usize {
        debug_assert!(zone.span_pages > 0);
        let base = zone.base.as_u64();
        debug_assert!(phys >= base);
        debug_assert!((phys - base).is_multiple_of(PAGE_SIZE));
        ((phys - base) / PAGE_SIZE) as usize
    }

    /// Performs the pair index operation.
    #[inline]
    fn pair_index(zone: &Zone, phys: u64, order: u8) -> usize {
        Self::page_index(zone, phys) >> (order as usize + 1)
    }

    /// Performs the toggle pair operation.
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

    /// Performs the buddy phys operation.
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

    /// Performs the mark allocated operation.
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

    /// Releases list push.
    fn free_list_push(zone: &mut Zone, phys: u64, order: u8) {
        let head = zone.free_lists[order as usize];
        Self::write_free_prev(phys, 0);
        Self::write_free_next(phys, head);
        if head != 0 {
            Self::write_free_prev(head, phys);
        }
        zone.free_lists[order as usize] = phys;
    }

    /// Releases list pop.
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

    /// Releases list remove.
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

    /// Returns whether protected module page.
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

    /// Performs the protected module ranges operation.
    fn protected_module_ranges() -> [Option<(u64, u64)>; boot_alloc::MAX_PROTECTED_RANGES] {
        boot_alloc::protected_module_ranges()
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
        bytes
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

    fn mark_block_allocated(frame_phys: u64, order: u8) {
        let page_count = 1usize << order;
        for page_idx in 0..page_count {
            let phys = frame_phys + page_idx as u64 * PAGE_SIZE;
            let meta = get_meta(PhysAddr::new(phys));
            // Sentinel must still be intact at this point — if not, the frame
            // was never on the free list (double-alloc or metadata corruption).
            debug_assert_eq!(
                meta.get_refcount(),
                crate::memory::frame::REFCOUNT_UNUSED,
                "buddy: mark_block_allocated on frame {:#x} with unexpected refcount (corruption?)",
                phys,
            );
            meta.set_flags(frame_flags::ALLOCATED);
            meta.set_order(order);
            // Leave refcount as REFCOUNT_UNUSED; FrameAllocOptions::allocate()
            // will perform CAS(REFCOUNT_UNUSED → 1) as the fail-fast handoff.
        }
    }

    fn mark_block_free(frame_phys: u64, order: u8) {
        Self::set_block_meta(
            frame_phys,
            order,
            frame_flags::FREE,
            crate::memory::frame::REFCOUNT_UNUSED,
        );
    }

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
        }
    }
}

static BUDDY_ALLOCATOR: SpinLock<Option<BuddyAllocator>> = SpinLock::new(None);

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
}

static LOCAL_FRAME_CACHES: [SpinLock<LocalFrameCache>; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { SpinLock::new(LocalFrameCache::new()) }; crate::arch::x86_64::percpu::MAX_CPUS];
static LOCAL_CACHED_FRAMES: AtomicUsize = AtomicUsize::new(0);
static LOCAL_CACHED_ZONE_FRAMES: [AtomicUsize; ZoneType::COUNT] =
    [const { AtomicUsize::new(0) }; ZoneType::COUNT];

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

    fn alloc(&mut self, order: u8) -> Result<PhysFrame, AllocError> {
        self.with_allocator(|allocator, token| allocator.alloc(order, token))
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
fn is_cacheable_phys(phys: u64) -> bool {
    zone_index_for_phys(phys) == ZoneType::Normal as usize
}

#[inline]
fn local_cached_inc_phys(phys: u64) {
    LOCAL_CACHED_FRAMES.fetch_add(1, AtomicOrdering::Relaxed);
    LOCAL_CACHED_ZONE_FRAMES[zone_index_for_phys(phys)].fetch_add(1, AtomicOrdering::Relaxed);
}

#[inline]
fn local_cached_dec_phys(phys: u64) {
    let prev_total = LOCAL_CACHED_FRAMES.fetch_sub(1, AtomicOrdering::Relaxed);
    debug_assert!(prev_total > 0);
    let zone = zone_index_for_phys(phys);
    let prev_zone = LOCAL_CACHED_ZONE_FRAMES[zone].fetch_sub(1, AtomicOrdering::Relaxed);
    debug_assert!(prev_zone > 0);
}

fn drain_local_caches_to_global(max_pages: usize, global: &mut OnDemandGlobalLock) -> usize {
    if max_pages == 0 {
        return 0;
    }

    let mut drained = 0usize;
    let mut batch = [0u64; LOCAL_CACHE_FLUSH_BATCH];
    for cpu in 0..crate::arch::x86_64::percpu::MAX_CPUS {
        if drained >= max_pages {
            break;
        }
        let target = core::cmp::min(batch.len(), max_pages.saturating_sub(drained));
        if target == 0 {
            break;
        }

        let popped = {
            let mut cache = LOCAL_FRAME_CACHES[cpu].lock();
            cache.pop_many(&mut batch[..target])
        };
        if popped == 0 {
            continue;
        }

        for phys in batch.iter().take(popped).copied() {
            local_cached_dec_phys(phys);
        }
        global.free_phys_batch(&batch, popped);

        // Keep lock acquisition on-demand during cross-CPU draining.
        global.unlock();
        drained += popped;
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

    let mut allocator = BuddyAllocator::new();
    allocator.init(memory_regions);
    *BUDDY_ALLOCATOR.lock() = Some(allocator);
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
) -> Result<PhysFrame, AllocError> {
    // Critical path: refill in batches from the global allocator to amortize lock contention.
    let (base, order) = match global.alloc(LOCAL_CACHE_REFILL_ORDER) {
        Ok(frame) => (frame, LOCAL_CACHE_REFILL_ORDER),
        Err(AllocError::OutOfMemory) => (global.alloc(0)?, 0),
        Err(e) => return Err(e),
    };
    global.unlock();

    let frame_count = 1usize << order;
    let mut overflow = [0u64; LOCAL_CACHE_REFILL_FRAMES];
    let mut overflow_len = 0usize;
    let mut ret = None;

    {
        let mut cache = LOCAL_FRAME_CACHES[cpu_idx].lock();
        for idx in 0..frame_count {
            let phys = base.start_address.as_u64() + (idx as u64) * PAGE_SIZE;
            let frame = PhysFrame {
                start_address: PhysAddr::new(phys),
            };
            if !is_cacheable_phys(phys) {
                overflow[overflow_len] = phys;
                overflow_len += 1;
                continue;
            }
            if ret.is_none() {
                ret = Some(frame);
                continue;
            }
            if cache.push(frame).is_ok() {
                local_cached_inc_phys(phys);
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

fn steal_from_other_caches(cpu_idx: usize) -> Option<PhysFrame> {
    let cpu_count = crate::arch::x86_64::percpu::cpu_count()
        .max(1)
        .min(crate::arch::x86_64::percpu::MAX_CPUS);

    for step in 1..cpu_count {
        let peer = (cpu_idx + step) % cpu_count;
        let mut cache = LOCAL_FRAME_CACHES[peer].lock();
        if let Some(frame) = cache.pop() {
            local_cached_dec_phys(frame.start_address.as_u64());
            return Some(frame);
        }
    }
    None
}

fn alloc_order0_cached() -> Result<PhysFrame, AllocError> {
    let cpu_idx = crate::arch::x86_64::percpu::current_cpu_index();

    {
        let mut cache = LOCAL_FRAME_CACHES[cpu_idx].lock();
        if let Some(frame) = cache.pop() {
            local_cached_dec_phys(frame.start_address.as_u64());
            return Ok(frame);
        }
    }

    let mut global = OnDemandGlobalLock::new();

    if let Ok(frame) = refill_local_cache(cpu_idx, &mut global) {
        return Ok(frame);
    }
    // Critical lock-order rule: never hold global while probing local caches.
    global.unlock();

    if let Some(frame) = steal_from_other_caches(cpu_idx) {
        return Ok(frame);
    }

    global.alloc(0)
}

fn free_order0_cached(frame: PhysFrame) {
    if !is_cacheable_phys(frame.start_address.as_u64()) {
        let mut global = OnDemandGlobalLock::new();
        global.free(frame, 0);
        return;
    }

    let cpu_idx = crate::arch::x86_64::percpu::current_cpu_index();
    let mut spill = [0u64; LOCAL_CACHE_FLUSH_BATCH];

    let spill_len = {
        let mut cache = LOCAL_FRAME_CACHES[cpu_idx].lock();
        if cache.push(frame).is_ok() {
            local_cached_inc_phys(frame.start_address.as_u64());
            return;
        }

        let mut spill_len = cache.pop_many(&mut spill);
        for phys in spill.iter().take(spill_len).copied() {
            local_cached_dec_phys(phys);
        }

        if cache.push(frame).is_ok() {
            local_cached_inc_phys(frame.start_address.as_u64());
        } else {
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
    if crate::silo::debug_boot_reg_active() {
        crate::serial_println!(
            "[trace][buddy] alloc enter order={} buddy_lock={:#x}",
            order,
            &BUDDY_ALLOCATOR as *const _ as usize
        );
    }
    if order == 0 {
        alloc_order0_cached()
    } else {
        let mut global = OnDemandGlobalLock::new();
        match global.alloc(order) {
            Ok(frame) => Ok(frame),
            Err(AllocError::OutOfMemory) => {
                // Critical lock-order rule: release global before draining local caches.
                global.unlock();
                let _ = drain_local_caches_to_global(usize::MAX, &mut global);
                global.alloc(order)
            }
            Err(e) => Err(e),
        }
    }
}

/// Free frames with per-CPU caching on order-0 requests.
///
/// `_token` is a compile-time proof that interrupts are disabled on the calling CPU.
pub fn free(_token: &IrqDisabledToken, frame: PhysFrame, order: u8) {
    if order == 0 {
        free_order0_cached(frame);
    } else {
        let mut global = OnDemandGlobalLock::new();
        global.free(frame, order);
    }
}

impl FrameAllocator for BuddyAllocator {
    /// Performs the alloc operation.
    fn alloc(&mut self, order: u8, token: &IrqDisabledToken) -> Result<PhysFrame, AllocError> {
        if order > MAX_ORDER as u8 {
            return Err(AllocError::InvalidOrder);
        }

        let cpu_idx = crate::arch::x86_64::percpu::current_cpu_index();
        if ALLOC_IN_PROGRESS[cpu_idx].swap(true, core::sync::atomic::Ordering::Acquire) {
            panic!("Recursive allocation detected on CPU {}!", cpu_idx);
        }

        let result = (|| {
            for zi in [
                ZoneType::Normal as usize,
                ZoneType::HighMem as usize,
                ZoneType::DMA as usize,
            ] {
                if let Some(frame) = Self::alloc_from_zone(&mut self.zones[zi], order, token) {
                    return Ok(frame);
                }
            }
            Err(AllocError::OutOfMemory)
        })();

        ALLOC_IN_PROGRESS[cpu_idx].store(false, core::sync::atomic::Ordering::Release);
        result
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
        Self::free_to_zone(zone, frame, order, token);

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
        if order > MAX_ORDER as u8 {
            return Err(AllocError::InvalidOrder);
        }

        let cpu_idx = crate::arch::x86_64::percpu::current_cpu_index();
        if ALLOC_IN_PROGRESS[cpu_idx].swap(true, core::sync::atomic::Ordering::Acquire) {
            panic!("Recursive allocation detected on CPU {}!", cpu_idx);
        }

        let result = Self::alloc_from_zone(&mut self.zones[zone as usize], order, token)
            .ok_or(AllocError::OutOfMemory);

        ALLOC_IN_PROGRESS[cpu_idx].store(false, core::sync::atomic::Ordering::Release);
        result
    }
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
        let cached_pages = LOCAL_CACHED_FRAMES.load(AtomicOrdering::Relaxed);
        allocated_pages = allocated_pages.saturating_sub(cached_pages);
        (total_pages, allocated_pages)
    }

    /// Snapshot zones without heap allocation.
    /// Returns the number of entries written to `out`.
    pub fn zone_snapshot(&self, out: &mut [(u8, u64, usize, usize)]) -> usize {
        let n = core::cmp::min(out.len(), self.zones.len());
        for (i, zone) in self.zones.iter().take(n).enumerate() {
            let cached = LOCAL_CACHED_ZONE_FRAMES[i].load(AtomicOrdering::Relaxed);
            out[i] = (
                zone.zone_type as u8,
                zone.base.as_u64(),
                zone.page_count,
                zone.allocated.saturating_sub(cached),
            );
        }
        n
    }
}
