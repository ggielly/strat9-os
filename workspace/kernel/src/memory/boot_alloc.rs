//! Allocateur physique de boot pour les structures permanentes du noyau.

use crate::{
    boot::entry::{MemoryKind, MemoryRegion},
    memory::phys_to_virt,
    serial_println,
    sync::SpinLock,
};
use crate::arch::xshim::PhysAddr;

const PAGE_SIZE: u64 = 4096;
pub const MAX_BOOT_ALLOC_REGIONS: usize = 512;
pub const MAX_PROTECTED_RANGES: usize = 32;

#[derive(Clone, Copy)]
struct BootRegion {
    start: u64,
    end: u64,
}

impl BootRegion {
    const fn empty() -> Self {
        Self { start: 0, end: 0 }
    }

    #[inline]
    const fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

pub struct BootAllocator {
    regions: [BootRegion; MAX_BOOT_ALLOC_REGIONS],
    len: usize,
    accessible_limit: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BootAllocStats {
    pub region_count: usize,
    pub total_free_bytes: u64,
    pub largest_region_bytes: u64,
    pub accessible_limit: u64,
}

impl BootAllocator {
    pub const fn new() -> Self {
        Self {
            regions: [BootRegion::empty(); MAX_BOOT_ALLOC_REGIONS],
            len: 0,
            accessible_limit: 0,
        }
    }

    pub fn init(&mut self, regions: &[MemoryRegion]) {
        // TEMP DEBUG: count init() calls - the post-switch V-storm may be this
        // function being re-entered by a corrupted resume.
        {
            static INIT_CALLS: core::sync::atomic::AtomicUsize =
                core::sync::atomic::AtomicUsize::new(0);
            let n = INIT_CALLS.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
            unsafe {
                let hex = b"0123456789abcdef";
                core::arch::asm!("out 0xe9, al", in("al") b'I', options(nomem, nostack));
                for sh in [12usize, 8, 4, 0] {
                    let nib = hex[((n >> sh) & 0xF) as usize];
                    core::arch::asm!("out 0xe9, al", in("al") nib, options(nomem, nostack));
                }
                core::arch::asm!("out 0xe9, al", in("al") b'\n', options(nomem, nostack));
            }
        }
        crate::e9_println!("BI init");
        if self.len != 0 {
            self.reset();
        }
        crate::e9_println!("BI reset");

        for region in regions {
            if !matches!(region.kind, MemoryKind::Free | MemoryKind::Reclaim) {
                continue;
            }

            let start = align_up(region.base, PAGE_SIZE);
            let end = align_down(region.base.saturating_add(region.size), PAGE_SIZE);
            if start >= end {
                continue;
            }

            self.push_region(BootRegion { start, end });
        }
        crate::e9_println!("BI push");

        self.normalize_regions();
        crate::e9_println!("BI norm1");

        crate::e9_mark!(b'U');
        let guard = PROTECTED_RANGES.lock();
        crate::e9_mark!(b'u');
        for entry in guard.iter() {
            let (base, size) = match *entry {
                Some(v) => v,
                None => continue,
            };
            if size == 0 {
                continue;
            }
            crate::e9_mark!(b'V');
            self.exclude_range(
                align_down(base, PAGE_SIZE),
                align_up(base.saturating_add(size), PAGE_SIZE),
            );
            crate::e9_mark!(b'v');
        }
        drop(guard);
        crate::e9_mark!(b'W');

        self.normalize_regions();
        crate::e9_println!("BI norm2 pre");
        self.rebuild_accessible_limit();
        crate::e9_println!("BI done");
    }

    pub fn alloc(&mut self, size: usize, align: usize) -> PhysAddr {
        self.try_alloc(size, align).unwrap_or_else(|| {
            panic!(
                "boot allocator: out of physical memory for size={} align={}",
                size, align
            )
        })
    }

    pub fn try_alloc(&mut self, size: usize, align: usize) -> Option<PhysAddr> {
        if crate::debug_cfg::is_quiet() {
            // TEMP DEBUG: 'b' pulse per try_alloc (throttled by caller loops anyway).
            unsafe { core::arch::asm!("out 0xe9, al", in("al") b'b', options(nomem, nostack)) };
        }
        if size == 0 {
            return Some(PhysAddr::new(0));
        }

        let align = normalize_align(align) as u64;
        let size = align_up(size as u64, PAGE_SIZE);

        for idx in 0..self.len {
            let region = self.regions[idx];
            if region.is_empty() {
                continue;
            }

            let alloc_start = align_up(region.start, align);
            let alloc_end = alloc_start.checked_add(size)?;
            if alloc_end > region.end {
                continue;
            }

            self.consume_region(idx, alloc_start, alloc_end);
            return Some(PhysAddr::new(alloc_start));
        }

        let stats = self.stats();
        serial_println!(
            "[boot_alloc] try_alloc failed: requested={} aligned={} largest_region={} regions={} total_free={}",
            size as usize,
            align as usize,
            stats.largest_region_bytes as usize,
            stats.region_count,
            stats.total_free_bytes as usize
        );
        None
    }

    pub fn try_alloc_accessible(&mut self, size: usize, align: usize) -> Option<PhysAddr> {
        if crate::debug_cfg::is_quiet() {
            unsafe { core::arch::asm!("out 0xe9, al", in("al") b'a', options(nomem, nostack)) };
        }
        if size == 0 {
            return Some(PhysAddr::new(0));
        }

        let align = normalize_align(align) as u64;
        let size = align_up(size as u64, PAGE_SIZE);

        for idx in 0..self.len {
            let region = self.regions[idx];
            if region.is_empty() {
                continue;
            }

            let alloc_start = align_up(region.start, align);
            let alloc_end = alloc_start.checked_add(size)?;
            if alloc_end > region.end {
                continue;
            }

            if self.accessible_limit != 0 && alloc_end > self.accessible_limit {
                continue;
            }

            if !crate::memory::paging::is_hhdm_range_mapped_now(alloc_start, size) {
                continue;
            }

            self.consume_region(idx, alloc_start, alloc_end);
            return Some(PhysAddr::new(alloc_start));
        }

        let stats = self.stats();
        serial_println!(
            "[boot_alloc] try_alloc_accessible failed: requested={} aligned={} largest_region={} regions={} total_free={} accessible_limit={:#x}",
            size as usize,
            align as usize,
            stats.largest_region_bytes as usize,
            stats.region_count,
            stats.total_free_bytes as usize
            ,stats.accessible_limit
        );
        None
    }

    pub fn snapshot_free_regions(&self, out: &mut [MemoryRegion]) -> usize {
        let count = core::cmp::min(self.len, out.len());
        for (dst, region) in out.iter_mut().zip(self.regions.iter()).take(count) {
            *dst = MemoryRegion {
                base: region.start,
                size: region.end.saturating_sub(region.start),
                kind: MemoryKind::Free,
            };
        }
        count
    }

    fn reset(&mut self) {
        self.regions = [BootRegion::empty(); MAX_BOOT_ALLOC_REGIONS];
        self.len = 0;
        self.accessible_limit = 0;
    }

    fn push_region(&mut self, region: BootRegion) {
        if region.is_empty() || self.len >= self.regions.len() {
            return;
        }
        self.regions[self.len] = region;
        self.len += 1;
    }

    fn exclude_range(&mut self, exclude_start: u64, exclude_end: u64) {
        if exclude_start >= exclude_end {
            return;
        }

        let mut idx = 0usize;
        while idx < self.len {
            let region = self.regions[idx];
            if exclude_end <= region.start || exclude_start >= region.end {
                idx += 1;
                continue;
            }

            if exclude_start <= region.start && exclude_end >= region.end {
                self.remove_region(idx);
                continue;
            }

            if exclude_start <= region.start {
                self.regions[idx].start = exclude_end.min(region.end);
                idx += 1;
                continue;
            }

            if exclude_end >= region.end {
                self.regions[idx].end = exclude_start.max(region.start);
                idx += 1;
                continue;
            }

            let right = BootRegion {
                start: exclude_end,
                end: region.end,
            };
            self.regions[idx].end = exclude_start;
            if self.len < self.regions.len() {
                self.insert_region(idx + 1, right);
            }
            idx += 2;
        }

        self.normalize_regions();
    }

    fn consume_region(&mut self, idx: usize, alloc_start: u64, alloc_end: u64) {
        let region = self.regions[idx];

        if alloc_start <= region.start && alloc_end >= region.end {
            self.remove_region(idx);
            self.rebuild_accessible_limit();
            return;
        }

        if alloc_start <= region.start {
            self.regions[idx].start = alloc_end;
            self.rebuild_accessible_limit();
            return;
        }

        if alloc_end >= region.end {
            self.regions[idx].end = alloc_start;
            self.rebuild_accessible_limit();
            return;
        }

        let right = BootRegion {
            start: alloc_end,
            end: region.end,
        };
        self.regions[idx].end = alloc_start;
        if self.len < self.regions.len() {
            self.insert_region(idx + 1, right);
        }

        self.normalize_regions();
        self.rebuild_accessible_limit();
    }

    fn insert_region(&mut self, idx: usize, region: BootRegion) {
        if region.is_empty() || self.len >= self.regions.len() {
            return;
        }

        for slot in (idx..self.len).rev() {
            self.regions[slot + 1] = self.regions[slot];
        }
        self.regions[idx] = region;
        self.len += 1;
    }

    fn remove_region(&mut self, idx: usize) {
        if idx >= self.len {
            return;
        }
        for slot in idx..self.len.saturating_sub(1) {
            self.regions[slot] = self.regions[slot + 1];
        }
        if self.len != 0 {
            self.len -= 1;
            self.regions[self.len] = BootRegion::empty();
        }
    }

    fn normalize_regions(&mut self) {
        crate::e9_println!("NR begin");
        if self.len <= 1 {
            crate::e9_mark!(b'S');
            self.rebuild_accessible_limit();
            crate::e9_mark!(b's');
            return;
        }

        crate::e9_mark!(b'B');
        for i in 1..self.len {
            let cur = self.regions[i];
            let mut j = i;
            while j > 0 && self.regions[j - 1].start > cur.start {
                self.regions[j] = self.regions[j - 1];
                j -= 1;
            }
            self.regions[j] = cur;
        }
        crate::e9_mark!(b'b');

        let mut write = 0usize;
        for read in 0..self.len {
            let cur = self.regions[read];
            if cur.is_empty() {
                continue;
            }
            if write == 0 {
                self.regions[write] = cur;
                write += 1;
                continue;
            }
            let prev = self.regions[write - 1];
            if cur.start <= prev.end {
                self.regions[write - 1].end = prev.end.max(cur.end);
            } else {
                self.regions[write] = cur;
                write += 1;
            }
        }
        crate::e9_mark!(b'c');

        for slot in write..self.regions.len() {
            self.regions[slot] = BootRegion::empty();
        }
        self.len = write;
        self.rebuild_accessible_limit();
        crate::e9_mark!(b'd');
    }

    /// Recompute the highest currently reachable physical byte for HHDM-backed boot allocations.
    fn rebuild_accessible_limit(&mut self) {
        // TEMP DEBUG: count rebuild calls; pulse a hex digit every 65536.
        REBUILD_CALL_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let n = REBUILD_CALL_COUNT.load(core::sync::atomic::Ordering::Relaxed);
        if n % 65536 == 0 {
            unsafe {
                let hex = b"0123456789abcdef";
                core::arch::asm!("out 0xe9, al", in("al") b'$', options(nomem, nostack));
                for sh in [28usize, 24, 20, 16, 12, 8, 4, 0] {
                    let nib = hex[((n >> sh) & 0xF) as usize];
                    core::arch::asm!("out 0xe9, al", in("al") nib, options(nomem, nostack));
                }
                core::arch::asm!("out 0xe9, al", in("al") b'\n', options(nomem, nostack));
            }
        }
        crate::e9_mark!(b'Q');
        let mut limit = 0u64;
        crate::e9_mark!(b'R');
        for region in self.regions.iter().take(self.len).copied() {
            crate::e9_mark!(b'S');
            limit = limit.max(self.accessible_prefix_end(region));
            crate::e9_mark!(b's');
        }
        crate::e9_mark!(b'T');
        self.accessible_limit = limit;
        crate::e9_mark!(b't');
    }

    /// Return the end of the longest mapped prefix of `region` visible through the current HHDM.
    fn accessible_prefix_end(&self, region: BootRegion) -> u64 {
        if region.is_empty() {
            return 0;
        }

        let total_pages = ((region.end - region.start) / PAGE_SIZE) as usize;
        if total_pages == 0 {
            return 0;
        }

        let mut low = 0usize;
        let mut high = total_pages;
        while low < high {
            let mid = (low + high).div_ceil(2);
            let size = mid as u64 * PAGE_SIZE;
            if crate::memory::paging::is_hhdm_range_mapped_now(region.start, size) {
                low = mid;
            } else {
                high = mid - 1;
            }
        }

        region.start + low as u64 * PAGE_SIZE
    }

    pub fn stats(&self) -> BootAllocStats {
        let mut total = 0u64;
        let mut largest = 0u64;
        for region in self.regions.iter().take(self.len) {
            let size = region.end.saturating_sub(region.start);
            total = total.saturating_add(size);
            largest = largest.max(size);
        }
        BootAllocStats {
            region_count: self.len,
            total_free_bytes: total,
            largest_region_bytes: largest,
            accessible_limit: self.accessible_limit,
        }
    }
}

static BOOT_ALLOCATOR: SpinLock<BootAllocator> = SpinLock::new(BootAllocator::new());
static REBUILD_CALL_COUNT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static PROTECTED_RANGES: SpinLock<[Option<(u64, u64)>; MAX_PROTECTED_RANGES]> =
    SpinLock::new([None; MAX_PROTECTED_RANGES]);

pub fn init_boot_allocator(regions: &[MemoryRegion]) {
    crate::e9_println!("IBA enter");
    let mut guard = BOOT_ALLOCATOR.lock();
    crate::e9_println!("IBA locked");
    guard.init(regions);
    crate::e9_println!("IBA init done");
    drop(guard);
}

pub fn get_boot_allocator() -> &'static SpinLock<BootAllocator> {
    &BOOT_ALLOCATOR
}

pub fn boot_allocator_stats() -> BootAllocStats {
    BOOT_ALLOCATOR.lock().stats()
}

pub fn alloc_bytes(size: usize, align: usize) -> Option<PhysAddr> {
    BOOT_ALLOCATOR.lock().try_alloc(size, align)
}

pub fn alloc_bytes_accessible(size: usize, align: usize) -> Option<PhysAddr> {
    BOOT_ALLOCATOR.lock().try_alloc_accessible(size, align)
}

pub fn snapshot_free_regions(out: &mut [MemoryRegion]) -> usize {
    BOOT_ALLOCATOR.lock().snapshot_free_regions(out)
}

/// Seal the boot allocator so no further allocations can be made from it.
///
/// Called immediately after the buddy allocator consumes the remaining free
/// regions via `snapshot_free_regions`. Any subsequent `alloc_stack` call
/// would otherwise double-allocate pages that are already tracked in the
/// buddy allocator's free lists.
pub fn seal() {
    BOOT_ALLOCATOR.lock().reset();
}

pub fn alloc_stack(size: usize) -> Option<u64> {
    let phys = alloc_bytes(size, PAGE_SIZE as usize)?;
    let span = align_up(size as u64, PAGE_SIZE);
    Some(phys_to_virt(phys.as_u64()).saturating_add(span))
}

pub fn set_protected_ranges(ranges: &[Option<(u64, u64)>]) {
    let mut protected = PROTECTED_RANGES.lock();
    *protected = [None; MAX_PROTECTED_RANGES];
    for (dst, src) in protected.iter_mut().zip(ranges.iter().copied()) {
        *dst = src;
    }
}

pub fn reset_protected_ranges() {
    *PROTECTED_RANGES.lock() = [None; MAX_PROTECTED_RANGES];
}

pub(crate) fn protected_ranges_snapshot() -> [Option<(u64, u64)>; MAX_PROTECTED_RANGES] {
    crate::e9_mark!(b'p');
    let guard = PROTECTED_RANGES.lock();
    crate::e9_mark!(b'q');
    // Avoid large struct copy (512 bytes) which generates a memcpy call
    // that resolves to an identity-mapped address → #UD.
    let mut result = [None; MAX_PROTECTED_RANGES];
    for (dst, src) in result.iter_mut().zip(guard.iter()) {
        *dst = *src;
    }
    crate::e9_mark!(b'r');
    result
}

#[inline]
const fn normalize_align(align: usize) -> usize {
    let align = if align == 0 { 1 } else { align };
    let align = if align < PAGE_SIZE as usize {
        PAGE_SIZE as usize
    } else {
        align
    };
    if align.is_power_of_two() {
        align
    } else {
        align.next_power_of_two()
    }
}

#[inline]
const fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

#[inline]
const fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}
