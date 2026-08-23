//! Runtime self-test battery for the buddy allocator (`feature = "selftest"`).
//!
//! Run with `cargo make kernel-test` (builds with `--features selftest`) and
//! boot the resulting kernel in QEMU; results are printed over COM1 and any
//! failure panics with the failing invariant name.
//!
//! Invariants exercised:
//! 1. Watermark sanity: min <= low <= high, all bounded by seedable pages.
//! 2. Accounting identity: free-list pages + allocated + unmanaged == managed.
//! 3. Parity-bit balance: a deterministic alloc/free storm must leave every
//!    buddy parity bit at zero once everything is freed again.
//! 4. Free-list structural integrity: no cycles, symmetric prev/next links,
//!    sentinel metadata (FREE flag, refcount UNUSED, matching order/MT).
//! 5. No free block may overlap a protected range (R1).
//! 6. Pure helpers: protected-interval union counting and zone intersection
//!    counting (R1/R2 math), verified against hand-computed expectations.

use super::*;
use crate::serial_println;
use crate::sync::with_irqs_disabled;
use alloc::vec::Vec;

struct Battery {
    passed: usize,
    failed: usize,
}

impl Battery {
    const fn new() -> Self {
        Self { passed: 0, failed: 0 }
    }

    fn check(&mut self, name: &str, ok: bool) {
        if ok {
            self.passed += 1;
            serial_println!("  [buddy-selftest] PASS {}", name);
        } else {
            self.failed += 1;
            serial_println!("  [buddy-selftest] FAIL {}", name);
        }
    }

    fn finish(self) {
        serial_println!(
            "[buddy-selftest] done: {} passed, {} failed",
            self.passed,
            self.failed
        );
        assert!(self.failed == 0, "buddy selftest battery failed");
    }
}

/// Deterministic LCG so failures are reproducible across runs.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 16
    }
}

/// Sum of pages currently on every free list of every zone.
fn total_free_list_pages() -> usize {
    let mut total = 0usize;
    let mut guard = get_allocator().lock();
    guard.with_mut_and_token(|slot, _token| {
        if let Some(alloc) = slot.as_mut() {
            for zone in &alloc.zones {
                total = total.saturating_add(zone.free_pages_by_migratetype().iter().sum());
            }
        }
    });
    total
}

/// Walk every free list checking structural integrity + sentinel metadata.
/// Returns (ok, detail) — walking is bounded so a duplicate/cycle cannot hang.
fn verify_free_lists() -> (bool, &'static str) {
    let mut guard = get_allocator().lock();
    let mut result = (true, "");
    guard.with_mut_and_token(|slot, _token| {
        let Some(alloc) = slot.as_mut() else {
            result = (false, "allocator not initialized");
            return;
        };
        'zones: for zone in &alloc.zones {
            for segment in zone.segments().iter().take(zone.segment_count) {
                for mt in Migratetype::ALL {
                    for order in 0..=MAX_ORDER as u8 {
                        // Bounded walk: a healthy list cannot exceed the page count.
                        let max_steps = segment.page_count + 1;
                        let mut phys = segment.free_lists[mt.index()][order as usize];
                        let mut prev: Option<u64> = None;
                        let mut steps = 0usize;
                        while phys != 0 {
                            steps += 1;
                            if steps > max_steps {
                                result = (false, "free list cycle or duplicate detected");
                                break 'zones;
                            }
                            let meta =
                                crate::memory::frame::get_meta(PhysAddr::new(phys));
                            if meta.get_refcount()
                                != crate::memory::frame::REFCOUNT_UNUSED
                            {
                                result = (
                                    false,
                                    "free-list frame without REFCOUNT_UNUSED sentinel",
                                );
                                break 'zones;
                            }
                            if meta.get_flags() & frame_flags::FREE == 0 {
                                result = (false, "free-list frame without FREE flag");
                                break 'zones;
                            }
                            if meta.get_order() != order {
                                result = (false, "free-list frame order mismatch");
                                break 'zones;
                            }
                            // Link symmetry: our next's prev must be us; a head's
                            // prev must be LINK_NONE.
                            match prev {
                                None => {
                                    if meta.prev()
                                        != crate::memory::frame::FRAME_META_LINK_NONE
                                    {
                                        result = (false, "list head prev is not LINK_NONE");
                                        break 'zones;
                                    }
                                }
                                Some(p) => {
                                    if meta.prev() != p {
                                        result =
                                            (false, "free list prev/next asymmetry");
                                        break 'zones;
                                    }
                                }
                            }
                            let next_raw = meta.next();
                            prev = Some(phys);
                            phys = if next_raw
                                == crate::memory::frame::FRAME_META_LINK_NONE
                            {
                                0
                            } else {
                                next_raw
                            };
                        }

                        // R1: nothing on any free list may overlap protection.
                        let mut p = segment.free_lists[mt.index()][order as usize];
                        while p != 0 {
                            let block_size = PAGE_SIZE << order;
                            if BuddyAllocator::protected_overlap_end(p, p + block_size)
                                .is_some()
                            {
                                result = (
                                    false,
                                    "free block overlaps a protected range",
                                );
                                break 'zones;
                            }
                            let m = crate::memory::frame::get_meta(PhysAddr::new(p)).next();
                            p = if m == crate::memory::frame::FRAME_META_LINK_NONE { 0 } else { m };
                        }
                    }
                }
            }
        }
    });
    result
}

/// All parity bits must read as cleared when every block is back on a list.
fn verify_parity_all_clear() -> bool {
    let mut guard = get_allocator().lock();
    let mut ok = true;
    guard.with_mut_and_token(|slot, _token| {
        if let Some(alloc) = slot.as_mut() {
            for zone in &alloc.zones {
                for segment in zone.segments().iter().take(zone.segment_count) {
                    for order in 0..=MAX_ORDER {
                        let bitmap = segment.buddy_bitmaps[order];
                        if bitmap.is_empty() {
                            continue;
                        }
                        for bit in 0..bitmap.num_bits {
                            if bitmap.test(bit) {
                                ok = false;
                            }
                        }
                    }
                }
            }
        } else {
            ok = false;
        }
    });
    ok
}

/// Identity: Σ free-list pages == Σ (seedable - allocated) - quarantined.
///
/// Quarantined poison pages are decremented from `allocated` without ever
/// re-entering a list, so they widen the gap; the global quarantine counter
/// accounts for them.
fn verify_accounting() -> (bool, &'static str) {
    let mut guard = get_allocator().lock();
    let mut result = (true, "");
    guard.with_mut_and_token(|slot, _token| {
        let Some(alloc) = slot.as_mut() else {
            result = (false, "allocator not initialized");
            return;
        };
        let mut list_pages_total = 0usize;
        let mut expected_total = 0usize;
        for zone in &alloc.zones {
            // Cached pages belong to `allocated` (their parent block was
            // allocated globally) and are NOT on any free list, so they
            // cancel out of the identity naturally.
            list_pages_total =
                list_pages_total.saturating_add(zone.free_pages_by_migratetype().iter().sum());
            let seedable = zone.page_count.saturating_sub(zone.unmanaged_pages);
            expected_total =
                expected_total.saturating_add(seedable.saturating_sub(zone.allocated));
        }
        let quarantined = super::poison_quarantine_pages_snapshot();
        if list_pages_total != expected_total.saturating_sub(quarantined) {
            result = (
                false,
                "free-list pages do not match seedable - allocated - quarantined",
            );
        }
    });
    result
}

fn watermarks_sane() -> bool {
    let mut guard = get_allocator().lock();
    let mut ok = true;
    guard.with_mut_and_token(|slot, _token| {
        if let Some(alloc) = slot.as_mut() {
            for zone in &alloc.zones {
                let seedable = zone.page_count.saturating_sub(zone.unmanaged_pages);
                if zone.watermark_min > zone.watermark_low
                    || zone.watermark_low > zone.watermark_high
                    || zone.watermark_high > seedable
                {
                    ok = false;
                }
            }
        } else {
            ok = false;
        }
    });
    ok
}

pub fn run_buddy_selftests() {
    serial_println!("[buddy-selftest] starting battery");
    let mut battery = Battery::new();

    // ---- Pure-helper checks (no allocator state needed) -------------------
    {
        // R1 core: interval union counting (overlapping + adjacent ranges).
        let cases: &[(&[(u64, u64)], u64)] = &[
            (&[], 0),
            (&[(0x1000, 0x2000)], 1),
            (&[(0x1000, 0x3000), (0x2000, 0x4000)], 3), // merged overlap
            (&[(0x1000, 0x3000), (0x3000, 0x5000)], 4), // adjacent merge
            (&[(0x1000, 0x2000), (0x4000, 0x6000)], 3), // disjoint
            (&[(0x4000, 0x6000), (0x1000, 0x2000)], 3), // unsorted input
            (&[(0x1000, 0x1800), (0x1400, 0x1C00)], 1), // nested
        ];
        let mut pure_ok = true;
        for (idx, (ivs, expected_pages)) in cases.iter().enumerate() {
            let got = BuddyAllocator::count_pages_union(ivs);
            let want = *expected_pages as usize;
            if got != want {
                serial_println!(
                    "  [buddy-selftest]   count_pages_union case {} got {} want {}",
                    idx,
                    got,
                    want
                );
                pure_ok = false;
            }
        }
        battery.check("pure: protected interval union counting", pure_ok);
    }
    {
        // R2 core: per-zone intersection counting on synthetic snapshots.
        let mk = |base: u64, size: u64| MemoryRegion {
            base,
            size,
            kind: MemoryKind::Free,
        };
        let regions = [
            mk(0x1000, 0x1000),          // DMA only
            mk(15u64 * 1024 * 1024, 2 * 1024 * 1024), // spans DMA|Normal boundary => 2 zones
            mk(900u64 * 1024 * 1024, 1024 * 1024), // HighMem only
        ];
        let counts = BuddyAllocator::zone_intersection_counts(&regions);
        battery.check(
            "pure: zone intersection counting (boundary split)",
            counts[ZoneType::DMA as usize] == 2
                && counts[ZoneType::Normal as usize] == 1
                && counts[ZoneType::HighMem as usize] == 1,
        );
        // Reserved kind must be ignored entirely.
        let reserved_only = [MemoryRegion {
            base: 0x1000,
            size: 0x10_0000,
            kind: MemoryKind::Reserved,
        }];
        let c = BuddyAllocator::zone_intersection_counts(&reserved_only);
        battery.check(
            "pure: reserved regions never counted",
            c.iter().all(|&v| v == 0),
        );
    }

    // ---- Live allocator invariants ----------------------------------------
    battery.check("watermarks sane", watermarks_sane());
    {
        let (ok, why) = verify_accounting();
        battery.check(if ok { "accounting identity (baseline)" } else { why }, ok);
    }
    {
        let (ok, why) = verify_free_lists();
        battery.check(if ok { "free-list integrity (baseline)" } else { why }, ok);
    }

    // ---- Alloc/free storm: parity balance + accounting after restore -------
    with_irqs_disabled(|token| {
        const ORDERS: [u8; 6] = [0, 1, 2, 3, 5, 7];
        let mut rng = Lcg(0x5EED_1234_ABCD_0001);
        let mut live: Vec<(PhysFrame, u8)> = Vec::new();
        let mut alloc_ok = true;

        // Phase A: allocate a mixed set of blocks (bounded by OOM tolerance).
        for round in 0..512u32 {
            let order = ORDERS[(rng.next() % ORDERS.len() as u64) as usize];
            let mt = if rng.next() & 1 == 0 {
                Migratetype::Unmovable
            } else {
                Migratetype::Movable
            };
            match super::alloc_migratetype(token, order, mt) {
                Ok(frame) => live.push((frame, order)),
                Err(_) => {
                    if order >= 2 && round > 64 {
                        // Under pressure later rounds may legitimately fail.
                        break;
                    }
                    alloc_ok = false;
                    break;
                }
            }
        }
        battery.check("storm: allocations succeeded", alloc_ok && !live.is_empty());

        // Phase B: interleaved partial frees with pseudo-random choice.
        let mut idx = 0usize;
        let mut freed_half = 0usize;
        while idx < live.len() && live.len() > 8 {
            if rng.next() & 1 == 1 {
                let (frame, order) = live.remove(idx);
                super::free(token, frame, order);
                freed_half += 1;
            } else {
                idx += 1;
            }
        }

        // Mid-storm structural check.
        {
            let (ok, why) = verify_free_lists();
            battery.check(if ok { "storm: mid-storm list integrity" } else { why }, ok);
        }

        // Phase C: free everything, then require perfect restoration.
        for (frame, order) in live.drain(..) {
            super::free(token, frame, order);
        }

        battery.check("storm: parity bits all clear when empty", verify_parity_all_clear());
        {
            let baseline_free = total_free_list_pages();
            let (acct_ok, acct_why) = verify_accounting();
            let _ = baseline_free;
            battery.check(if acct_ok { "storm: accounting restored" } else { acct_why }, acct_ok);
        }
        {
            let (ok, why) = verify_free_lists();
            battery.check(if ok { "storm: final list integrity" } else { why }, ok);
        }
        let _ = freed_half;
    });

    // ---- Order sweep: exercise split/coalesce up to the highest order that
    // this machine can actually provide (MAX_ORDER availability depends on
    // total RAM; only totals-restored is a pass criterion).
    with_irqs_disabled(|token| {
        let before = total_free_list_pages();
        let mut taken: Vec<(PhysFrame, u8)> = Vec::new();
        let mut highest_reached: u8 = 0;
        for order in (0..=MAX_ORDER as u8).rev() {
            let mut any = false;
            for _ in 0..4 {
                match super::alloc_migratetype(token, order, Migratetype::Unmovable) {
                    Ok(frame) => {
                        taken.push((frame, order));
                        any = true;
                    }
                    Err(_) => break,
                }
            }
            if any && order > highest_reached {
                highest_reached = order;
            }
        }
        serial_println!(
            "  [buddy-selftest]   sweep: {} blocks taken, highest order reached = {}",
            taken.len(),
            highest_reached
        );
        for (frame, order) in taken.drain(..) {
            super::free(token, frame, order);
        }
        let after = total_free_list_pages();
        battery.check(
            "order sweep: totals restored after high-order churn",
            before == after,
        );
    });

    // ---- R1 regression: protected accounting keeps identity coherent -------
    // With the current (empty) protected snapshot this asserts the zero-case:
    // unmanaged == 0 and identity holds exactly. The pure-union tests above
    // cover the non-empty math deterministically.
    {
        let mut guard = get_allocator().lock();
        let mut zero_case_ok = true;
        guard.with_mut_and_token(|slot, _token| {
            if let Some(alloc) = slot.as_mut() {
                for zone in &alloc.zones {
                    if !boot_alloc_snapshot_protected_empty() {
                        continue; // protection active: skip zero-only assertion
                    }
                    if zone.unmanaged_pages != 0 {
                        zero_case_ok = false;
                    }
                }
            } else {
                zero_case_ok = false;
            }
        });
        battery.check("R1: unmanaged pages are zero without protection", zero_case_ok);
    }

    battery.finish();
}

/// Whether the boot allocator has no protected ranges configured.
fn boot_alloc_snapshot_protected_empty() -> bool {
    BuddyAllocator::protected_module_ranges()
        .into_iter()
        .flatten()
        .all(|(_, size)| size == 0)
}
