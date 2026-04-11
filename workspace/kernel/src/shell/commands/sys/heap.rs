//! Allocator inspection and stress tests for the kernel shell.
//!
//! Commands such as `heap live` print task ids, addresses, and source locations
//! from vmalloc attribution — useful for debugging but **sensitive** if the
//! serial console is exposed; restrict shell access accordingly.

use crate::{
    alloc::string::String,
    shell::{output::format_bytes, ShellError},
    shell_println,
};

const HEAP_USAGE: &str = "Usage: heap [summary|vmalloc|live [limit]|fail|diag|stress [rounds]]";
const MAX_LIVE_LIMIT: usize = 4096;

/// Maximum number of pointers held on the stack during a slab stress test.
/// Sized to cover the densest class (8 B, 509 blocks/page) over 1 page.
const STRESS_MAX_BLOCKS: usize = 512;
const STRESS_WORKLOAD_OBSERVE_TICKS: u64 = 100;
const STRESS_WORKLOAD_EXIT_TIMEOUT_TICKS: u64 = 1_000;

enum StressOutcome {
    Pass,
    Fail(&'static str),
    Skip(&'static str),
}

/// `heap` — allocator telemetry and diagnostics.
pub fn cmd_heap(args: &[String]) -> Result<(), ShellError> {
    match args.first().map(|s| s.as_str()) {
        None | Some("summary") => cmd_heap_summary(),
        Some("vmalloc") => cmd_heap_vmalloc(),
        Some("live") => cmd_heap_live(args.get(1)),
        Some("fail") => cmd_heap_fail(),
        Some("diag") => {
            crate::memory::heap::dump_diagnostics();
            Ok(())
        }
        Some("stress") => cmd_heap_stress(args.get(1)),
        Some(_) => {
            shell_println!("{}", HEAP_USAGE);
            Err(ShellError::InvalidArguments)
        }
    }
}

fn cmd_heap_summary() -> Result<(), ShellError> {
    let (total_pages, allocated_pages) = {
        let Some(guard) = crate::memory::buddy::get_allocator().try_lock() else {
            shell_println!("heap: buddy allocator busy, retry");
            return Ok(());
        };
        let Some(alloc) = guard.as_ref() else {
            shell_println!("heap: allocator not initialized");
            return Ok(());
        };
        alloc.page_totals()
    };

    let free_pages = total_pages.saturating_sub(allocated_pages);
    let fail_counts = crate::memory::buddy::buddy_alloc_fail_counts_snapshot();
    let slab = crate::memory::heap::slab_diag_snapshot();
    let phys = crate::memory::phys_contiguous_diag();

    let (total_val, total_unit) = format_bytes(total_pages.saturating_mul(4096));
    let (used_val, used_unit) = format_bytes(allocated_pages.saturating_mul(4096));
    let (free_val, free_unit) = format_bytes(free_pages.saturating_mul(4096));

    shell_println!("Heap summary:");
    shell_println!(
        "  Buddy: total={} {} used={} {} free={} {}",
        total_val,
        total_unit,
        used_val,
        used_unit,
        free_val,
        free_unit
    );
    shell_println!(
        "  Slab: pages_allocated={} pages_reclaimed={} pages_live={}",
        slab.pages_allocated,
        slab.pages_reclaimed,
        slab.pages_live
    );
    shell_println!(
        "  Phys-contig: live_pages={} alloc_failures={}",
        phys.pages_live,
        phys.alloc_fail_count
    );

    let mut any_fail = false;
    for count in fail_counts {
        if count != 0 {
            any_fail = true;
            break;
        }
    }
    if any_fail {
        let mut line = alloc::string::String::from("  Buddy failures:");
        for (order, count) in fail_counts.iter().enumerate() {
            if *count != 0 {
                use core::fmt::Write;
                let _ = write!(line, " o{}={} ", order, count);
            }
        }
        shell_println!("{}", line);
    }

    Ok(())
}

fn cmd_heap_vmalloc() -> Result<(), ShellError> {
    let Some(diag) = crate::memory::vmalloc::diag_snapshot() else {
        shell_println!("vmalloc: not initialized");
        return Ok(());
    };

    shell_println!("Vmalloc:");
    shell_println!("  Arena: 0x{:x}..0x{:x}", diag.arena_start, diag.arena_end);
    shell_println!(
        "  Usage: allocs={} alloc_pages={} free_pages={} peak_pages={}",
        diag.alloc_count,
        diag.allocated_pages,
        diag.free_pages,
        diag.peak_pages
    );
    shell_println!(
        "  Meta: extents={} largest_free_pages={} metadata_pages={} node_pool_free={}",
        diag.free_extent_count,
        diag.largest_free_pages,
        diag.metadata_pages,
        diag.node_pool_free
    );
    shell_println!(
        "  Failures: vmalloc={} policy_rejects={} total_seq={}",
        diag.fail_count,
        diag.policy_rejects,
        diag.total_seq
    );
    if let Some(last) = diag.last_failure {
        shell_println!(
            "  Last failure: size={} pages={} error={:?}",
            last.size,
            last.pages,
            last.error
        );
    }

    Ok(())
}

fn cmd_heap_live(limit_arg: Option<&String>) -> Result<(), ShellError> {
    let limit = match limit_arg {
        None => 32usize,
        Some(raw) => raw
            .parse::<usize>()
            .map_err(|_| ShellError::InvalidArguments)?
            .min(MAX_LIVE_LIMIT),
    };
    if limit == 0 {
        shell_println!("{}", HEAP_USAGE);
        return Err(ShellError::InvalidArguments);
    }

    let mut rows = alloc::vec::Vec::new();
    rows.resize(
        limit,
        crate::memory::vmalloc::VmallocLiveAllocationSnapshot {
            seq: 0,
            task_id: 0,
            pid: 0,
            tid: 0,
            silo_id: 0,
            size: 0,
            pages: 0,
            vaddr: 0,
            backend: crate::memory::vmalloc::VmallocAllocBackend::KernelVirtual,
            caller_file: "",
            caller_line: 0,
            caller_column: 0,
        },
    );

    let Some(diag) = crate::memory::vmalloc::diag_snapshot() else {
        shell_println!("vmalloc: not initialized");
        return Ok(());
    };
    let count = crate::memory::vmalloc::live_allocations_snapshot(&mut rows[..]);
    // Non-atomic diagnostic read: alloc_count and live rows are obtained under
    // separate VMALLOC acquisitions, so they may reflect slightly different
    // moments in time under concurrent allocation traffic.
    let total_live = diag.alloc_count;

    if count == 0 {
        shell_println!("heap live: no active vmalloc allocations");
        return Ok(());
    }

    shell_println!("Live vmalloc allocations:");
    for entry in rows.iter().take(count) {
        shell_println!(
            "  seq={} task={} pid={} tid={} silo={} size={} pages={} vaddr=0x{:x} caller={}:{}:{}",
            entry.seq,
            entry.task_id,
            entry.pid,
            entry.tid,
            entry.silo_id,
            entry.size,
            entry.pages,
            entry.vaddr,
            entry.caller_file,
            entry.caller_line,
            entry.caller_column
        );
    }
    let hidden = total_live.saturating_sub(count);
    if hidden != 0 {
        shell_println!("  ... {} more allocation(s) not shown", hidden);
    }

    Ok(())
}

fn cmd_heap_fail() -> Result<(), ShellError> {
    match crate::memory::heap::last_heap_failure_snapshot() {
        Some(failure) => shell_println!(
            "Last heap failure: backend={:?} requested={} align={} effective={} error={:?}",
            failure.backend,
            failure.requested_size,
            failure.align,
            failure.effective_size,
            failure.error
        ),
        None => shell_println!("Last heap failure: none"),
    }

    match crate::memory::vmalloc::last_failure_snapshot() {
        Some(last) => shell_println!(
            "Last vmalloc failure: size={} pages={} error={:?}",
            last.size,
            last.pages,
            last.error
        ),
        None => shell_println!("Last vmalloc failure: none"),
    }

    Ok(())
}

// =============================================================================
// Stress tests
// =============================================================================

/// `heap stress [rounds]` — exercise allocator smoke paths and one bounded
/// userspace workload path.
///
/// Each round runs:
///   slab_reclaim[S]    — fill/drain slab classes without leaking.
///   slab_frag[256]     — verify a page becomes partial after partial free.
///   vmalloc_cycle      — alloc/free vmalloc ranges and verify live tracking.
///   vmalloc_frag       — random-size allocs freed in random order; checks that
///                        virtual fragmentation is observable and all pages are
///                        returned after drain.
///   telemetry          — sanity-check counters are self-consistent.
///   userspace_workload — launch `/initfs/test_mem_stressed` in a silo and
///                        observe its lifecycle for a bounded period.
fn cmd_heap_stress(rounds_arg: Option<&String>) -> Result<(), ShellError> {
    let rounds = match rounds_arg {
        None => 1,
        Some(r) => r
            .parse::<usize>()
            .map_err(|_| ShellError::InvalidArguments)?
            .max(1)
            .min(32),
    };

    shell_println!("heap stress: {} round(s)", rounds);

    let mut total_pass = 0usize;
    let mut total_fail = 0usize;
    let mut total_skip = 0usize;

    for round in 0..rounds {
        if crate::shell::is_interrupted() {
            shell_println!("^C");
            return Ok(());
        }
        if rounds > 1 {
            shell_println!("--- round {}/{} ---", round + 1, rounds);
        }

        let mut run = |name: &str, result: StressOutcome| match result {
            StressOutcome::Pass => {
                shell_println!("  {:<36} PASS", name);
                total_pass += 1;
            }
            StressOutcome::Fail(msg) => {
                shell_println!("  {:<36} FAIL  {}", name, msg);
                total_fail += 1;
            }
            StressOutcome::Skip(msg) => {
                shell_println!("  {:<36} SKIP  {}", name, msg);
                total_skip += 1;
            }
        };

        run("slab_reclaim[2048 ci=25 p=4]", stress_slab_reclaim(25, 4));
        run("slab_reclaim[512 ci=17 p=3]", stress_slab_reclaim(17, 3));
        run("slab_reclaim[64 ci=5 p=2]", stress_slab_reclaim(5, 2));
        run("slab_reclaim[8 ci=0 p=1]", stress_slab_reclaim(0, 1));
        run("slab_frag[256 ci=13]", stress_slab_frag(13));
        run("vmalloc_cycle", stress_vmalloc_cycle());
        run("vmalloc_frag", stress_vmalloc_frag());
        run("telemetry_consistency", stress_telemetry());
        run("userspace_workload", stress_userspace_workload());
    }

    shell_println!(
        "heap stress: {} passed, {} failed, {} skipped",
        total_pass,
        total_fail,
        total_skip
    );
    if total_fail == 0 {
        Ok(())
    } else {
        Err(ShellError::ExecutionFailed)
    }
}

// ---------------------------------------------------------------------------
// Sub-test: slab_reclaim
//
// Allocate `pages` worth of slab objects for class `ci`, then free them all.
// This is a smoke test for fill/drain behavior, not an isolated proof about
// global reclaim counters under concurrent allocator activity.
// ---------------------------------------------------------------------------
fn stress_slab_reclaim(ci: usize, pages: usize) -> StressOutcome {
    use alloc::alloc::{alloc, dealloc, Layout};

    let class_size = crate::memory::heap::slab_class_size(ci);
    let blocks_per_page = crate::memory::heap::slab_blocks_per_page(ci);
    let total = pages * blocks_per_page;

    if total > STRESS_MAX_BLOCKS {
        return StressOutcome::Skip("test config exceeds STRESS_MAX_BLOCKS");
    }

    let layout = match Layout::from_size_align(class_size, 8) {
        Ok(layout) => layout,
        Err(_) => return StressOutcome::Fail("Layout::from_size_align failed"),
    };

    let before = crate::memory::heap::slab_diag_snapshot();

    let mut ptrs = [core::ptr::null_mut::<u8>(); STRESS_MAX_BLOCKS];
    let mut count = 0usize;

    for i in 0..total {
        if crate::shell::is_interrupted() {
            for j in 0..count {
                unsafe { dealloc(ptrs[j], layout) };
            }
            return StressOutcome::Skip("interrupted");
        }
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            for j in 0..count {
                unsafe { dealloc(ptrs[j], layout) };
            }
            return StressOutcome::Fail("OOM during slab reclaim fill phase");
        }
        ptrs[i] = ptr;
        count += 1;
    }

    for i in 0..count {
        unsafe { dealloc(ptrs[i], layout) };
        ptrs[i] = core::ptr::null_mut();
    }

    let after = crate::memory::heap::slab_diag_snapshot();

    // Check 1: pages_live must return to (at most) baseline + 1.
    // Tolerates ±1 for atomic snapshot races between the two load() calls.
    if after.pages_live > before.pages_live.saturating_add(1) {
        return StressOutcome::Fail("slab pages not fully reclaimed after freeing all blocks");
    }

    // Check 2: pages_reclaimed must have grown by at least `pages`.
    // Catches bugs where pages are silently lost (neither live nor reclaimed):
    // pages_live alone cannot distinguish between correct reclaim and a leak
    // that happens to match the baseline by coincidence.
    if after.pages_reclaimed < before.pages_reclaimed.saturating_add(pages) {
        return StressOutcome::Fail("slab pages_reclaimed did not increase by expected count");
    }

    // Sanity: allocator must still be functional after a full fill/drain cycle.
    let ptr = unsafe { alloc(layout) };
    if ptr.is_null() {
        return StressOutcome::Fail("slab unusable after fill/drain cycle");
    }
    unsafe { dealloc(ptr, layout) };

    StressOutcome::Pass
}

// ---------------------------------------------------------------------------
// Sub-test: slab_frag
//
// Allocate one page worth of blocks for class `ci`, free half of them, and
// verify the backing page becomes visible in the partial list. This test is
// skipped when the allocator is already using multiple pages for the sample,
// because that means concurrent or pre-existing activity breaks the single-page
// assumption required for a precise page-local assertion.
// ---------------------------------------------------------------------------
fn stress_slab_frag(ci: usize) -> StressOutcome {
    use alloc::alloc::{alloc, dealloc, Layout};

    let class_size = crate::memory::heap::slab_class_size(ci);
    let bpp = crate::memory::heap::slab_blocks_per_page(ci);

    if bpp < 2 {
        return StressOutcome::Skip("class has < 2 blocks/page");
    }
    if bpp > STRESS_MAX_BLOCKS {
        return StressOutcome::Skip("blocks_per_page > STRESS_MAX_BLOCKS");
    }

    let layout = match Layout::from_size_align(class_size, 8) {
        Ok(layout) => layout,
        Err(_) => return StressOutcome::Fail("Layout::from_size_align failed"),
    };

    let mut ptrs = [core::ptr::null_mut::<u8>(); STRESS_MAX_BLOCKS];

    for i in 0..bpp {
        if crate::shell::is_interrupted() {
            for j in 0..i {
                unsafe { dealloc(ptrs[j], layout) };
            }
            return StressOutcome::Skip("interrupted");
        }
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            for j in 0..i {
                unsafe { dealloc(ptrs[j], layout) };
            }
            return StressOutcome::Fail("OOM during slab frag alloc phase");
        }
        ptrs[i] = ptr;
    }

    let first_page = page_base(ptrs[0]);
    for ptr in ptrs.iter().take(bpp) {
        if page_base(*ptr) != first_page {
            for ptr in ptrs.iter().take(bpp) {
                unsafe { dealloc(*ptr, layout) };
            }
            return StressOutcome::Skip("allocator not quiescent for single-page frag check");
        }
    }

    for i in (0..bpp).step_by(2) {
        unsafe { dealloc(ptrs[i], layout) };
        ptrs[i] = core::ptr::null_mut();
    }

    let Some(partial_seen) = crate::memory::heap::slab_page_in_partial_list(ci, first_page) else {
        for i in (1..bpp).step_by(2) {
            if !ptrs[i].is_null() {
                unsafe { dealloc(ptrs[i], layout) };
            }
        }
        return StressOutcome::Skip("slab lock busy");
    };
    if !partial_seen {
        for i in (1..bpp).step_by(2) {
            if !ptrs[i].is_null() {
                unsafe { dealloc(ptrs[i], layout) };
            }
        }
        return StressOutcome::Fail("page did not appear in partial list after partial free");
    }

    for i in (1..bpp).step_by(2) {
        if !ptrs[i].is_null() {
            unsafe { dealloc(ptrs[i], layout) };
            ptrs[i] = core::ptr::null_mut();
        }
    }

    let Some(still_partial) = crate::memory::heap::slab_page_in_partial_list(ci, first_page) else {
        return StressOutcome::Skip("slab lock busy after free");
    };
    if still_partial {
        return StressOutcome::Skip(
            "page still visible as partial after full free; concurrent same-class activity suspected",
        );
    }

    StressOutcome::Pass
}

// ---------------------------------------------------------------------------
// Sub-test: vmalloc_cycle
//
// Allocate and free several vmalloc regions of increasing size. Validation is
// based on the presence/absence of the specific ranges in the live set, not on
// global counters that can move under concurrent allocator traffic.
// ---------------------------------------------------------------------------
fn stress_vmalloc_cycle() -> StressOutcome {
    const SIZES: [usize; 4] = [4096, 16384, 65536, 262144];
    let mut vptrs = [core::ptr::null_mut::<u8>(); 4];

    if crate::memory::vmalloc::diag_snapshot().is_none() {
        return StressOutcome::Skip("vmalloc not initialised");
    }

    for (i, &size) in SIZES.iter().enumerate() {
        if crate::shell::is_interrupted() {
            for ptr in vptrs.iter_mut() {
                if !ptr.is_null() {
                    crate::sync::with_irqs_disabled(|token| {
                        crate::memory::free_kernel_virtual(*ptr, token);
                    });
                    *ptr = core::ptr::null_mut();
                }
            }
            return StressOutcome::Skip("interrupted");
        }
        let ptr = crate::sync::with_irqs_disabled(|token| {
            crate::memory::allocate_kernel_virtual(size, token).ok()
        });
        match ptr {
            Some(p) if !p.is_null() => vptrs[i] = p,
            _ => {
                // OOM or arena exhausted: free what we have.
                for j in 0..i {
                    if !vptrs[j].is_null() {
                        crate::sync::with_irqs_disabled(|token| {
                            crate::memory::free_kernel_virtual(vptrs[j], token);
                        });
                    }
                }
                return StressOutcome::Fail("vmalloc returned null during cycle alloc phase");
            }
        }

        match crate::memory::vmalloc::is_live_allocation(vptrs[i]) {
            Some(true) => {}
            Some(false) => {
                for ptr in vptrs.iter_mut().take(i + 1) {
                    if !ptr.is_null() {
                        crate::sync::with_irqs_disabled(|token| {
                            crate::memory::free_kernel_virtual(*ptr, token);
                        });
                        *ptr = core::ptr::null_mut();
                    }
                }
                return StressOutcome::Fail("vmalloc allocation missing from live set");
            }
            None => {
                for ptr in vptrs.iter_mut().take(i + 1) {
                    if !ptr.is_null() {
                        crate::sync::with_irqs_disabled(|token| {
                            crate::memory::free_kernel_virtual(*ptr, token);
                        });
                        *ptr = core::ptr::null_mut();
                    }
                }
                return StressOutcome::Skip("VMALLOC lock busy during live-set check");
            }
        }
    }

    for ptr in vptrs.iter_mut() {
        if !ptr.is_null() {
            crate::sync::with_irqs_disabled(|token| {
                crate::memory::free_kernel_virtual(*ptr, token);
            });
            match crate::memory::vmalloc::is_live_allocation(*ptr) {
                Some(false) => {}
                Some(true) => return StressOutcome::Fail("freed vmalloc range still marked live"),
                None => return StressOutcome::Skip("VMALLOC lock busy during post-free check"),
            }
            *ptr = core::ptr::null_mut();
        }
    }

    StressOutcome::Pass
}

// ---------------------------------------------------------------------------
// Sub-test: vmalloc_frag
//
// Stress the vmalloc extent allocator with random-size allocations freed in
// a random order to verify:
//
//  1. Virtual fragmentation is observable: after freeing half the regions in
//     shuffled order while the other half remain live, free_extent_count must
//     exceed the pre-test baseline (the arena was a single large free extent).
//  2. No silent leaks: after a full drain, free_pages returns to baseline.
//  3. Coherence: largest_free_pages ≤ free_pages.
//
// Uses an Xorshift64 PRNG seeded from the tick counter — no heap allocation
// for PRNG state (stack-only bookkeeping, sizes and order vary across runs).
//
// Note B (ticket #49): SMP contention is not exercised here.
// That requires a dedicated benchmark harness, not a shell sub-test.
// ---------------------------------------------------------------------------
const VMALLOC_FRAG_COUNT: usize = 32;

fn stress_vmalloc_frag() -> StressOutcome {
    #[inline(always)]
    fn xorshift64(s: &mut u64) -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    }

    let before = match crate::memory::vmalloc::diag_snapshot() {
        Some(s) => s,
        None => return StressOutcome::Skip("vmalloc not initialised"),
    };

    // Non-zero seed so sizes and shuffle order vary across runs.
    let mut rng: u64 = crate::process::scheduler::ticks() | 1;

    let mut ptrs = [core::ptr::null_mut::<u8>(); VMALLOC_FRAG_COUNT];
    let mut sizes = [0usize; VMALLOC_FRAG_COUNT];
    let mut allocated = 0usize;

    // Phase 1: allocate VMALLOC_FRAG_COUNT regions of random sizes (1-16 pages).
    for i in 0..VMALLOC_FRAG_COUNT {
        if crate::shell::is_interrupted() {
            for j in 0..allocated {
                if !ptrs[j].is_null() {
                    crate::sync::with_irqs_disabled(|token| {
                        crate::memory::free_kernel_virtual(ptrs[j], token);
                    });
                }
            }
            return StressOutcome::Skip("interrupted");
        }
        let pages = (xorshift64(&mut rng) as usize % 16) + 1; // 1..=16 pages
        let size = pages * 4096;
        let ptr = crate::sync::with_irqs_disabled(|token| {
            crate::memory::allocate_kernel_virtual(size, token).ok()
        });
        match ptr {
            Some(p) if !p.is_null() => {
                ptrs[i] = p;
                sizes[i] = size;
                allocated += 1;
            }
            _ => break, // arena exhausted — test with however many we got
        }
    }

    if allocated < 8 {
        for j in 0..allocated {
            if !ptrs[j].is_null() {
                crate::sync::with_irqs_disabled(|token| {
                    crate::memory::free_kernel_virtual(ptrs[j], token);
                });
            }
        }
        return StressOutcome::Skip("vmalloc arena too small for frag test (< 8 regions)");
    }

    // Phase 2: Fisher-Yates shuffle of indices [0..allocated].
    let mut order = [0usize; VMALLOC_FRAG_COUNT];
    for i in 0..allocated {
        order[i] = i;
    }
    for i in (1..allocated).rev() {
        let j = (xorshift64(&mut rng) as usize) % (i + 1);
        order.swap(i, j);
    }

    // Phase 3: free the first half of the shuffled order.
    // The remaining half stays live, creating non-contiguous holes in the arena.
    let half = allocated / 2;
    for &idx in &order[..half] {
        if !ptrs[idx].is_null() {
            crate::sync::with_irqs_disabled(|token| {
                crate::memory::free_kernel_virtual(ptrs[idx], token);
            });
            ptrs[idx] = core::ptr::null_mut();
        }
    }

    // Phase 4: verify fragmentation is visible.
    // With `half` regions freed in random order and `allocated - half` still
    // live, the free space is split into non-contiguous holes →
    // free_extent_count must exceed the pre-test baseline.
    let mid = match crate::memory::vmalloc::diag_snapshot() {
        Some(s) => s,
        None => {
            for &idx in &order[half..allocated] {
                if !ptrs[idx].is_null() {
                    crate::sync::with_irqs_disabled(|token| {
                        crate::memory::free_kernel_virtual(ptrs[idx], token);
                    });
                }
            }
            return StressOutcome::Skip("VMALLOC lock busy during mid-frag snapshot");
        }
    };
    // Capture result before freeing remaining regions so cleanup always runs.
    let frag_ok = mid.free_extent_count > before.free_extent_count;

    // Phase 5: free the second half of the shuffled order.
    for &idx in &order[half..allocated] {
        if !ptrs[idx].is_null() {
            crate::sync::with_irqs_disabled(|token| {
                crate::memory::free_kernel_virtual(ptrs[idx], token);
            });
            ptrs[idx] = core::ptr::null_mut();
        }
    }

    // Phase 6: final coherence checks.
    let after = match crate::memory::vmalloc::diag_snapshot() {
        Some(s) => s,
        None => return StressOutcome::Skip("VMALLOC lock busy during final frag snapshot"),
    };

    // All allocated pages must be returned (±1 for snapshot race).
    let total_pages: usize = sizes.iter().take(allocated).map(|&s| s / 4096).sum();
    let expected_free = before.free_pages.saturating_add(total_pages);
    if after.free_pages.saturating_add(1) < expected_free {
        return StressOutcome::Fail("vmalloc_frag: pages not fully returned after drain");
    }

    // Coherence: largest free extent must fit within total free pages.
    if after.largest_free_pages > after.free_pages.saturating_add(1) {
        return StressOutcome::Fail("vmalloc_frag: largest_free_pages > free_pages (incoherent)");
    }

    if !frag_ok {
        return StressOutcome::Fail("vmalloc_frag: fragmentation not visible after half-drain");
    }

    StressOutcome::Pass
}

// ---------------------------------------------------------------------------
// Sub-test: telemetry_consistency
//
// Sanity-check that all allocator counters are internally consistent.
// Does not allocate anything — pure read of existing state.
// ---------------------------------------------------------------------------
fn stress_telemetry() -> StressOutcome {
    // Slab: reclaimed must not exceed allocated.
    let slab = crate::memory::heap::slab_diag_snapshot();
    if slab.pages_reclaimed > slab.pages_allocated {
        return StressOutcome::Fail("slab: pages_reclaimed > pages_allocated (counter corruption)");
    }

    // Phys-contiguous: freed must not exceed allocated.
    let phys = crate::memory::phys_contiguous_diag();
    if phys.pages_freed > phys.pages_allocated {
        return StressOutcome::Fail(
            "phys_contiguous: pages_freed > pages_allocated (counter corruption)",
        );
    }

    // vmalloc: allocated_pages must fit in the arena; peak must be a watermark.
    if let Some(vm) = crate::memory::vmalloc::diag_snapshot() {
        let arena_pages = (vm.arena_end.saturating_sub(vm.arena_start)) as usize / 4096;

        if vm.allocated_pages > arena_pages {
            return StressOutcome::Fail("vmalloc: allocated_pages > arena capacity (impossible)");
        }
        if vm.allocated_pages.saturating_add(vm.free_pages) > arena_pages.saturating_add(1) {
            // ±1 for the ARENA_START_PAGE reservation
            return StressOutcome::Fail(
                "vmalloc: allocated + free > arena capacity (accounting error)",
            );
        }
        if (vm.peak_pages as usize) < vm.allocated_pages {
            return StressOutcome::Fail(
                "vmalloc: peak_pages < allocated_pages (watermark regression)",
            );
        }
    }

    StressOutcome::Pass
}

fn stress_userspace_workload() -> StressOutcome {
    let path = "/initfs/test_mem_stressed";
    let fd = match crate::vfs::open(path, crate::vfs::OpenFlags::READ) {
        Ok(fd) => fd,
        Err(_) => return StressOutcome::Skip("userspace stress binary not present in initfs"),
    };
    let data = match crate::vfs::read_all(fd) {
        Ok(d) => d,
        Err(_) => {
            let _ = crate::vfs::close(fd);
            return StressOutcome::Fail("failed to read userspace stress binary");
        }
    };
    let _ = crate::vfs::close(fd);

    let label = alloc::format!("heap-stress-{}", crate::process::scheduler::ticks());
    let silo_id = match crate::silo::kernel_spawn_strate(&data, Some(label.as_str()), None) {
        Ok(sid) => sid,
        Err(_) => return StressOutcome::Fail("failed to spawn userspace stress workload"),
    };

    let appeared = match stress_wait_until(STRESS_WORKLOAD_OBSERVE_TICKS / 2, || {
        crate::silo::list_silos_snapshot()
            .iter()
            .any(|s| s.id == silo_id && s.task_count > 0)
    }) {
        Ok(v) => v,
        Err(msg) => {
            let _ = crate::silo::kernel_destroy_silo(label.as_str());
            return StressOutcome::Skip(msg);
        }
    };
    if !appeared {
        let _ = crate::silo::kernel_destroy_silo(label.as_str());
        return StressOutcome::Fail("userspace workload never became runnable");
    }

    let observed = match stress_wait_until(STRESS_WORKLOAD_OBSERVE_TICKS, || {
        crate::silo::list_silos_snapshot()
            .iter()
            .any(|s| s.id == silo_id && s.task_count > 0)
    }) {
        Ok(v) => v,
        Err(msg) => {
            let _ = crate::silo::kernel_destroy_silo(label.as_str());
            return StressOutcome::Skip(msg);
        }
    };
    if !observed {
        let _ = crate::silo::kernel_destroy_silo(label.as_str());
        return StressOutcome::Fail("userspace workload exited too early");
    }

    let quiesced = match stress_wait_until(STRESS_WORKLOAD_EXIT_TIMEOUT_TICKS, || {
        let silos = crate::silo::list_silos_snapshot();
        !silos.iter().any(|s| s.id == silo_id && s.task_count > 0)
    }) {
        Ok(v) => v,
        Err(msg) => {
            let _ = crate::silo::kernel_destroy_silo(label.as_str());
            return StressOutcome::Skip(msg);
        }
    };

    if !quiesced {
        let _ = crate::silo::kernel_destroy_silo(label.as_str());
        return StressOutcome::Fail("userspace workload did not quiesce before timeout");
    }

    let _ = crate::silo::kernel_destroy_silo(label.as_str());
    StressOutcome::Pass
}

fn stress_wait_until(
    timeout_ticks: u64,
    mut cond: impl FnMut() -> bool,
) -> Result<bool, &'static str> {
    let start = crate::process::scheduler::ticks();
    loop {
        if cond() {
            return Ok(true);
        }
        if crate::shell::is_interrupted() {
            return Err("interrupted");
        }
        if crate::process::scheduler::ticks().saturating_sub(start) > timeout_ticks {
            return Ok(false);
        }
        crate::process::yield_task();
    }
}

#[inline]
fn page_base(ptr: *mut u8) -> u64 {
    (ptr as u64) & !0xfff
}
