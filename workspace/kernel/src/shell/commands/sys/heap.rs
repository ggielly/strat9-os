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

/// `heap` : allocator telemetry and diagnostics.
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

/// `heap stress [rounds]` : exercise the slab and vmalloc allocators,
/// validate partial-page reclaim, fragmentation handling, and telemetry
/// consistency.  All tests run in kernel context from the shell task.
///
/// Each round runs 7 sub-tests:
///   slab_reclaim[S]  : fill N complete slab pages for class S, free all,
///                      verify the pages are reclaimed to the buddy.
///   slab_frag[256]   : allocate one page, free in non-LIFO order, verify
///                      the page is not reclaimed mid-way and is reclaimed
///                      only when fully empty.
///   vmalloc_cycle    : alloc/free several vmalloc regions, check telemetry.
///   telemetry        : sanity-check all counters are self-consistent.
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

    for round in 0..rounds {
        if rounds > 1 {
            shell_println!("--- round {}/{} ---", round + 1, rounds);
        }

        // Helper: run a sub-test and print PASS/FAIL.
        // Returns true on pass.
        let mut run = |name: &str, result: Result<(), &'static str>| -> bool {
            match result {
                Ok(()) => {
                    shell_println!("  {:<36} PASS", name);
                    true
                }
                Err(msg) => {
                    shell_println!("  {:<36} FAIL  {}", name, msg);
                    false
                }
            }
        };

        // slab_reclaim: largest class (1 block/page → easy reclaim signal)
        let ok = run("slab_reclaim[2048 ci=25 p=4]", stress_slab_reclaim(25, 4));
        if ok {
            total_pass += 1;
        } else {
            total_fail += 1;
        }

        let ok = run("slab_reclaim[512 ci=17 p=3]", stress_slab_reclaim(17, 3));
        if ok {
            total_pass += 1;
        } else {
            total_fail += 1;
        }

        let ok = run("slab_reclaim[64 ci=5 p=2]", stress_slab_reclaim(5, 2));
        if ok {
            total_pass += 1;
        } else {
            total_fail += 1;
        }

        let ok = run("slab_reclaim[8 ci=0 p=1]", stress_slab_reclaim(0, 1));
        if ok {
            total_pass += 1;
        } else {
            total_fail += 1;
        }

        let ok = run("slab_frag[256 ci=13]", stress_slab_frag(13));
        if ok {
            total_pass += 1;
        } else {
            total_fail += 1;
        }

        let ok = run("vmalloc_cycle", stress_vmalloc_cycle());
        if ok {
            total_pass += 1;
        } else {
            total_fail += 1;
        }

        let ok = run("telemetry_consistency", stress_telemetry());
        if ok {
            total_pass += 1;
        } else {
            total_fail += 1;
        }
    }

    shell_println!("heap stress: {} passed, {} failed", total_pass, total_fail);
    if total_fail == 0 {
        Ok(())
    } else {
        Err(ShellError::ExecutionFailed)
    }
}

// ---------------------------------------------------------------------------
// Sub-test: slab_reclaim
//
// Allocate `pages` worth of complete slab pages for class `ci`, then free
// all blocks and verify the pages are returned to the buddy allocator.
//
// Pointer storage lives on the stack (STRESS_MAX_BLOCKS × 8 bytes ≈ 4 KiB).
// No heap allocation is used for bookkeeping, so the snapshot deltas are clean.
// ---------------------------------------------------------------------------
fn stress_slab_reclaim(ci: usize, pages: usize) -> Result<(), &'static str> {
    use alloc::alloc::{alloc, dealloc, Layout};

    let class_size = crate::memory::heap::slab_class_size(ci);
    let blocks_per_page = crate::memory::heap::slab_blocks_per_page(ci);
    let total = pages * blocks_per_page;

    if total > STRESS_MAX_BLOCKS {
        return Err("test config: total_blocks > STRESS_MAX_BLOCKS, reduce pages");
    }

    let layout =
        Layout::from_size_align(class_size, 8).map_err(|_| "Layout::from_size_align failed")?;

    // Stack storage : no heap interaction for bookkeeping.
    let mut ptrs = [core::ptr::null_mut::<u8>(); STRESS_MAX_BLOCKS];
    let mut count = 0usize;

    let before = crate::memory::heap::slab_diag_snapshot();

    // Fill `pages` complete slab pages.
    for i in 0..total {
        // SAFETY: layout is valid; LockedHeap is the global allocator.
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            // OOM: clean up and fail.
            for j in 0..count {
                unsafe { dealloc(ptrs[j], layout) };
            }
            return Err("OOM during slab reclaim fill phase");
        }
        ptrs[i] = ptr;
        count += 1;
    }

    let mid = crate::memory::heap::slab_diag_snapshot();

    // Free all blocks : should trigger full-page reclaim.
    for i in 0..count {
        // SAFETY: ptr was returned by alloc with the same layout.
        unsafe { dealloc(ptrs[i], layout) };
        ptrs[i] = core::ptr::null_mut();
    }

    let after = crate::memory::heap::slab_diag_snapshot();

    // Verify: the slab allocated at least `pages` new pages during the fill.
    let pages_added = mid.pages_allocated.saturating_sub(before.pages_allocated);
    if pages_added < pages {
        return Err("slab allocated fewer pages than expected during fill");
    }

    // Verify: reclamation happened : pages_live must return to baseline (±1
    // for any transient races between the two atomic reads in the snapshot).
    if after.pages_live > before.pages_live.saturating_add(1) {
        return Err("slab pages not fully reclaimed after freeing all blocks");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Sub-test: slab_frag
//
// Allocate one complete slab page for class `ci`, then free blocks in a
// non-LIFO order (even indices first, then odd).  Verify that:
//   1. No page is reclaimed after the first (partial) free.
//   2. The page IS reclaimed after all blocks are freed.
// ---------------------------------------------------------------------------
fn stress_slab_frag(ci: usize) -> Result<(), &'static str> {
    use alloc::alloc::{alloc, dealloc, Layout};

    let class_size = crate::memory::heap::slab_class_size(ci);
    let bpp = crate::memory::heap::slab_blocks_per_page(ci);

    if bpp < 2 {
        return Err("class has < 2 blocks/page, frag test not meaningful");
    }
    if bpp > STRESS_MAX_BLOCKS {
        return Err("blocks_per_page > STRESS_MAX_BLOCKS");
    }

    let layout =
        Layout::from_size_align(class_size, 8).map_err(|_| "Layout::from_size_align failed")?;

    let mut ptrs = [core::ptr::null_mut::<u8>(); STRESS_MAX_BLOCKS];

    let before = crate::memory::heap::slab_diag_snapshot();

    // Allocate exactly one page worth of blocks.
    for i in 0..bpp {
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            for j in 0..i {
                unsafe { dealloc(ptrs[j], layout) };
            }
            return Err("OOM during slab frag alloc phase");
        }
        ptrs[i] = ptr;
    }

    let after_alloc = crate::memory::heap::slab_diag_snapshot();

    // Free even-indexed blocks : page goes partial but NOT fully empty.
    for i in (0..bpp).step_by(2) {
        unsafe { dealloc(ptrs[i], layout) };
        ptrs[i] = core::ptr::null_mut();
    }

    let after_partial = crate::memory::heap::slab_diag_snapshot();

    // Check: the page must NOT have been reclaimed yet.
    let reclaimed_so_far = after_partial
        .pages_reclaimed
        .saturating_sub(before.pages_reclaimed);
    if reclaimed_so_far > 0 {
        // Clean up remaining blocks before returning.
        for i in (1..bpp).step_by(2) {
            if !ptrs[i].is_null() {
                unsafe { dealloc(ptrs[i], layout) };
            }
        }
        return Err("page reclaimed prematurely (after partial free : still has live blocks)");
    }

    // Free odd-indexed blocks : page becomes fully empty and should be reclaimed.
    for i in (1..bpp).step_by(2) {
        if !ptrs[i].is_null() {
            unsafe { dealloc(ptrs[i], layout) };
            ptrs[i] = core::ptr::null_mut();
        }
    }

    let after_full = crate::memory::heap::slab_diag_snapshot();

    // Verify page was allocated during the fill phase.
    let pages_added = after_alloc
        .pages_allocated
        .saturating_sub(before.pages_allocated);
    if pages_added == 0 {
        return Err("no slab page was allocated during frag test fill");
    }

    // Verify the page was reclaimed after all blocks were freed.
    let reclaimed_total = after_full
        .pages_reclaimed
        .saturating_sub(before.pages_reclaimed);
    if reclaimed_total == 0 {
        return Err("slab page not reclaimed after all blocks freed (fragmentation regression)");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Sub-test: vmalloc_cycle
//
// Allocate and free several vmalloc regions of increasing size.  Verify that
// alloc_count increases during the fill and that allocated_pages returns to
// the baseline after all frees.
// ---------------------------------------------------------------------------
fn stress_vmalloc_cycle() -> Result<(), &'static str> {
    // Sizes chosen to cover 1, 4, 16, and 64 pages.
    const SIZES: [usize; 4] = [4096, 16384, 65536, 262144];
    let mut vptrs = [core::ptr::null_mut::<u8>(); 4];

    let before = crate::memory::vmalloc::diag_snapshot().ok_or("vmalloc not initialised")?;

    // Allocate all regions.
    for (i, &size) in SIZES.iter().enumerate() {
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
                return Err("vmalloc returned null during cycle alloc phase");
            }
        }
    }

    let mid =
        crate::memory::vmalloc::diag_snapshot().ok_or("vmalloc snapshot failed after alloc")?;

    // Free all regions.
    for ptr in vptrs.iter_mut() {
        if !ptr.is_null() {
            crate::sync::with_irqs_disabled(|token| {
                crate::memory::free_kernel_virtual(*ptr, token);
            });
            *ptr = core::ptr::null_mut();
        }
    }

    let after =
        crate::memory::vmalloc::diag_snapshot().ok_or("vmalloc snapshot failed after free")?;

    // Verify alloc_count grew by the expected number of allocations.
    let added = mid.alloc_count.saturating_sub(before.alloc_count);
    if added < SIZES.len() {
        return Err("vmalloc alloc_count did not increase by expected amount");
    }

    // Verify pages were freed: allocated_pages must return to baseline (±1).
    if after.allocated_pages > before.allocated_pages.saturating_add(1) {
        return Err("vmalloc allocated_pages did not return to baseline after free");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Sub-test: telemetry_consistency
//
// Sanity-check that all allocator counters are internally consistent.
// Does not allocate anything : pure read of existing state.
// ---------------------------------------------------------------------------
fn stress_telemetry() -> Result<(), &'static str> {
    // Slab: reclaimed must not exceed allocated.
    let slab = crate::memory::heap::slab_diag_snapshot();
    if slab.pages_reclaimed > slab.pages_allocated {
        return Err("slab: pages_reclaimed > pages_allocated (counter corruption)");
    }

    // Phys-contiguous: freed must not exceed allocated.
    let phys = crate::memory::phys_contiguous_diag();
    if phys.pages_freed > phys.pages_allocated {
        return Err("phys_contiguous: pages_freed > pages_allocated (counter corruption)");
    }

    // vmalloc: allocated_pages must fit in the arena; peak must be a watermark.
    if let Some(vm) = crate::memory::vmalloc::diag_snapshot() {
        let arena_pages = (vm.arena_end.saturating_sub(vm.arena_start)) as usize / 4096;

        if vm.allocated_pages > arena_pages {
            return Err("vmalloc: allocated_pages > arena capacity (impossible)");
        }
        if vm.allocated_pages.saturating_add(vm.free_pages) > arena_pages.saturating_add(1) {
            // ±1 for the ARENA_START_PAGE reservation
            return Err("vmalloc: allocated + free > arena capacity (accounting error)");
        }
        if (vm.peak_pages as usize) < vm.allocated_pages {
            return Err("vmalloc: peak_pages < allocated_pages (watermark regression)");
        }
    }

    Ok(())
}
