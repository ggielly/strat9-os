use crate::{
    alloc::string::String,
    shell::{output::format_bytes, ShellError},
    shell_println,
};

const HEAP_USAGE: &str = "Usage: heap [summary|vmalloc|live [limit]|fail|diag]";
const MAX_LIVE_LIMIT: usize = 4096;

/// `heap` — allocator telemetry and diagnostics.
pub fn cmd_heap(args: &[String]) -> Result<(), ShellError> {
    match args.first().map(|s| s.as_str()) {
        None | Some("summary") => cmd_heap_summary(),
        Some("vmalloc") => cmd_heap_vmalloc(),
        Some("live") => cmd_heap_live(args.get(1))?,
        Some("fail") => cmd_heap_fail(),
        Some("diag") => {
            crate::memory::heap::dump_diagnostics();
            Ok(())
        }
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
    shell_println!(
        "  Arena: 0x{:x}..0x{:x}",
        diag.arena_start,
        diag.arena_end
    );
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
