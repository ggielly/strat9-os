//! Memory management commands
use crate::{
    shell::{output::format_bytes, ShellError},
    shell_println,
};
use alloc::string::String;

/// Display memory status
pub fn cmd_mem(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        return cmd_mem_summary();
    }

    match args[0].as_str() {
        "zones" => cmd_mem_zones(),
        "diag" => cmd_mem_diag(),
        _ => {
            shell_println!("Usage: mem [zones|diag]");
            Ok(())
        }
    }
}

/// Summary view (default for `mem` with no subcommand).
fn cmd_mem_summary() -> Result<(), ShellError> {
    let (total_pages, allocated_pages) = {
        let allocator_guard = crate::memory::buddy::get_allocator().lock();
        if let Some(ref allocator) = *allocator_guard {
            allocator.page_totals()
        } else {
            shell_println!("  Memory allocator not initialized");
            return Ok(());
        }
    };

    let total_bytes = total_pages * 4096;
    let used_bytes = allocated_pages * 4096;
    let free_bytes = total_bytes - used_bytes;

    let (total_val, total_unit) = format_bytes(total_bytes);
    let (used_val, used_unit) = format_bytes(used_bytes);
    let (free_val, free_unit) = format_bytes(free_bytes);

    shell_println!("Memory status:");
    shell_println!(
        "  Total:     {} {} ({} pages)",
        total_val,
        total_unit,
        total_pages
    );
    shell_println!(
        "  Used:      {} {} ({} pages)",
        used_val,
        used_unit,
        allocated_pages
    );
    shell_println!(
        "  Free:      {} {} ({} pages)",
        free_val,
        free_unit,
        total_pages - allocated_pages
    );
    shell_println!("");

    Ok(())
}

/// Display detailed memory zone information
fn cmd_mem_zones() -> Result<(), ShellError> {
    const MAX_ZONES: usize = 4;
    let mut zones_info = [(0u8, 0u64, 0usize, 0usize); MAX_ZONES];
    let zone_count;

    {
        let allocator_guard = crate::memory::buddy::get_allocator().lock();
        if let Some(ref allocator) = *allocator_guard {
            zone_count = allocator.zone_snapshot(&mut zones_info);
        } else {
            shell_println!("  Memory allocator not initialized");
            return Ok(());
        }
    }

    shell_println!("Memory zones:");
    for i in 0..zone_count {
        let (zone_type, base, page_count, allocated) = zones_info[i];
        let total_bytes = page_count * 4096;
        let free_bytes = (page_count - allocated) * 4096;

        let (total_val, total_unit) = format_bytes(total_bytes);
        let (free_val, free_unit) = format_bytes(free_bytes);

        shell_println!("  Zone {:?}:", zone_type_from_u8(zone_type));
        shell_println!("    Base:      0x{:016x}", base);
        shell_println!(
            "    Total:     {} {} ({} pages)",
            total_val,
            total_unit,
            page_count
        );
        shell_println!(
            "    Free:      {} {} ({} pages)",
            free_val,
            free_unit,
            page_count - allocated
        );
        shell_println!("    Used:      {} pages", allocated);
        shell_println!("");
    }

    Ok(())
}

/// Performs the zone type from u8 operation.
fn zone_type_from_u8(val: u8) -> crate::memory::zone::ZoneType {
    match val {
        0 => crate::memory::zone::ZoneType::DMA,
        1 => crate::memory::zone::ZoneType::Normal,
        2 => crate::memory::zone::ZoneType::HighMem,
        _ => crate::memory::zone::ZoneType::DMA,
    }
}

/// Diagnostic view — poison quarantine, slab health, buddy alloc failures.
fn cmd_mem_diag() -> Result<(), ShellError> {
    // ── Poison quarantine ──────────────────────────────────────────────
    let quarantine = crate::memory::poison_quarantine_pages_snapshot();
    let (q_val, q_unit) = format_bytes(quarantine.saturating_mul(4096));
    shell_println!("Poison quarantine:");
    shell_println!("  Quarantined pages: {} ({} {})", quarantine, q_val, q_unit);
    shell_println!("");

    // ── Buddy allocation failures ──────────────────────────────────────
    let fail_counts = crate::memory::buddy::buddy_alloc_fail_counts_snapshot();
    let any_fail = fail_counts.iter().any(|&c| c > 0);
    if any_fail {
        shell_println!("Buddy allocation failures (by order):");
        for (order, &count) in fail_counts.iter().enumerate() {
            if count > 0 {
                let size = 4096usize << order;
                let (v, u) = format_bytes(size);
                shell_println!(
                    "  order {:>2} ({} {}): {} failures",
                    order, v, u, count
                );
            }
        }
        shell_println!("");
    } else {
        shell_println!("Buddy allocation failures: none");
        shell_println!("");
    }

    // ── Slab allocator ─────────────────────────────────────────────────
    let slab = crate::memory::heap::slab_diag_snapshot();
    let (sa_v, sa_u) = format_bytes(slab.pages_allocated.saturating_mul(4096));
    let (sr_v, sr_u) = format_bytes(slab.pages_reclaimed.saturating_mul(4096));
    let (sl_v, sl_u) = format_bytes(slab.pages_live.saturating_mul(4096));
    shell_println!("Slab allocator:");
    shell_println!("  Pages allocated:  {} ({} {})", slab.pages_allocated, sa_v, sa_u);
    shell_println!("  Pages reclaimed:  {} ({} {})", slab.pages_reclaimed, sr_v, sr_u);
    shell_println!("  Pages live:       {} ({} {})", slab.pages_live, sl_v, sl_u);
    shell_println!("");

    // ── Last heap failure ──────────────────────────────────────────────
    if let Some(fail) = crate::memory::heap::last_heap_failure_snapshot() {
        shell_println!("Last heap allocation failure:");
        shell_println!("  Backend:  {:?}", fail.backend);
        shell_println!(
            "  Request:  size={} align={} effective={}",
            fail.requested_size,
            fail.align,
            fail.effective_size
        );
        shell_println!("  Error:    {:?}", fail.error);
        shell_println!("");
    }

    // ── Slab size classes ──────────────────────────────────────────────
    shell_println!("Slab size classes:");
    for ci in 0..crate::memory::heap::SLAB_NUM_CLASSES {
        let block = crate::memory::heap::slab_class_size(ci);
        let blocks = crate::memory::heap::slab_blocks_per_page(ci);
        let waste = block.saturating_sub(1); // worst-case internal waste
        shell_println!(
            "  class {:>2}: block={:>5}B  blocks/page={:>3}  max_waste={:>4}B",
            ci, block, blocks, waste
        );
    }

    Ok(())
}
