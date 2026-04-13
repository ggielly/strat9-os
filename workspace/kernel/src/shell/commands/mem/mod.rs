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
    let (total_pages, allocated_pages, reserved_pages, cached_pages, pressured_zones) = {
        let allocator_guard = crate::memory::buddy::get_allocator().lock();
        if let Some(ref allocator) = *allocator_guard {
            let (total_pages, allocated_pages) = allocator.page_totals();
            let mut zones =
                [crate::memory::buddy::ZoneStats::empty(); crate::memory::zone::ZoneType::COUNT];
            let zone_count = allocator.zone_snapshot(&mut zones);
            let reserved_pages = zones
                .iter()
                .take(zone_count)
                .map(|zone| zone.reserved_pages)
                .sum::<usize>();
            let cached_pages = zones
                .iter()
                .take(zone_count)
                .map(|zone| zone.cached_pages)
                .sum::<usize>();
            let pressured_zones = zones
                .iter()
                .take(zone_count)
                .filter(|zone| zone.pressure() != crate::memory::buddy::ZonePressure::Healthy)
                .count();
            (
                total_pages,
                allocated_pages,
                reserved_pages,
                cached_pages,
                pressured_zones,
            )
        } else {
            shell_println!("  Memory allocator not initialized");
            return Ok(());
        }
    };

    let total_bytes = total_pages * 4096;
    let used_bytes = allocated_pages * 4096;
    let free_bytes = total_bytes - used_bytes;
    let reserved_bytes = reserved_pages * 4096;
    let cached_bytes = cached_pages * 4096;

    let (total_val, total_unit) = format_bytes(total_bytes);
    let (used_val, used_unit) = format_bytes(used_bytes);
    let (free_val, free_unit) = format_bytes(free_bytes);
    let (reserved_val, reserved_unit) = format_bytes(reserved_bytes);
    let (cached_val, cached_unit) = format_bytes(cached_bytes);

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
    shell_println!(
        "  Reserved:  {} {} ({} pages)",
        reserved_val,
        reserved_unit,
        reserved_pages
    );
    shell_println!(
        "  Cached:    {} {} ({} pages)",
        cached_val,
        cached_unit,
        cached_pages
    );
    shell_println!(
        "  Pressure:  {} zone(s) below high watermark",
        pressured_zones
    );
    shell_println!("");

    Ok(())
}

/// Display detailed memory zone information
fn cmd_mem_zones() -> Result<(), ShellError> {
    const MAX_ZONES: usize = crate::memory::zone::ZoneType::COUNT;
    let mut zones_info = [crate::memory::buddy::ZoneStats::empty(); MAX_ZONES];
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
    for info in zones_info.iter().take(zone_count) {
        let managed_bytes = info.managed_pages * 4096;
        let present_bytes = info.present_pages * 4096;
        let reserved_bytes = info.reserved_pages * 4096;
        let free_bytes = info.free_pages * 4096;
        let movable_bytes = info.movable_free_pages * 4096;
        let unmovable_bytes = info.unmovable_free_pages * 4096;

        let (managed_val, managed_unit) = format_bytes(managed_bytes);
        let (present_val, present_unit) = format_bytes(present_bytes);
        let (reserved_val, reserved_unit) = format_bytes(reserved_bytes);
        let (free_val, free_unit) = format_bytes(free_bytes);
        let (movable_val, movable_unit) = format_bytes(movable_bytes);
        let (unmovable_val, unmovable_unit) = format_bytes(unmovable_bytes);

        shell_println!("  Zone {:?}:", info.zone_type);
        shell_println!("    Base:      0x{:016x}", info.base);
        shell_println!(
            "    Managed:   {} {} ({} pages)",
            managed_val,
            managed_unit,
            info.managed_pages
        );
        shell_println!(
            "    Present:   {} {} ({} pages)",
            present_val,
            present_unit,
            info.present_pages
        );
        shell_println!(
            "    Reserved:  {} {} ({} pages)",
            reserved_val,
            reserved_unit,
            info.reserved_pages
        );
        shell_println!(
            "    Free:      {} {} ({} pages)",
            free_val,
            free_unit,
            info.free_pages
        );
        shell_println!("    Used:      {} pages", info.allocated_pages);
        shell_println!("    Cached:    {} pages", info.cached_pages);
        shell_println!(
            "    Cached(u/m): {} / {} pages",
            info.cached_unmovable_pages,
            info.cached_movable_pages
        );
        shell_println!(
            "    Segments:  {}/{}",
            info.segment_count,
            info.segment_capacity
        );
        shell_println!(
            "    Free(u/m): {} {} / {} {}",
            unmovable_val,
            unmovable_unit,
            movable_val,
            movable_unit
        );
        if let Some(order) = info.largest_free_order {
            let largest_bytes = 4096usize << order;
            let (largest_val, largest_unit) = format_bytes(largest_bytes);
            shell_println!(
                "    Largest:   order {} ({} {})",
                order,
                largest_val,
                largest_unit
            );
        } else {
            shell_println!("    Largest:   none");
        }
        shell_println!(
            "    Policy:    min={} low={} high={} reserve={}",
            info.watermark_min,
            info.watermark_low,
            info.watermark_high,
            info.lowmem_reserve_pages
        );
        shell_println!(
            "    State:     {:?} (avail_after_reserve={} pages, holes={} pages)",
            info.pressure(),
            info.available_after_reserve_pages(),
            info.hole_pages()
        );
        shell_println!("");
    }

    Ok(())
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
                shell_println!("  order {:>2} ({} {}): {} failures", order, v, u, count);
            }
        }
        shell_println!("");
    } else {
        shell_println!("Buddy allocation failures: none");
        shell_println!("");
    }

    // ── Buddy zone policy / fragmentation view ────────────────────────
    {
        let allocator_guard = crate::memory::buddy::get_allocator().lock();
        if let Some(ref allocator) = *allocator_guard {
            let mut zones =
                [crate::memory::buddy::ZoneStats::empty(); crate::memory::zone::ZoneType::COUNT];
            let zone_count = allocator.zone_snapshot(&mut zones);
            shell_println!("Buddy zones:");
            for (zone_idx, info) in zones.iter().take(zone_count).enumerate() {
                let zone = allocator.get_zone(zone_idx);
                let mut frag = String::new();
                for order in 1..=crate::memory::zone::MAX_ORDER {
                    use core::fmt::Write;
                    let score = zone.fragmentation_score(order as u8, info.cached_pages);
                    let _ = write!(frag, "o{}={}% ", order, score);
                }
                match info.largest_free_order {
                    Some(order) => shell_println!(
                        "  {:?}: state={:?} free={} used={} cached={} avail={} segments={}/{} u/m={}/{} cu/cm={}/{} watermarks={}/{}/{} reserve={} largest=o{}",
                        info.zone_type,
                        info.pressure(),
                        info.free_pages,
                        info.allocated_pages,
                        info.cached_pages,
                        info.available_after_reserve_pages(),
                        info.segment_count,
                        info.segment_capacity,
                        info.unmovable_free_pages,
                        info.movable_free_pages,
                        info.cached_unmovable_pages,
                        info.cached_movable_pages,
                        info.watermark_min,
                        info.watermark_low,
                        info.watermark_high,
                        info.lowmem_reserve_pages,
                        order
                    ),
                    None => shell_println!(
                        "  {:?}: state={:?} free={} used={} cached={} avail={} segments={}/{} u/m={}/{} cu/cm={}/{} watermarks={}/{}/{} reserve={} largest=none",
                        info.zone_type,
                        info.pressure(),
                        info.free_pages,
                        info.allocated_pages,
                        info.cached_pages,
                        info.available_after_reserve_pages(),
                        info.segment_count,
                        info.segment_capacity,
                        info.unmovable_free_pages,
                        info.movable_free_pages,
                        info.cached_unmovable_pages,
                        info.cached_movable_pages,
                        info.watermark_min,
                        info.watermark_low,
                        info.watermark_high,
                        info.lowmem_reserve_pages
                    ),
                }
                shell_println!("    frag/order: {}", frag);
            }
            shell_println!("");
        }
    }

    // ── Slab allocator ─────────────────────────────────────────────────
    let slab = crate::memory::heap::slab_diag_snapshot();
    let (sa_v, sa_u) = format_bytes(slab.pages_allocated.saturating_mul(4096));
    let (sr_v, sr_u) = format_bytes(slab.pages_reclaimed.saturating_mul(4096));
    let (sl_v, sl_u) = format_bytes(slab.pages_live.saturating_mul(4096));
    shell_println!("Slab allocator:");
    shell_println!(
        "  Pages allocated:  {} ({} {})",
        slab.pages_allocated,
        sa_v,
        sa_u
    );
    shell_println!(
        "  Pages reclaimed:  {} ({} {})",
        slab.pages_reclaimed,
        sr_v,
        sr_u
    );
    shell_println!(
        "  Pages live:       {} ({} {})",
        slab.pages_live,
        sl_v,
        sl_u
    );
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
            ci,
            block,
            blocks,
            waste
        );
    }

    Ok(())
}
