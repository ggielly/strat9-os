//! Memory management commands
use crate::{
    memory::buddy::{ZonePressure, ZoneStats},
    shell::{output::human_bytes, ShellError},
    shell_println,
};
use alloc::{format, string::String};

/// Bytes in one managed page, taken from the frame allocator so these commands
/// cannot drift from the page size the kernel actually hands out.
const PAGE_BYTES: usize = crate::memory::frame::PAGE_SIZE as usize;

/// Upper bound on the zones one snapshot can hold.
const ZONE_CAP: usize = crate::memory::zone::ZoneType::COUNT;

/// Highest buddy order, i.e. how many per-order figures `mem diag` prints.
const MAX_ORDER: usize = crate::memory::zone::MAX_ORDER;

/// Width of the `mem zones` label column; the longest label is `Cached(u/m):`.
const LABEL_COL: usize = 12;

/// Lines `mem zones` prints per zone, including the trailing blank one.
const ZONE_LINES: usize = 16;

/// Display memory status
pub fn cmd_mem(args: &[String]) -> Result<(), ShellError> {
    let Some(sub) = args.first() else {
        return cmd_mem_summary();
    };
    match sub.as_str() {
        "zones" | "diag" => {}
        other => {
            shell_println!("mem: unknown subcommand '{}'", other);
            shell_println!("Usage: mem [zones|diag]");
            return Err(ShellError::InvalidArguments);
        }
    }
    if let Some(extra) = args.get(1) {
        shell_println!("mem {}: unexpected argument '{}'", sub, extra);
        return Err(ShellError::InvalidArguments);
    }

    if sub == "zones" {
        cmd_mem_zones()
    } else {
        cmd_mem_diag()
    }
}

/// Run `f` with the buddy allocator, or fail if memory management is not up.
///
/// The guard is released before `f`'s result is returned, so `f` must stay
/// allocation-free: the heap's slab refill path takes a frame from this very
/// allocator, so allocating while the lock is held self-deadlocks.
fn with_allocator<R>(
    f: impl FnOnce(&crate::memory::buddy::BuddyAllocator) -> R,
) -> Result<R, ShellError> {
    let guard = crate::memory::buddy::get_allocator().lock();
    let Some(allocator) = guard.as_ref() else {
        shell_println!("  Memory allocator not initialized");
        return Err(ShellError::ExecutionFailed);
    };
    Ok(f(allocator))
}

/// Bytes covered by `pages` managed pages.
pub(crate) fn page_bytes(pages: usize) -> u64 {
    (pages as u64).saturating_mul(PAGE_BYTES as u64)
}

/// Size of a buddy order, saturating instead of overflowing.
///
/// `order` comes from allocator state, so a nonsensical value must not wrap
/// (or panic on a checked shift) inside a diagnostic command.
pub(crate) fn order_bytes(order: usize) -> u64 {
    if order >= u64::BITS as usize {
        return u64::MAX;
    }
    (PAGE_BYTES as u64).saturating_mul(1u64 << order)
}

/// `    Label:  value` with every label in the same column.
pub(crate) fn format_field(label: &str, value: &str) -> String {
    format!("    {:<w$}{}", label, value, w = LABEL_COL)
}

/// `1MB (256 pages)`: a byte size next to the page count it came from.
fn format_page_value(pages: usize) -> String {
    format!("{} ({} pages)", human_bytes(page_bytes(pages)), pages)
}

/// `    Label:  12MB (3072 pages)` for a page counter.
pub(crate) fn format_page_field(label: &str, pages: usize) -> String {
    format_field(label, &format_page_value(pages))
}

/// `1MB (256 pages) / 2MB (512 pages)`, unmovable first.
pub(crate) fn format_page_pair(unmovable: usize, movable: usize) -> String {
    format!(
        "{} / {}",
        format_page_value(unmovable),
        format_page_value(movable)
    )
}

/// `3/12` for two plain counters.
pub(crate) fn format_count_pair(first: usize, second: usize) -> String {
    format!("{}/{}", first, second)
}

/// `order 11 (8MB)`, or `none` when the zone has no free block of any order.
pub(crate) fn format_largest(order: Option<u8>) -> String {
    match order {
        Some(order) => format!(
            "order {} ({})",
            order,
            human_bytes(order_bytes(usize::from(order)))
        ),
        None => String::from("none"),
    }
}

/// `o11`, the same figure compressed for the one-line `mem diag` zone summary.
pub(crate) fn format_largest_tag(order: Option<u8>) -> String {
    match order {
        Some(order) => format!("o{}", order),
        None => String::from("none"),
    }
}

/// The `mem zones` report for one zone, fully formatted.
///
/// Kept apart from the command so the layout, the shared `bytes (pages)`
/// spelling and the `u/m` ordering can be checked without a kernel.
pub(crate) fn zone_lines(info: &ZoneStats) -> [String; ZONE_LINES] {
    [
        format_field("Zone:", &format!("{:?}", info.zone_type)),
        format_field("Base:", &format!("0x{:016x}", info.base)),
        format_page_field("Managed:", info.managed_pages),
        format_page_field("Present:", info.present_pages),
        format_page_field("Reserved:", info.reserved_pages),
        format_page_field("Free:", info.free_pages),
        format_page_field("Used:", info.allocated_pages),
        format_page_field("Cached:", info.cached_pages),
        format_field(
            "Cached(u/m):",
            &format_page_pair(info.cached_unmovable_pages, info.cached_movable_pages),
        ),
        format_field(
            "Segments:",
            &format_count_pair(info.segment_count, info.segment_capacity),
        ),
        format_field(
            "Pageblocks:",
            &format!(
                "{} (u/m = {}, order={})",
                info.pageblock_count,
                format_count_pair(info.unmovable_pageblocks, info.movable_pageblocks),
                crate::memory::zone::PAGEBLOCK_ORDER
            ),
        ),
        format_field(
            "Free(u/m):",
            &format_page_pair(info.unmovable_free_pages, info.movable_free_pages),
        ),
        format_field("Largest:", &format_largest(info.largest_free_order)),
        format_field(
            "Policy:",
            &format!(
                "min={} low={} high={} reserve={}",
                info.watermark_min,
                info.watermark_low,
                info.watermark_high,
                info.lowmem_reserve_pages
            ),
        ),
        format_field(
            "State:",
            &format!(
                "{:?} (avail_after_reserve={} pages, holes={} pages)",
                info.pressure(),
                info.available_after_reserve_pages(),
                info.hole_pages()
            ),
        ),
        String::new(),
    ]
}

/// One `mem zones` line, indented like the rest of the report.
fn print_zone_lines(info: &ZoneStats) {
    for line in zone_lines(info) {
        shell_println!("{}", line);
    }
}

/// `o1=0% o2=12% ...` for orders 1..=MAX_ORDER, in order.
pub(crate) fn format_frag_scores(scores: &[u8]) -> String {
    let mut out = String::new();
    for (i, &score) in scores.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let _ = core::fmt::Write::write_fmt(&mut out, format_args!("o{}={}%", i + 1, score));
    }
    out
}

/// The single-line per-zone summary `mem diag` prints.
pub(crate) fn zone_diag_line(info: &ZoneStats) -> String {
    format!(
        "  {:?}: state={:?} free={} used={} cached={} avail={} segments={} pageblocks=u{}/m{} u/m={}/{} cu/cm={}/{} watermarks={}/{}/{} reserve={} largest={}",
        info.zone_type,
        info.pressure(),
        info.free_pages,
        info.allocated_pages,
        info.cached_pages,
        info.available_after_reserve_pages(),
        format_count_pair(info.segment_count, info.segment_capacity),
        info.unmovable_pageblocks,
        info.movable_pageblocks,
        info.unmovable_free_pages,
        info.movable_free_pages,
        info.cached_unmovable_pages,
        info.cached_movable_pages,
        info.watermark_min,
        info.watermark_low,
        info.watermark_high,
        info.lowmem_reserve_pages,
        format_largest_tag(info.largest_free_order),
    )
}

/// One `mem diag` slab size-class line.
///
/// `blocks_per_page` comes from the heap, whose slab geometry assumes a 4 KiB
/// page independently of [`PAGE_BYTES`].
pub(crate) fn slab_class_line(ci: usize, block: usize, blocks_per_page: usize) -> String {
    format!(
        "  class {:>2}: block={:>5}B  blocks/page={:>3}  max_waste={:>4}B",
        ci,
        block,
        blocks_per_page,
        // Worst-case internal waste of a single block.
        block.saturating_sub(1)
    )
}

/// One zone's `mem diag` figures.
#[derive(Clone, Copy)]
struct ZoneFrag {
    /// The zone counters, copied out of the allocator.
    stats: ZoneStats,
    /// Fragmentation score for orders 1..=`MAX_ORDER`, in order. The score is a
    /// percentage, so `u8` is lossless and keeps the snapshot small.
    scores: [u8; MAX_ORDER],
}

impl ZoneFrag {
    const EMPTY: Self = Self {
        stats: ZoneStats::empty(),
        scores: [0; MAX_ORDER],
    };
}

/// Sample the zone counters plus their fragmentation scores under one lock hold.
///
/// `fragmentation_score` needs the live `Zone`, so the scores can only be read
/// here; they are copied out as plain numbers and formatted after the lock is
/// released, because formatting allocates.
fn sample_buddy_zones() -> Result<(usize, [ZoneFrag; ZONE_CAP]), ShellError> {
    with_allocator(|allocator| {
        let mut stats = [ZoneStats::empty(); ZONE_CAP];
        let count = allocator.zone_snapshot(&mut stats);
        let mut zones = [ZoneFrag::EMPTY; ZONE_CAP];
        for (idx, (zone, info)) in zones.iter_mut().zip(stats.iter()).take(count).enumerate() {
            zone.stats = *info;
            for (i, score) in zone.scores.iter_mut().enumerate() {
                *score = u8::try_from(
                    allocator
                        .get_zone(idx)
                        .fragmentation_score((i + 1) as u8, info.cached_pages),
                )
                .unwrap_or(u8::MAX);
            }
        }
        (count, zones)
    })
}

/// Summary view (default for `mem` with no subcommand).
fn cmd_mem_summary() -> Result<(), ShellError> {
    let (total_pages, allocated_pages, reserved_pages, cached_pages, pressured_zones) =
        with_allocator(|allocator| {
            let (total_pages, allocated_pages) = allocator.page_totals();
            let mut zones = [ZoneStats::empty(); ZONE_CAP];
            let count = allocator.zone_snapshot(&mut zones);
            let reserved_pages = zones
                .iter()
                .take(count)
                .map(|zone| zone.reserved_pages)
                .sum::<usize>();
            let cached_pages = zones
                .iter()
                .take(count)
                .map(|zone| zone.cached_pages)
                .sum::<usize>();
            let pressured_zones = zones
                .iter()
                .take(count)
                .filter(|zone| zone.pressure() != ZonePressure::Healthy)
                .count();
            (
                total_pages,
                allocated_pages,
                reserved_pages,
                cached_pages,
                pressured_zones,
            )
        })?;

    let free_pages = total_pages.saturating_sub(allocated_pages);

    shell_println!("Memory status:");
    shell_println!(
        "  Total:     {} ({} pages)",
        human_bytes(page_bytes(total_pages)),
        total_pages
    );
    shell_println!(
        "  Used:      {} ({} pages)",
        human_bytes(page_bytes(allocated_pages)),
        allocated_pages
    );
    shell_println!(
        "  Free:      {} ({} pages)",
        human_bytes(page_bytes(free_pages)),
        free_pages
    );
    shell_println!(
        "  Reserved:  {} ({} pages)",
        human_bytes(page_bytes(reserved_pages)),
        reserved_pages
    );
    shell_println!(
        "  Cached:    {} ({} pages)",
        human_bytes(page_bytes(cached_pages)),
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
    let (count, zones) = with_allocator(|allocator| {
        let mut zones = [ZoneStats::empty(); ZONE_CAP];
        let count = allocator.zone_snapshot(&mut zones);
        (count, zones)
    })?;

    shell_println!("Memory zones:");
    for info in zones.iter().take(count) {
        print_zone_lines(info);
    }

    Ok(())
}

/// Diagnostic view: poison quarantine, buddy failures, slab health.
fn cmd_mem_diag() -> Result<(), ShellError> {
    // Poison quarantine
    let quarantine = crate::memory::poison_quarantine_pages_snapshot();
    shell_println!("Poison quarantine:");
    shell_println!(
        "  Quarantined pages: {} ({})",
        quarantine,
        human_bytes(page_bytes(quarantine))
    );
    shell_println!("");

    // Buddy allocation failures
    let fail_counts = crate::memory::buddy::buddy_alloc_fail_counts_snapshot();
    if fail_counts.iter().any(|&count| count > 0) {
        shell_println!("Buddy allocation failures (by order):");
        for (order, &count) in fail_counts.iter().enumerate() {
            if count > 0 {
                shell_println!(
                    "  order {:>2} ({}): {} failures",
                    order,
                    human_bytes(order_bytes(order)),
                    count
                );
            }
        }
    } else {
        shell_println!("Buddy allocation failures: none");
    }
    shell_println!("");

    // Buddy zone policy / fragmentation view
    let (zone_count, zones) = sample_buddy_zones()?;
    shell_println!("Buddy zones:");
    for zone in zones.iter().take(zone_count) {
        shell_println!("{}", zone_diag_line(&zone.stats));
        shell_println!("    frag/order: {}", format_frag_scores(&zone.scores));
    }
    shell_println!("");

    // Slab allocator
    let slab = crate::memory::heap::slab_diag_snapshot();
    shell_println!("Slab allocator:");
    shell_println!(
        "  Pages allocated:  {} ({})",
        slab.pages_allocated,
        human_bytes(page_bytes(slab.pages_allocated))
    );
    shell_println!(
        "  Pages reclaimed:  {} ({})",
        slab.pages_reclaimed,
        human_bytes(page_bytes(slab.pages_reclaimed))
    );
    shell_println!(
        "  Pages live:       {} ({})",
        slab.pages_live,
        human_bytes(page_bytes(slab.pages_live))
    );
    shell_println!("");

    // Last heap failure
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

    // Slab size classes
    shell_println!("Slab size classes:");
    for ci in 0..crate::memory::heap::SLAB_NUM_CLASSES {
        shell_println!(
            "{}",
            slab_class_line(
                ci,
                crate::memory::heap::slab_class_size(ci),
                crate::memory::heap::slab_blocks_per_page(ci),
            )
        );
    }

    Ok(())
}
