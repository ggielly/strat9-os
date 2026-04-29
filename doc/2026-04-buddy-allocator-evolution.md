# Strat9-OS memory allocator evolution - April 2026

Technical notes for the April 2026 engineering update.

## Overview

This month of april, the Strat9-OS physical memory allocator went through a substantial redesign. The work started as a narrow debugging exercise around VMware-specific freezes and ended as a broader allocator hardening effort covering topology, boot-time safety, accounting, fragmentation control, diagnostics, and the first compaction-oriented policies.

The end result is not just a buddy allocator that "works on QEMU". It is now much closer to the design principles used by mature kernels:

- zones are modeled as segmented contiguous extents instead of one holey span;
- allocator metadata is reserved only from memory that is actually reachable at the current boot stage;
- diagnostics distinguish present, managed, reserved, cached, and fragmented memory;
- order-0 fast paths are per-CPU and split by migratetype;
- movable allocations are biased toward high memory;
- pageblocks now carry migratetype grouping state to prepare for future compaction work.

This post documents the evolution step by step, the reasoning behind each change, and the concrete implementation choices made in Strat9-OS.

## Initial symptoms

The allocator work began with two practical symptoms:

1. A few correctness issues in `buddy.rs`, including a duplicated seeding path and an invalid alignment call.
2. A more serious runtime issue: the kernel booted under QEMU but could freeze under VMware Workstation.

The VMware behavior was the real signal that the allocator design had structural problems. The issue was not just "one bad branch". It came from a combination of topology assumptions and early boot memory reachability.

The three main root causes were:

1. Each zone was treated as one large span even when the firmware memory map contained holes.
2. Some allocator metadata and boot-time state could be touched through the HHDM before the full RAM mapping was guaranteed to exist on VMware.
3. Free-range seeding was too optimistic in the original design and did not fully respect block-level constraints when encountering protected ranges.

That combination created a system that could appear correct under QEMU but fail on a stricter or differently ordered platform.

## Design goals

The redesign followed a few explicit goals:

- make the allocator topology reflect the actual firmware map instead of a simplified continuous model;
- make early boot reservations safe before `map_all_ram()` and before all RAM is reliably accessible through the higher-half direct map;
- separate low-level allocator policy from diagnostics so failures become observable, not speculative;
- move the design toward established practices used by production kernels without copying Linux complexity wholesale.

This last point mattered. The goal was not to turn Strat9-OS into a Linux clone. The goal was to borrow the ideas that have proven robust over time: zones, watermarks, reserves, per-CPU hot paths, anti-fragmentation grouping, and rich diagnostics.

## Phase 1: from holey zones to segmented zones

The first major change was the most important one architecturally.

Previously, a zone could behave like a single logical span even if the firmware map had multiple usable regions separated by reserved holes. That is fragile for a buddy allocator because buddy arithmetic assumes that the managed range for a given structure is internally coherent.

The fix was to move to segmented zones. Each zone now owns a dynamic array of contiguous `ZoneSegment` extents, and each segment has its own free lists and buddy parity bitmaps.

Short version of the segment structure:

```rust
pub struct ZoneSegment {
    pub base: PhysAddr,
    pub page_count: usize,
    pub free_lists: [[u64; MAX_ORDER + 1]; Migratetype::COUNT],
    pub buddy_bitmaps: [BuddyBitmap; MAX_ORDER + 1],
    pub pageblock_tags: *mut u8,
    pub pageblock_count: usize,
}
```

This solved a class of correctness issues at the root:

- buddy pairing is now evaluated only inside a contiguous segment;
- holes no longer silently participate in merge or split logic;
- diagnostics can accurately distinguish `spanned_pages` from `managed_pages`.

This mirrors a core idea described in Linux memory documentation: the physical memory model may span holes, but allocator-managed memory and accounting must distinguish present pages from spanned ranges and reserved pages rather than pretending everything is one flat continuous pool.

Reference:

- Linux kernel documentation, "Physical Memory": <https://docs.kernel.org/mm/physical_memory.html>

## Phase 2: boot-time reachability

The next critical hardening step was to stop assuming that every physical page was safely reachable through the HHDM during the allocator bootstrap.

In practice, the bug pattern looked like this:

- reserve metadata from memory that is technically free;
- access that memory via `phys_to_virt()`;
- discover later that the mapping is not yet globally valid on the current platform.

To fix this, boot-time allocator reservations were made explicitly accessibility-aware. Metadata pools and frame-management structures are now reserved only from memory known to be reachable at that phase of boot. The buddy allocator is initialized in place under the global lock after the relevant bootstrap state is known to be safe.

This is a good example of a rule that sounds trivial but is easy to violate in kernel code:

> During early boot, "free" is not the same thing as "safely dereferenceable through your chosen virtual mapping strategy".

That distinction was essential to eliminating the VMware freeze.

## Phase 3: safe seeding and protected ranges

The seeding logic was then tightened so that free memory is introduced into the buddy only when the candidate block is valid as a whole, not just because its first page looks legal.

The relevant logic now checks the entire candidate block before insertion:

```rust
let block_size = PAGE_SIZE << order;
let block_end = addr.saturating_add(block_size);

if Self::protected_overlap_end(addr, block_end).is_some() {
    order -= 1;
    continue;
}

let migratetype = Self::pageblock_migratetype(
    segment,
    addr,
    Self::default_pageblock_migratetype(zone_type),
);
Self::insert_free_block(segment, addr, order, migratetype);
```

This matters because protected boot modules, firmware-owned ranges, and allocator-reserved metadata must not enter the free lists in partial or misclassified form.

## Phase 4: richer zone accounting

Once the segmented design was in place, allocator accounting became much more explicit.

Instead of only tracking a rough page count, zones now track at least these separate notions:

- `present_pages`
- `managed_pages`
- `spanned_pages`
- `reserved_pages`
- `allocated_pages`
- `cached_pages`

That distinction appears in `ZoneStats` and in runtime diagnostics.

```rust
pub struct ZoneStats {
    pub managed_pages: usize,
    pub present_pages: usize,
    pub spanned_pages: usize,
    pub reserved_pages: usize,
    pub allocated_pages: usize,
    pub cached_pages: usize,
    pub pageblock_count: usize,
    pub largest_free_order: Option<u8>,
}
```

This was not just for pretty diagnostics. It enabled better policy decisions:

- watermark decisions can be based on effective free pages rather than raw managed capacity;
- hole pages become visible instead of being silently lost inside a large zone span;
- crash diagnostics can distinguish actual memory pressure from fragmentation or reservation pressure.

Again, this follows a documented best practice from the Linux side: `managed_pages`, `present_pages`, and `spanned_pages` each answer a different question and should not be collapsed into one metric.

Reference:

- Linux kernel documentation, zone accounting fields in "Physical Memory": <https://docs.kernel.org/mm/physical_memory.html>

## Phase 5: watermarks and lowmem reserves

After topology and accounting came policy.

Zones now expose a simple but useful pressure model based on:

- minimum watermark;
- low watermark;
- high watermark;
- low-memory reserve.

The allocator derives a `ZonePressure` state from those values:

```rust
pub enum ZonePressure {
    Healthy,
    High,
    Low,
    Min,
}
```

This is intentionally smaller than Linux reclaim machinery, but the principle is the same: allocator decisions should not look only at "is there at least one free block". They should understand whether a zone is already below healthy operating margins.

This becomes especially important in a kernel with separate low-memory constraints, because not all free memory is equally valuable. In Strat9-OS, `Normal` memory is still more precious for directly accessed kernel structures than `HighMem`.

Reference:

- Linux kernel documentation, zone watermarks and `lowmem_reserve`: <https://docs.kernel.org/mm/physical_memory.html>

## Phase 6: migratetypes and purpose-driven allocation

The allocator was then taught to distinguish allocation intent, not just allocation size.

Two migratetypes were introduced as a minimal anti-fragmentation model:

- `Unmovable`
- `Movable`

This is intentionally much smaller than Linux's full matrix, but it is enough to create a clean separation between pinned kernel data and memory that is a future candidate for migration or compaction.

Purpose-based frame allocation now maps user frames into the movable class:

```rust
match purpose {
    FramePurpose::UserData => {
        frame_flags::USER | frame_flags::ALLOCATED | frame_flags::MOVABLE
    }
    _ => { /* kernel-oriented flags */ }
}
```

And the public API gained helpers that expose that policy clearly:

- `allocate_frame_for_purpose(...)`
- `allocate_user_frame(...)`

This matters because fragmentation control is not a property you can bolt on at free time only. It has to begin when allocations are classified.

## Phase 7: zone preference using mobility class

Once movable and unmovable allocations existed, the allocator began scanning zones differently depending on the request type.

Unmovable allocations still prefer `Normal` first, because those pages are likely to be touched directly by the kernel.

Movable allocations now prefer `HighMem` first, preserving scarce lower memory for pinned structures and emergency paths.

```rust
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
```

This is a strategic change, not just a micro-optimization. It means the allocator actively protects low memory instead of consuming it opportunistically.

## Phase 8: Per-CPU order-0 caches split by Migratetype

High-frequency single-page traffic should not always hit the global allocator lock. That led to the next step: order-0 per-CPU caches, split by migratetype.

The allocator already had a hot path for order-0 pages. The redesign made it explicitly class-aware, so a CPU can satisfy frequent single-page requests locally while preserving mobility classification.

The implementation keeps separate caches per CPU and per migratetype, with batch refill and spill behavior.

This follows a very common production-kernel pattern. Linux documents the same principle clearly: the allocator first serves frequent requests from per-CPU pagesets and only falls back to the global buddy when needed.

Reference:

- Linux kernel documentation, Per-CPU Pagesets and two-step allocation strategy: <https://docs.kernel.org/mm/physical_memory.html>

## Phase 9: fragmentation telemetry

Before implementing more policy, the allocator needed to become measurable.

That led to per-order fragmentation telemetry. The guiding question is simple:

> If a zone has free memory, how much of that free memory is actually usable for a request of order `n`?

The score is computed from the fraction of free pages trapped below a target order, with cached order-0 pages included as fragments:

```rust
pub fn fragmentation_score(&self, order: u8, cached_order0_pages: usize) -> usize {
    if order == 0 {
        return 0;
    }

    let total_free = self.available_pages().saturating_add(cached_order0_pages);
    let usable = self.free_pages_at_or_above_order(order);
    let fragmented = total_free.saturating_sub(usable);
    fragmented.saturating_mul(100) / total_free
}
```

This metric was wired into:

- `mem diag`
- `heap diag`
- crash dump output

That changed debugging quality significantly. Instead of seeing only "allocation failed", we can now answer:

- was the zone genuinely out of free pages?
- was memory available but trapped below the requested order?
- how many pages were parked in per-CPU caches?

## Phase 10: pageblock grouping

The next major step toward compaction-readiness was pageblock grouping.

Strat9-OS now tracks migratetype tags per pageblock, with a pageblock order of 9, ანუ 2 MiB. This is a pragmatic choice because it aligns with a common huge-page granularity and gives the allocator a coarser grouping unit for anti-fragmentation policy.

The constants are explicit:

```rust
pub const PAGEBLOCK_ORDER: usize = 9;
pub const PAGEBLOCK_PAGES: usize = 1 << PAGEBLOCK_ORDER;
```

Each segment owns its pageblock tag array. Allocation and free paths use those tags to keep free memory grouped by mobility class over time.

Two key rules were introduced:

1. Movable allocations retag the pageblocks they consume.
2. Freed blocks re-enter the buddy according to the current pageblock class, not just the freeing block's historical class.

That produces a very important long-term effect: once a region trends movable, subsequent frees tend to reinforce that grouping instead of re-randomizing the free lists.

This idea is directly aligned with the anti-fragmentation direction used by Linux pageblocks and migratetypes, even though Strat9-OS currently implements a much smaller policy surface.

Reference:

- Linux kernel documentation, `pageblock_flags`, migratetype-aware compaction fields, and `ZONE_MOVABLE`: <https://docs.kernel.org/mm/physical_memory.html>

## Phase 11: compaction-assisted retry without full migration

The most recent allocator policy change adds a first compaction-oriented retry path, without yet implementing full page migration.

When a higher-order allocation fails, the allocator now checks whether the failure looks like recoverable fragmentation rather than true exhaustion. If the signal is strong enough, it:

1. identifies the most promising zone;
2. estimates a targeted drain budget;
3. drains order-0 pages from local CPU caches for that zone first;
4. retries the allocation;
5. records compaction-assist telemetry.

The threshold is intentionally explicit and easy to tune:

```rust
const COMPACTION_FRAGMENTATION_THRESHOLD: usize = 35;
```

And the allocator records the last assist attempt in a compact telemetry structure:

```rust
pub struct CompactionStats {
    pub attempts: usize,
    pub successes: usize,
    pub last_order: Option<u8>,
    pub last_zone: Option<ZoneType>,
    pub last_fragmentation_score: usize,
    pub last_drained_pages: usize,
}
```

This is not a full compaction engine yet. No pages are migrated. No reclaim daemon is running. But it is a meaningful step because the allocator now distinguishes between:

- "there is no memory left";
- "there is memory left, but it is fragmented or cached in the wrong place".

That distinction is exactly what unlocks the next stage of design.

## Diagnostics and crash analysis

A large part of this month's work was about observability.

The allocator now exposes much richer runtime and fault-time information:

- zone pressure state;
- free and cached pages split by migratetype;
- pageblock counts per class;
- largest free order;
- fragmentation scores by order;
- buddy allocation failure counters;
- poison quarantine pages;
- the last compaction-assist attempt.

The crash dump now prints allocator state that is actionable during a page fault instead of just dumping totals. That is extremely useful when debugging subtle boot or VM issues, because allocator state often explains secondary failures that would otherwise look unrelated.

## Why this better

A memory allocator can be "correct enough" on one hypervisor and still be architecturally weak.

This month’s changes improved three things at the same time:

1. Correctness.
   The segmented design and reachability-aware bootstrap removed an entire class of invalid assumptions.

2. Resilience.
   Watermarks, reserves, migratetypes, and pageblocks provide structure for future reclaim and compaction work.

3. Debuggability.
   The allocator can now explain its own failures in a much more useful way.

That combination is usually what turns a hobby-style allocator into a kernel subsystem that can keep evolving safely.

## What comes next now

1. a true migration or reclaim path driven by pageblock grouping and fragmentation scores;
2. compaction heuristics that consider repeated failure history instead of a single snapshot;
3. optional background pressure handling once the VM policy side of the kernel matures;
4. more stress testing under VMware and real hardware for high-order allocation churn.

## References

The design was informed by public documentation and widely accepted allocator practices, especially around zone accounting, watermark-based pressure, per-CPU fast paths, and anti-fragmentation grouping.

- Linux kernel documentation, "Physical Memory"  
  <https://docs.kernel.org/mm/physical_memory.html>

- Linux kernel documentation, "Page Allocation"  
  <https://www.kernel.org/doc/html/latest/mm/page_allocation.html>

- OSDev Wiki, "Page Frame Allocation"  
  <https://wiki.osdev.org/Page_Frame_Allocation>

These references were used as design guidance, not as a blueprint to duplicate wholesale. The Strat9-OS allocator remains intentionally smaller and simpler than Linux, but the direction is now aligned with techniques that have proven robust in real kernels.
