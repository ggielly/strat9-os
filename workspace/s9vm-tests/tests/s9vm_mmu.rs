/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! L2: s9vm second-level translation (real kernel code, host memory).

extern crate alloc;

use std::collections::HashMap;

#[path = "../../kernel/src/s9vm/memmap.rs"]
mod memmap;

#[path = "../../kernel/src/s9vm/mmu.rs"]
mod mmu;

use memmap::{
    contiguous_2m_aligned, plan_map, GuestMap, MapError, MapSegment, PageSize, LARGE_PAGE_FRAMES,
    LARGE_PAGE_SIZE,
};
use mmu::{
    encode_second_level_pointer, entry, MmuError, Perms, SecondLevel, TableMemory, PAGE_SIZE,
};

/// Host-memory table provider: each table is an array of
/// 512 entries, identified by a synthetic physical integer.
struct HostTables {
    tables: HashMap<u64, [u64; 512]>,
    next: u64,
    limit: usize,
    allocations: usize,
}

impl HostTables {
    fn new() -> Self {
        Self {
            tables: HashMap::new(),
            next: 0x1000,
            limit: usize::MAX,
            allocations: 0,
        }
    }

    fn with_limit(limit: usize) -> Self {
        let mut tables = Self::new();
        tables.limit = limit;
        tables
    }
}

impl TableMemory for HostTables {
    fn alloc_table(&mut self) -> Option<u64> {
        if self.allocations >= self.limit {
            return None;
        }
        let id = self.next;
        self.next += PAGE_SIZE;
        self.tables.insert(id, [0u64; 512]);
        self.allocations += 1;
        Some(id)
    }

    fn free_table(&mut self, table: u64) {
        self.tables.remove(&table);
    }

    fn read_entry(&self, table: u64, index: usize) -> u64 {
        self.tables
            .get(&table)
            .map(|entries| entries[index])
            .unwrap_or(0)
    }

    fn write_entry(&mut self, table: u64, index: usize, value: u64) {
        self.tables.entry(table).or_insert([0u64; 512])[index] = value;
    }
}

#[test]
fn allocates_root() {
    let mut memory = HostTables::new();
    let table = SecondLevel::new(&mut memory).expect("root allocation");
    assert_eq!(table.root_phys(), 0x1000);
    assert_eq!(memory.allocations, 1);
}

#[test]
fn maps_and_translates_four_kib_pages() {
    let mut memory = HostTables::new();
    let table = SecondLevel::new(&mut memory).expect("root");
    table
        .map_4k(
            &mut memory,
            0x10_0000,
            0x20_0000,
            3 * PAGE_SIZE,
            Perms::read_write_execute(),
        )
        .expect("map");

    assert_eq!(table.translate(&memory, 0x10_0000), Some(0x20_0000));
    assert_eq!(
        table.translate(&memory, 0x10_0000 + PAGE_SIZE),
        Some(0x20_1000)
    );
    assert_eq!(table.translate(&memory, 0x10_2000), Some(0x20_2000));
    assert_eq!(table.translate(&memory, 0x11_0000), None);
    // Beyond the mapped range.
    assert_eq!(table.translate(&memory, 0x10_0000 + 3 * PAGE_SIZE), None);
}

#[test]
fn leaf_entries_carry_permissions_and_memory_type() {
    let mut memory = HostTables::new();
    let table = SecondLevel::new(&mut memory).expect("root");
    table
        .map_4k(&mut memory, 0x0, 0x1000, PAGE_SIZE, Perms::read_execute())
        .expect("map");

    // Finds the leaf by walking the tables.
    let leaf = find_leaf(&memory, table.root_phys(), 0x0);
    assert_eq!(leaf & entry::READ, entry::READ);
    assert_eq!(leaf & entry::WRITE, 0);
    assert_eq!(leaf & entry::EXECUTE, entry::EXECUTE);
    assert_eq!(leaf & entry::MEMTYPE_WB, entry::MEMTYPE_WB);
    assert_eq!(leaf & entry::ADDR_MASK, 0x1000);
}

#[test]
fn rejects_misaligned_ranges() {
    let mut memory = HostTables::new();
    let table = SecondLevel::new(&mut memory).expect("root");
    assert_eq!(
        table.map_4k(&mut memory, 0x1001, 0x2000, PAGE_SIZE, Perms::read_write()),
        Err(MmuError::InvalidRange)
    );
    assert_eq!(
        table.map_4k(&mut memory, 0x1000, 0x2000, 12, Perms::read_write()),
        Err(MmuError::InvalidRange)
    );
    assert_eq!(
        table.map_2m(
            &mut memory,
            0x10_0000 + 0x1000,
            0x20_0000,
            0x20_0000,
            Perms::read_write()
        ),
        Err(MmuError::Misaligned)
    );
}

#[test]
fn maps_large_pages_with_page_size_bit() {
    let mut memory = HostTables::new();
    let table = SecondLevel::new(&mut memory).expect("root");
    table
        .map_2m(
            &mut memory,
            0x4000_0000,
            0x8000_0000,
            2 * entry::LARGE_2MB,
            Perms::read_write(),
        )
        .expect("map 2m");

    assert_eq!(table.translate(&memory, 0x4000_0000), Some(0x8000_0000));
    assert_eq!(
        table.translate(&memory, 0x4000_0000 + 0x1F_FFFF),
        Some(0x801F_FFFF)
    );
    assert_eq!(table.translate(&memory, 0x4020_0000), Some(0x8020_0000));
    assert_eq!(table.translate(&memory, 0x4040_0000), None);

    let leaf = find_pd_entry(&memory, table.root_phys(), 0x4000_0000);
    assert_eq!(leaf & entry::LARGE_PAGE, entry::LARGE_PAGE);
    assert_eq!(leaf & entry::MEMTYPE_WB, entry::MEMTYPE_WB);
}

#[test]
fn unmaps_leaf_entries() {
    let mut memory = HostTables::new();
    let table = SecondLevel::new(&mut memory).expect("root");
    table
        .map_4k(
            &mut memory,
            0x3000,
            0x4000,
            2 * PAGE_SIZE,
            Perms::read_write(),
        )
        .expect("map");
    assert!(table.unmap_4k(&mut memory, 0x3000));
    assert_eq!(table.translate(&memory, 0x3000), None);
    assert_eq!(table.translate(&memory, 0x4000), Some(0x5000));
    // Second unmap: no leaf anymore.
    assert!(!table.unmap_4k(&mut memory, 0x3000));
}

#[test]
fn reports_out_of_memory_without_leaking_partial_state() {
    // Root + PDPT + PD + PT = 4 tables for a 4 KiB mapping.
    let mut memory = HostTables::with_limit(2);
    let table = SecondLevel::new(&mut memory).expect("root");
    // The third allocation (PD) must fail.
    assert_eq!(
        table.map_4k(&mut memory, 0x1000, 0x2000, PAGE_SIZE, Perms::read_write()),
        Err(MmuError::OutOfMemory)
    );
    assert_eq!(memory.allocations, 2);
    assert_eq!(table.translate(&memory, 0x1000), None);
}

#[test]
fn detects_conflicting_mappings() {
    let mut memory = HostTables::new();
    let table = SecondLevel::new(&mut memory).expect("root");
    table
        .map_4k(&mut memory, 0x1000, 0x2000, PAGE_SIZE, Perms::read_write())
        .expect("first");
    assert_eq!(
        table.map_4k(&mut memory, 0x1000, 0x9000, PAGE_SIZE, Perms::read_write()),
        Err(MmuError::Conflict)
    );
}

#[test]
fn encodes_second_level_pointer() {
    let root = 0xDEAD_0000u64;
    let value = encode_second_level_pointer(root, 6, true, false);
    assert_eq!(value & 0x7, 6);
    assert_eq!((value >> 3) & 0x7, 3);
    assert_eq!(value & (1 << 6), 0);
    assert_eq!(value & entry::ADDR_MASK, root);

    let with_ad = encode_second_level_pointer(root, 6, true, true);
    assert_ne!(with_ad & (1 << 6), 0);
}

/// Finds the leaf entry (PT level) for a GPA, for inspection.
fn find_leaf(memory: &HostTables, root: u64, gpa: u64) -> u64 {
    let pml4 = memory.read_entry(root, ((gpa >> 39) & 0x1FF) as usize);
    let pdpt = memory.read_entry(pml4 & entry::ADDR_MASK, ((gpa >> 30) & 0x1FF) as usize);
    let pd = memory.read_entry(pdpt & entry::ADDR_MASK, ((gpa >> 21) & 0x1FF) as usize);
    let pt = memory.read_entry(pd & entry::ADDR_MASK, ((gpa >> 12) & 0x1FF) as usize);
    pt
}

/// Finds the PD-level entry for a GPA (2 MiB page).
fn find_pd_entry(memory: &HostTables, root: u64, gpa: u64) -> u64 {
    let pml4 = memory.read_entry(root, ((gpa >> 39) & 0x1FF) as usize);
    let pdpt = memory.read_entry(pml4 & entry::ADDR_MASK, ((gpa >> 30) & 0x1FF) as usize);
    memory.read_entry(pdpt & entry::ADDR_MASK, ((gpa >> 21) & 0x1FF) as usize)
}

// ---------------------------------------------------------------------------
// 2 MiB mapping plan (`memmap::plan_map`)
// ---------------------------------------------------------------------------

#[test]
fn plan_aligned_range_uses_2m_segments() {
    // 4 MiB = two 2 MiB leaves.
    let plan = plan_map(0x4000_0000, 2 * LARGE_PAGE_SIZE).expect("plan");
    assert_eq!(plan.len(), 2);
    for (index, segment) in plan.iter().enumerate() {
        assert_eq!(segment.page_size, PageSize::Page2M);
        assert_eq!(segment.len, LARGE_PAGE_SIZE);
        assert_eq!(segment.gpa, 0x4000_0000 + index as u64 * LARGE_PAGE_SIZE);
        assert_eq!(segment.pages(), 512);
        assert!(segment.is_large());
    }
    assert_eq!(
        plan.iter().map(|segment| segment.pages()).sum::<u64>(),
        1024
    );
}

#[test]
fn plan_unaligned_range_keeps_4k_head_and_tail() {
    let gpa = 0x4000_1000;
    let len = 6 * 1024 * 1024;
    let plan = plan_map(gpa, len).expect("plan");
    assert_eq!(plan.len(), 4);
    assert_eq!(plan[0].page_size, PageSize::Page4K);
    assert_eq!(plan[0].gpa, gpa);
    assert_eq!(plan[0].len, LARGE_PAGE_SIZE - PAGE_SIZE);
    assert_eq!(plan[1].page_size, PageSize::Page2M);
    assert_eq!(plan[2].page_size, PageSize::Page2M);
    assert_eq!(plan[3].page_size, PageSize::Page4K);
    assert_eq!(plan[3].len, PAGE_SIZE);
    assert_eq!(plan[0].gpa, gpa);
    assert_eq!(plan.last().expect("tail").end(), gpa + len);
    // The plan is a contiguous partition of the range.
    for pair in plan.windows(2) {
        assert_eq!(pair[0].end(), pair[1].gpa);
    }
}

#[test]
fn plan_small_range_is_one_4k_segment() {
    let plan = plan_map(0x123000, 3 * PAGE_SIZE).expect("plan");
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].page_size, PageSize::Page4K);
    assert_eq!(plan[0].len, 3 * PAGE_SIZE);
    assert_eq!(plan[0].pages(), 3);
}

#[test]
fn plan_never_mixes_granularity_inside_a_2m_region() {
    let gpa = 0x4000_1000;
    let len = 6 * 1024 * 1024;
    let plan = plan_map(gpa, len).expect("plan");
    let window = |address: u64| address & !(LARGE_PAGE_SIZE - 1);
    for segment in &plan {
        match segment.page_size {
            PageSize::Page2M => {
                assert_eq!(segment.gpa % LARGE_PAGE_SIZE, 0);
                assert_eq!(segment.len % LARGE_PAGE_SIZE, 0);
            }
            PageSize::Page4K => {
                // A 4 KiB segment must stay inside a single 2 MiB window.
                assert_eq!(window(segment.gpa), window(segment.end() - 1));
            }
        }
    }
    // No 2 MiB window contains both granularities.
    for segment in plan.iter().filter(|segment| segment.is_large()) {
        for other in &plan {
            if other.page_size == PageSize::Page4K {
                let overlap = other.gpa < segment.end() && segment.gpa < other.end();
                assert!(!overlap, "4 KiB segment overlaps a 2 MiB leaf");
            }
        }
    }
}

#[test]
fn plan_rejects_invalid_ranges() {
    assert_eq!(plan_map(0x1000, 0), Err(MapError::InvalidRange));
    assert_eq!(plan_map(0x1001, PAGE_SIZE), Err(MapError::InvalidRange));
    assert_eq!(plan_map(0x1000, PAGE_SIZE + 1), Err(MapError::InvalidRange));
    assert_eq!(
        plan_map((1u64 << 48) - PAGE_SIZE, 2 * PAGE_SIZE),
        Err(MapError::InvalidRange)
    );
}

#[test]
fn reserve_with_plan_enforces_quota_in_4k_pages() {
    let mut guest = GuestMap::new(1024);
    let (_, plan) = guest
        .reserve_with_plan(0x4000_0000, 2 * LARGE_PAGE_SIZE, 3, 0)
        .expect("reserve 4 MiB");
    assert_eq!(plan.len(), 2);
    assert_eq!(guest.pages(), 1024);
    assert_eq!(guest.region_count(), 1);

    let mut too_small = GuestMap::new(1023);
    assert_eq!(
        too_small.reserve_with_plan(0x4000_0000, 2 * LARGE_PAGE_SIZE, 3, 0),
        Err(MapError::QuotaExceeded)
    );
    assert_eq!(too_small.pages(), 0);
    assert_eq!(too_small.region_count(), 0);

    // 4 MiB + one 4 KiB page needs 1025 pages.
    let mut guest = GuestMap::new(1024);
    assert_eq!(
        guest.reserve_with_plan(0x4000_0000, 2 * LARGE_PAGE_SIZE + PAGE_SIZE, 3, 0),
        Err(MapError::QuotaExceeded)
    );
}

// ---------------------------------------------------------------------------
// 2 MiB leaves in the built tables (`mmu::SecondLevel::map_2m_leaf`)
// ---------------------------------------------------------------------------

#[test]
fn installs_2m_leaves_for_aligned_range() {
    let mut memory = HostTables::new();
    let table = SecondLevel::new(&mut memory).expect("root");
    for index in 0..2u64 {
        table
            .map_2m_leaf(
                &mut memory,
                0x4000_0000 + index * LARGE_PAGE_SIZE,
                0x8000_0000 + index * LARGE_PAGE_SIZE,
                Perms::read_write_execute(),
            )
            .expect("map 2m leaf");
    }
    // Root + PDPT + PD: no PT table is allocated for large leaves.
    assert_eq!(memory.allocations, 3);
    assert_eq!(table.translate(&memory, 0x4000_0000), Some(0x8000_0000));
    assert_eq!(
        table.translate(&memory, 0x4000_0000 + LARGE_PAGE_SIZE - 1),
        Some(0x801F_FFFF)
    );
    assert_eq!(table.translate(&memory, 0x4020_0000), Some(0x8020_0000));
    assert_eq!(table.translate(&memory, 0x4040_0000 - 1), Some(0x803F_FFFF));
    assert_eq!(table.translate(&memory, 0x4040_0000), None);
    let leaf = find_pd_entry(&memory, table.root_phys(), 0x4020_0000);
    assert_eq!(leaf & entry::LARGE_PAGE, entry::LARGE_PAGE);
    assert_eq!(leaf & entry::MEMTYPE_WB, entry::MEMTYPE_WB);
    assert_eq!(leaf & entry::READ, entry::READ);
    assert_eq!(leaf & entry::WRITE, entry::WRITE);
    assert_eq!(find_leaf(&memory, table.root_phys(), 0x4000_0000), 0);
}

#[test]
fn mixed_range_maps_4k_edges_and_2m_middle() {
    let mut memory = HostTables::new();
    let table = SecondLevel::new(&mut memory).expect("root");
    let gpa = 0x4000_1000;
    let head_len = LARGE_PAGE_SIZE - PAGE_SIZE;
    table
        .map_4k(&mut memory, gpa, 0x8000_1000, head_len, Perms::read_write())
        .expect("head 4k");
    table
        .map_2m_leaf(&mut memory, 0x4020_0000, 0x8020_0000, Perms::read_write())
        .expect("middle 2m");
    table
        .map_4k(
            &mut memory,
            0x4040_0000,
            0x8040_0000,
            PAGE_SIZE,
            Perms::read_write(),
        )
        .expect("tail 4k");

    // Head uses a PT leaf; the middle slot is a large leaf; the tail a PT leaf.
    assert_eq!(
        find_leaf(&memory, table.root_phys(), 0x4000_1000) & entry::LARGE_PAGE,
        0
    );
    assert_eq!(
        find_pd_entry(&memory, table.root_phys(), 0x4020_0000) & entry::LARGE_PAGE,
        entry::LARGE_PAGE
    );
    assert_eq!(
        find_leaf(&memory, table.root_phys(), 0x4040_0000) & entry::LARGE_PAGE,
        0
    );
    // Root + PDPT + PD + head PT + tail PT.
    assert_eq!(memory.allocations, 5);
}

#[test]
fn translate_covers_whole_mixed_range() {
    let mut memory = HostTables::new();
    let table = SecondLevel::new(&mut memory).expect("root");
    let gpa = 0x4000_1000;
    table
        .map_4k(
            &mut memory,
            gpa,
            0x8000_1000,
            LARGE_PAGE_SIZE - PAGE_SIZE,
            Perms::read_write(),
        )
        .expect("head");
    table
        .map_2m_leaf(&mut memory, 0x4020_0000, 0x8020_0000, Perms::read_write())
        .expect("middle");
    table
        .map_4k(
            &mut memory,
            0x4040_0000,
            0x8040_0000,
            PAGE_SIZE,
            Perms::read_write(),
        )
        .expect("tail");

    assert_eq!(table.translate(&memory, gpa), Some(0x8000_1000));
    assert_eq!(
        table.translate(&memory, gpa + PAGE_SIZE - 1),
        Some(0x8000_1FFF)
    );
    assert_eq!(
        table.translate(&memory, 0x4020_0000 + 0x1234),
        Some(0x8020_1234)
    );
    assert_eq!(table.translate(&memory, 0x403F_FFFF), Some(0x803F_FFFF));
    assert_eq!(table.translate(&memory, 0x4040_0000), Some(0x8040_0000));
    assert_eq!(table.translate(&memory, 0x4040_1000), None);
}

#[test]
fn map_2m_leaf_rejects_conflict_with_4k_entries() {
    let mut memory = HostTables::new();
    let table = SecondLevel::new(&mut memory).expect("root");
    table
        .map_4k(
            &mut memory,
            0x4000_1000,
            0x9000_1000,
            PAGE_SIZE,
            Perms::read_write(),
        )
        .expect("4k page");
    assert_eq!(
        table.map_2m_leaf(&mut memory, 0x4000_0000, 0x8000_0000, Perms::read_write()),
        Err(MmuError::Conflict)
    );
    // The existing 4 KiB mapping is untouched.
    assert_eq!(table.translate(&memory, 0x4000_1000), Some(0x9000_1000));
}

#[test]
fn map_4k_rejects_region_mapped_as_2m() {
    let mut memory = HostTables::new();
    let table = SecondLevel::new(&mut memory).expect("root");
    table
        .map_2m_leaf(&mut memory, 0x4000_0000, 0x8000_0000, Perms::read_write())
        .expect("2m leaf");
    // Walk-down must refuse to treat the large leaf as a PT table.
    assert_eq!(
        table.map_4k(
            &mut memory,
            0x4000_1000,
            0x9000_1000,
            PAGE_SIZE,
            Perms::read_write()
        ),
        Err(MmuError::Conflict)
    );
    assert_eq!(table.translate(&memory, 0x4000_1000), Some(0x8000_1000));
}

#[test]
fn map_2m_leaf_rejects_misalignment_and_overflow() {
    let mut memory = HostTables::new();
    let table = SecondLevel::new(&mut memory).expect("root");
    assert_eq!(
        table.map_2m_leaf(&mut memory, 0x4000_1000, 0x8000_0000, Perms::read_write()),
        Err(MmuError::Misaligned)
    );
    assert_eq!(
        table.map_2m_leaf(&mut memory, 0x4000_0000, 0x8000_1000, Perms::read_write()),
        Err(MmuError::Misaligned)
    );
    assert_eq!(
        table.map_2m_leaf(&mut memory, 1 << 48, 0x8000_0000, Perms::read_write()),
        Err(MmuError::InvalidRange)
    );
}

#[test]
fn unmap_rules_stay_coherent_for_large_pages() {
    let mut memory = HostTables::new();
    let table = SecondLevel::new(&mut memory).expect("root");
    table
        .map_2m_leaf(&mut memory, 0x4000_0000, 0x8000_0000, Perms::read_write())
        .expect("2m leaf");
    // A 4 KiB unmap must not tear down a 2 MiB leaf.
    assert!(!table.unmap_4k(&mut memory, 0x4000_0000));
    assert_eq!(table.translate(&memory, 0x4000_0000), Some(0x8000_0000));
    assert!(table.unmap_2m(&mut memory, 0x4000_0000));
    assert_eq!(table.translate(&memory, 0x4000_0000), None);
    assert!(!table.unmap_2m(&mut memory, 0x4000_0000));
    // After a full unmap the same 2 MiB slot can be remapped as 4 KiB.
    table
        .map_4k(
            &mut memory,
            0x4000_0000,
            0x9000_0000,
            PAGE_SIZE,
            Perms::read_write(),
        )
        .expect("4k after unmap");
    assert_eq!(table.translate(&memory, 0x4000_0000), Some(0x9000_0000));
}

#[test]
fn four_kib_mapping_behaviour_unchanged() {
    let mut memory = HostTables::new();
    let table = SecondLevel::new(&mut memory).expect("root");
    table
        .map_4k(
            &mut memory,
            0x10_0000,
            0x20_0000,
            3 * PAGE_SIZE,
            Perms::read_write(),
        )
        .expect("map 4k");
    assert_eq!(memory.allocations, 4);
    assert_eq!(table.translate(&memory, 0x10_0000), Some(0x20_0000));
    assert_eq!(table.translate(&memory, 0x10_1000), Some(0x20_1000));
    assert_eq!(table.translate(&memory, 0x10_3000), None);
    let plan = plan_map(0x10_0000, 3 * PAGE_SIZE).expect("plan");
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].page_size, PageSize::Page4K);
    let segment: MapSegment = plan[0];
    assert_eq!(segment.end(), 0x10_3000);
}

// ---------------------------------------------------------------------------
// Host-contiguity test for 2 MiB leaves (`memmap::contiguous_2m_aligned`)
// ---------------------------------------------------------------------------

/// Builds the host frame list of one aligned 2 MiB block.
fn aligned_block(base: u64) -> Vec<u64> {
    (0..LARGE_PAGE_FRAMES as u64)
        .map(|index| base + index * PAGE_SIZE)
        .collect()
}

#[test]
fn contiguity_accepts_aligned_block() {
    let frames = aligned_block(0x8000_0000);
    assert!(contiguous_2m_aligned(0x8000_0000, &frames));
}

#[test]
fn contiguity_accepts_frames_in_any_order() {
    let mut frames = aligned_block(0x8000_0000);
    frames.reverse();
    assert!(contiguous_2m_aligned(0x8000_0000, &frames));
    frames.swap(0, LARGE_PAGE_FRAMES - 1);
    assert!(contiguous_2m_aligned(0x8000_0000, &frames));
}

#[test]
fn contiguity_rejects_unaligned_base() {
    // A perfectly contiguous block whose base is only 4 KiB aligned cannot
    // back a 2 MiB leaf.
    let frames = aligned_block(0x8000_1000);
    assert!(!contiguous_2m_aligned(0x8000_1000, &frames));
}

#[test]
fn contiguity_rejects_out_of_block_frame() {
    let mut frames = aligned_block(0x8000_0000);
    // Point the last frame just past the 2 MiB block: simulates a hole.
    frames[LARGE_PAGE_FRAMES - 1] = 0x8020_0000;
    assert!(!contiguous_2m_aligned(0x8000_0000, &frames));
}

#[test]
fn contiguity_rejects_duplicate_frame() {
    let mut frames = aligned_block(0x8000_0000);
    frames[7] = frames[0];
    assert!(!contiguous_2m_aligned(0x8000_0000, &frames));
}

#[test]
fn contiguity_rejects_wrong_frame_count() {
    let frames = aligned_block(0x8000_0000);
    assert!(!contiguous_2m_aligned(
        0x8000_0000,
        &frames[..LARGE_PAGE_FRAMES - 1]
    ));
    assert!(!contiguous_2m_aligned(0x8000_0000, &[]));
}

#[test]
fn aligned_four_mib_reservation_installs_two_large_leaves() {
    let plan = plan_map(0x4000_0000, 2 * LARGE_PAGE_SIZE).expect("plan");
    assert_eq!(plan.len(), 2);
    let mut memory = HostTables::new();
    let table = SecondLevel::new(&mut memory).expect("root");
    for (index, segment) in plan.iter().enumerate() {
        assert!(segment.is_large());
        let hpa = 0x8000_0000 + index as u64 * LARGE_PAGE_SIZE;
        let frames = aligned_block(hpa);
        let base = *frames.iter().min().expect("non-empty");
        assert!(contiguous_2m_aligned(base, &frames));
        table
            .map_2m_leaf(&mut memory, segment.gpa, hpa, Perms::read_write_execute())
            .expect("large leaf");
    }
    // Root + PDPT + PD: both 2 MiB leaves live in the same PD.
    assert_eq!(memory.allocations, 3);
    assert_eq!(table.translate(&memory, 0x4000_0000), Some(0x8000_0000));
    assert_eq!(
        table.translate(&memory, 0x4000_0000 + LARGE_PAGE_SIZE - 1),
        Some(0x801F_FFFF)
    );
    assert_eq!(table.translate(&memory, 0x4020_0000), Some(0x8020_0000));
    assert_eq!(table.translate(&memory, 0x4040_0000 - 1), Some(0x803F_FFFF));
    assert_eq!(table.translate(&memory, 0x4040_0000), None);
    assert_eq!(
        find_pd_entry(&memory, table.root_phys(), 0x4000_0000) & entry::LARGE_PAGE,
        entry::LARGE_PAGE
    );
    assert_eq!(
        find_pd_entry(&memory, table.root_phys(), 0x4020_0000) & entry::LARGE_PAGE,
        entry::LARGE_PAGE
    );
}

#[test]
fn fragmented_host_falls_back_to_four_kib_pages() {
    // The allocator returned 512 consecutive frames, but the block starts at
    // a 4 KiB-aligned (not 2 MiB-aligned) HPA: a 2 MiB leaf cannot be used.
    let gpa = 0x4000_0000;
    let hpa = 0x8000_1000;
    let frames = aligned_block(hpa);
    let base = *frames.iter().min().expect("non-empty");
    assert!(!contiguous_2m_aligned(base, &frames));

    let mut memory = HostTables::new();
    let table = SecondLevel::new(&mut memory).expect("root");
    for (index, frame_hpa) in frames.iter().enumerate() {
        table
            .map_4k(
                &mut memory,
                gpa + index as u64 * PAGE_SIZE,
                *frame_hpa,
                PAGE_SIZE,
                Perms::read_write(),
            )
            .expect("4k fallback");
    }
    assert_eq!(memory.allocations, 4);
    assert_eq!(table.translate(&memory, gpa), Some(hpa));
    assert_eq!(
        table.translate(&memory, gpa + LARGE_PAGE_SIZE - 1),
        Some(hpa + LARGE_PAGE_SIZE - 1)
    );
    assert_eq!(
        find_pd_entry(&memory, table.root_phys(), gpa) & entry::LARGE_PAGE,
        0
    );
}

#[test]
fn unaligned_range_has_no_large_segments() {
    // A 2 MiB range that is not 2 MiB aligned is entirely head/tail: no large
    // leaf can be planned, so the mapper stays on 4 KiB pages.
    let plan = plan_map(0x4000_1000, LARGE_PAGE_SIZE).expect("plan");
    assert_eq!(plan.len(), 2);
    assert!(plan.iter().all(|segment| !segment.is_large()));
    assert_eq!(plan[0].len, LARGE_PAGE_SIZE - PAGE_SIZE);
    assert_eq!(plan[1].len, PAGE_SIZE);
}
