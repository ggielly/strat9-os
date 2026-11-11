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

//! L2: s9vm guest page tables for a 64-bit entry (real kernel code).
//!
//! The builder is exercised against an in-memory table provider: every table
//! page is 4 KiB of host memory and the handle is its guest-physical address,
//! exactly the contract the kernel's frame provider implements.

extern crate alloc;

#[path = "../../kernel/src/s9vm/mmu.rs"]
mod mmu;
#[path = "../../kernel/src/s9vm/guestpt.rs"]
mod guestpt;

use guestpt::{
    entry, index_of, phys_of, GuestPageTables, IdentityRange, PtError, PtPerms, ENTRY_COUNT,
    LARGE_1GB, LARGE_2MB, MAX_LINEAR, SHIFT_PD, SHIFT_PDPT, SHIFT_PML4, SHIFT_PT,
};
use mmu::{TableMemory, PAGE_SIZE};

/// Host-memory table provider: `pages` is a flat slice of 8-byte entries.
struct TestMemory {
    entries: Vec<u64>,
    next_frame: u64,
    allocated: usize,
    freed: usize,
    /// When true the allocator returns a misaligned handle.
    misalign: bool,
    /// Maximum number of allocations before returning `None`.
    budget: Option<usize>,
}

impl TestMemory {
    fn new() -> Self {
        Self {
            entries: vec![0u64; 1024 * ENTRY_COUNT],
            next_frame: 0x0010_0000,
            allocated: 0,
            freed: 0,
            misalign: false,
            budget: None,
        }
    }

    fn offset(table: u64, index: usize) -> usize {
        let base = (table / PAGE_SIZE) as usize * ENTRY_COUNT;
        base + index
    }
}

impl TableMemory for TestMemory {
    fn alloc_table(&mut self) -> Option<u64> {
        if let Some(budget) = self.budget {
            if self.allocated >= budget {
                return None;
            }
        }
        let frame = if self.misalign {
            self.next_frame + 1
        } else {
            self.next_frame
        };
        self.next_frame += PAGE_SIZE;
        self.allocated += 1;
        Some(frame)
    }

    fn free_table(&mut self, table: u64) {
        let base = (table / PAGE_SIZE) as usize;
        let end = (base + ENTRY_COUNT).min(self.entries.len());
        if base < end {
            for slot in &mut self.entries[base..end] {
                *slot = 0;
            }
            self.freed += 1;
        }
    }

    fn read_entry(&self, table: u64, index: usize) -> u64 {
        self.entries[TestMemory::offset(table, index)]
    }

    fn write_entry(&mut self, table: u64, index: usize, value: u64) {
        self.entries[TestMemory::offset(table, index)] = value;
    }
}

fn rwx(start: u64, len: u64) -> IdentityRange {
    IdentityRange::new(start, len, PtPerms::KERNEL_RWX)
}

#[test]
fn constants_are_the_four_level_architecture() {
    assert_eq!(ENTRY_COUNT, 512);
    assert_eq!(SHIFT_PML4, 39);
    assert_eq!(SHIFT_PDPT, 30);
    assert_eq!(SHIFT_PD, 21);
    assert_eq!(SHIFT_PT, 12);
    assert_eq!(LARGE_2MB, 2 * 1024 * 1024);
    assert_eq!(LARGE_1GB, 1024 * 1024 * 1024);
    assert_eq!(MAX_LINEAR, 1 << 48);
    assert_eq!(PAGE_SIZE, 4096);
    assert_eq!(entry::PRESENT, 1);
    assert_eq!(entry::WRITABLE, 2);
    assert_eq!(entry::LARGE_PAGE, 1 << 7);
    assert_eq!(entry::NO_EXECUTE, 1 << 63);
}

#[test]
fn index_and_phys_helpers_match_the_architecture() {
    assert_eq!(index_of(0, SHIFT_PT), 0);
    assert_eq!(index_of(PAGE_SIZE, SHIFT_PT), 1);
    assert_eq!(index_of(0x0000_0000_0080_0000, SHIFT_PD), 4);
    assert_eq!(index_of(0x0000_0040_0000_0000, SHIFT_PDPT), 256);
    assert_eq!(index_of(0x0000_0080_0000_0000, SHIFT_PML4), 1);
    // Only the physical address bits survive.
    assert_eq!(phys_of(0x8000_0000_0000_0000 | 0x1234_5000), 0x1234_5000);
}

#[test]
fn permissions_encode_present_write_user_and_no_execute() {
    let rwx = PtPerms::KERNEL_RWX;
    assert_eq!(rwx.leaf_bits() & entry::PRESENT, entry::PRESENT);
    assert_eq!(rwx.leaf_bits() & entry::WRITABLE, entry::WRITABLE);
    assert_eq!(rwx.leaf_bits() & entry::NO_EXECUTE, 0);
    assert_eq!(rwx.leaf_bits() & entry::USER, 0);

    let rw = PtPerms::KERNEL_RW;
    assert_eq!(rw.leaf_bits() & entry::WRITABLE, entry::WRITABLE);
    assert_eq!(rw.leaf_bits() & entry::NO_EXECUTE, entry::NO_EXECUTE);

    let ro = PtPerms::KERNEL_RO;
    assert_eq!(ro.leaf_bits() & entry::WRITABLE, 0);
    assert_eq!(ro.leaf_bits() & entry::NO_EXECUTE, entry::NO_EXECUTE);

    let user = PtPerms {
        writable: true,
        executable: true,
        user: true,
    };
    assert_eq!(user.leaf_bits() & entry::USER, entry::USER);
}

#[test]
fn identity_map_of_an_aligned_span_uses_large_pages() {
    let mut memory = TestMemory::new();
    let start = 0x0000_0000_0020_0000u64;
    let len = 16 * LARGE_2MB;
    let tables = GuestPageTables::build(&mut memory, &[rwx(start, len)]).unwrap();
    // PML4 + PDPT + PD: no page table is needed for a 2 MiB mapping.
    assert_eq!(tables.table_count(), 3);
    for address in [start, start + LARGE_2MB, start + len - PAGE_SIZE] {
        let (physical, leaf) = tables.translate(&memory, address).unwrap();
        assert_eq!(physical, address);
        assert_ne!(leaf & entry::LARGE_PAGE, 0);
        assert_ne!(leaf & entry::PRESENT, 0);
    }
}

#[test]
fn identity_map_translates_the_last_byte_of_the_span() {
    let mut memory = TestMemory::new();
    let start = 0x0000_0000_0000_0000u64;
    let len = 4 * LARGE_2MB;
    let tables = GuestPageTables::build(&mut memory, &[rwx(start, len)]).unwrap();
    let last = len - 1;
    let (physical, _) = tables.translate(&memory, last).unwrap();
    assert_eq!(physical, last);
}

#[test]
fn unaligned_ranges_use_small_pages() {
    let mut memory = TestMemory::new();
    let tables = GuestPageTables::build(&mut memory, &[rwx(0x1_0000, 0x3000)]).unwrap();
    for address in [0x1_0000u64, 0x1_1000, 0x1_2FFF] {
        let (physical, leaf) = tables.translate(&memory, address).unwrap();
        assert_eq!(physical, address);
        assert_eq!(leaf & entry::LARGE_PAGE, 0);
    }
}

#[test]
fn a_range_that_starts_below_a_large_page_boundary_maps_the_prefix_small() {
    let mut memory = TestMemory::new();
    let start = 0x0010_0000u64;
    let len = 0x0030_0000u64;
    let tables = GuestPageTables::build(&mut memory, &[rwx(start, len)]).unwrap();
    let (physical, prefix) = tables.translate(&memory, start).unwrap();
    assert_eq!(physical, start);
    assert_eq!(prefix & entry::LARGE_PAGE, 0);
    let (_, middle) = tables.translate(&memory, 0x0020_0000).unwrap();
    assert_ne!(middle & entry::LARGE_PAGE, 0);
    let (physical, tail) = tables.translate(&memory, start + len - 1).unwrap();
    assert_eq!(physical, start + len - 1);
    assert_ne!(tail & entry::LARGE_PAGE, 0);
}

#[test]
fn a_range_that_ends_below_a_large_page_boundary_maps_the_tail_small() {
    let mut memory = TestMemory::new();
    let start = 0x0020_0000u64;
    let len = LARGE_2MB + 0x1000;
    let tables = GuestPageTables::build(&mut memory, &[rwx(start, len)]).unwrap();
    let (_, head) = tables.translate(&memory, start).unwrap();
    assert_ne!(head & entry::LARGE_PAGE, 0);
    let (physical, tail) = tables.translate(&memory, start + len - 1).unwrap();
    assert_eq!(physical, start + len - 1);
    assert_eq!(tail & entry::LARGE_PAGE, 0);
}

#[test]
fn boot_parameter_range_is_writable_and_not_executable() {
    let mut memory = TestMemory::new();
    let tables = GuestPageTables::build(
        &mut memory,
        &[
            IdentityRange::new(0x1_0000, 0x1000, PtPerms::KERNEL_RW),
            IdentityRange::new(0x10_0000, 0x1000, PtPerms::KERNEL_RO),
        ],
    )
    .unwrap();
    let (physical, leaf) = tables.translate(&memory, 0x1_0000).unwrap();
    assert_eq!(physical, 0x1_0000);
    assert_eq!(leaf & entry::WRITABLE, entry::WRITABLE);
    assert_eq!(leaf & entry::NO_EXECUTE, entry::NO_EXECUTE);

    let (_, ro) = tables.translate(&memory, 0x10_0000).unwrap();
    assert_eq!(ro & entry::WRITABLE, 0);
}

#[test]
fn overlapping_ranges_are_rejected_and_frames_are_returned() {
    let mut memory = TestMemory::new();
    let result = GuestPageTables::build(
        &mut memory,
        &[
            IdentityRange::new(0x20_0000, LARGE_2MB, PtPerms::KERNEL_RWX),
            IdentityRange::new(0x20_0000, LARGE_2MB, PtPerms::KERNEL_RW),
        ],
    );
    assert_eq!(result.unwrap_err(), PtError::Conflict);
    assert_eq!(memory.freed, memory.allocated);
}

#[test]
fn empty_range_is_rejected() {
    let mut memory = TestMemory::new();
    let result = GuestPageTables::build(&mut memory, &[rwx(0, 0)]);
    assert_eq!(result.unwrap_err(), PtError::InvalidRange);
    assert_eq!(memory.allocated, 0);
}

#[test]
fn unaligned_start_is_rejected() {
    let mut memory = TestMemory::new();
    let result = GuestPageTables::build(&mut memory, &[rwx(0x1234, PAGE_SIZE)]);
    assert_eq!(result.unwrap_err(), PtError::InvalidRange);
}

#[test]
fn unaligned_length_is_rejected() {
    let mut memory = TestMemory::new();
    let result = GuestPageTables::build(&mut memory, &[rwx(0x1000, 0x1800)]);
    assert_eq!(result.unwrap_err(), PtError::InvalidRange);
}

#[test]
fn range_beyond_the_four_level_space_is_rejected() {
    let mut memory = TestMemory::new();
    let result = GuestPageTables::build(&mut memory, &[rwx(MAX_LINEAR - PAGE_SIZE, 2 * PAGE_SIZE)]);
    assert_eq!(result.unwrap_err(), PtError::InvalidRange);
}

#[test]
fn an_exhausted_provider_reports_out_of_memory_and_frees_what_it_took() {
    let mut memory = TestMemory::new();
    memory.budget = Some(2);
    let result = GuestPageTables::build(&mut memory, &[rwx(0x10_0000, 4 * LARGE_2MB)]);
    assert_eq!(result.unwrap_err(), PtError::OutOfMemory);
    assert_eq!(memory.freed, memory.allocated);
}

#[test]
fn a_misaligned_table_frame_is_rejected() {
    let mut memory = TestMemory::new();
    memory.misalign = true;
    let result = GuestPageTables::build(&mut memory, &[rwx(0x10_0000, 4 * LARGE_2MB)]);
    assert_eq!(result.unwrap_err(), PtError::BadTable);
}

#[test]
fn root_cr3_and_frames_are_consistent() {
    let mut memory = TestMemory::new();
    let tables = GuestPageTables::build(&mut memory, &[rwx(0x10_0000, LARGE_2MB)]).unwrap();
    assert_eq!(tables.root_phys(), tables.cr3());
    assert_eq!(tables.frames()[0], tables.root_phys());
    assert_eq!(tables.frames().len(), tables.table_count());
}

#[test]
fn release_returns_every_frame() {
    let mut memory = TestMemory::new();
    let tables = GuestPageTables::build(&mut memory, &[rwx(0x10_0000, 6 * LARGE_2MB)]).unwrap();
    let count = tables.table_count();
    assert!(count > 1);
    tables.release(&mut memory);
    assert_eq!(memory.freed, count);
}

#[test]
fn translate_reports_none_outside_the_mapped_ranges() {
    let mut memory = TestMemory::new();
    let tables = GuestPageTables::build(&mut memory, &[rwx(0x10_0000, LARGE_2MB)]).unwrap();
    assert!(tables.translate(&memory, 0x0FFF_FFFF).is_none());
    assert!(tables.translate(&memory, 0x0).is_none());
    assert!(tables.translate(&memory, 0x40_0000).is_none());
}

#[test]
fn high_guest_addresses_are_supported() {
    let mut memory = TestMemory::new();
    let start = 0x0000_0100_0000_0000u64;
    let tables = GuestPageTables::build(&mut memory, &[rwx(start, 4 * LARGE_2MB)]).unwrap();
    let (physical, _) = tables.translate(&memory, start + 0x1234).unwrap();
    assert_eq!(physical, start + 0x1234);
}

#[test]
fn ranges_inside_the_low_megabyte_are_supported() {
    let mut memory = TestMemory::new();
    let tables = GuestPageTables::build(
        &mut memory,
        &[
            IdentityRange::new(0, 0x9_F000, PtPerms::KERNEL_RWX),
            IdentityRange::new(0x9_F000, 0x1000, PtPerms::KERNEL_RO),
        ],
    )
    .unwrap();
    let (physical, _) = tables.translate(&memory, 0).unwrap();
    assert_eq!(physical, 0);
    let (physical, _) = tables.translate(&memory, 0x9_F000).unwrap();
    assert_eq!(physical, 0x9_F000);
}

#[test]
fn intermediate_tables_are_present_and_writable() {
    let mut memory = TestMemory::new();
    let tables = GuestPageTables::build(&mut memory, &[rwx(0x10_0000, LARGE_2MB)]).unwrap();
    let root = tables.root_phys();
    let pml4 = memory.read_entry(root, index_of(0x10_0000, SHIFT_PML4));
    assert_ne!(pml4 & entry::PRESENT, 0);
    assert_ne!(pml4 & entry::WRITABLE, 0);
    let pdpt = memory.read_entry(phys_of(pml4), index_of(0x10_0000, SHIFT_PDPT));
    assert_ne!(pdpt & entry::PRESENT, 0);
    assert_eq!(pdpt & entry::LARGE_PAGE, 0);
    let pd = memory.read_entry(phys_of(pdpt), index_of(0x10_0000, SHIFT_PD));
    assert_ne!(pd & entry::PRESENT, 0);
}

#[test]
fn a_two_megabyte_range_reuses_one_page_directory() {
    let mut memory = TestMemory::new();
    let tables = GuestPageTables::build(&mut memory, &[rwx(0x40_0000, 8 * LARGE_2MB)]).unwrap();
    // One PML4, one PDPT and one PD cover the whole span.
    assert_eq!(tables.table_count(), 3);
    let pd_frame = phys_of(memory.read_entry(
        phys_of(memory.read_entry(tables.root_phys(), 0)),
        0,
    ));
    let mut present = 0;
    for slot in 0..ENTRY_COUNT {
        if memory.read_entry(pd_frame, slot) & entry::PRESENT != 0 {
            present += 1;
        }
    }
    assert_eq!(present, 8);
}

#[test]
fn empty_range_list_builds_an_empty_root() {
    let mut memory = TestMemory::new();
    let tables = GuestPageTables::build(&mut memory, &[]).unwrap();
    assert_eq!(tables.table_count(), 1);
    assert!(tables.translate(&memory, 0).is_none());
}
