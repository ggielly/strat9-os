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

//! L2: guest-physical layout of a 64-bit boot-protocol guest (real kernel code).
//!
//! The planner is checked against the boot protocol contract: object placement,
//! non-overlap, identity coverage and the page-table reservation are validated
//! on the host, and one test builds the actual guest page tables from the
//! layout to prove the mapping is usable.

extern crate alloc;

#[path = "../../kernel/src/s9vm/mmu.rs"]
mod mmu;
#[path = "../../kernel/src/s9vm/guestpt.rs"]
mod guestpt;
#[path = "../../kernel/src/s9vm/linuxboot.rs"]
mod linuxboot;

use alloc::vec::Vec;

use guestpt::{GuestPageTables, PtPerms, ENTRY_COUNT};
use linuxboot::{
    align_up, page_table_budget, plan, LayoutError, LayoutRequest, BOOT_PARAMS_GPA,
    BOOT_GDT_GPA, BOOT_PARAMS_SIZE, CMDLINE_GPA, CMDLINE_MAX, HIGH_LOAD_BASE, INITRD_ALIGN, LOW_IDENTITY_END,
    LOW_MEMORY_END, PAGE_TABLES_GPA, STACK_GUARD_END, STACK_TOP,
};
use mmu::{TableMemory, PAGE_SIZE};

/// Host-memory table provider for the integration test.
struct TestMemory {
    entries: Vec<u64>,
    next_frame: u64,
}

impl TestMemory {
    fn new() -> Self {
        Self {
            entries: alloc::vec![0u64; 512 * ENTRY_COUNT],
            next_frame: 0x0010_0000,
        }
    }
}

impl TableMemory for TestMemory {
    fn alloc_table(&mut self) -> Option<u64> {
        let frame = self.next_frame;
        self.next_frame += PAGE_SIZE;
        Some(frame)
    }

    fn free_table(&mut self, _table: u64) {}

    fn read_entry(&self, table: u64, index: usize) -> u64 {
        let base = (table / PAGE_SIZE) as usize * ENTRY_COUNT;
        self.entries[base + index]
    }

    fn write_entry(&mut self, table: u64, index: usize, value: u64) {
        let base = (table / PAGE_SIZE) as usize * ENTRY_COUNT;
        self.entries[base + index] = value;
    }
}

fn request(ram_mb: u64) -> LayoutRequest {
    LayoutRequest {
        ram_bytes: ram_mb * 1024 * 1024,
        pref_address: 0x10_0000,
        kernel_alignment: 0x20_0000,
        init_size: 8 * 1024 * 1024,
        relocatable: true,
        initrd_bytes: 0,
        cmdline_len: 32,
    }
}

#[test]
fn typical_layout_places_every_object() {
    let layout = plan(&request(64)).unwrap();
    // A relocatable image with a 2 MiB alignment requirement: the preferred
    // address is 1 MiB, so the planner rounds it up to the next 2 MiB.
    assert_eq!(layout.kernel_base, 0x0020_0000);
    assert_eq!(layout.kernel_end, 0x0020_0000 + 8 * 1024 * 1024);
    assert_eq!(layout.boot_params_gpa, BOOT_PARAMS_GPA);
    assert_eq!(layout.gdt_gpa, BOOT_GDT_GPA);
    assert_eq!(layout.cmdline_gpa, CMDLINE_GPA);
    assert_eq!(layout.page_tables_gpa, PAGE_TABLES_GPA);
    assert_eq!(layout.stack_top, STACK_TOP);
    assert_eq!(layout.ram_top, 64 * 1024 * 1024);
    assert!(!layout.has_initrd());
    assert_eq!(layout.initrd_gpa, 0);
    assert_eq!(layout.initrd_end, 0);
}

#[test]
fn entry_point_is_the_kernel_start_plus_the_header() {
    let layout = plan(&request(64)).unwrap();
    assert_eq!(layout.entry_gpa(), layout.kernel_base + 0x200);
}

#[test]
fn identity_mapping_covers_the_boot_objects() {
    let layout = plan(&request(64)).unwrap();
    assert!(layout.covers(BOOT_PARAMS_GPA, BOOT_PARAMS_SIZE));
    assert!(layout.covers(CMDLINE_GPA, 32));
    assert!(layout.covers(
        PAGE_TABLES_GPA,
        layout.page_table_pages * PAGE_SIZE
    ));
    assert!(layout.covers(layout.entry_gpa(), 1));
    assert!(layout.covers(layout.kernel_base, layout.kernel_end - layout.kernel_base));
    assert!(layout.covers(0, LOW_IDENTITY_END));
}

#[test]
fn the_gap_between_low_memory_and_the_kernel_is_not_mapped() {
    let layout = plan(&request(64)).unwrap();
    assert!(!layout.covers(LOW_IDENTITY_END, 0x1000));
    assert!(!layout.covers(0x000B_0000, 0x1000));
    assert!(layout.covers(0x0008_0000, 0x1000));
}

#[test]
fn objects_do_not_overlap() {
    let layout = plan(&request(64)).unwrap();
    let mut objects = alloc::vec![
        (layout.boot_params_gpa, layout.boot_params_gpa + BOOT_PARAMS_SIZE),
        (layout.cmdline_gpa, layout.cmdline_gpa + layout.cmdline_len),
        (
            layout.page_tables_gpa,
            layout.page_tables_gpa + layout.page_table_pages * PAGE_SIZE
        ),
        (layout.kernel_base, layout.kernel_end),
    ];
    if layout.has_initrd() {
        objects.push((layout.initrd_gpa, layout.initrd_end));
    }
    objects.sort_unstable();
    for pair in objects.windows(2) {
        assert!(
            pair[0].1 <= pair[1].0,
            "objects overlap: {:#x?} and {:#x?}",
            pair[0],
            pair[1]
        );
    }
}

#[test]
fn the_page_table_reservation_stays_below_the_stack_guard() {
    for ram_mb in [32u64, 64, 512, 2048, 4080] {
        let layout = plan(&request(ram_mb)).unwrap();
        let end = PAGE_TABLES_GPA + layout.page_table_pages * PAGE_SIZE;
        assert!(end <= STACK_GUARD_END, "ram={ram_mb} MiB end={end:#x}");
        assert!(layout.page_table_pages >= 16);
    }
}

#[test]
fn the_ramdisk_is_placed_above_the_kernel_and_aligned() {
    let mut input = request(128);
    input.initrd_bytes = 16 * 1024 * 1024;
    let layout = plan(&input).unwrap();
    assert!(layout.has_initrd());
    assert!(layout.initrd_gpa >= layout.kernel_end);
    assert_eq!(layout.initrd_gpa % INITRD_ALIGN, 0);
    assert_eq!(layout.initrd_end, layout.initrd_gpa + input.initrd_bytes);
    assert!(layout.initrd_end <= layout.ram_top);
}

#[test]
fn a_ramdisk_that_does_not_fit_is_rejected() {
    let mut input = request(64);
    input.initrd_bytes = 60 * 1024 * 1024;
    assert_eq!(plan(&input).unwrap_err(), LayoutError::RamdiskTooBig);
}

#[test]
fn a_kernel_window_that_does_not_fit_is_rejected() {
    let mut input = request(64);
    input.init_size = 128 * 1024 * 1024;
    assert_eq!(plan(&input).unwrap_err(), LayoutError::RamTooSmall);
}

#[test]
fn a_non_relocatable_image_uses_its_preferred_address() {
    let mut input = request(64);
    input.relocatable = false;
    input.pref_address = 0x0040_0000;
    let layout = plan(&input).unwrap();
    assert_eq!(layout.kernel_base, 0x0040_0000);
}

#[test]
fn a_non_relocatable_image_below_the_high_load_base_is_rejected() {
    let mut input = request(64);
    input.relocatable = false;
    input.pref_address = 0x0001_0000;
    assert_eq!(plan(&input).unwrap_err(), LayoutError::NotRelocatable);
}

#[test]
fn a_relocatable_image_honours_a_preferred_address_above_one_mib() {
    let mut input = request(64);
    input.pref_address = 0x0040_0000;
    let layout = plan(&input).unwrap();
    assert_eq!(layout.kernel_base, 0x0040_0000);
}

#[test]
fn a_relocatable_image_is_aligned_up() {
    let mut input = request(64);
    input.pref_address = 0x0021_0000;
    input.kernel_alignment = 0x20_0000;
    let layout = plan(&input).unwrap();
    assert_eq!(layout.kernel_base, 0x0040_0000);
    assert_eq!(layout.kernel_base % 0x20_0000, 0);
}

#[test]
fn a_bad_alignment_is_rejected() {
    let mut input = request(64);
    input.kernel_alignment = 3;
    assert_eq!(plan(&input).unwrap_err(), LayoutError::BadAlignment);
}

#[test]
fn the_command_line_cannot_overrun_the_page_tables() {
    let mut input = request(64);
    input.cmdline_len = CMDLINE_MAX as u64 + 1;
    assert_eq!(plan(&input).unwrap_err(), LayoutError::CmdlineTooLong);
    input.cmdline_len = 0;
    assert_eq!(plan(&input).unwrap_err(), LayoutError::CmdlineTooLong);
}

#[test]
fn the_command_line_fits_up_to_the_protocol_maximum() {
    let mut input = request(64);
    input.cmdline_len = CMDLINE_MAX as u64;
    let layout = plan(&input).unwrap();
    assert_eq!(layout.cmdline_len, CMDLINE_MAX as u64);
    assert!(layout.covers(CMDLINE_GPA, CMDLINE_MAX as u64));
}

#[test]
fn an_unaligned_init_size_still_maps_whole_pages() {
    let mut input = request(64);
    input.init_size = 8 * 1024 * 1024 + 0x123;
    let layout = plan(&input).unwrap();
    let window = layout.identity.last().unwrap();
    assert_eq!(window.start, layout.kernel_base);
    assert_eq!(window.len % PAGE_SIZE, 0);
    assert!(window.len >= input.init_size);
}

#[test]
fn the_identity_ranges_are_usable_by_the_page_table_builder() {
    let layout = plan(&request(64)).unwrap();
    assert_eq!(layout.identity.len(), 2);
    assert_eq!(layout.identity[0].start, 0);
    assert_eq!(layout.identity[0].len, LOW_IDENTITY_END);
    assert_eq!(layout.identity[1].start, layout.kernel_base);
    assert_eq!(layout.identity[0].perms, PtPerms::KERNEL_RWX);
}

#[test]
fn building_the_guest_tables_from_the_layout_maps_every_boot_object() {
    let layout = plan(&request(64)).unwrap();
    let mut memory = TestMemory::new();
    let tables = GuestPageTables::build(&mut memory, &layout.identity).unwrap();
    for address in [
        BOOT_PARAMS_GPA,
        CMDLINE_GPA,
        PAGE_TABLES_GPA,
        STACK_TOP - 8,
        layout.entry_gpa(),
        layout.kernel_base,
        layout.kernel_end - 1,
    ] {
        let (physical, leaf) = tables
            .translate(&memory, address)
            .unwrap_or_else(|| panic!("address {address:#x} is not mapped"));
        assert_eq!(physical, address);
        assert_ne!(leaf & 1, 0);
    }
    assert!(
        tables.table_count() as u64 <= layout.page_table_pages,
        "tables={} reserved={}",
        tables.table_count(),
        layout.page_table_pages
    );
}

#[test]
fn page_table_budget_grows_with_the_mapped_space() {
    assert!(page_table_budget(0x10_0000) >= 2);
    assert!(page_table_budget(4 * 1024 * 1024 * 1024) >= page_table_budget(0x10_0000));
    assert!(page_table_budget(1 << 39) > page_table_budget(4 * 1024 * 1024 * 1024));
}

#[test]
fn align_up_rounds_and_rejects_bad_alignment() {
    assert_eq!(align_up(0, 0x1000).unwrap(), 0);
    assert_eq!(align_up(0x1001, 0x1000).unwrap(), 0x2000);
    assert_eq!(align_up(0x2000, 0x1000).unwrap(), 0x2000);
    assert_eq!(align_up(1, 0x200000).unwrap(), 0x200000);
    assert_eq!(align_up(1, 3).unwrap_err(), LayoutError::BadAlignment);
    assert_eq!(align_up(u64::MAX, 0x1000).unwrap_err(), LayoutError::Overflow);
}

#[test]
fn the_layout_is_deterministic() {
    let first = plan(&request(64)).unwrap();
    let second = plan(&request(64)).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.identity, second.identity);
}

#[test]
fn layout_constants_are_the_boot_protocol_contract() {
    assert_eq!(BOOT_PARAMS_GPA, 0x1_0000);
    assert_eq!(BOOT_PARAMS_SIZE, 0x1000);
    assert_eq!(CMDLINE_GPA, 0x2_0000);
    assert_eq!(PAGE_TABLES_GPA, 0x3_0000);
    assert_eq!(STACK_TOP, 0x9_F000);
    assert_eq!(HIGH_LOAD_BASE, 0x10_0000);
    assert_eq!(LOW_MEMORY_END, 0x9_FC00);
    assert_eq!(INITRD_ALIGN, 2 * 1024 * 1024);
}
