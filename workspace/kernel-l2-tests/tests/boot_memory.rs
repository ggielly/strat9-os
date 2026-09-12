//! Regression cases for the bootloader's actual pure code. No firmware or
//! privileged instructions run here. This suite was added without compiling it.
#![allow(dead_code)]

#[path = "../../bootloader/src/elf.rs"]
mod elf;
#[path = "../../bootloader/src/memory_map.rs"]
mod memory_map;

use memory_map::{
    page_allocation_size, MemoryMapBuilder, PageFrameCursor, PhysicalRange, PAGE_SIZE,
};
use strat9_abi::boot::{MemoryKind, MemoryRegion};

const EMPTY: MemoryRegion = MemoryRegion {
    base: 0,
    size: 0,
    kind: MemoryKind::Null,
};

fn region(start_page: u64, pages: u64, kind: MemoryKind) -> MemoryRegion {
    MemoryRegion {
        base: start_page * PAGE_SIZE,
        size: pages * PAGE_SIZE,
        kind,
    }
}

fn reservation(start_page: u64, pages: u64) -> PhysicalRange {
    PhysicalRange {
        base: start_page * PAGE_SIZE,
        size: pages * PAGE_SIZE,
    }
}

fn convert(input: &[MemoryRegion], owned: &[PhysicalRange]) -> Vec<MemoryRegion> {
    let mut output = [EMPTY; 64];
    let len = {
        let mut builder = MemoryMapBuilder::new(&mut output, owned).unwrap();
        for &descriptor in input {
            builder.push(descriptor).unwrap();
        }
        builder.len()
    };
    output[..len].to_vec()
}

#[test]
fn reservations_preserve_every_page_across_firmware_boundaries() {
    // Real allocations can straddle the descriptor splits used by firmware.
    // Descriptor order is deliberately non-monotonic; no pages may disappear,
    // duplicate, or become allocatable because of that order.
    let input = [
        region(11, 6, MemoryKind::Free),
        region(1, 5, MemoryKind::Reclaim),
        region(6, 5, MemoryKind::Reserved),
    ];
    for start in 1..17 {
        for end in start + 1..=17 {
            let owned = [reservation(start, end - start)];
            let output = convert(&input, &owned);
            assert_eq!(output.iter().map(|r| r.size).sum::<u64>(), 16 * PAGE_SIZE);
            for page in 1..17 {
                let address = page * PAGE_SIZE;
                let covering: Vec<_> = output
                    .iter()
                    .filter(|r| r.base <= address && address < r.base + r.size)
                    .collect();
                assert_eq!(covering.len(), 1, "page {page}, reservation {start}..{end}");
                let expected = if (start..end).contains(&page) || (6..11).contains(&page) {
                    MemoryKind::Reserved
                } else if page < 6 {
                    MemoryKind::Reclaim
                } else {
                    MemoryKind::Free
                };
                assert_eq!(covering[0].kind, expected);
            }
        }
    }
}

#[test]
fn module_payloads_and_handoff_pages_are_not_reclaimable() {
    let owned = [reservation(2, 2), reservation(6, 1), reservation(7, 2)];
    let output = convert(&[region(1, 10, MemoryKind::Reclaim)], &owned);
    let actual: Vec<_> = output
        .iter()
        .map(|r| (r.base / PAGE_SIZE, r.size / PAGE_SIZE, r.kind))
        .collect();
    assert_eq!(
        actual,
        vec![
            (1, 1, MemoryKind::Reclaim),
            (2, 2, MemoryKind::Reserved),
            (4, 2, MemoryKind::Reclaim),
            (6, 3, MemoryKind::Reserved),
            (9, 2, MemoryKind::Reclaim),
        ]
    );
}

#[test]
fn full_map_returns_error_without_overwriting_adjacent_storage() {
    let sentinel = region(99, 1, MemoryKind::Reserved);
    let mut storage = [sentinel; 4];
    let owned = [reservation(2, 1)];
    {
        let mut builder = MemoryMapBuilder::new(&mut storage[1..3], &owned).unwrap();
        // Requires three regions, while the caller supplied space for two.
        assert!(builder.push(region(1, 3, MemoryKind::Free)).is_err());
        assert_eq!(builder.len(), 2);
    }
    for index in [0, 3] {
        assert_eq!(storage[index].base, sentinel.base);
        assert_eq!(storage[index].size, sentinel.size);
        assert_eq!(storage[index].kind, sentinel.kind);
    }
}

#[test]
fn malformed_ranges_fail_before_emitting_descriptors() {
    let mut output = [EMPTY; 8];
    for owned in [
        vec![reservation(2, 3), reservation(4, 1)], // overlap
        vec![reservation(4, 1), reservation(2, 1)], // unordered
        vec![PhysicalRange {
            base: 1,
            size: PAGE_SIZE,
        }],
        vec![reservation(1, 0)],
        vec![PhysicalRange {
            base: u64::MAX - PAGE_SIZE + 1,
            size: PAGE_SIZE,
        }],
    ] {
        assert!(MemoryMapBuilder::new(&mut output, &owned).is_err());
    }
    let mut builder = MemoryMapBuilder::new(&mut output, &[]).unwrap();
    assert!(builder
        .push(MemoryRegion {
            base: u64::MAX - 1,
            size: PAGE_SIZE,
            kind: MemoryKind::Free,
        })
        .is_err());
    assert_eq!(builder.len(), 0);
}

#[test]
fn page_table_arena_exhaustion_never_yields_a_frame_outside_ownership() {
    let owned = reservation(0x1200, 3);
    let mut cursor = PageFrameCursor::new(owned).unwrap();
    for page in 0..3 {
        assert_eq!(cursor.next_frame().unwrap(), owned.base + page * PAGE_SIZE);
    }
    for _ in 0..3 {
        assert!(cursor.next_frame().is_err());
    }
    assert!(PageFrameCursor::new(reservation(0, 1)).is_err());
    assert!(PageFrameCursor::new(PhysicalRange {
        base: owned.base + 1,
        size: PAGE_SIZE
    })
    .is_err());
    assert!(PageFrameCursor::new(reservation(1, 0)).is_err());
}

#[test]
fn allocation_rounding_rejects_zero_and_overflow() {
    assert!(page_allocation_size(0).is_err());
    assert!(page_allocation_size(u64::MAX).is_err());
    assert_eq!(page_allocation_size(PAGE_SIZE).unwrap(), PAGE_SIZE);
    assert_eq!(page_allocation_size(PAGE_SIZE + 1).unwrap(), 2 * PAGE_SIZE);
}

const VIRTUAL_BASE: u64 = 0xFFFF_FFFF_8000_0000;

fn kernel_file() -> Vec<u8> {
    let mut file = vec![0; 8196];
    file[..6].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1]);
    file[6] = 1;
    file[16..18].copy_from_slice(&2u16.to_le_bytes());
    file[18..20].copy_from_slice(&62u16.to_le_bytes());
    file[20..24].copy_from_slice(&1u32.to_le_bytes());
    file[0x18..0x20].copy_from_slice(&VIRTUAL_BASE.to_le_bytes());
    file[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
    file[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
    file[52..54].copy_from_slice(&64u16.to_le_bytes());
    file[0x38..0x3A].copy_from_slice(&2u16.to_le_bytes());
    for (index, offset, displacement) in [(0, 4096u64, 0), (1, 8192u64, 3 * PAGE_SIZE)] {
        let header = 64 + index * 56;
        file[header..header + 4].copy_from_slice(&1u32.to_le_bytes());
        file[header + 4..header + 8].copy_from_slice(&5u32.to_le_bytes());
        for (field, value) in [
            (8, offset),
            (16, VIRTUAL_BASE + displacement),
            (24, VIRTUAL_BASE + displacement),
            (32, 4),
            (40, 4),
            (48, PAGE_SIZE),
        ] {
            file[header + field..header + field + 8].copy_from_slice(&value.to_le_bytes());
        }
    }
    file[4096..4100].copy_from_slice(b"TEXT");
    file[8192..8196].copy_from_slice(b"DATA");
    file
}

/// Page-aligned host storage with a guard page on either side of the destination.
struct ImageBuffer {
    ptr: std::ptr::NonNull<u8>,
    layout: std::alloc::Layout,
    size: usize,
}

impl ImageBuffer {
    fn new(size: u64, fill: u8) -> Self {
        let size = page_allocation_size(size).unwrap() as usize;
        let layout =
            std::alloc::Layout::from_size_align(size + 2 * PAGE_SIZE as usize, PAGE_SIZE as usize)
                .unwrap();
        let ptr = std::ptr::NonNull::new(unsafe { std::alloc::alloc(layout) }).unwrap();
        unsafe { std::ptr::write_bytes(ptr.as_ptr(), 0xA5, layout.size()) };
        unsafe { std::ptr::write_bytes(ptr.as_ptr().add(PAGE_SIZE as usize), fill, size) };
        Self { ptr, layout, size }
    }

    fn destination(&self) -> PhysicalRange {
        PhysicalRange {
            base: self.ptr.as_ptr() as u64 + PAGE_SIZE,
            size: self.size as u64,
        }
    }

    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().add(PAGE_SIZE as usize), self.size) }
    }

    fn assert_guards(&self) {
        let all = unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.layout.size()) };
        assert!(all[..PAGE_SIZE as usize].iter().all(|&b| b == 0xA5));
        assert!(all[PAGE_SIZE as usize + self.size..]
            .iter()
            .all(|&b| b == 0xA5));
    }
}

impl Drop for ImageBuffer {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

#[test]
fn parsing_never_dereferences_physical_addresses() {
    // A parser that still writes to 1 MiB cannot safely run as a host test.
    let file = kernel_file();
    let plan = elf::parse_elf64(&file).unwrap();
    assert_eq!(plan.phys_base, 0x10_0000);
    assert_eq!(plan.segment_count, 2);
    assert_eq!(plan.entry, VIRTUAL_BASE);
}

#[test]
fn kernel_load_rebases_only_physical_addresses_and_respects_guards() {
    let file = kernel_file();
    let mut plan = elf::parse_elf64(&file).unwrap();
    let image = ImageBuffer::new(plan.image_size(), 0);
    let destination = image.destination();
    unsafe { plan.load_into(&file, destination) }.unwrap();
    assert_eq!(plan.phys_base, destination.base);
    assert_eq!(plan.segments[1].phys_addr, destination.base + 3 * PAGE_SIZE);
    assert_eq!(plan.segments[1].virt_addr, VIRTUAL_BASE + 3 * PAGE_SIZE);
    assert_eq!(plan.entry, VIRTUAL_BASE);
    assert_eq!(&image.bytes()[..4], b"TEXT");
    assert_eq!(
        &image.bytes()[3 * PAGE_SIZE as usize..3 * PAGE_SIZE as usize + 4],
        b"DATA"
    );
    assert!(image.bytes()[4..3 * PAGE_SIZE as usize]
        .iter()
        .all(|&b| b == 0));
    image.assert_guards();
}

#[test]
fn invalid_last_segment_causes_no_partial_kernel_copy() {
    let file = kernel_file();
    let mut plan = elf::parse_elf64(&file).unwrap();
    let image = ImageBuffer::new(plan.image_size(), 0xA5);
    assert!(unsafe { plan.load_into(&file[..8193], image.destination()) }.is_err());
    assert!(image.bytes().iter().all(|&b| b == 0xA5));
    assert_eq!(plan.phys_base, 0x10_0000);
    image.assert_guards();
}

#[test]
fn undersized_kernel_destination_causes_no_copy() {
    let file = kernel_file();
    let mut plan = elf::parse_elf64(&file).unwrap();
    let image = ImageBuffer::new(PAGE_SIZE, 0xA5);
    assert!(unsafe { plan.load_into(&file, image.destination()) }.is_err());
    assert!(image.bytes().iter().all(|&b| b == 0xA5));
    image.assert_guards();
}

#[test]
fn overflowing_file_range_is_rejected_during_planning() {
    let mut file = kernel_file();
    file[64 + 8..64 + 16].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(elf::parse_elf64(&file).is_err());
}

#[test]
fn page_tables_spanning_two_firmware_descriptors_keep_both_remainders() {
    // R07: [0x1000,0x3000) intersects tables [0x2000,0x4000).
    let output = convert(
        &[
            region(1, 2, MemoryKind::Free),
            region(3, 2, MemoryKind::Reclaim),
        ],
        &[reservation(2, 2)],
    );
    let actual: Vec<_> = output.iter().map(|r| (r.base, r.size, r.kind)).collect();
    assert_eq!(
        actual,
        vec![
            (0x1000, 0x1000, MemoryKind::Free),
            (0x2000, 0x2000, MemoryKind::Reserved),
            (0x4000, 0x1000, MemoryKind::Reclaim),
        ]
    );
}

#[test]
fn final_split_is_visible_to_the_kernel_across_a_page_boundary() {
    // R08: 170 descriptors fit in 4096 bytes; 172 require 4128 bytes.
    let mut storage = [EMPTY; memory_map::MAX_MEMORY_REGIONS];
    let owned = [reservation(1001, 1)];
    let final_count = {
        let mut builder = MemoryMapBuilder::new(&mut storage, &owned).unwrap();
        for index in 0..169 {
            builder
                .push(region(index * 2 + 1, 1, MemoryKind::Reserved))
                .unwrap();
        }
        builder.push(region(1000, 3, MemoryKind::Free)).unwrap();
        builder.len()
    };
    assert_eq!(final_count, 172);
    let mut args: strat9_abi::boot::KernelArgs = unsafe { core::mem::zeroed() };
    args.memory_map_base = storage.as_ptr() as u64;
    args.memory_map_size = (final_count * core::mem::size_of::<MemoryRegion>()) as u64;
    let visible = unsafe { args.memory_regions() }.unwrap();
    assert_eq!(visible.len(), 172);
    assert_eq!(visible[171].base, 1002 * PAGE_SIZE);
    assert_eq!(visible[171].kind, MemoryKind::Free);
}

#[test]
fn final_split_refuses_a_one_page_map_without_overwriting_the_guard() {
    let sentinel = region(0xFFFF, 1, MemoryKind::Reserved);
    let mut storage = [sentinel; 171];
    let owned = [reservation(1001, 1)];
    {
        let mut builder = MemoryMapBuilder::new(&mut storage[..170], &owned).unwrap();
        for index in 0..169 {
            builder
                .push(region(index * 2 + 1, 1, MemoryKind::Reserved))
                .unwrap();
        }
        assert!(builder.push(region(1000, 3, MemoryKind::Free)).is_err());
    }
    assert_eq!(storage[170].base, sentinel.base);
    assert_eq!(storage[170].size, sentinel.size);
    assert_eq!(storage[170].kind, sentinel.kind);
}

#[test]
fn converting_a_smaller_final_map_does_not_publish_stale_preview_entries() {
    let mut storage = [EMPTY; 8];
    {
        let mut preview = MemoryMapBuilder::new(&mut storage, &[]).unwrap();
        for index in 0..8 {
            preview
                .push(region(index * 2 + 1, 1, MemoryKind::Reserved))
                .unwrap();
        }
    }
    let final_count = {
        let mut final_map = MemoryMapBuilder::new(&mut storage, &[]).unwrap();
        final_map.push(region(1, 16, MemoryKind::Free)).unwrap();
        final_map.len()
    };
    let mut args: strat9_abi::boot::KernelArgs = unsafe { core::mem::zeroed() };
    args.memory_map_base = storage.as_ptr() as u64;
    args.memory_map_size = (final_count * core::mem::size_of::<MemoryRegion>()) as u64;
    let visible = unsafe { args.memory_regions() }.unwrap();
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].size, 16 * PAGE_SIZE);
    assert_eq!(visible[0].kind, MemoryKind::Free);
}

fn set_segment_field(file: &mut [u8], index: usize, field: usize, value: u64) {
    let offset = 64 + index * 56 + field;
    file[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn pure_bss_larger_than_eight_mib_is_allocated_and_cleared_through_its_last_byte() {
    let mut file = kernel_file();
    file[56..58].copy_from_slice(&3u16.to_le_bytes());
    let header = 64 + 2 * 56;
    file[header..header + 4].copy_from_slice(&1u32.to_le_bytes());
    file[header + 4..header + 8].copy_from_slice(&6u32.to_le_bytes());
    let bss_size = 12 * 1024 * 1024 + 3;
    for (field, value) in [
        (8, 0x10000), // No file bytes: an offset beyond EOF is valid.
        (16, VIRTUAL_BASE + 4 * PAGE_SIZE),
        (24, VIRTUAL_BASE + 4 * PAGE_SIZE),
        (32, 0),
        (40, bss_size),
        (48, PAGE_SIZE),
    ] {
        set_segment_field(&mut file, 2, field, value);
    }
    let mut plan = elf::parse_elf64(&file).unwrap();
    assert_eq!(plan.segment_count, 3);
    assert_eq!(plan.image_size(), 4 * PAGE_SIZE + bss_size);
    assert_eq!(plan.bss_range(), (VIRTUAL_BASE + 4 * PAGE_SIZE, bss_size));
    let image = ImageBuffer::new(plan.image_size(), 0xA5);
    unsafe { plan.load_into(&file, image.destination()) }.unwrap();
    assert_eq!(&image.bytes()[..4], b"TEXT");
    assert_eq!(
        &image.bytes()[3 * PAGE_SIZE as usize..3 * PAGE_SIZE as usize + 4],
        b"DATA"
    );
    assert!(image.bytes()[4 * PAGE_SIZE as usize..]
        .iter()
        .all(|&byte| byte == 0));
    image.assert_guards();
}

#[test]
fn mixed_file_and_zero_fill_segment_clears_its_exact_tail() {
    let mut file = kernel_file();
    set_segment_field(&mut file, 1, 40, PAGE_SIZE + 3);
    let mut plan = elf::parse_elf64(&file).unwrap();
    assert_eq!(
        plan.bss_range(),
        (VIRTUAL_BASE + 3 * PAGE_SIZE + 4, PAGE_SIZE - 1)
    );
    let image = ImageBuffer::new(plan.image_size(), 0xA5);
    unsafe { plan.load_into(&file, image.destination()) }.unwrap();
    assert!(image.bytes()[3 * PAGE_SIZE as usize + 4..]
        .iter()
        .all(|&byte| byte == 0));
    image.assert_guards();
}

#[test]
fn unsupported_elf_headers_are_rejected() {
    for (offset, bytes) in [
        (4, vec![1]),
        (5, vec![2]),
        (6, vec![0]),
        (16, 3u16.to_le_bytes().to_vec()),
        (18, 3u16.to_le_bytes().to_vec()),
        (20, 0u32.to_le_bytes().to_vec()),
        (52, 63u16.to_le_bytes().to_vec()),
        (54, 55u16.to_le_bytes().to_vec()),
        (56, 0u16.to_le_bytes().to_vec()),
        (56, 17u16.to_le_bytes().to_vec()),
        (32, (u64::MAX - 55).to_le_bytes().to_vec()),
    ] {
        let mut file = kernel_file();
        file[offset..offset + bytes.len()].copy_from_slice(&bytes);
        assert!(elf::parse_elf64(&file).is_err(), "header field at {offset}");
    }
}

#[test]
fn invalid_segment_geometry_is_rejected_before_loading() {
    for (field, value) in [
        (32, 5),                            // filesz > memsz
        (40, u64::MAX),                     // end overflow
        (40, elf::MAX_KERNEL_IMAGE_SIZE),   // exceeds supported virtual window
        (48, 3),                            // not power of two
        (8, 8193),                          // file and virtual alignment disagree
        (16, VIRTUAL_BASE),                 // overlaps the first segment
        (24, VIRTUAL_BASE + 5 * PAGE_SIZE), // incompatible physical layout
    ] {
        let mut file = kernel_file();
        set_segment_field(&mut file, 1, field, value);
        assert!(
            elf::parse_elf64(&file).is_err(),
            "segment field {field}, value {value}"
        );
    }
}

#[test]
fn entry_must_be_backed_by_file_bytes_in_an_executable_segment() {
    for entry in [
        0,
        VIRTUAL_BASE - 1,
        VIRTUAL_BASE + 4,
        VIRTUAL_BASE + PAGE_SIZE,
    ] {
        let mut file = kernel_file();
        // A zero-fill tail is not a valid entry, even with PF_X on that segment.
        set_segment_field(&mut file, 0, 40, 8);
        file[24..32].copy_from_slice(&entry.to_le_bytes());
        assert!(elf::parse_elf64(&file).is_err());
    }
    let mut file = kernel_file();
    file[68..72].copy_from_slice(&6u32.to_le_bytes());
    assert!(elf::parse_elf64(&file).is_err());
}

#[test]
fn dynamically_linked_or_tls_kernels_are_refused() {
    for program_type in [2u32, 3, 5, 7] {
        let mut file = kernel_file();
        file[120..124].copy_from_slice(&program_type.to_le_bytes());
        assert!(elf::parse_elf64(&file).is_err());
    }
}
