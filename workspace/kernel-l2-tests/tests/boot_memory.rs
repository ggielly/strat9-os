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
    let mut file = vec![0; 516];
    file[..6].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1]);
    file[0x18..0x20].copy_from_slice(&VIRTUAL_BASE.to_le_bytes());
    file[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
    file[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
    file[0x38..0x3A].copy_from_slice(&2u16.to_le_bytes());
    for (index, offset, displacement) in [(0, 256u64, 0), (1, 512u64, 3 * PAGE_SIZE)] {
        let header = 64 + index * 56;
        file[header..header + 4].copy_from_slice(&1u32.to_le_bytes());
        file[header + 4..header + 8].copy_from_slice(&5u32.to_le_bytes());
        for (field, value) in [
            (8, offset),
            (16, VIRTUAL_BASE + displacement),
            (24, VIRTUAL_BASE + displacement),
            (32, 4),
            (40, 4),
        ] {
            file[header + field..header + field + 8].copy_from_slice(&value.to_le_bytes());
        }
    }
    file[256..260].copy_from_slice(b"TEXT");
    file[512..516].copy_from_slice(b"DATA");
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
    assert!(unsafe { plan.load_into(&file[..513], image.destination()) }.is_err());
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
