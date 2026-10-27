//! Host regression cases for the actual shared boot ABI. No firmware is needed.

use strat9_abi::boot::{
    KernelArgs, MemoryKind, MemoryRegion, ModuleEntry, ModuleTable, MAX_BOOT_MEMORY_REGIONS,
    MAX_BOOT_MODULES, MODULE_TABLE_SIZE,
};

#[repr(align(8))]
struct AlignedBytes<const N: usize>([u8; N]);

fn args() -> KernelArgs {
    // SAFETY: KernelArgs consists entirely of integer fields.
    unsafe { core::mem::zeroed() }
}

fn modules(count: usize) -> Vec<ModuleEntry> {
    (0..count)
        .map(|index| {
            let mut name = [0; 64];
            name[..4].copy_from_slice(b"init");
            name[4] = b'A' + (index % 26) as u8;
            ModuleEntry {
                name,
                base: 0x100_0000 + index as u64 * 0x2000,
                size: 4097,
            }
        })
        .collect()
}

#[test]
fn fixed_table_roundtrips_boundary_counts_without_touching_guard_bytes() {
    assert_eq!(MODULE_TABLE_SIZE, 5128);
    for count in [0, 1, 51, 52, MAX_BOOT_MODULES] {
        let mut guarded = AlignedBytes([0xA5; 8192 + 16]);
        let entries = modules(count);
        let storage = &mut guarded.0[8..8 + 8192];
        ModuleTable::write_into(storage, &entries).unwrap();
        assert_eq!(ModuleTable::read_from(storage).unwrap(), entries.as_slice());
        // Includes unused entries: the ABI always transfers the complete table.
        assert!(storage[8 + count * 80..MODULE_TABLE_SIZE]
            .iter()
            .all(|&byte| byte == 0));
        assert!(storage[4..8].iter().all(|&byte| byte == 0));
        assert!(storage[MODULE_TABLE_SIZE..]
            .iter()
            .all(|&byte| byte == 0xA5));

        let mut handoff = args();
        handoff.modules_base = storage.as_ptr() as u64;
        handoff.modules_size = MODULE_TABLE_SIZE as u64;
        // SAFETY: the aligned, initialized host allocation remains live here.
        assert_eq!(unsafe { handoff.modules() }.unwrap(), entries.as_slice());
        assert!(guarded.0[..8].iter().all(|&byte| byte == 0xA5));
        assert!(guarded.0[8 + 8192..].iter().all(|&byte| byte == 0xA5));
    }
}

#[test]
fn short_destination_is_rejected_before_any_write_even_without_modules() {
    for size in [0, 4, 8, 88, 4096, MODULE_TABLE_SIZE - 1] {
        let mut storage = AlignedBytes([0xA5; 8192]);
        assert!(ModuleTable::write_into(&mut storage.0[..size], &[]).is_err());
        assert!(storage.0.iter().all(|&byte| byte == 0xA5));
    }
}

#[test]
fn sixty_fifth_module_is_rejected_before_any_write() {
    let mut storage = AlignedBytes([0xA5; 8192]);
    assert!(ModuleTable::write_into(&mut storage.0, &modules(MAX_BOOT_MODULES + 1)).is_err());
    assert!(storage.0.iter().all(|&byte| byte == 0xA5));
}

#[test]
fn reader_rejects_excess_count_even_when_backing_storage_is_large() {
    let mut storage = AlignedBytes([0; 8192]);
    for count in [65u32, u32::MAX] {
        storage.0[..4].copy_from_slice(&count.to_ne_bytes());
        assert!(ModuleTable::read_from(&storage.0).is_err());
        let mut handoff = args();
        handoff.modules_base = storage.0.as_ptr() as u64;
        handoff.modules_size = storage.0.len() as u64;
        assert!(unsafe { handoff.modules() }.is_err());
    }
}

#[test]
fn reader_obeys_advertised_size_even_with_a_complete_backing_allocation() {
    let mut storage = AlignedBytes([0; 8192]);
    ModuleTable::write_into(&mut storage.0, &modules(1)).unwrap();
    let mut handoff = args();
    handoff.modules_base = storage.0.as_ptr() as u64;
    for size in [0, 4, 8, 88, 4096, MODULE_TABLE_SIZE - 1] {
        handoff.modules_size = size as u64;
        assert!(unsafe { handoff.modules() }.is_err());
        assert!(ModuleTable::read_from(&storage.0[..size]).is_err());
    }
}

#[test]
fn unaligned_module_storage_is_neither_read_nor_written() {
    let mut storage = AlignedBytes([0xA5; 8192]);
    assert!(ModuleTable::write_into(&mut storage.0[1..], &modules(1)).is_err());
    assert!(storage.0.iter().all(|&byte| byte == 0xA5));
    assert!(ModuleTable::read_from(&storage.0[1..]).is_err());
    let mut handoff = args();
    handoff.modules_base = storage.0.as_ptr() as u64 + 1;
    handoff.modules_size = MODULE_TABLE_SIZE as u64;
    assert!(unsafe { handoff.modules() }.is_err());
}

#[test]
fn absent_tables_require_both_pointer_and_size_to_be_zero() {
    let mut handoff = args();
    assert!(unsafe { handoff.modules() }.unwrap().is_empty());
    assert!(unsafe { handoff.memory_regions() }.unwrap().is_empty());
    handoff.modules_size = MODULE_TABLE_SIZE as u64;
    handoff.memory_map_size = core::mem::size_of::<MemoryRegion>() as u64;
    // Both null pointers must be rejected before dereferencing them.
    assert!(unsafe { handoff.modules() }.is_err());
    assert!(unsafe { handoff.memory_regions() }.is_err());
}

#[test]
fn overflowing_handoff_addresses_are_rejected_before_dereference() {
    let mut handoff = args();
    // These ranges necessarily fail numeric validation; no backing is accessed.
    handoff.modules_base = u64::MAX - 7;
    handoff.modules_size = MODULE_TABLE_SIZE as u64;
    handoff.memory_map_base = u64::MAX - 7;
    handoff.memory_map_size = core::mem::size_of::<MemoryRegion>() as u64;
    assert!(unsafe { handoff.modules() }.is_err());
    assert!(unsafe { handoff.memory_regions() }.is_err());
}

#[test]
fn oversized_slice_lengths_are_rejected_before_dereference() {
    let storage = AlignedBytes([0; 8192]);
    let mut handoff = args();
    handoff.modules_base = storage.0.as_ptr() as u64;
    handoff.modules_size = isize::MAX as u64 + 1;
    handoff.memory_map_base = storage.0.as_ptr() as u64;
    handoff.memory_map_size = isize::MAX as u64 + 1;
    assert!(unsafe { handoff.modules() }.is_err());
    assert!(unsafe { handoff.memory_regions() }.is_err());
}

#[test]
fn memory_map_rejects_partial_descriptors_and_inconsistent_extents() {
    let storage = AlignedBytes([0; 128]);
    let mut handoff = args();
    handoff.memory_map_base = storage.0.as_ptr() as u64;
    for size in [0, 1, 23, 25, 47] {
        handoff.memory_map_size = size;
        assert!(unsafe { handoff.memory_regions() }.is_err());
    }
    handoff.memory_map_base += 1;
    handoff.memory_map_size = 24;
    assert!(unsafe { handoff.memory_regions() }.is_err());
}

#[test]
fn kernel_map_capacity_is_accepted_exactly_and_never_silently_truncated() {
    let regions = vec![
        MemoryRegion {
            base: 0x1000,
            size: 0x1000,
            kind: MemoryKind::Reserved
        };
        MAX_BOOT_MEMORY_REGIONS + 1
    ];
    let mut handoff = args();
    handoff.memory_map_base = regions.as_ptr() as u64;
    handoff.memory_map_size =
        (MAX_BOOT_MEMORY_REGIONS * core::mem::size_of::<MemoryRegion>()) as u64;
    assert_eq!(
        unsafe { handoff.memory_regions() }.unwrap().len(),
        MAX_BOOT_MEMORY_REGIONS
    );
    handoff.memory_map_size += core::mem::size_of::<MemoryRegion>() as u64;
    assert!(unsafe { handoff.memory_regions() }.is_err());
}
