//! L2: s9vm second-level translation (real kernel code, host memory).

use std::collections::HashMap;

#[path = "../../kernel/src/s9vm/mmu.rs"]
mod mmu;

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
        self.tables
            .entry(table)
            .or_insert([0u64; 512])[index] = value;
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
    assert_eq!(table.translate(&memory, 0x10_0000 + PAGE_SIZE), Some(0x20_1000));
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
        table.map_2m(&mut memory, 0x10_0000 + 0x1000, 0x20_0000, 0x20_0000, Perms::read_write()),
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
    assert_eq!(
        table.translate(&memory, 0x4020_0000),
        Some(0x8020_0000)
    );
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
        .map_4k(&mut memory, 0x3000, 0x4000, 2 * PAGE_SIZE, Perms::read_write())
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
