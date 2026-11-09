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

//! s9vm — second-level translation (hardware page tables).
//!
//! The module builds and walks the tables that translate guest physical
//! addresses (GPA) to host physical addresses (HPA), following the Intel
//! SDM (second-level translation, "EPT"). It is **pure**: it knows
//! neither `HHDM` nor a frame allocator. Memory access to the tables is
//! provided by a [`TableMemory`] (the kernel provides an HHDM
//! implementation, the tests a host-memory implementation).
//!
//! Convention: the addresses handled are **physical** addresses; the
//! [`TableMemory`] provider knows how to read and write them.

/// Size of a base page.
pub const PAGE_SIZE: u64 = 4096;
/// Number of entries per table.
pub const ENTRY_COUNT: usize = 512;
/// Level shifts of the 4-level page-table walk.
pub const SHIFT_PML4: u32 = 39;
pub const SHIFT_PDPT: u32 = 30;
pub const SHIFT_PD: u32 = 21;
pub const SHIFT_PT: u32 = 12;
/// Maximum guest physical address width covered (48 bits).
pub const MAX_GPA: u64 = 1 << 48;

/// Bits and masks of second-level table entries.
pub mod entry {
    /// Present entry.
    pub const PRESENT: u64 = 1 << 0;
    /// Read allowed (EPT bit 0).
    pub const READ: u64 = 1 << 0;
    /// Write allowed (EPT bit 1).
    pub const WRITE: u64 = 1 << 1;
    /// Execute allowed (EPT bit 2).
    pub const EXECUTE: u64 = 1 << 2;
    /// *Write-back* memory type (bits 5:3 = 6).
    pub const MEMTYPE_WB: u64 = 6 << 3;
    /// Large page (bit 7, 2 MiB page at the PD level).
    pub const LARGE_PAGE: u64 = 1 << 7;
    /// Mask of the encoded physical address (bits 51:12).
    pub const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    /// Alignment of a 2 MiB page.
    pub const LARGE_2MB: u64 = 2 * 1024 * 1024;
    /// Alignment of a 1 GiB page.
    pub const LARGE_1GB: u64 = 1024 * 1024 * 1024;
}

/// Permissions for intermediate (non-leaf) EPT entries. EPT permissions are
/// AND-ed across all levels, so an intermediate entry must grant read, write
/// and execute; the effective access is then constrained by the leaf. Omitting
/// execute here would make every guest instruction fetch fault with an EPT
/// violation regardless of the leaf permission.
const INTERMEDIATE_PERMS: u64 = entry::READ | entry::WRITE | entry::EXECUTE;

/// Permissions requested for a mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Perms {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Perms {
    /// Read-only and execute (guest code).
    pub const fn read_execute() -> Self {
        Self {
            read: true,
            write: false,
            execute: true,
        }
    }

    /// Read/write (guest data).
    pub const fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
        }
    }

    /// All permissions (regular RAM).
    pub const fn read_write_execute() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
        }
    }

    /// Encodes the permissions into bits 2:0 of an entry.
    pub const fn bits(self) -> u64 {
        let mut bits = 0;
        if self.read {
            bits |= entry::READ;
        }
        if self.write {
            bits |= entry::WRITE;
        }
        if self.execute {
            bits |= entry::EXECUTE;
        }
        bits
    }
}

/// Table manipulation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmuError {
    /// The provider has no more table available.
    OutOfMemory,
    /// Invalid address or length.
    InvalidRange,
    /// A 2 MiB page is misaligned.
    Misaligned,
    /// The memory obtained from the provider is not usable.
    BadMemory,
    /// The requested mapping overlaps an existing incompatible mapping.
    Conflict,
}

/// Memory provider for the tables (allocation, read, write).
///
/// The kernel implements this trait by allocating frames and going through the
/// HHDM; the tests use a host-memory table. Each handle
/// (`table`) identifies a table of 512 8-byte entries.
pub trait TableMemory {
    /// Allocates a zeroed table and returns its handle (physical identifier).
    fn alloc_table(&mut self) -> Option<u64>;
    /// Frees a previously allocated table.
    fn free_table(&mut self, table: u64);
    /// Reads entry `index` of the table.
    fn read_entry(&self, table: u64, index: usize) -> u64;
    /// Writes entry `index` of the table.
    fn write_entry(&mut self, table: u64, index: usize, value: u64);
}

/// Root of a second-level translation.
#[derive(Debug)]
pub struct SecondLevel {
    root: u64,
}

impl SecondLevel {
    /// Creates an empty translation (a zeroed root table).
    pub fn new<M: TableMemory>(memory: &mut M) -> Result<Self, MmuError> {
        let root = memory.alloc_table().ok_or(MmuError::OutOfMemory)?;
        Ok(Self { root })
    }

    /// Physical address of the root.
    pub const fn root_phys(&self) -> u64 {
        self.root
    }

    /// Frees the root (the sub-tables must have been freed by
    /// [`Self::unmap`] or by the caller).
    pub fn release<M: TableMemory>(&self, memory: &mut M) {
        memory.free_table(self.root);
    }

    /// Maps a range of `len` bytes (multiple of 4 KiB) in 4 KiB pages.
    ///
    /// `gpa` and `hpa` must be 4 KiB aligned.
    pub fn map_4k<M: TableMemory>(
        &self,
        memory: &mut M,
        gpa: u64,
        hpa: u64,
        len: u64,
        perms: Perms,
    ) -> Result<(), MmuError> {
        if len == 0 || gpa % PAGE_SIZE != 0 || hpa % PAGE_SIZE != 0 || len % PAGE_SIZE != 0 {
            return Err(MmuError::InvalidRange);
        }
        if gpa.checked_add(len).map_or(true, |end| end > MAX_GPA) {
            return Err(MmuError::InvalidRange);
        }
        let leaf = perms.bits() | entry::MEMTYPE_WB;
        let pages = len / PAGE_SIZE;
        for index in 0..pages {
            let offset = index * PAGE_SIZE;
            let table = self.ensure_table(memory, gpa + offset, SHIFT_PT)?;
            let slot = index_of(gpa + offset, SHIFT_PT);
            let existing = memory.read_entry(table, slot);
            if existing & entry::PRESENT != 0 && existing & entry::LARGE_PAGE == 0 {
                return Err(MmuError::Conflict);
            }
            memory.write_entry(table, slot, (hpa + offset) | leaf);
        }
        Ok(())
    }

    /// Maps a range of `len` bytes in 2 MiB pages.
    ///
    /// `gpa`, `hpa`, and `len` must be 2 MiB aligned.
    pub fn map_2m<M: TableMemory>(
        &self,
        memory: &mut M,
        gpa: u64,
        hpa: u64,
        len: u64,
        perms: Perms,
    ) -> Result<(), MmuError> {
        let align = entry::LARGE_2MB;
        if len == 0 || gpa % align != 0 || hpa % align != 0 || len % align != 0 {
            return Err(MmuError::Misaligned);
        }
        if gpa.checked_add(len).map_or(true, |end| end > MAX_GPA) {
            return Err(MmuError::InvalidRange);
        }
        let leaf = perms.bits() | entry::MEMTYPE_WB | entry::LARGE_PAGE;
        let pages = len / align;
        for index in 0..pages {
            let offset = index * align;
            let table = self.ensure_table(memory, gpa + offset, SHIFT_PD)?;
            let slot = index_of(gpa + offset, SHIFT_PD);
            let existing = memory.read_entry(table, slot);
            if existing & entry::PRESENT != 0 {
                return Err(MmuError::Conflict);
            }
            memory.write_entry(table, slot, (hpa + offset) | leaf);
        }
        Ok(())
    }

    /// Translates a GPA to an HPA, if a leaf exists.
    pub fn translate<M: TableMemory>(&self, memory: &M, gpa: u64) -> Option<u64> {
        if gpa >= MAX_GPA {
            return None;
        }
        let pml4 = memory.read_entry(self.root, index_of(gpa, SHIFT_PML4));
        if pml4 & entry::PRESENT == 0 {
            return None;
        }
        let pdpt_table = pml4 & entry::ADDR_MASK;
        let pdpt = memory.read_entry(pdpt_table, index_of(gpa, SHIFT_PDPT));
        if pdpt & entry::PRESENT == 0 {
            return None;
        }
        if pdpt & entry::LARGE_PAGE != 0 {
            // 1 GiB pages: supported only if the provider has
            // placed them; they are accepted for reading.
            let base = pdpt & entry::ADDR_MASK & !(entry::LARGE_1GB - 1);
            return Some(base | (gpa & (entry::LARGE_1GB - 1)));
        }
        let pd_table = pdpt & entry::ADDR_MASK;
        let pd = memory.read_entry(pd_table, index_of(gpa, SHIFT_PD));
        if pd & entry::PRESENT == 0 {
            return None;
        }
        if pd & entry::LARGE_PAGE != 0 {
            let base = pd & entry::ADDR_MASK & !(entry::LARGE_2MB - 1);
            return Some(base | (gpa & (entry::LARGE_2MB - 1)));
        }
        let pt_table = pd & entry::ADDR_MASK;
        let pt = memory.read_entry(pt_table, index_of(gpa, SHIFT_PT));
        if pt & entry::PRESENT == 0 {
            return None;
        }
        Some((pt & entry::ADDR_MASK) | (gpa & (PAGE_SIZE - 1)))
    }

    /// Removes a 4 KiB mapping. Returns `true` if a leaf existed.
    ///
    /// Intermediate tables that become empty are not freed (they
    /// can be reused by a later mapping); use
    /// [`Self::release`] after [`Self::release_all`] or let the
    /// provider owner reclaim them.
    pub fn unmap_4k<M: TableMemory>(&self, memory: &mut M, gpa: u64) -> bool {
        let Some(pt_table) = self.leaf_table(memory, gpa, SHIFT_PT) else {
            return false;
        };
        let slot = index_of(gpa, SHIFT_PT);
        let existing = memory.read_entry(pt_table, slot);
        if existing & entry::PRESENT == 0 || existing & entry::LARGE_PAGE != 0 {
            return false;
        }
        memory.write_entry(pt_table, slot, 0);
        true
    }

    /// Removes a 2 MiB mapping. Returns `true` if a leaf existed.
    pub fn unmap_2m<M: TableMemory>(&self, memory: &mut M, gpa: u64) -> bool {
        let Some(pd_table) = self.leaf_table(memory, gpa, SHIFT_PD) else {
            return false;
        };
        let slot = index_of(gpa, SHIFT_PD);
        let existing = memory.read_entry(pd_table, slot);
        if existing & entry::PRESENT == 0 || existing & entry::LARGE_PAGE == 0 {
            return false;
        }
        memory.write_entry(pd_table, slot, 0);
        true
    }

    /// Walks the tables down to the table containing the leaf of the requested
    /// level (`SHIFT_PT` for 4 KiB, `SHIFT_PD` for 2 MiB).
    fn leaf_table<M: TableMemory>(&self, memory: &M, gpa: u64, leaf_shift: u32) -> Option<u64> {
        if gpa >= MAX_GPA {
            return None;
        }
        let pml4 = memory.read_entry(self.root, index_of(gpa, SHIFT_PML4));
        if pml4 & entry::PRESENT == 0 {
            return None;
        }
        let pdpt = memory.read_entry(pml4 & entry::ADDR_MASK, index_of(gpa, SHIFT_PDPT));
        if pdpt & entry::PRESENT == 0 || pdpt & entry::LARGE_PAGE != 0 {
            return None;
        }
        let pd = memory.read_entry(pdpt & entry::ADDR_MASK, index_of(gpa, SHIFT_PD));
        if pd & entry::PRESENT == 0 {
            return None;
        }
        if leaf_shift == SHIFT_PD {
            return Some(pdpt & entry::ADDR_MASK);
        }
        if pd & entry::LARGE_PAGE != 0 {
            return None;
        }
        Some(pd & entry::ADDR_MASK)
    }

    /// Creates (if necessary) the table of level `shift` for the given GPA and
    /// returns its handle. Allocates the missing levels.
    fn ensure_table<M: TableMemory>(
        &self,
        memory: &mut M,
        gpa: u64,
        shift: u32,
    ) -> Result<u64, MmuError> {
        debug_assert!(shift >= SHIFT_PT);
        let pml4_slot = index_of(gpa, SHIFT_PML4);
        let pml4 = memory.read_entry(self.root, pml4_slot);
        let pdpt_table = if pml4 & entry::PRESENT != 0 {
            pml4 & entry::ADDR_MASK
        } else {
            let table = memory.alloc_table().ok_or(MmuError::OutOfMemory)?;
            memory.write_entry(self.root, pml4_slot, table | INTERMEDIATE_PERMS);
            table
        };
        if shift == SHIFT_PDPT {
            return Ok(pdpt_table);
        }
        let pdpt_slot = index_of(gpa, SHIFT_PDPT);
        let pdpt = memory.read_entry(pdpt_table, pdpt_slot);
        let pd_table = if pdpt & entry::PRESENT != 0 {
            pdpt & entry::ADDR_MASK
        } else {
            let table = memory.alloc_table().ok_or(MmuError::OutOfMemory)?;
            memory.write_entry(pdpt_table, pdpt_slot, table | INTERMEDIATE_PERMS);
            table
        };
        if shift == SHIFT_PD {
            return Ok(pd_table);
        }
        let pd_slot = index_of(gpa, SHIFT_PD);
        let pd = memory.read_entry(pd_table, pd_slot);
        let pt_table = if pd & entry::PRESENT != 0 {
            pd & entry::ADDR_MASK
        } else {
            let table = memory.alloc_table().ok_or(MmuError::OutOfMemory)?;
            memory.write_entry(pd_table, pd_slot, table | INTERMEDIATE_PERMS);
            table
        };
        Ok(pt_table)
    }
}

/// Index of an address in the table of level `shift`.
const fn index_of(addr: u64, shift: u32) -> usize {
    ((addr >> shift) & 0x1FF) as usize
}

/// Encodes the activation value of second-level translation (`EPTP`).
///
/// Format (SDM): bits 2:0 = memory type (6 = WB), bits 5:3 = walk
/// length minus 1 (3 for 4 levels), bit 6 = A/D, bits 51:12 = root.
pub const fn encode_second_level_pointer(
    root_phys: u64,
    memory_type: u8,
    four_levels: bool,
    accessed_dirty: bool,
) -> u64 {
    let mut value = (memory_type as u64) & 0x7;
    if four_levels {
        value |= 3 << 3;
    }
    if accessed_dirty {
        value |= 1 << 6;
    }
    value | (root_phys & entry::ADDR_MASK)
}
