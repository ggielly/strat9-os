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

//! s9vm — guest page tables for a 64-bit guest entry.
//!
//! A 64-bit guest is entered with paging already enabled: the processor
//! translates every guest-linear access through the guest's own four-level
//! tables, then the second-level tables translate the resulting guest-physical
//! address again. The second level is built by [`super::mmu`]; this module
//! builds the **first** level (the guest's `CR3` hierarchy) when the guest
//! cannot build it itself.
//!
//! That is the case of the 64-bit boot protocol: the boot loader must hand the
//! kernel an identity mapping covering the image it loads (`init_size` bytes
//! from the image start), the boot parameter page and the command line, with a
//! flat 64-bit code and data segment. The guest kernel then installs its own
//! tables. Providing the mapping here keeps the loader generic and testable.
//!
//! # Design
//!
//! Tables are allocated through [`TableMemory`], the same provider the
//! second-level tables use: the kernel supplies frames and writes them through
//! the direct map, the host tests supply a byte vector. Every table is a 512
//! entry, 4 KiB aligned array; a table handle is its guest-physical address.
//!
//! Mapping uses 2 MiB pages when the range allows it and 4 KiB pages
//! otherwise: a range is split into an optional 4 KiB prefix, a 2 MiB aligned
//! middle and an optional 4 KiB tail. Permission bits are per range, so the
//! image can be mapped execute-only while the boot parameters are writable.
//!
//! Overlapping ranges are rejected ([`PtError::Conflict`]) rather than merged:
//! the boot mapping is a small, known set, and silently picking one of two
//! permissions would hide a loader bug. Addresses must be canonical in the
//! 48-bit sense — the guest kernel is entered in 4-level paging mode.
//!
//! Testable on the host (L2 tests).

use alloc::vec::Vec;

use super::mmu::{TableMemory, PAGE_SIZE};

/// Number of entries in one table page.
pub const ENTRY_COUNT: usize = 512;
/// Shift of the PML4 index.
pub const SHIFT_PML4: u32 = 39;
/// Shift of the PDPT index.
pub const SHIFT_PDPT: u32 = 30;
/// Shift of the page-directory index.
pub const SHIFT_PD: u32 = 21;
/// Shift of the page-table index.
pub const SHIFT_PT: u32 = 12;
/// Size of a 2 MiB page.
pub const LARGE_2MB: u64 = 2 * 1024 * 1024;
/// Size of a 1 GiB page.
pub const LARGE_1GB: u64 = 1024 * 1024 * 1024;
/// Highest guest-linear address representable with 4-level paging.
pub const MAX_LINEAR: u64 = 1 << 48;
/// Physical address mask of a table entry (bits 51:12).
pub const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Page-table entry bits.
pub mod entry {
    /// Present.
    pub const PRESENT: u64 = 1 << 0;
    /// Writable.
    pub const WRITABLE: u64 = 1 << 1;
    /// User-accessible.
    pub const USER: u64 = 1 << 2;
    /// Write-through.
    pub const PWT: u64 = 1 << 3;
    /// Cache-disable.
    pub const PCD: u64 = 1 << 4;
    /// Accessed (set by the processor; the model leaves it clear).
    pub const ACCESSED: u64 = 1 << 5;
    /// Page size: a 1 GiB PDPTE or a 2 MiB PDE.
    pub const LARGE_PAGE: u64 = 1 << 7;
    /// No-execute (bit 63, requires `EFER.NXE`).
    pub const NO_EXECUTE: u64 = 1 << 63;
}

/// Permission set of one mapped range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtPerms {
    /// The page is writable.
    pub writable: bool,
    /// The page is executable (clears the no-execute bit).
    pub executable: bool,
    /// The page is user-accessible.
    pub user: bool,
}

impl PtPerms {
    /// Supervisor read/write/execute page (the boot mapping of the image).
    pub const KERNEL_RWX: Self = Self {
        writable: true,
        executable: true,
        user: false,
    };
    /// Supervisor read-write, non-executable page (boot parameters).
    pub const KERNEL_RW: Self = Self {
        writable: true,
        executable: false,
        user: false,
    };
    /// Supervisor read-only, non-executable page.
    pub const KERNEL_RO: Self = Self {
        writable: false,
        executable: false,
        user: false,
    };

    /// Encodes the permission bits of a leaf entry.
    pub const fn leaf_bits(self) -> u64 {
        let mut bits = entry::PRESENT;
        if self.writable {
            bits |= entry::WRITABLE;
        }
        if self.user {
            bits |= entry::USER;
        }
        if !self.executable {
            bits |= entry::NO_EXECUTE;
        }
        bits
    }
}

/// One identity-mapped range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityRange {
    /// First guest-linear address, page aligned.
    pub start: u64,
    /// Number of bytes, page aligned.
    pub len: u64,
    /// Permissions of every page of the range.
    pub perms: PtPerms,
}

impl IdentityRange {
    /// Creates a range, without validating it.
    pub const fn new(start: u64, len: u64, perms: PtPerms) -> Self {
        Self { start, len, perms }
    }

    /// Last byte of the range, exclusive.
    pub const fn end(&self) -> u64 {
        self.start.saturating_add(self.len)
    }
}

/// Errors of the guest page-table builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtError {
    /// The table provider ran out of frames.
    OutOfMemory,
    /// A range is empty, unaligned or beyond the 4-level linear space.
    InvalidRange,
    /// The range crosses a 2 MiB or 1 GiB boundary where a large page was
    /// requested.
    Misaligned,
    /// The range overlaps an existing mapping with different permissions.
    Conflict,
    /// The provider returned a table page that cannot hold entries (not 4 KiB
    /// aligned).
    BadTable,
}

/// Guest `CR3` hierarchy built by this module.
#[derive(Debug)]
pub struct GuestPageTables {
    root: u64,
    frames: Vec<u64>,
}

impl GuestPageTables {
    /// Builds an identity mapping for `ranges`.
    ///
    /// The first table allocated is the PML4; every later allocation is a
    /// sub-table. On error the frames allocated so far are returned to the
    /// provider, so a failed build leaves no leak.
    pub fn build<M: TableMemory>(
        memory: &mut M,
        ranges: &[IdentityRange],
    ) -> Result<Self, PtError> {
        for range in ranges {
            validate_range(range)?;
        }
        let root = memory.alloc_table().ok_or(PtError::OutOfMemory)?;
        let mut frames = Vec::new();
        frames.push(root);
        for range in ranges {
            if let Err(error) = map_range(memory, &mut frames, root, range) {
                for frame in frames.iter().rev() {
                    memory.free_table(*frame);
                }
                return Err(error);
            }
        }
        Ok(Self { root, frames })
    }

    /// Guest-physical address of the PML4, the value the guest's `CR3` must
    /// hold.
    pub const fn root_phys(&self) -> u64 {
        self.root
    }

    /// Value to load in `CR3` (the root, without cache bits).
    pub const fn cr3(&self) -> u64 {
        self.root
    }

    /// Every table frame of the hierarchy, root first.
    pub fn frames(&self) -> &[u64] {
        &self.frames
    }

    /// Number of table pages allocated.
    pub fn table_count(&self) -> usize {
        self.frames.len()
    }

    /// Frees every table page, root last.
    pub fn release<M: TableMemory>(&self, memory: &mut M) {
        for frame in self.frames.iter().rev() {
            memory.free_table(*frame);
        }
    }

    /// Translates one guest-linear address through the built tables.
    ///
    /// Returns the guest-physical address and the permission bits of the leaf
    /// that maps it. A walk stops at the first non-present entry.
    pub fn translate<M: TableMemory>(&self, memory: &M, address: u64) -> Option<(u64, u64)> {
        let pml4 = memory.read_entry(self.root, index_of(address, SHIFT_PML4));
        if pml4 & entry::PRESENT == 0 {
            return None;
        }
        let pdpt = memory.read_entry(phys_of(pml4), index_of(address, SHIFT_PDPT));
        if pdpt & entry::PRESENT == 0 {
            return None;
        }
        if pdpt & entry::LARGE_PAGE != 0 {
            return Some((phys_of(pdpt) + (address & (LARGE_1GB - 1)), pdpt));
        }
        let pd = memory.read_entry(phys_of(pdpt), index_of(address, SHIFT_PD));
        if pd & entry::PRESENT == 0 {
            return None;
        }
        if pd & entry::LARGE_PAGE != 0 {
            return Some((phys_of(pd) + (address & (LARGE_2MB - 1)), pd));
        }
        let pt = memory.read_entry(phys_of(pd), index_of(address, SHIFT_PT));
        if pt & entry::PRESENT == 0 {
            return None;
        }
        Some((phys_of(pt) + (address & (PAGE_SIZE - 1)), pt))
    }
}

/// Maps one validated range into the hierarchy rooted at `root`.
fn map_range<M: TableMemory>(
    memory: &mut M,
    frames: &mut Vec<u64>,
    root: u64,
    range: &IdentityRange,
) -> Result<(), PtError> {
    let leaf = range.perms.leaf_bits();
    let mut cursor = range.start;
    let end = range.end();
    while cursor < end {
        // A 2 MiB page can only start on a 2 MiB boundary and must be fully
        // inside the range; otherwise map 4 KiB pages until the next boundary.
        let to_boundary = LARGE_2MB - (cursor % LARGE_2MB);
        let remaining = end - cursor;
        if cursor % LARGE_2MB == 0 && remaining >= LARGE_2MB {
            map_large(memory, frames, root, cursor, leaf)?;
            cursor += LARGE_2MB;
        } else {
            let chunk = to_boundary.min(remaining);
            map_small(memory, frames, root, cursor, chunk, leaf)?;
            cursor += chunk;
        }
    }
    Ok(())
}

/// Maps one 2 MiB leaf at `address` (2 MiB aligned).
fn map_large<M: TableMemory>(
    memory: &mut M,
    frames: &mut Vec<u64>,
    root: u64,
    address: u64,
    leaf: u64,
) -> Result<(), PtError> {
    let pd = ensure_table(memory, frames, root, address, SHIFT_PD)?;
    let slot = index_of(address, SHIFT_PD);
    let existing = memory.read_entry(pd, slot);
    if existing & entry::PRESENT != 0 {
        return Err(PtError::Conflict);
    }
    memory.write_entry(pd, slot, address | leaf | entry::LARGE_PAGE);
    Ok(())
}

/// Maps `len` bytes of 4 KiB pages starting at `address`.
fn map_small<M: TableMemory>(
    memory: &mut M,
    frames: &mut Vec<u64>,
    root: u64,
    address: u64,
    len: u64,
    leaf: u64,
) -> Result<(), PtError> {
    let mut offset = 0u64;
    while offset < len {
        let current = address + offset;
        let pt = ensure_table(memory, frames, root, current, SHIFT_PT)?;
        let slot = index_of(current, SHIFT_PT);
        let existing = memory.read_entry(pt, slot);
        if existing & entry::PRESENT != 0 {
            return Err(PtError::Conflict);
        }
        memory.write_entry(pt, slot, current | leaf);
        offset += PAGE_SIZE;
    }
    Ok(())
}

/// Ensures the table that holds `address` at level `shift` exists and returns
/// its frame.
///
/// `shift` is the shift of the entries of the table being returned (so a
/// `SHIFT_PT` request returns the page table holding 4 KiB leaves). Intermediate
/// tables are allocated on demand and recorded in `frames`.
fn ensure_table<M: TableMemory>(
    memory: &mut M,
    frames: &mut Vec<u64>,
    root: u64,
    address: u64,
    shift: u32,
) -> Result<u64, PtError> {
    let mut table = root;
    let mut level = SHIFT_PML4;
    while level > shift {
        let slot = index_of(address, level);
        let entry = memory.read_entry(table, slot);
        if entry & entry::PRESENT != 0 {
            if entry & entry::LARGE_PAGE != 0 {
                // A large page already covers the requested address; the
                // caller treats this as a conflict.
                return Err(PtError::Conflict);
            }
            table = phys_of(entry);
        } else {
            let next = memory.alloc_table().ok_or(PtError::OutOfMemory)?;
            if next % PAGE_SIZE != 0 {
                memory.free_table(next);
                return Err(PtError::BadTable);
            }
            frames.push(next);
            memory.write_entry(table, slot, next | entry::PRESENT | entry::WRITABLE);
            table = next;
        }
        level = match level {
            SHIFT_PML4 => SHIFT_PDPT,
            SHIFT_PDPT => SHIFT_PD,
            _ => SHIFT_PT,
        };
    }
    Ok(table)
}

/// Validates one range before any allocation.
fn validate_range(range: &IdentityRange) -> Result<(), PtError> {
    if range.len == 0 || range.start % PAGE_SIZE != 0 || range.len % PAGE_SIZE != 0 {
        return Err(PtError::InvalidRange);
    }
    if range.start >= MAX_LINEAR
        || range
            .start
            .checked_add(range.len)
            .map_or(true, |end| end > MAX_LINEAR)
    {
        return Err(PtError::InvalidRange);
    }
    Ok(())
}

/// Index of `address` in the table selected by `shift`.
pub const fn index_of(address: u64, shift: u32) -> usize {
    ((address >> shift) & (ENTRY_COUNT as u64 - 1)) as usize
}

/// Physical address encoded in a table entry.
pub const fn phys_of(entry: u64) -> u64 {
    entry & ADDR_MASK
}
