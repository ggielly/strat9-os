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

//! ACPI table definitions and basic SDT structures.
//! Inspired by Theseus OS.

use zerocopy::FromBytes;

/// The size in bytes of the ACPI SDT Header (`Sdt` struct).
pub const SDT_SIZE_IN_BYTES: usize = core::mem::size_of::<Sdt>();

/// An ACPI System Descriptor Table.
/// This is the header (the first part) of every ACPI table.
#[derive(Copy, Clone, Debug, FromBytes)]
#[repr(C, packed)]
pub struct Sdt {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
}

/// A struct used to describe the position and layout of registers
/// related to ACPI tables.
#[derive(Clone, Copy, Debug, FromBytes)]
#[repr(C, packed)]
pub struct GenericAddressStructure {
    pub address_space: u8,
    pub bit_width: u8,
    pub bit_offset: u8,
    pub access_size: u8,
    pub phys_addr: u64,
}
