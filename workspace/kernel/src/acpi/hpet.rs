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

//! Support for the HPET: High Precision Event Timer.
//! Inspired by Theseus OS.

use super::sdt::{GenericAddressStructure, Sdt};
use zerocopy::FromBytes;

pub const HPET_SIGNATURE: &[u8; 4] = b"HPET";

/// The structure of the HPET ACPI table.
#[derive(Clone, Copy, Debug, FromBytes)]
#[repr(C, packed)]
pub struct HpetAcpiTable {
    pub header: Sdt,
    pub hardware_revision_id: u8,
    pub comparator_descriptor: u8,
    pub pci_vendor_id: u16,
    pub gen_addr_struct: GenericAddressStructure,
    pub hpet_number: u8,
    pub min_periodic_clock_tick: u16,
    /// also called 'page_protection'
    pub oem_attribute: u8,
}

impl HpetAcpiTable {
    /// Finds the HPET in the given `AcpiTables` and returns a reference to it.
    pub fn get() -> Option<&'static HpetAcpiTable> {
        unsafe { super::find_table(HPET_SIGNATURE).map(|ptr| &*(ptr as *const HpetAcpiTable)) }
    }
}
