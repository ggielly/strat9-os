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

//! Support for the BGRT ACPI table (Boot Graphics Resource Table).
//! Provides information about the boot logo/image.
//!
//! Reference: ACPI spec 5.0+
//! Source : https://uefi.org/sites/default/files/resources/ACPI_5_1_Errata_B.PDF
//!

use super::sdt::Sdt;
use zerocopy::FromBytes;

pub const BGRT_SIGNATURE: &[u8; 4] = b"BGRT";

/// BGRT status values
pub const BGRT_STATUS_DISPLAYED: u8 = 1;

/// BGRT image format
pub const BGRT_FORMAT_BMP: u16 = 0;

/// BGRT ACPI table structure
#[derive(Clone, Copy, Debug, FromBytes)]
#[repr(C, packed)]
pub struct Bgrt {
    pub header: Sdt,
    pub version: u16,
    pub status: u8,
    pub image_type: u8,
    pub image_base: u64,
    pub image_offset_x: u32,
    pub image_offset_y: u32,
}

impl Bgrt {
    /// Finds the BGRT and returns a reference to it.
    pub fn get() -> Option<&'static Bgrt> {
        unsafe { super::find_table(BGRT_SIGNATURE).map(|ptr| &*(ptr as *const Bgrt)) }
    }

    /// Check if the image was displayed by firmware
    pub fn was_displayed(&self) -> bool {
        (self.status & BGRT_STATUS_DISPLAYED) != 0
    }

    /// Get image format (0 = BMP)
    pub fn image_format(&self) -> u16 {
        self.image_type.into()
    }

    /// Get image base address
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Get image X offset
    pub fn image_offset_x(&self) -> u32 {
        self.image_offset_x
    }

    /// Get image Y offset
    pub fn image_offset_y(&self) -> u32 {
        self.image_offset_y
    }
}
