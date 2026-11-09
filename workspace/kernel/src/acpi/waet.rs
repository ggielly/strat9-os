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

//! Definitions for WAET, the Windows ACPI Emulated devices Table.
//! Inspired by Theseus OS.

use super::sdt::Sdt;
use zerocopy::FromBytes;

pub const WAET_SIGNATURE: &[u8; 4] = b"WAET";

/// The Windows ACPI Emulated devices Table (WAET) allows virtualized OSes
/// to avoid workarounds for errata on physical devices.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, FromBytes)]
pub struct Waet {
    pub header: Sdt,
    pub emulated_device_flags: u32,
}

impl Waet {
    /// Finds the WAET in the given `AcpiTables` and returns a reference to it.
    pub fn get() -> Option<&'static Waet> {
        unsafe { super::find_table(WAET_SIGNATURE).map(|ptr| &*(ptr as *const Waet)) }
    }

    /// Returns whether the RTC has been enhanced not to require
    /// acknowledgment after it asserts an interrupt.
    pub fn rtc_good(&self) -> bool {
        const RTC_GOOD: u32 = 1 << 0;
        self.emulated_device_flags & RTC_GOOD == RTC_GOOD
    }

    /// Returns whether the ACPI PM timer has been enhanced not to require
    /// multiple reads.
    pub fn acpi_pm_timer_good(&self) -> bool {
        const ACPI_PM_TIMER_GOOD: u32 = 1 << 1;
        self.emulated_device_flags & ACPI_PM_TIMER_GOOD == ACPI_PM_TIMER_GOOD
    }
}
