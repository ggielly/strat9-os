//! Definitions for the DMAR, the Direct Memory Access (DMA) Remapping ACPI table.
//! Inspired by Theseus OS.

use super::sdt::Sdt;
use zerocopy::{FromBytes, FromZeroes};

pub const DMAR_SIGNATURE: &[u8; 4] = b"DMAR";

#[derive(Clone, Copy, Debug, FromBytes, FromZeroes)]
#[repr(C, packed)]
struct DmarReporting {
    header: Sdt,
    host_address_width: u8,
    flags: u8,
    _reserved: [u8; 10],
}

pub struct Dmar {
    table: &'static DmarReporting,
}

impl Dmar {
    pub fn get() -> Option<Self> {
        unsafe {
            super::find_table(DMAR_SIGNATURE).map(|ptr| Dmar {
                table: &*(ptr as *const DmarReporting),
            })
        }
    }

    pub fn host_address_width(&self) -> u8 {
        self.table.host_address_width + 1
    }

    pub fn flags(&self) -> u8 {
        self.table.flags
    }
}
