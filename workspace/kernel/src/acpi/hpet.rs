//! Support for the HPET: High Precision Event Timer.
//! Inspired by Theseus OS.

use super::sdt::{GenericAddressStructure, Sdt};
use zerocopy::{FromBytes, FromZeroes};

pub const HPET_SIGNATURE: &[u8; 4] = b"HPET";

/// The structure of the HPET ACPI table.
#[derive(Clone, Copy, Debug, FromBytes, FromZeroes)]
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
