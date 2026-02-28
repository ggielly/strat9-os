//! Support for the SLIT ACPI table (System Locality Information Table).
//! Provides information about NUMA node distances.
//!
//! Reference: ACPI spec 2.0+

use super::sdt::Sdt;
use zerocopy::{FromBytes, FromZeroes};

pub const SLIT_SIGNATURE: &[u8; 4] = b"SLIT";

/// SLIT ACPI table structure
#[derive(Clone, Copy, Debug, FromBytes, FromZeroes)]
#[repr(C, packed)]
pub struct Slit {
    pub header: Sdt,
    pub locality_count: u64,
    // Followed by locality_count * locality_count bytes of distance data
}

impl Slit {
    /// Finds the SLIT and returns a reference to it.
    pub fn get() -> Option<&'static Slit> {
        unsafe { super::find_table(SLIT_SIGNATURE).map(|ptr| &*(ptr as *const Slit)) }
    }

    /// Get number of system localities (NUMA nodes)
    pub fn num_localities(&self) -> u64 {
        self.locality_count
    }

    /// Get distance between two localities
    /// Returns 255 if indices are out of bounds
    pub fn distance(&self, from: u64, to: u64) -> u8 {
        if from >= self.locality_count || to >= self.locality_count {
            return 255;
        }

        let offset = core::mem::size_of::<Slit>();
        let index = (from * self.locality_count + to) as usize;
        let ptr = (self as *const Slit as *const u8).add(offset + index);

        unsafe { core::ptr::read_volatile(ptr) }
    }

    /// Get all distances for a locality
    pub fn locality_distances(&self, from: u64) -> Option<&[u8]> {
        if from >= self.locality_count {
            return None;
        }

        let offset = core::mem::size_of::<Slit>();
        let start = offset + (from * self.locality_count) as usize;
        let len = self.locality_count as usize;

        let ptr = (self as *const Slit as *const u8).add(start);

        Some(unsafe { core::slice::from_raw_parts(ptr, len) })
    }
}

/// Default distance value (same locality)
pub const DISTANCE_LOCAL: u8 = 10;

/// Default distance value (different locality)
pub const DISTANCE_REMOTE: u8 = 20;
