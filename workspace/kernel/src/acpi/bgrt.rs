//! Support for the BGRT ACPI table (Boot Graphics Resource Table).
//! Provides information about the boot logo/image.
//!
//! Reference: ACPI spec 5.0+

use super::sdt::Sdt;
use zerocopy::{FromBytes, FromZeroes};

pub const BGRT_SIGNATURE: &[u8; 4] = b"BGRT";

/// BGRT status values
pub const BGRT_STATUS_DISPLAYED: u8 = 1;

/// BGRT image format
pub const BGRT_FORMAT_BMP: u16 = 0;

/// BGRT ACPI table structure
#[derive(Clone, Copy, Debug, FromBytes, FromZeroes)]
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
