use alloc::vec::Vec;
use core::{cell::RefCell, mem, ptr, slice};

use crate::os::{Os, OsHwDesc, OsKey, OsVideoMode};

// TODO: implement UEFI-specific modules
// mod acpi;
// mod arch;
// mod device;
// mod disk;
// mod display;
// #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
// pub mod dtb;
// mod memory_map;
// mod video_mode;

// Placeholder UEFI disk type
pub struct UefiDisk;

impl crate::disk::BlockDevice for UefiDisk {
    fn read(&mut self, _block: u64, _buffer: &mut [u8]) -> Result<(), crate::disk::BlockError> {
        Err(crate::disk::BlockError::NotReady)
    }

    fn write(&mut self, _block: u64, _buffer: &[u8]) -> Result<(), crate::disk::BlockError> {
        Err(crate::disk::BlockError::NotReady)
    }

    fn block_size(&self) -> usize {
        512
    }

    fn block_count(&self) -> u64 {
        0
    }
}

// Placeholder video mode iterator
pub struct VideoModeIter;

impl Iterator for VideoModeIter {
    type Item = crate::os::OsVideoMode;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

pub struct OsEfi;

impl OsEfi {
    pub fn new() -> Self {
        Self
    }
}

impl Os for OsEfi {
    type D = UefiDisk;
    type V = VideoModeIter;

    #[cfg(target_arch = "aarch64")]
    fn name(&self) -> &str {
        "aarch64/UEFI"
    }

    #[cfg(target_arch = "x86_64")]
    fn name(&self) -> &str {
        "x86_64/UEFI"
    }

    #[cfg(target_arch = "riscv64")]
    fn name(&self) -> &str {
        "riscv64/UEFI"
    }

    fn alloc_zeroed_page_aligned(&self, size: usize) -> *mut u8 {
        // TODO: Implement UEFI memory allocation
        ptr::null_mut()
    }

    fn page_size(&self) -> usize {
        4096
    }

    fn boot_disk(&self) -> Option<UefiDisk> {
        // TODO: implement UEFI disk detection
        // Will search for EXT4 partitions on UEFI block devices
        log::debug!("UEFI boot disk: not yet implemented");
        None
    }

    fn hwdesc(&self) -> OsHwDesc {
        // TODO: Implement ACPI/DTB detection for UEFI
        log::debug!("UEFI hwdesc: not yet implemented");
        OsHwDesc::NotFound
    }

    fn video_outputs(&self) -> usize {
        // TODO: implement UEFI GOP video output detection
        0
    }

    fn video_modes(&self, _output_i: usize) -> VideoModeIter {
        VideoModeIter
    }

    fn set_video_mode(&self, _output_i: usize, _mode: &mut OsVideoMode) {
        // TODO: Implement UEFI video mode setting
    }

    fn best_resolution(&self, _output_i: usize) -> Option<(u32, u32)> {
        // TODO: implement EDID reading from UEFI
        None
    }

    fn get_key(&self) -> OsKey {
        // TODO: implement UEFI keyboard input
        OsKey::Other
    }

    fn clear_text(&self) {
        // TODO: implement UEFI text clearing
    }

    fn get_text_position(&self) -> (usize, usize) {
        (0, 0)
    }

    fn set_text_position(&self, _x: usize, _y: usize) {
        // TODO: implement UEFI cursor positioning
    }

    fn set_text_highlight(&self, _highlight: bool) {
        // TODO: implement UEFI text highlighting
    }
}