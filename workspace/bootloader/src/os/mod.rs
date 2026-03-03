use crate::disk::BlockDevice;

#[cfg(all(target_arch = "x86", target_os = "none"))]
pub use self::bios::*;

#[cfg(all(target_arch = "x86", target_os = "none"))]
#[macro_use]
mod bios;

#[cfg(any(target_arch = "riscv64", target_os = "uefi"))]
#[allow(unused_imports)]
pub use self::uefi::*;

#[cfg(any(target_arch = "riscv64", target_os = "uefi"))]
#[macro_use]
mod uefi;

#[derive(Clone, Copy, Debug)]
pub enum OsHwDesc {
    Acpi(u64, u64),
    DeviceTree(u64, u64),
    NotFound,
}

#[derive(Clone, Copy, Debug)]
pub enum OsKey {
    Left,
    Right,
    Up,
    Down,
    Backspace,
    Delete,
    Enter,
    Char(char),
    Other,
}

pub use strat9_abi::boot::MemoryKind as OsMemoryKind;
pub use strat9_abi::boot::MemoryRegion as OsMemoryEntry;

#[derive(Clone, Copy, Debug)]
pub struct OsVideoMode {
    pub id: u32,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub base: u64,
}

pub trait Os {
    type D: BlockDevice;
    type V: Iterator<Item = OsVideoMode>;

    /// Performs the name operation.
    fn name(&self) -> &str;

    /// Allocates zeroed page aligned.
    fn alloc_zeroed_page_aligned(&self, size: usize) -> *mut u8;

    /// Performs the page size operation.
    #[allow(dead_code)]
    fn page_size(&self) -> usize;

    /// Get the boot disk as a block device
    /// This will be used to search for EXT4 partitions
    fn boot_disk(&self) -> Option<Self::D>;

    /// Performs the hwdesc operation.
    fn hwdesc(&self) -> OsHwDesc;

    /// Performs the video outputs operation.
    fn video_outputs(&self) -> usize;
    /// Performs the video modes operation.
    fn video_modes(&self, output_i: usize) -> Self::V;
    /// Sets video mode.
    fn set_video_mode(&self, output_i: usize, mode: &mut OsVideoMode);
    /// Performs the best resolution operation.
    fn best_resolution(&self, output_i: usize) -> Option<(u32, u32)>;

    /// Returns key.
    fn get_key(&self) -> OsKey;

    /// Performs the clear text operation.
    fn clear_text(&self);
    /// Returns text position.
    fn get_text_position(&self) -> (usize, usize);
    /// Sets text position.
    fn set_text_position(&self, x: usize, y: usize);
    /// Sets text highlight.
    fn set_text_highlight(&self, highlight: bool);
}