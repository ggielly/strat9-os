use zerocopy::{FromBytes, IntoBytes};

pub const STRAT9_BOOT_ABI_VERSION: u32 = 1;
pub const STRAT9_BOOT_MAGIC: u32 = 0x5354_3942; // "ST9B"

/// Bootloader-to-kernel handoff structure.
///
/// Passed by the bootloader to the kernel at entry point.
/// Layout is `#[repr(C)]` for natural alignment across all fields.
#[derive(Debug, FromBytes, IntoBytes)]
#[repr(C)]
pub struct KernelArgs {
    pub magic: u32,
    pub abi_version: u32,
    pub kernel_base: u64,
    pub kernel_size: u64,
    pub stack_base: u64,
    pub stack_size: u64,
    pub env_base: u64,
    pub env_size: u64,
    pub acpi_rsdp_base: u64,
    pub acpi_rsdp_size: u64,
    pub memory_map_base: u64,
    pub memory_map_size: u64,
    pub initfs_base: u64,
    pub initfs_size: u64,
    pub framebuffer_addr: u64,
    pub framebuffer_width: u32,
    pub framebuffer_height: u32,
    pub framebuffer_stride: u32,
    pub framebuffer_bpp: u16,
    pub framebuffer_red_mask_size: u8,
    pub framebuffer_red_mask_shift: u8,
    pub framebuffer_green_mask_size: u8,
    pub framebuffer_green_mask_shift: u8,
    pub framebuffer_blue_mask_size: u8,
    pub framebuffer_blue_mask_shift: u8,
    pub _padding1: u32,
    pub hhdm_offset: u64,
}

/// Memory region descriptor for the bootloader memory map.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub kind: MemoryKind,
}

/// Memory region type identifier.
///
/// Used by the bootloader to communicate the memory map to the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct MemoryKind(pub u64);

#[allow(non_upper_case_globals)]
impl MemoryKind {
    pub const Null: Self = Self(0);
    pub const Free: Self = Self(1);
    pub const Reclaim: Self = Self(2);
    pub const Reserved: Self = Self(3);
}

// ABI size assertions for bootloader structures
static_assertions::assert_eq_size!(KernelArgs, [u8; 144]);
static_assertions::const_assert_eq!(core::mem::align_of::<KernelArgs>(), 8);
static_assertions::assert_eq_size!(MemoryRegion, [u8; 24]);
static_assertions::const_assert_eq!(core::mem::align_of::<MemoryRegion>(), 8);
static_assertions::assert_eq_size!(MemoryKind, [u8; 8]);
