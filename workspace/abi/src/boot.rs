pub const STRAT9_BOOT_ABI_VERSION: u32 = 1;
pub const STRAT9_BOOT_MAGIC: u32 = 0x5354_3942; // "ST9B"

#[derive(Debug)]
#[repr(C, packed(8))]
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
    pub hhdm_offset: u64,
}

#[repr(C, packed(8))]
#[derive(Clone, Copy)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub kind: MemoryKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum MemoryKind {
    Null = 0,
    Free = 1,
    Reclaim = 2,
    Reserved = 3,
}
