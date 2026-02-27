// KernelArgs structures for bootloader handoff

/// KernelArgs passed by the custom bootloader (future use)
#[repr(C, packed(8))]
pub struct KernelArgs {
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
    pub framebuffer_stride: u32, // bytes per scanline (pitch)
    pub framebuffer_bpp: u16,
    pub framebuffer_red_mask_size: u8,
    pub framebuffer_red_mask_shift: u8,
    pub framebuffer_green_mask_size: u8,
    pub framebuffer_green_mask_shift: u8,
    pub framebuffer_blue_mask_size: u8,
    pub framebuffer_blue_mask_shift: u8,
    /// Higher Half Direct Map offset (0 for identity-mapped / BIOS boot)
    pub hhdm_offset: u64,
}

#[repr(C, packed(8))]
#[derive(Clone, Copy)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub kind: MemoryKind,
}

#[derive(Clone, Copy, Debug)]
#[repr(u64)]
pub enum MemoryKind {
    Null = 0,
    Free = 1,
    Reclaim = 2,
    Reserved = 3,
}
