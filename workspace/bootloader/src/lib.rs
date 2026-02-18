#![no_std]
#![feature(allocator_api)]

extern crate alloc;

pub mod arch;
pub mod disk;
pub mod ext4;  // EXT4 filesystem support (primary)
pub mod main;  // Main bootloader logic
pub mod os;
// pub mod xfs;   // TODO XFS filesystem support (disabled, reserved for future use)

/// Kernel arguments structure passed from bootloader to kernel
#[repr(C, packed(8))]
#[derive(Debug, Clone, Copy)]
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
    pub framebuffer_stride: u32,
}

/// Memory region type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryKind {
    Free = 0,
    Reserved = 1,
    Kernel = 2,
    Device = 3,
    Reclaim = 4,
}

/// Memory region descriptor
#[repr(C, packed(8))]
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub kind: MemoryKind,
}
