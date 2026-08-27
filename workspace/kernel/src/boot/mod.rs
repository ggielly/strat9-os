//! Boot subsystem
//!
//! Regroups all code involved in the early kernel startup:
//! - assembly stubs (16-bit => 64-bit transition)
//! - bootloader handoff structures (KernelArgs)
//! - Boot-protocol entry point
//! - Device Tree (FDT) parsing
//! - Block device abstraction
//! - FAT32 module loader
//! - early serial logger
//! - kernel panic handler
//! - simple TOML parser for kernel configuration

// Assembly stub that includes boot64.S
pub mod assembly;

/// KernelArgs structures shared between bootloader and kernel
pub mod entry;

/// Boot-protocol entry point (DTB/PVH)
pub mod dtb_boot;

/// Device Tree (FDT) parsing
pub mod fdt;

/// Block device abstraction
pub mod block_device;

/// VirtIO block device driver
pub mod virtio_blk;

/// FAT32 module loader
pub mod fat32_loader;

/// Early serial logger (used throughout the kernel lifetime)
pub mod logger;

/// Kernel panic handler
pub mod panic;

/// Kernel symbol table for panic backtrace resolution
pub mod symbols;

/// Centralized kernel.toml configuration application
pub mod config;

/// Simple TOML parser for kernel boot configuration
pub mod toml;

/// Boot-module lookup used by shell commands. With U-Boot the Limine backend
/// is gone; modules load from the FAT32 boot partition (Phase 4), so these
/// are empty stubs until that lands.
pub mod limine_shim {
    pub fn kernel_elf_bytes() -> Option<&'static [u8]> {
        None
    }
    pub fn test_exec_module() -> Option<(u64, u64)> {
        None
    }
    pub fn test_exec_helper_module() -> Option<(u64, u64)> {
        None
    }
    pub fn test_syscalls_module() -> Option<(u64, u64)> {
        None
    }
    pub fn test_mem_module() -> Option<(u64, u64)> {
        None
    }
}
