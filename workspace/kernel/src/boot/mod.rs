/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

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

/// Physical boot-module validation and initfs address conversion.
pub mod modules;

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
