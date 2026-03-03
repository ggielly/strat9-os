#![no_std]
#![feature(allocator_api)]

extern crate alloc;

pub mod arch;
pub mod disk;
pub mod ext4;  // EXT4 filesystem support (primary)
pub mod main;  // Main bootloader logic
pub mod os;
// pub mod xfs;   // TODO XFS filesystem support (disabled, reserved for future use)

pub use strat9_abi::boot::{KernelArgs, MemoryKind, MemoryRegion};
