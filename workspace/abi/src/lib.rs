#![no_std]

pub const ABI_VERSION_MAJOR: u16 = 0;
pub const ABI_VERSION_MINOR: u16 = 1;
/// Packed return format for `SYS_ABI_VERSION`: `(major << 16) | minor`.
pub const ABI_VERSION_PACKED: u32 = ((ABI_VERSION_MAJOR as u32) << 16) | (ABI_VERSION_MINOR as u32);

pub mod boot;
pub mod data;
pub mod errno;
pub mod flag;
pub mod ipc;
pub mod syscall;
