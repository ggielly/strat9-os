#![no_std]

pub const ABI_VERSION_MAJOR: u16 = 0;
pub const ABI_VERSION_MINOR: u16 = 1;

pub mod boot;
pub mod data;
pub mod errno;
pub mod flag;
pub mod ipc;
pub mod syscall;
