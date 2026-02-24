#![no_std]

extern crate alloc;

pub mod syscalls;

pub use strat9_syscall::data::IpcMessage;

pub const OPCODE_OPEN: u32 = 0x01;
pub const OPCODE_READ: u32 = 0x02;
pub const OPCODE_WRITE: u32 = 0x03;
pub const OPCODE_CLOSE: u32 = 0x04;
