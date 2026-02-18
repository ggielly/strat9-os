#![no_std]

extern crate alloc;

pub mod syscalls;

/// IPC Message format (64 bytes, cache-line aligned)
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct IpcMessage {
    pub sender: u64,
    pub msg_type: u32,
    pub flags: u32,
    pub payload: [u8; 48],
}

impl IpcMessage {
    pub fn new(msg_type: u32) -> Self {
        IpcMessage {
            sender: 0,
            msg_type,
            flags: 0,
            payload: [0u8; 48],
        }
    }

    pub fn error_reply(sender: u64, status: i32) -> Self {
        let mut msg = IpcMessage::new(0x81); // 0x81 = Generic error reply
        msg.sender = sender;
        msg.payload[0..4].copy_from_slice(&(status as u32).to_le_bytes());
        msg
    }
}

pub const OPCODE_OPEN: u32 = 0x01;
pub const OPCODE_READ: u32 = 0x02;
pub const OPCODE_WRITE: u32 = 0x03;
pub const OPCODE_CLOSE: u32 = 0x04;
