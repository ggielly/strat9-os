#![no_std]

/// IPC opcodes for the network driver silo protocol.
///
/// A silo-hosted driver sends these to the kernel stub, which translates
/// them into `net_core::NetworkDevice` calls on the backing hardware.
pub mod opcodes {
    pub const NET_SEND: u32 = 0x40;
    pub const NET_RECV: u32 = 0x41;
    pub const NET_MAC_ADDR: u32 = 0x42;
    pub const NET_LINK_STATUS: u32 = 0x43;
    pub const NET_LIST_IFACES: u32 = 0x44;
}

/// Packet header prepended to IPC-transported frames.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetIpcHeader {
    pub opcode: u32,
    pub iface_id: u16,
    pub flags: u16,
    pub payload_len: u32,
}

/// Response header from kernel to silo.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetIpcReply {
    pub status: i32,
    pub payload_len: u32,
}
