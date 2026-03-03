use zerocopy::{FromBytes, IntoBytes};

pub const IPC_HANDSHAKE_MAGIC: u32 = 0x4950_4339; // "IPC9"
pub const IPC_PROTOCOL_VERSION: u16 = 1;

/// First message a client sends after `ipc_connect` to negotiate protocol.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct IpcHandshake {
    pub magic: u32,
    pub protocol_version: u16,
    pub _reserved: u16,
    pub client_abi_major: u16,
    pub client_abi_minor: u16,
    pub nonce: u32,
    pub flags: u32,
}

impl IpcHandshake {
    pub const fn new() -> Self {
        Self::new_with_nonce(0)
    }

    pub const fn new_with_nonce(nonce: u32) -> Self {
        Self {
            magic: IPC_HANDSHAKE_MAGIC,
            protocol_version: IPC_PROTOCOL_VERSION,
            _reserved: 0,
            client_abi_major: crate::ABI_VERSION_MAJOR,
            client_abi_minor: crate::ABI_VERSION_MINOR,
            nonce,
            flags: 0,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.magic == IPC_HANDSHAKE_MAGIC
    }

    pub fn is_compatible(&self) -> bool {
        self.is_valid() && self.protocol_version == IPC_PROTOCOL_VERSION
    }
}

/// Server reply to a handshake.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct IpcHandshakeReply {
    pub magic: u32,
    pub protocol_version: u16,
    pub status: u16,
    pub server_abi_major: u16,
    pub server_abi_minor: u16,
    pub flags: u32,
}

pub const IPC_HANDSHAKE_OK: u16 = 0;
pub const IPC_HANDSHAKE_VERSION_MISMATCH: u16 = 1;
pub const IPC_HANDSHAKE_REJECTED: u16 = 2;

impl IpcHandshakeReply {
    pub const fn ok() -> Self {
        Self {
            magic: IPC_HANDSHAKE_MAGIC,
            protocol_version: IPC_PROTOCOL_VERSION,
            status: IPC_HANDSHAKE_OK,
            server_abi_major: crate::ABI_VERSION_MAJOR,
            server_abi_minor: crate::ABI_VERSION_MINOR,
            flags: 0,
        }
    }

    pub const fn reject(status: u16) -> Self {
        Self {
            magic: IPC_HANDSHAKE_MAGIC,
            protocol_version: IPC_PROTOCOL_VERSION,
            status,
            server_abi_major: crate::ABI_VERSION_MAJOR,
            server_abi_minor: crate::ABI_VERSION_MINOR,
            flags: 0,
        }
    }
}

static_assertions::assert_eq_size!(IpcHandshake, [u8; 20]);
static_assertions::assert_eq_size!(IpcHandshakeReply, [u8; 16]);
