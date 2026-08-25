//! IPC handshake protocol for connection negotiation.
//!
//! When a client connects to a server via IPC, it first sends an
//! [`IpcHandshake`] message. The server validates the magic number and
//! protocol version, then replies with an [`IpcHandshakeReply`].
//!
//! # Handshake flow
//!
//! ```text
//! Client                          Server
//!   │                               │
//!   │── IpcHandshake ──────────────▶│
//!   │   (magic, version, nonce)     │
//!   │                               │
//!   │◀── IpcHandshakeReply ─────────│
//!   │   (magic, version, status)    │
//!   │                               │
//!   │── normal IPC messages ───────▶│
//! ```
//!
//! # Example
//!
//! ```ignore
//! use strat9_abi::ipc::{IpcHandshake, IpcHandshakeReply};
//!
//! // Client builds a handshake
//! let handshake = IpcHandshake::new_with_nonce(0xDEAD_BEEF);
//! assert!(handshake.is_valid());
//! assert!(handshake.is_compatible());
//!
//! // Server validates and replies
//! let reply = if handshake.is_compatible() {
//!     IpcHandshakeReply::ok()
//! } else {
//!     IpcHandshakeReply::reject(1) // VERSION_MISMATCH
//! };
//! ```

use zerocopy::{FromBytes, IntoBytes};

/// Magic number for IPC handshake (`"IPC9"` in ASCII).
///
/// Both client and server must agree on this value. If the magic doesn't
/// match, the connection is rejected immediately.
pub const IPC_HANDSHAKE_MAGIC: u32 = 0x4950_4339; // "IPC9"

/// Current IPC protocol version.
///
/// Increment when the handshake format or IPC wire protocol changes.
/// A version mismatch causes the server to reject the connection.
pub const IPC_PROTOCOL_VERSION: u16 = 1;

/// First message a client sends after `ipc_connect` to negotiate protocol.
///
/// Wire size: 20 bytes.
///
/// # Fields
///
/// - `magic`: must be [`IPC_HANDSHAKE_MAGIC`] (`0x4950_4339`)
/// - `protocol_version`: client's IPC protocol version
/// - `client_abi_major/minor`: client's ABI version
/// - `nonce`: random value for connection identification (optional)
/// - `flags`: reserved for future use (must be 0)
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct IpcHandshake {
    /// Magic number (`"IPC9"`).
    pub magic: u32,
    /// IPC protocol version.
    pub protocol_version: u16,
    pub _reserved: u16,
    /// Client ABI major version.
    pub client_abi_major: u16,
    /// Client ABI minor version.
    pub client_abi_minor: u16,
    /// Random nonce for connection identification.
    pub nonce: u32,
    /// Reserved flags (must be 0).
    pub flags: u32,
}

impl IpcHandshake {
    /// Build a default handshake with a zero nonce.
    pub const fn new() -> Self {
        Self::new_with_nonce(0)
    }

    /// Build a handshake with a caller-provided nonce.
    ///
    /// The nonce is used by the server to uniquely identify this connection.
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

    /// Return true when the message carries the expected handshake magic.
    pub fn is_valid(&self) -> bool {
        self.magic == IPC_HANDSHAKE_MAGIC
    }

    /// Return true when magic and protocol version match this ABI.
    pub fn is_compatible(&self) -> bool {
        self.is_valid() && self.protocol_version == IPC_PROTOCOL_VERSION
    }

    /// Return true when any reserved field is non-zero.
    ///
    /// Reserved fields must be zero on the wire; servers should reject
    /// such handshakes so that future protocol upgrades cannot smuggle
    /// new semantics past a validator that ignores them.
    pub fn has_reserved_bits_set(&self) -> bool {
        self._reserved != 0 || self.flags != 0
    }
}

/// Server reply to a handshake.
///
/// Wire size: 16 bytes.
///
/// # Fields
///
/// - `magic`: echo of [`IPC_HANDSHAKE_MAGIC`]
/// - `protocol_version`: server's IPC protocol version
/// - `status`: result code (`IPC_HANDSHAKE_OK`, `_VERSION_MISMATCH`, or `_REJECTED`)
/// - `server_abi_major/minor`: server's ABI version
/// - `flags`: reserved for future use
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct IpcHandshakeReply {
    /// Echo of the handshake magic.
    pub magic: u32,
    /// Server's IPC protocol version.
    pub protocol_version: u16,
    /// Handshake status code.
    pub status: u16,
    /// Server ABI major version.
    pub server_abi_major: u16,
    /// Server ABI minor version.
    pub server_abi_minor: u16,
    /// Reserved flags.
    pub flags: u32,
}

/// Handshake succeeded.
pub const IPC_HANDSHAKE_OK: u16 = 0;

/// Protocol version mismatch between client and server.
pub const IPC_HANDSHAKE_VERSION_MISMATCH: u16 = 1;

/// Connection rejected by the server (permissions, capacity, etc.).
pub const IPC_HANDSHAKE_REJECTED: u16 = 2;
impl IpcHandshakeReply {
    /// Build a successful handshake reply for the current ABI version.
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

    /// Build a rejected handshake reply with an explicit status code.
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

    /// Return true when any reserved field is non-zero
    /// (see [`IpcHandshake::has_reserved_bits_set`]).
    pub fn has_reserved_bits_set(&self) -> bool {
        self.flags != 0
    }
}

static_assertions::assert_eq_size!(IpcHandshake, [u8; 20]);
static_assertions::assert_eq_size!(IpcHandshakeReply, [u8; 16]);
