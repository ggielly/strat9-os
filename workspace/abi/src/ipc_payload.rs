//! Typed `repr(C)` payload structs for fixed-size IPC messages.
//!
//! Each struct derives zerocopy's `FromBytes + IntoBytes + Immutable`,
//! enabling safe zero-cost cast to/from [`IpcMessage`] payloads via
//! [`encode_fixed`] / [`decode_fixed`].
//!
//! # Conventions
//!
//! - All sizes are ≤ 48 bytes (the payload capacity).
//! - Variable-length path/data fields use an [`InlineBlobHeader`] prefix.
//! - `status == 0` means success; non-zero is an errno-compatible error code.
//!
//! [`IpcMessage`]: crate::data::IpcMessage
//! [`encode_fixed`]: crate::ipc_codec::encode_fixed
//! [`decode_fixed`]: crate::ipc_codec::decode_fixed
//! [`InlineBlobHeader`]: crate::ipc_codec::InlineBlobHeader

use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::ipc_codec::InlineBlobHeader;

// ===========================================================================
// Helpers for compile-time size checks
// ===========================================================================

macro_rules! assert_payload_size {
    ($ty:ty) => {
        static_assertions::const_assert!(core::mem::size_of::<$ty>() <= 48);
    };
}

// ===========================================================================
// Generic status-only reply, this usd by every scheme)
// ===========================================================================

/// Minimal reply carrying only a status code.
///
/// Wire offset: `status @ 0..4`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct StatusReply {
    pub status: u32,
}
assert_payload_size!(StatusReply);

// ===========================================================================
// VFS / file-system scheme payloads
// ===========================================================================

/// Open request.
///
/// Wire layout:
///   `flags @ 0..4`, `path_hdr @ 4..8` (InlineBlobHeader), `path_data @ 8..`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct OpenRequest {
    pub flags: u32,
    /// InlineBlobHeader describing the path that follows.
    /// `kind` should be `0` for a plain path.
    pub path_hdr: InlineBlobHeader,
}
assert_payload_size!(OpenRequest);

/// Open reply.
///
/// Wire layout:
///   `status @ 0..4`, `_pad0 @ 4..8`, `ino @ 8..16`, `size @ 16..24`,
///   `file_flags @ 24..28`, `_pad1 @ 28..32`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct OpenReply {
    pub status: u32,
    pub _pad0: u32,
    pub ino: u64,
    pub size: u64,
    pub file_flags: u32,
    pub _pad1: u32,
}
assert_payload_size!(OpenReply);
static_assertions::assert_eq_size!(OpenReply, [u8; 32]);

/// Read request.
///
/// Wire layout:
///   `ino @ 0..8`, `offset @ 8..16`, `count @ 16..20`, `_pad @ 20..24`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct ReadRequest {
    pub ino: u64,
    pub offset: u64,
    pub count: u32,
    pub _pad: u32,
}
assert_payload_size!(ReadRequest);
static_assertions::assert_eq_size!(ReadRequest, [u8; 24]);

/// Read reply prefix (variable-length data follows).
///
/// Wire layout:
///   `status @ 0..4`, `count @ 4..8`, `data @ 8..`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct ReadReply {
    pub status: u32,
    /// Number of data bytes written starting at offset 8.
    pub count: u32,
}
assert_payload_size!(ReadReply);

/// Write request with variable-length inline data.
///
/// Wire layout:
///   `ino @ 0..8`, `offset @ 8..16`, `data_hdr @ 16..20`, `_pad @ 20..24`,
///   `data @ 24..`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct WriteRequest {
    pub ino: u64,
    pub offset: u64,
    pub data_hdr: InlineBlobHeader,
    pub _pad: u32,
}
assert_payload_size!(WriteRequest);
static_assertions::assert_eq_size!(WriteRequest, [u8; 24]);

/// Write reply.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct WriteReply {
    pub status: u32,
    pub written: u32,
}
assert_payload_size!(WriteReply);

/// Create request (file or directory).
///
/// Wire layout:
///   `mode @ 0..4`, `path_hdr @ 4..8`, `path_data @ 8..`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct CreateRequest {
    pub mode: u32,
    pub path_hdr: InlineBlobHeader,
}
assert_payload_size!(CreateRequest);

/// Create reply.
///
/// Wire layout:
///   `status @ 0..4`, `_pad @ 4..8`, `ino @ 8..16`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct CreateReply {
    pub status: u32,
    pub _pad: u32,
    pub ino: u64,
}
assert_payload_size!(CreateReply);
static_assertions::assert_eq_size!(CreateReply, [u8; 16]);

/// Close request.
///
/// Wire layout: `ino @ 0..8`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct CloseRequest {
    pub ino: u64,
}
assert_payload_size!(CloseRequest);

/// Stat request.
///
/// Wire layout: `ino @ 0..8`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct StatRequest {
    pub ino: u64,
}
assert_payload_size!(StatRequest);

/// Lseek request.
///
/// Wire layout: `ino @ 0..8`, `offset @ 8..16`, `whence @ 16..20`, `_pad @ 20..24`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct LseekRequest {
    pub ino: u64,
    pub offset: i64,
    pub whence: u32,
    pub _pad: u32,
}
assert_payload_size!(LseekRequest);
static_assertions::assert_eq_size!(LseekRequest, [u8; 24]);

/// Lseek reply.
///
/// Wire layout: `status @ 0..4`, `_pad @ 4..8`, `offset @ 8..16`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct LseekReply {
    pub status: u32,
    pub _pad: u32,
    pub offset: i64,
}
assert_payload_size!(LseekReply);
static_assertions::assert_eq_size!(LseekReply, [u8; 16]);

// ===========================================================================
// Network scheme payloads
// ===========================================================================

/// TCP connect request.
///
/// Wire layout:
///   `port @ 0..4`, `addr_hdr @ 4..8`, `addr_data @ 8..`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct TcpConnectRequest {
    pub port: u16,
    pub _padding: [u8; 2],
    pub addr_hdr: InlineBlobHeader,
}
assert_payload_size!(TcpConnectRequest);

/// TCP connect reply.
///
/// Wire layout: `status @ 0..4`, `_pad @ 4..8`, `conn_id @ 8..16`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct TcpConnectReply {
    pub status: u32,
    pub _pad: u32,
    pub conn_id: u64,
}
assert_payload_size!(TcpConnectReply);
static_assertions::assert_eq_size!(TcpConnectReply, [u8; 16]);
