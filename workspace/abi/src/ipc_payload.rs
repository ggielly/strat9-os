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
//! - Padding fields are named `_pad` or `_reserved` and must be zero.
//!
//! # Wire format
//!
//! Messages are sent through IPC ports or channels as raw bytes.
//! The `msg_type` field in the `IpcMessage` header identifies the operation.
//! The `payload` field contains the struct-specific data.
//!
//! # Example
//!
//! ```ignore
//! use strat9_abi::ipc_codec::{encode_fixed, decode_fixed, put_str, InlineBlobHeader};
//! use strat9_abi::ipc_payload::{OpenRequest, OpenReply};
//!
//! // Encode an open request with path "/tmp/test"
//! let mut msg = encode_fixed(0x01, &OpenRequest {
//!     flags: 0x02,  // WRITE
//!     path_hdr: InlineBlobHeader { len: 10, kind: 0 },
//! });
//! put_str(&mut msg.payload, 8, "/tmp/test").unwrap();
//!
//! // Decode the reply
//! let reply: &OpenReply = decode_fixed(&reply_msg).unwrap();
//! assert_eq!(reply.status, 0); // success
//! ```

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
// Generic status-only reply (used by every scheme)
// ===========================================================================

/// Minimal reply carrying only a status code.
///
/// Used by scheme handlers that don't need to return additional data.
///
/// Wire layout: `status @ 0..4`.
///
/// # Example
///
/// ```ignore
/// let reply = StatusReply { status: 0 }; // success
/// let err = StatusReply { status: 13 };  // EACCES
/// ```
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct StatusReply {
    /// Status code: 0 = success, non-zero = errno.
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
///
/// The path is variable-length and follows the header at offset 8.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct OpenRequest {
    /// Open flags (`O_RDONLY`, `O_WRONLY`, `O_RDWR`, `O_CREAT`, etc.).
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
///
/// # Example
///
/// ```ignore
/// let reply = OpenReply {
///     status: 0,
///     _pad0: 0,
///     ino: 42,
///     size: 1024,
///     file_flags: 0x01, // readable
///     _pad1: 0,
/// };
/// ```
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct OpenReply {
    /// Status code: 0 = success.
    pub status: u32,
    pub _pad0: u32,
    /// Inode number of the opened file.
    pub ino: u64,
    /// File size in bytes.
    pub size: u64,
    /// File flags (device, pipe, append, etc.).
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
    /// Inode number of the file to read.
    pub ino: u64,
    /// Byte offset in the file to start reading from.
    pub offset: u64,
    /// Maximum number of bytes to read.
    pub count: u32,
    pub _pad: u32,
}
assert_payload_size!(ReadRequest);
static_assertions::assert_eq_size!(ReadRequest, [u8; 24]);

/// Read reply prefix (variable-length data follows at offset 8).
///
/// Wire layout:
///   `status @ 0..4`, `count @ 4..8`, `data @ 8..`.
///
/// The `data` field contains `count` bytes of file content.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct ReadReply {
    /// Status code: 0 = success.
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
///
/// The data is variable-length and follows the header at offset 24.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct WriteRequest {
    /// Inode number of the file to write.
    pub ino: u64,
    /// Byte offset in the file to start writing.
    pub offset: u64,
    /// InlineBlobHeader describing the data that follows.
    pub data_hdr: InlineBlobHeader,
    pub _pad: u32,
}
assert_payload_size!(WriteRequest);
static_assertions::assert_eq_size!(WriteRequest, [u8; 24]);

/// Write reply.
///
/// Wire layout: `status @ 0..4`, `written @ 4..8`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct WriteReply {
    /// Status code: 0 = success.
    pub status: u32,
    /// Number of bytes actually written.
    pub written: u32,
}
assert_payload_size!(WriteReply);

/// Create request (file or directory).
///
/// Wire layout:
///   `mode @ 0..4`, `path_hdr @ 4..8`, `path_data @ 8..`.
///
/// The `mode` field specifies permissions (e.g. `0o755` for directories).
/// The path is variable-length and follows the header at offset 8.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct CreateRequest {
    /// Permission mode (e.g. `0o644` for files, `0o755` for directories).
    pub mode: u32,
    /// InlineBlobHeader describing the path that follows.
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
    /// Status code: 0 = success.
    pub status: u32,
    pub _pad: u32,
    /// Inode number of the newly created file/directory.
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
    /// Inode number of the file to close.
    pub ino: u64,
}
assert_payload_size!(CloseRequest);

/// Stat request.
///
/// Wire layout: `ino @ 0..8`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct StatRequest {
    /// Inode number to query.
    pub ino: u64,
}
assert_payload_size!(StatRequest);

/// Lseek request.
///
/// Wire layout: `ino @ 0..8`, `offset @ 8..16`, `whence @ 16..20`, `_pad @ 20..24`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct LseekRequest {
    /// Inode number of the file.
    pub ino: u64,
    /// Offset relative to `whence` (can be negative).
    pub offset: i64,
    /// Whence: `SEEK_SET` (0), `SEEK_CUR` (1), or `SEEK_END` (2).
    pub whence: u32,
    pub _pad: u32,
}
assert_payload_size!(LseekRequest);
static_assertions::assert_eq_size!(LseekRequest, [u8; 24]);

/// Lseek reply.
///
/// Wire layout:
///   `status @ 0..4`, `_pad @ 4..8`, `offset @ 8..16`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct LseekReply {
    /// Status code: 0 = success.
    pub status: u32,
    pub _pad: u32,
    /// New file position (absolute offset from beginning of file).
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
///
/// The address is variable-length and follows the header at offset 8.
/// For IPv4: 4 bytes of network-order octets.
/// For IPv6: 16 bytes of network-order octets.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct TcpConnectRequest {
    /// Target port number (host byte order).
    pub port: u16,
    pub _padding: [u8; 2],
    /// InlineBlobHeader describing the address that follows.
    pub addr_hdr: InlineBlobHeader,
}
assert_payload_size!(TcpConnectRequest);

/// TCP connect reply.
///
/// Wire layout:
///   `status @ 0..4`, `_pad @ 4..8`, `conn_id @ 8..16`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct TcpConnectReply {
    /// Status code: 0 = success.
    pub status: u32,
    pub _pad: u32,
    /// Connection identifier for subsequent read/write operations.
    pub conn_id: u64,
}
assert_payload_size!(TcpConnectReply);
static_assertions::assert_eq_size!(TcpConnectReply, [u8; 16]);
