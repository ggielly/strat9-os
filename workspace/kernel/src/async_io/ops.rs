//! Asynchronous I/O ABI types : stable across kernel versions.
//!
//! Defines the [`AsyncOp`] opcode enum, [`AsyncSqe`] (submission queue entry),
//! and [`AsyncCqe`] (completion queue event) as `#[repr(C)]` structs.

/// Operation opcode submitted through the async ring.
///
/// **Do not reorder** existing variants : the numeric value is part of the
/// userspace ABI and must remain stable.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum AsyncOp {
    /// No-op : used for testing and ring probing.
    Nop = 0,
    /// VFS: read from an open file descriptor.
    Read = 1,
    /// VFS: write to an open file descriptor.
    Write = 2,
    /// VFS: open a file (async version).
    Open = 3,
    /// VFS: close a file descriptor.
    Close = 4,
    /// VFS: stat / fstat a file.
    Stat = 5,

    /// IPC: send a message to a port (non-blocking).
    IpcSend = 10,
    /// IPC: receive a message from a port (non-blocking).
    IpcRecv = 11,
    /// IPC: combined send + recv (reply channel).
    IpcCall = 12,

    /// Poll: add an fd to the epoll set.
    PollAdd = 20,
    /// Poll: remove an fd from the epoll set.
    PollRemove = 21,

    /// Timer: arm a timeout completion.
    Timeout = 30,
    /// Timer: remove a previously armed timeout.
    TimeoutRemove = 31,

    /// Network: accept a connection on a listening socket.
    Accept = 40,
    /// Network: connect to a remote endpoint.
    Connect = 41,

    /// Storage: read sectors from a block device (AHCI / NVMe).
    StorageRead = 50,
    /// Storage: write sectors to a block device.
    StorageWrite = 51,

    /// Cancel an in-flight operation by its `user_data` token.
    Cancel = 254,
}

// =============================================================================
// SQE : Submission Queue Entry (64 bytes, cache-line aligned)
// =============================================================================

/// A single I/O submission, written by userspace into the SQ ring.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AsyncSqe {
    /// Operation opcode ([`AsyncOp`] variant).
    pub opcode: u8,
    /// Flags: `FIXED_FILE`, `IO_LINK`, `IO_DRAIN`, `IO_HARDLINK`.
    pub flags: u8,
    /// Priority hint (ioprio class << 13 | ioprio data).
    pub ioprio: u16,
    /// File descriptor (VFS fd) or IPC port id.
    pub fd: u32,
    /// File offset (for read/write) or endpoint id (for IPC).
    pub off: u64,
    /// Buffer virtual address (userspace pointer : validated by kernel).
    pub addr: u64,
    /// Buffer length in bytes.
    pub len: u32,
    /// Operation-specific flags (e.g. `RW_FSYNC` for write).
    pub op_flags: u32,
    /// Opaque correlation token : echoed in the CQE on completion.
    pub user_data: u64,
    /// Personality / capability context (silo token).
    pub personality: u16,
    /// Padding to 64 bytes (cache-line aligned).
    pub _pad: [u8; 22],
}

// Compile-time size check : must be exactly 64 bytes.
const _: () = assert!(core::mem::size_of::<AsyncSqe>() == 64);

// =============================================================================
// CQE : Completion Queue Event (16 bytes)
// =============================================================================

/// A single I/O completion, written by the kernel into the CQ ring.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AsyncCqe {
    /// Opaque correlation token from the originating SQE.
    pub user_data: u64,
    /// Result: bytes transferred on success, or a negative errno on failure.
    pub res: i32,
    /// Flags: `CQE_F_BUFFER`, `CQE_F_MORE`.
    pub flags: u32,
}

// Compile-time size check : must be exactly 16 bytes.
const _: () = assert!(core::mem::size_of::<AsyncCqe>() == 16);

// =============================================================================
// Shared constants
// =============================================================================

/// Maximum number of in-flight operations per ring.
pub const MAX_IN_FLIGHT: usize = 4096;

/// Default SQE ring size (must be a power of two).
pub const DEFAULT_RING_ENTRIES: u32 = 256;
