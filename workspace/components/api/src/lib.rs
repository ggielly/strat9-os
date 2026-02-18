//! Strat9-OS Component API
//!
//! Defines the common traits, types, and IPC message structures that all
//! userspace component servers use to communicate with each other and with
//! the Bedrock kernel.
//!
//! This crate is `no_std` + `alloc`-compatible for use in freestanding
//! component binaries.

#![no_std]
#![cfg_attr(not(any(test, feature = "std")), no_std)]

extern crate alloc;

use alloc::sync::Arc;

// ---------------------------------------------------------------------------
// IPC primitives (standalone, no kernel dependency)
// ---------------------------------------------------------------------------

/// Inline IPC message (cache-line sized, 64 bytes).
///
/// Used for small synchronous messages between components. Bulk data
/// transfers use shared-memory ring buffers instead.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IpcMessage {
    /// Message type / opcode
    pub msg_type: u32,
    /// Flags (reserved)
    pub flags: u32,
    /// Payload (up to 56 bytes inline)
    pub payload: [u8; 56],
}

impl IpcMessage {
    pub const fn new(msg_type: u32) -> Self {
        Self {
            msg_type,
            flags: 0,
            payload: [0u8; 56],
        }
    }
}

// ---------------------------------------------------------------------------
// Filesystem abstractions
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum FsError {
    NotFound,
    PermissionDenied,
    InvalidFormat,
    Corrupted,
    IsADirectory,
    NotADirectory,
    NotImplemented,
    IoError,
    OutOfMemory,
    InvalidArgument,
}

pub type FsResult<T> = Result<T, FsError>;

#[derive(Debug, Clone, Copy)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug)]
pub struct FileStat {
    pub size: u64,
    pub file_type: FileType,
    pub permissions: u8,
    pub modified: u64,
}

pub trait BlockDevice: Send + Sync {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize>;
    fn write_at(&self, offset: u64, data: &[u8]) -> FsResult<usize>;
    fn size(&self) -> u64;
}

pub trait FileSystem: Send + Sync {
    fn mount(&mut self, device: Arc<dyn BlockDevice>) -> FsResult<()>;
    fn unmount(&mut self) -> FsResult<()>;
    fn lookup(&self, path: &str) -> FsResult<u64>;
    fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> FsResult<usize>;
    fn write(&mut self, ino: u64, offset: u64, buf: &[u8]) -> FsResult<usize>;
    fn create(&mut self, parent: u64, name: &str, file_type: FileType) -> FsResult<u64>;
    fn remove(&mut self, parent: u64, name: &str) -> FsResult<()>;
    fn stat(&self, ino: u64) -> FsResult<FileStat>;
    fn readdir(&self, ino: u64) -> FsResult<alloc::vec::Vec<(alloc::string::String, u64)>>;
}

pub struct FileHandle {
    pub ino: u64,
    pub offset: u64,
}
