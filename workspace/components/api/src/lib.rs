//! Strat9-OS Component API
//!
//! Defines the common traits, types, and IPC message structures that all
//! userspace component servers use to communicate with each other and with
//! the Bedrock kernel.
//!
//! This crate is `no_std` + `alloc`-compatible for use in freestanding
//! component binaries.

#![no_std]

extern crate alloc;

use alloc::sync::Arc;

// ---------------------------------------------------------------------------
// Filesystem abstractions — re-exported from strate-fs-abstraction
// ---------------------------------------------------------------------------

pub use strate_fs_abstraction::error::{FsError, FsResult};

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
    /// Reads at.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize>;
    /// Writes at.
    fn write_at(&self, offset: u64, data: &[u8]) -> FsResult<usize>;
    /// Implements size.
    fn size(&self) -> u64;
}

pub trait FileSystem: Send + Sync {
    /// Implements mount.
    fn mount(&mut self, device: Arc<dyn BlockDevice>) -> FsResult<()>;
    /// Implements unmount.
    fn unmount(&mut self) -> FsResult<()>;
    /// Implements lookup.
    fn lookup(&self, path: &str) -> FsResult<u64>;
    /// Implements read.
    fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> FsResult<usize>;
    /// Implements write.
    fn write(&mut self, ino: u64, offset: u64, buf: &[u8]) -> FsResult<usize>;
    /// Implements create.
    fn create(&mut self, parent: u64, name: &str, file_type: FileType) -> FsResult<u64>;
    /// Implements remove.
    fn remove(&mut self, parent: u64, name: &str) -> FsResult<()>;
    /// Implements stat.
    fn stat(&self, ino: u64) -> FsResult<FileStat>;
    /// Implements readdir.
    fn readdir(&self, ino: u64) -> FsResult<alloc::vec::Vec<(alloc::string::String, u64)>>;
}

pub struct FileHandle {
    pub ino: u64,
    pub offset: u64,
}
