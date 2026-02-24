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
