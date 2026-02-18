//! Pure Rust XFS filesystem parser.
//!
//! This crate provides a `no_std` compatible parser for the XFS filesystem
//! format. It can parse:
//!
//! - Superblock (filesystem metadata)
//! - Inodes (file metadata)
//! - Extents (block allocations)
//! - Directories (file listings)
//! - B+Tree structures (for large files/directories)
//!
//! # Features
//!
//! - `alloc`: Enables `Vec` and `Box` support for dynamic data structures
//! - `std`: Enables full standard library support (for user-mode applications)
//!
//! # XFS Format
//!
//! XFS is a high-performance journaling filesystem. Key characteristics:
//!
//! - All on-disk values are big-endian
//! - Allocation Groups (AG) divide the filesystem
//! - Extent-based allocation
//! - B+Trees for large files and directories
//!
//! # References
//!
//! - [XFS Wiki](https://xfs.wiki.kernel.org/)
//! - [Linux kernel xfs_format.h](https://github.com/torvalds/linux/blob/master/fs/xfs/libxfs/xfs_format.h)

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod address;
pub mod ag;
pub mod btree;
pub mod constants;
pub mod crc;
pub mod dir_write;
pub mod directory;
pub mod extent;
pub mod freespace;
pub mod inode;
#[cfg(feature = "std")]
pub mod inode_alloc;
pub mod journal;
pub mod superblock;

pub use ag::{AgFreeHeader, AgInodeHeader};
pub use btree::BtreeBlockLong;
#[cfg(feature = "alloc")]
pub use btree::{BlockReader, BmbtRoot};
pub use constants::*;
pub use extent::Extent;
pub use freespace::{AllocBtreeBlock, AllocRec};
pub use fs_abstraction::{FsError, FsResult};
pub use inode::{DataFork, Inode, InodeCore, InodeFormat};
#[cfg(feature = "std")]
pub use inode_alloc::{InodeBtreeBlock, InodeBtreeRec};
pub use superblock::Superblock;
