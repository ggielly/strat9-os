//! Address calculation utilities for XFS.
//!
//! XFS uses multiple address formats:
//! - Absolute block numbers (filesystem-wide)
//! - AG-relative block numbers
//! - Inode numbers (packed AG + offset)

use fs_abstraction::{safe_math::CheckedOps, FsError, FsResult};

use crate::Superblock;

/// Splits an inode number into AG number and AG-relative inode.
///
/// XFS inode numbers are packed as:
/// - High bits: AG number
/// - Low bits: AG-relative inode offset
///
/// The split point is determined by `sb.ag_block_log + sb.inode_per_block_log`.
pub fn split_inode_number(sb: &Superblock, inode: u64) -> FsResult<(u32, u32)> {
    // Calculate the number of bits for the AG-relative part
    let ino_bits = sb.ag_block_log + sb.inode_per_block_log;
    if ino_bits >= 32 {
        return Err(FsError::Corrupted);
    }

    let ag_ino_mask = (1u64 << ino_bits) - 1;
    let ag = (inode >> ino_bits) as u32;
    let ag_ino = (inode & ag_ino_mask) as u32;

    if ag >= sb.ag_count {
        return Err(FsError::InodeNotFound);
    }

    Ok((ag, ag_ino))
}

/// Calculates the absolute block number for an inode.
///
/// The inode's block is:
/// - AG's starting block + (ag_ino / inodes_per_block)
pub fn inode_to_block(sb: &Superblock, inode: u64) -> FsResult<u64> {
    let (ag, ag_ino) = split_inode_number(sb, inode)?;

    // Calculate the block within the AG
    let ag_block = ag_ino / sb.inodes_per_block as u32;

    // Calculate absolute block
    sb.ag_to_absolute_block(ag, ag_block)
}

/// Calculates the byte offset within a block for an inode.
pub fn inode_block_offset(sb: &Superblock, inode: u64) -> FsResult<usize> {
    let (_, ag_ino) = split_inode_number(sb, inode)?;

    // Offset within the block
    let offset_in_block = (ag_ino % sb.inodes_per_block as u32) as usize * sb.inode_size as usize;

    Ok(offset_in_block)
}

/// Calculates the absolute byte offset for an inode on disk.
pub fn inode_to_byte_offset(sb: &Superblock, inode: u64) -> FsResult<u64> {
    let block = inode_to_block(sb, inode)?;
    let block_offset = sb.block_to_byte_offset(block)?;
    let offset_in_block = inode_block_offset(sb, inode)? as u64;

    block_offset.checked_add_offset(offset_in_block)
}

/// Constructs an inode number from AG and AG-relative inode.
pub fn make_inode_number(sb: &Superblock, ag: u32, ag_ino: u32) -> FsResult<u64> {
    if ag >= sb.ag_count {
        return Err(FsError::InvalidBlockAddress);
    }

    let ino_bits = sb.ag_block_log + sb.inode_per_block_log;
    let inode = ((ag as u64) << ino_bits) | (ag_ino as u64);

    Ok(inode)
}

/// Converts a file offset (in bytes) to a block number within the file.
pub fn byte_to_file_block(sb: &Superblock, byte_offset: u64) -> u64 {
    byte_offset >> sb.block_log
}

/// Converts a file block number to a byte offset.
pub fn file_block_to_byte(sb: &Superblock, block: u64) -> FsResult<u64> {
    block
        .checked_shl(sb.block_log as u32)
        .ok_or(FsError::ArithmeticOverflow)
}

/// Calculates the offset within a block for a given byte offset.
pub fn byte_offset_in_block(sb: &Superblock, byte_offset: u64) -> usize {
    (byte_offset & ((1 << sb.block_log) - 1)) as usize
}

/// Calculates how many blocks are needed to store a given number of bytes.
pub fn bytes_to_blocks(sb: &Superblock, bytes: u64) -> FsResult<u64> {
    let block_size = sb.block_size as u64;
    // (bytes + block_size - 1) / block_size, but checked
    bytes
        .checked_add(block_size - 1)
        .map(|n| n / block_size)
        .ok_or(FsError::ArithmeticOverflow)
}

/// Information about an inode's location on disk.
#[derive(Debug, Clone, Copy)]
pub struct InodeLocation {
    /// Allocation Group number.
    pub ag: u32,
    /// AG-relative inode number.
    pub ag_inode: u32,
    /// Absolute block number containing the inode.
    pub block: u64,
    /// Byte offset within the block.
    pub offset_in_block: usize,
    /// Absolute byte offset on disk.
    pub byte_offset: u64,
}

impl InodeLocation {
    /// Calculates the location of an inode.
    pub fn from_inode(sb: &Superblock, inode: u64) -> FsResult<Self> {
        let (ag, ag_inode) = split_inode_number(sb, inode)?;
        let block = inode_to_block(sb, inode)?;
        let offset_in_block = inode_block_offset(sb, inode)?;
        let byte_offset = inode_to_byte_offset(sb, inode)?;

        Ok(Self {
            ag,
            ag_inode,
            block,
            offset_in_block,
            byte_offset,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_superblock() -> Superblock {
        // Minimal superblock for testing
        Superblock {
            magic: 0x58465342,
            block_size: 4096,
            total_blocks: 1000000,
            realtime_blocks: 0,
            realtime_extents: 0,
            uuid: [0; 16],
            log_start: 0,
            root_inode: 128,
            realtime_bitmap_inode: 0,
            realtime_summary_inode: 0,
            realtime_extent_size: 0,
            ag_blocks: 250000,
            ag_count: 4,
            realtime_bitmap_blocks: 0,
            log_blocks: 0,
            version: 5,
            sector_size: 512,
            inode_size: 512,
            inodes_per_block: 8,
            name: [0; 12],
            block_log: 12,          // log2(4096)
            sector_log: 9,          // log2(512)
            inode_log: 9,           // log2(512)
            inode_per_block_log: 3, // log2(8)
            ag_block_log: 18,       // log2(262144) approximately
            realtime_extent_log: 0,
            in_progress: 0,
            inode_max_percent: 25,
            inode_count: 0,
            free_inodes: 0,
            free_blocks: 0,
            free_realtime_extents: 0,
            features_compat: 0,
            features_ro_compat: 0,
            features_incompat: 0,
            features_log_incompat: 0,
            crc: 0,
            sparse_inode_align: 0,
            project_quota_inode: 0,
            lsn: 0,
            meta_uuid: [0; 16],
        }
    }

    #[test]
    fn test_split_inode() {
        let sb = make_test_superblock();
        // Root inode 128 should be in AG 0
        let (ag, ag_ino) = split_inode_number(&sb, 128).unwrap();
        assert_eq!(ag, 0);
        assert_eq!(ag_ino, 128);
    }
}
