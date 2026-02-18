//! Inode Allocation for XFS write support.
//!
//! XFS uses B+trees per Allocation Group for inode management:
//! - IBT (Inode B+Tree): Tracks allocated inode chunks
//! - FIBT (Free Inode B+Tree): Tracks free inodes within allocated chunks
//!
//! This module provides inode allocation and deallocation functionality.

extern crate alloc;

use alloc::vec::Vec;

use fs_abstraction::{safe_math::CheckedSliceOps, FsError, FsResult};

use crate::constants::*;

/// Number of inodes per inode chunk.
pub const XFS_INODES_PER_CHUNK: u32 = 64;

/// Inode B+tree record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeBtreeRec {
    /// Starting inode number (AG-relative).
    pub start_ino: u32,
    /// Count of free inodes in this chunk (FIBT) or hole count (IBT).
    pub free_count: u32,
    /// Free inode bitmap (64 bits for 64 inodes).
    pub free_bitmap: u64,
}

impl InodeBtreeRec {
    pub const SIZE: usize = 16;

    /// Parse from bytes.
    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }

        Ok(Self {
            start_ino: buffer.read_be_u32(0)?,
            free_count: buffer.read_be_u32(4)?,
            free_bitmap: buffer.read_be_u64(8)?,
        })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.start_ino.to_be_bytes());
        buf[4..8].copy_from_slice(&self.free_count.to_be_bytes());
        buf[8..16].copy_from_slice(&self.free_bitmap.to_be_bytes());
        buf
    }

    /// Check if a specific inode in the chunk is free.
    pub fn is_inode_free(&self, index: u32) -> bool {
        if index >= XFS_INODES_PER_CHUNK {
            return false;
        }
        (self.free_bitmap & (1u64 << index)) != 0
    }

    /// Get the first free inode in this chunk.
    pub fn first_free_inode(&self) -> Option<u32> {
        if self.free_count == 0 {
            return None;
        }
        // Find first set bit
        let trailing = self.free_bitmap.trailing_zeros();
        if trailing < 64 {
            Some(self.start_ino + trailing)
        } else {
            None
        }
    }

    /// Mark an inode as allocated (clear the free bit).
    pub fn allocate_inode(&mut self, index: u32) -> bool {
        if index >= XFS_INODES_PER_CHUNK {
            return false;
        }
        let mask = 1u64 << index;
        if (self.free_bitmap & mask) == 0 {
            return false; // Already allocated
        }
        self.free_bitmap &= !mask;
        self.free_count = self.free_count.saturating_sub(1);
        true
    }

    /// Mark an inode as free (set the free bit).
    pub fn free_inode(&mut self, index: u32) -> bool {
        if index >= XFS_INODES_PER_CHUNK {
            return false;
        }
        let mask = 1u64 << index;
        if (self.free_bitmap & mask) != 0 {
            return false; // Already free
        }
        self.free_bitmap |= mask;
        self.free_count = self.free_count.saturating_add(1);
        true
    }
}

/// Inode B+tree key (for internal nodes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeBtreeKey {
    /// Starting inode number.
    pub start_ino: u32,
}

impl InodeBtreeKey {
    pub const SIZE: usize = 4;

    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }
        Ok(Self {
            start_ino: buffer.read_be_u32(0)?,
        })
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.start_ino.to_be_bytes()
    }
}

/// Inode B+tree pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeBtreePtr {
    /// Block number (AG-relative).
    pub block: u32,
}

impl InodeBtreePtr {
    pub const SIZE: usize = 4;

    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }
        Ok(Self {
            block: buffer.read_be_u32(0)?,
        })
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.block.to_be_bytes()
    }
}

/// Inode B+tree block header (short form - AG local).
#[derive(Debug, Clone)]
pub struct InodeBtreeBlock {
    /// Magic number.
    pub magic: u32,
    /// B+tree level (0 = leaf).
    pub level: u16,
    /// Number of records.
    pub num_recs: u16,
    /// Left sibling block.
    pub left_sibling: u32,
    /// Right sibling block.
    pub right_sibling: u32,
    /// Block number (v5 only).
    pub blkno: u64,
    /// Log sequence number (v5 only).
    pub lsn: u64,
    /// UUID (v5 only).
    pub uuid: [u8; 16],
    /// Owner AG (v5 only).
    pub owner: u32,
    /// CRC (v5 only).
    pub crc: u32,
}

impl InodeBtreeBlock {
    /// Header size for v4.
    pub const V4_SIZE: usize = 16;
    /// Header size for v5.
    pub const V5_SIZE: usize = 56;

    /// Parse header from buffer.
    pub fn parse(buffer: &[u8], is_v5: bool) -> FsResult<Self> {
        let min_size = if is_v5 { Self::V5_SIZE } else { Self::V4_SIZE };
        if buffer.len() < min_size {
            return Err(FsError::BufferTooSmall);
        }

        let magic = buffer.read_be_u32(0)?;

        // Validate magic
        let valid_magic = match magic {
            XFS_IBT_MAGIC | XFS_IBT_CRC_MAGIC | XFS_FIBT_MAGIC | XFS_FIBT_CRC_MAGIC => true,
            _ => false,
        };
        if !valid_magic {
            return Err(FsError::InvalidMagic);
        }

        let level = buffer.read_be_u16(4)?;
        let num_recs = buffer.read_be_u16(6)?;
        let left_sibling = buffer.read_be_u32(8)?;
        let right_sibling = buffer.read_be_u32(12)?;

        let (blkno, lsn, uuid, owner, crc) = if is_v5 {
            let blkno = buffer.read_be_u64(16)?;
            let lsn = buffer.read_be_u64(24)?;
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&buffer[32..48]);
            let owner = buffer.read_be_u32(48)?;
            let crc = buffer.read_be_u32(52)?;
            (blkno, lsn, uuid, owner, crc)
        } else {
            (0, 0, [0u8; 16], 0, 0)
        };

        Ok(Self {
            magic,
            level,
            num_recs,
            left_sibling,
            right_sibling,
            blkno,
            lsn,
            uuid,
            owner,
            crc,
        })
    }

    /// Check if this is a leaf block.
    pub fn is_leaf(&self) -> bool {
        self.level == 0
    }

    /// Check if this is an IBT (allocated inodes) or FIBT (free inodes).
    pub fn is_fibt(&self) -> bool {
        self.magic == XFS_FIBT_MAGIC || self.magic == XFS_FIBT_CRC_MAGIC
    }

    /// Get the header size.
    pub fn header_size(&self, is_v5: bool) -> usize {
        if is_v5 {
            Self::V5_SIZE
        } else {
            Self::V4_SIZE
        }
    }
}

/// Read leaf records from an inode B+tree block.
pub fn read_inode_btree_records(
    buffer: &[u8],
    header: &InodeBtreeBlock,
    is_v5: bool,
) -> FsResult<Vec<InodeBtreeRec>> {
    if !header.is_leaf() {
        return Err(FsError::InvalidBlockType);
    }

    let header_size = header.header_size(is_v5);
    let mut records = Vec::with_capacity(header.num_recs as usize);

    for i in 0..header.num_recs as usize {
        let rec_offset = header_size + i * InodeBtreeRec::SIZE;
        if rec_offset + InodeBtreeRec::SIZE > buffer.len() {
            break;
        }
        records.push(InodeBtreeRec::parse(&buffer[rec_offset..])?);
    }

    Ok(records)
}

/// Find a free inode in the FIBT.
///
/// Returns (chunk_record, inode_index_in_chunk) if found.
pub fn find_free_inode(
    buffer: &[u8],
    header: &InodeBtreeBlock,
    is_v5: bool,
) -> FsResult<Option<(InodeBtreeRec, u32)>> {
    if !header.is_leaf() || !header.is_fibt() {
        return Err(FsError::InvalidBlockType);
    }

    let records = read_inode_btree_records(buffer, header, is_v5)?;

    for rec in records {
        if rec.free_count > 0 {
            if let Some(idx) = rec.first_free_inode() {
                let local_idx = idx - rec.start_ino;
                return Ok(Some((rec, local_idx)));
            }
        }
    }

    Ok(None)
}

/// Find a free inode in the IBT (Inode B+tree).
///
/// This is used when FIBT (Free Inode B+tree) is not available.
/// The IBT contains ALL allocated inode chunks, so we scan for chunks
/// that have at least one free inode (free_bitmap != 0).
///
/// Returns (chunk_record, inode_index_in_chunk) if found.
pub fn find_free_inode_in_ibt(
    buffer: &[u8],
    header: &InodeBtreeBlock,
    is_v5: bool,
) -> FsResult<Option<(InodeBtreeRec, u32)>> {
    if !header.is_leaf() {
        return Err(FsError::InvalidBlockType);
    }

    // IBT records have the same format as FIBT records
    let records = read_inode_btree_records(buffer, header, is_v5)?;

    for rec in records {
        // In IBT, free_bitmap shows which inodes are free (bit set = free)
        // free_count may be used differently but free_bitmap is reliable
        if rec.free_bitmap != 0 {
            if let Some(idx) = rec.first_free_inode() {
                let local_idx = idx - rec.start_ino;
                return Ok(Some((rec, local_idx)));
            }
        }
    }

    Ok(None)
}

/// Write leaf records to an inode B+tree block.
pub fn write_inode_btree_records(
    buffer: &mut [u8],
    header: &InodeBtreeBlock,
    records: &[InodeBtreeRec],
    is_v5: bool,
) -> FsResult<()> {
    let header_size = header.header_size(is_v5);

    for (i, rec) in records.iter().enumerate() {
        let rec_offset = header_size + i * InodeBtreeRec::SIZE;
        if rec_offset + InodeBtreeRec::SIZE > buffer.len() {
            return Err(FsError::BufferTooSmall);
        }
        buffer[rec_offset..rec_offset + InodeBtreeRec::SIZE].copy_from_slice(&rec.to_bytes());
    }

    Ok(())
}

/// Calculate the absolute inode number from AG number and AG-relative inode.
pub fn make_absolute_inode(
    ag_num: u32,
    ag_ino: u32,
    ag_block_log: u8,
    inode_per_block_log: u8,
) -> u64 {
    let shift = ag_block_log + inode_per_block_log;
    ((ag_num as u64) << shift) | (ag_ino as u64)
}

/// Extract AG number and AG-relative inode from absolute inode number.
pub fn split_inode_number(ino: u64, ag_block_log: u8, inode_per_block_log: u8) -> (u32, u32) {
    let shift = ag_block_log + inode_per_block_log;
    let ag_num = (ino >> shift) as u32;
    let ag_ino = (ino & ((1u64 << shift) - 1)) as u32;
    (ag_num, ag_ino)
}

/// Create a new empty inode core with default values.
pub fn create_empty_inode_core(
    mode: u16,
    uid: u32,
    gid: u32,
    version: u8,
    ino: u64,
    uuid: &[u8; 16],
) -> crate::InodeCore {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);

    crate::InodeCore {
        magic: XFS_DINODE_MAGIC,
        mode,
        version,
        format: crate::InodeFormat::Local,
        onlink: 0,
        uid,
        gid,
        nlink: 1,
        projid_lo: 0,
        projid_hi: 0,
        atime_sec: now,
        atime_nsec: 0,
        mtime_sec: now,
        mtime_nsec: 0,
        ctime_sec: now,
        ctime_nsec: 0,
        size: 0,
        nblocks: 0,
        extsize: 0,
        nextents: 0,
        anextents: 0,
        forkoff: 0,
        aformat: crate::InodeFormat::Extents as u8,
        dmevmask: 0,
        dmstate: 0,
        flags: 0,
        gen: 1,
        next_unlinked: 0xFFFFFFFF, // NULLAGINO
        crc: 0,
        changecount: 1,
        lsn: 0,
        flags2: 0,
        cowextsize: 0,
        crtime_sec: now,
        crtime_nsec: 0,
        ino,
        uuid: *uuid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inode_btree_rec_parse() {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&100u32.to_be_bytes()); // start_ino
        buf[4..8].copy_from_slice(&5u32.to_be_bytes()); // free_count
        buf[8..16].copy_from_slice(&0x1Fu64.to_be_bytes()); // free_bitmap (first 5 bits set)

        let rec = InodeBtreeRec::parse(&buf).unwrap();
        assert_eq!(rec.start_ino, 100);
        assert_eq!(rec.free_count, 5);
        assert!(rec.is_inode_free(0));
        assert!(rec.is_inode_free(4));
        assert!(!rec.is_inode_free(5));
    }

    #[test]
    fn test_inode_allocation() {
        let mut rec = InodeBtreeRec {
            start_ino: 64,
            free_count: 64,
            free_bitmap: u64::MAX, // All free
        };

        // First free should be index 0
        assert_eq!(rec.first_free_inode(), Some(64));

        // Allocate it
        assert!(rec.allocate_inode(0));
        assert_eq!(rec.free_count, 63);
        assert!(!rec.is_inode_free(0));

        // Next free should be index 1
        assert_eq!(rec.first_free_inode(), Some(65));
    }

    #[test]
    fn test_inode_number_split() {
        let ag_block_log = 16u8;
        let inode_per_block_log = 4u8;

        let (ag, ag_ino) = split_inode_number(0x0001_2345, ag_block_log, inode_per_block_log);
        let reconstructed = make_absolute_inode(ag, ag_ino, ag_block_log, inode_per_block_log);

        assert_eq!(reconstructed, 0x0001_2345);
    }
}
