//! Free Space B+Tree operations for XFS write support.
//!
//! XFS uses two B+trees per Allocation Group to manage free space:
//! - BNO tree: Sorted by block number (for adjacency lookups)
//! - CNT tree: Sorted by extent count (for size-based allocation)
//!
//! This module provides read/write operations for these trees.

extern crate alloc;

use alloc::{vec, vec::Vec};

use fs_abstraction::{safe_math::CheckedSliceOps, FsError, FsResult};

use crate::constants::*;

/// Free space B+tree record (same for BNO and CNT trees).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocRec {
    /// Starting block number (AG-relative).
    pub start_block: u32,
    /// Number of blocks in this free extent.
    pub block_count: u32,
}

impl AllocRec {
    /// Size of an allocation record (8 bytes).
    pub const SIZE: usize = 8;

    /// Parse an allocation record from bytes.
    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }
        Ok(Self {
            start_block: buffer.read_be_u32(0)?,
            block_count: buffer.read_be_u32(4)?,
        })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.start_block.to_be_bytes());
        buf[4..8].copy_from_slice(&self.block_count.to_be_bytes());
        buf
    }

    /// Returns the end block (exclusive).
    pub fn end_block(&self) -> u32 {
        self.start_block.saturating_add(self.block_count)
    }

    /// Check if this record is adjacent to another (can be merged).
    pub fn is_adjacent_to(&self, other: &Self) -> bool {
        self.end_block() == other.start_block || other.end_block() == self.start_block
    }
}

/// Free space B+tree key (for BNO tree: block number, for CNT tree: count then
/// block).
#[derive(Debug, Clone, Copy)]
pub struct AllocKey {
    /// For BNO: start block. For CNT: block count.
    pub key1: u32,
    /// For BNO: unused (0). For CNT: start block (secondary sort).
    pub key2: u32,
}

impl AllocKey {
    /// Size of an allocation key.
    pub const SIZE: usize = 8;

    /// Parse a key from bytes.
    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }
        Ok(Self {
            key1: buffer.read_be_u32(0)?,
            key2: buffer.read_be_u32(4)?,
        })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.key1.to_be_bytes());
        buf[4..8].copy_from_slice(&self.key2.to_be_bytes());
        buf
    }

    /// Create a BNO key from a record.
    pub fn from_bno_rec(rec: &AllocRec) -> Self {
        Self {
            key1: rec.start_block,
            key2: 0,
        }
    }

    /// Create a CNT key from a record.
    pub fn from_cnt_rec(rec: &AllocRec) -> Self {
        Self {
            key1: rec.block_count,
            key2: rec.start_block,
        }
    }
}

/// Pointer in free space B+tree (AG-relative block number).
#[derive(Debug, Clone, Copy)]
pub struct AllocPtr {
    pub block: u32,
}

impl AllocPtr {
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

/// Result of searching for free space.
#[derive(Debug, Clone)]
pub struct FreeSpaceResult {
    /// The free extent found.
    pub extent: AllocRec,
    /// AG number containing this extent.
    pub ag_num: u32,
    /// Path through the BNO tree to this record (for updates).
    pub bno_path: Vec<TreePathEntry>,
    /// Path through the CNT tree to this record (for updates).
    pub cnt_path: Vec<TreePathEntry>,
}

/// Entry in a tree traversal path (for updates).
#[derive(Debug, Clone)]
pub struct TreePathEntry {
    /// Block number of this node.
    pub block_num: u32,
    /// Index of the key/pointer used.
    pub index: u16,
    /// Level in the tree.
    pub level: u16,
}

/// Header for free space B+tree blocks (short format, AG-local).
#[derive(Debug, Clone)]
pub struct AllocBtreeBlock {
    /// Magic number (XFS_ABTB_MAGIC, XFS_ABTC_MAGIC, or CRC variants).
    pub magic: u32,
    /// Level (0 = leaf).
    pub level: u16,
    /// Number of records/keys.
    pub num_recs: u16,
    /// Left sibling (AG-relative, NULLAGBLOCK if none).
    pub left_sibling: u32,
    /// Right sibling (AG-relative, NULLAGBLOCK if none).
    pub right_sibling: u32,
    /// Block number (v5).
    pub block_no: u64,
    /// LSN (v5).
    pub lsn: u64,
    /// UUID (v5).
    pub uuid: [u8; 16],
    /// Owner AG (v5).
    pub owner: u32,
    /// CRC (v5).
    pub crc: u32,
}

impl AllocBtreeBlock {
    /// V4 header size.
    pub const SIZE_V4: usize = 16;
    /// V5 header size.
    pub const SIZE_V5: usize = 56;

    /// Parse from bytes.
    pub fn parse(buffer: &[u8], is_v5: bool) -> FsResult<Self> {
        let min_size = if is_v5 { Self::SIZE_V5 } else { Self::SIZE_V4 };
        if buffer.len() < min_size {
            return Err(FsError::BufferTooSmall);
        }

        let magic = buffer.read_be_u32(0)?;
        let level = buffer.read_be_u16(4)?;
        let num_recs = buffer.read_be_u16(6)?;
        let left_sibling = buffer.read_be_u32(8)?;
        let right_sibling = buffer.read_be_u32(12)?;

        let (block_no, lsn, uuid, owner, crc) = if is_v5 {
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&buffer[28..44]);
            (
                buffer.read_be_u64(16)?,
                buffer.read_be_u64(24)?,
                uuid,
                buffer.read_be_u32(44)?,
                buffer.read_be_u32(48)?,
            )
        } else {
            (0, 0, [0u8; 16], 0, 0)
        };

        Ok(Self {
            magic,
            level,
            num_recs,
            left_sibling,
            right_sibling,
            block_no,
            lsn,
            uuid,
            owner,
            crc,
        })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self, is_v5: bool) -> Vec<u8> {
        let size = if is_v5 { Self::SIZE_V5 } else { Self::SIZE_V4 };
        let mut buf = vec![0u8; size];

        buf[0..4].copy_from_slice(&self.magic.to_be_bytes());
        buf[4..6].copy_from_slice(&self.level.to_be_bytes());
        buf[6..8].copy_from_slice(&self.num_recs.to_be_bytes());
        buf[8..12].copy_from_slice(&self.left_sibling.to_be_bytes());
        buf[12..16].copy_from_slice(&self.right_sibling.to_be_bytes());

        if is_v5 {
            buf[16..24].copy_from_slice(&self.block_no.to_be_bytes());
            buf[24..32].copy_from_slice(&self.lsn.to_be_bytes());
            buf[28..44].copy_from_slice(&self.uuid);
            buf[44..48].copy_from_slice(&self.owner.to_be_bytes());
            buf[48..52].copy_from_slice(&self.crc.to_be_bytes());
        }

        buf
    }

    pub fn is_leaf(&self) -> bool {
        self.level == 0
    }

    pub fn header_size(&self, is_v5: bool) -> usize {
        if is_v5 {
            Self::SIZE_V5
        } else {
            Self::SIZE_V4
        }
    }

    /// Check if this is a BNO tree block.
    pub fn is_bno_tree(&self) -> bool {
        self.magic == XFS_ABTB_MAGIC || self.magic == XFS_ABTB_CRC_MAGIC
    }

    /// Check if this is a CNT tree block.
    pub fn is_cnt_tree(&self) -> bool {
        self.magic == XFS_ABTC_MAGIC || self.magic == XFS_ABTC_CRC_MAGIC
    }
}

/// NULLAGBLOCK constant (indicates no sibling).
pub const NULLAGBLOCK: u32 = 0xFFFFFFFF;

/// Search result from B+tree lookup.
#[derive(Debug)]
pub enum SearchResult {
    /// Exact match found at this index.
    Found(usize),
    /// Not found, but would be inserted at this index.
    NotFound(usize),
}

/// Search a leaf block for a record by start block (BNO tree).
pub fn search_bno_leaf(
    buffer: &[u8],
    header: &AllocBtreeBlock,
    start_block: u32,
    is_v5: bool,
) -> FsResult<SearchResult> {
    let header_size = header.header_size(is_v5);
    let num_recs = header.num_recs as usize;

    // Binary search
    let mut left = 0;
    let mut right = num_recs;

    while left < right {
        let mid = left + (right - left) / 2;
        let rec_offset = header_size + mid * AllocRec::SIZE;
        let rec = AllocRec::parse(&buffer[rec_offset..])?;

        if rec.start_block == start_block {
            return Ok(SearchResult::Found(mid));
        } else if rec.start_block < start_block {
            left = mid + 1;
        } else {
            right = mid;
        }
    }

    Ok(SearchResult::NotFound(left))
}

/// Search a leaf block for a record by count (CNT tree).
pub fn search_cnt_leaf(
    buffer: &[u8],
    header: &AllocBtreeBlock,
    block_count: u32,
    start_block: u32,
    is_v5: bool,
) -> FsResult<SearchResult> {
    let header_size = header.header_size(is_v5);
    let num_recs = header.num_recs as usize;

    // Binary search by count, then by start_block
    let mut left = 0;
    let mut right = num_recs;

    while left < right {
        let mid = left + (right - left) / 2;
        let rec_offset = header_size + mid * AllocRec::SIZE;
        let rec = AllocRec::parse(&buffer[rec_offset..])?;

        if rec.block_count == block_count && rec.start_block == start_block {
            return Ok(SearchResult::Found(mid));
        } else if rec.block_count < block_count
            || (rec.block_count == block_count && rec.start_block < start_block)
        {
            left = mid + 1;
        } else {
            right = mid;
        }
    }

    Ok(SearchResult::NotFound(left))
}

/// Find the first free extent with at least `min_blocks` blocks.
pub fn find_free_extent_by_size(
    buffer: &[u8],
    header: &AllocBtreeBlock,
    min_blocks: u32,
    is_v5: bool,
) -> FsResult<Option<(AllocRec, usize)>> {
    if !header.is_leaf() {
        return Err(FsError::InvalidBlockType);
    }

    let header_size = header.header_size(is_v5);

    // In CNT tree, records are sorted by count ascending
    // Binary search for the first record with count >= min_blocks
    let num_recs = header.num_recs as usize;
    let mut left = 0;
    let mut right = num_recs;

    while left < right {
        let mid = left + (right - left) / 2;
        let rec_offset = header_size + mid * AllocRec::SIZE;
        let rec = AllocRec::parse(&buffer[rec_offset..])?;

        if rec.block_count < min_blocks {
            left = mid + 1;
        } else {
            right = mid;
        }
    }

    if left < num_recs {
        let rec_offset = header_size + left * AllocRec::SIZE;
        let rec = AllocRec::parse(&buffer[rec_offset..])?;
        if rec.block_count >= min_blocks {
            return Ok(Some((rec, left)));
        }
    }

    Ok(None)
}

/// Read all records from a leaf block.
pub fn read_leaf_records(
    buffer: &[u8],
    header: &AllocBtreeBlock,
    is_v5: bool,
) -> FsResult<Vec<AllocRec>> {
    if !header.is_leaf() {
        return Err(FsError::InvalidBlockType);
    }

    let header_size = header.header_size(is_v5);
    let mut records = Vec::with_capacity(header.num_recs as usize);

    for i in 0..header.num_recs as usize {
        let rec_offset = header_size + i * AllocRec::SIZE;
        records.push(AllocRec::parse(&buffer[rec_offset..])?);
    }

    Ok(records)
}

/// Write records to a leaf block buffer.
pub fn write_leaf_records(
    buffer: &mut [u8],
    header: &AllocBtreeBlock,
    records: &[AllocRec],
    is_v5: bool,
) -> FsResult<()> {
    let header_size = header.header_size(is_v5);

    for (i, rec) in records.iter().enumerate() {
        let rec_offset = header_size + i * AllocRec::SIZE;
        if rec_offset + AllocRec::SIZE > buffer.len() {
            return Err(FsError::BufferTooSmall);
        }
        buffer[rec_offset..rec_offset + AllocRec::SIZE].copy_from_slice(&rec.to_bytes());
    }

    Ok(())
}
