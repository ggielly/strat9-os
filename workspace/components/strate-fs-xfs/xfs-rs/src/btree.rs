//! XFS B+Tree structures.
//!
//! XFS uses B+Trees for:
//! - Large file extent lists (BMBT)
//! - Large directories
//! - Free space tracking
//! - Inode allocation

#[cfg(feature = "alloc")]
extern crate alloc;

use fs_abstraction::{safe_math::CheckedSliceOps, FsError, FsResult};

use crate::constants::*;

/// B+Tree block types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtreeType {
    /// Block map B+tree (for file extents).
    BlockMap,
    /// Directory B+tree.
    Directory,
    /// Free space by block number.
    AllocByBlock,
    /// Free space by size.
    AllocBySize,
    /// Inode B+tree.
    Inode,
    /// Reverse map B+tree.
    ReverseMap,
    /// Reference count B+tree.
    RefCount,
}

/// B+Tree block header (long format, for BMBT).
#[derive(Debug, Clone)]
pub struct BtreeBlockLong {
    /// Magic number.
    pub magic: u32,
    /// B+tree level (0 = leaf).
    pub level: u16,
    /// Number of records/keys.
    pub num_recs: u16,
    /// Left sibling block.
    pub left_sibling: u64,
    /// Right sibling block.
    pub right_sibling: u64,
    /// Block number (v5).
    pub block_no: u64,
    /// Log sequence number (v5).
    pub lsn: u64,
    /// UUID (v5).
    pub uuid: [u8; 16],
    /// Owner inode (v5).
    pub owner: u64,
    /// CRC (v5).
    pub crc: u32,
}

impl BtreeBlockLong {
    /// Size of v4 header.
    pub const SIZE_V4: usize = 24;
    /// Size of v5 header.
    pub const SIZE_V5: usize = 72;

    /// Parses a long-format B+tree block header.
    pub fn parse(buffer: &[u8], is_v5: bool) -> FsResult<Self> {
        let min_size = if is_v5 { Self::SIZE_V5 } else { Self::SIZE_V4 };
        if buffer.len() < min_size {
            return Err(FsError::BufferTooSmall);
        }

        let magic = buffer.read_be_u32(0)?;
        // Validate magic
        if magic != XFS_BMAP_MAGIC && magic != XFS_BMAP_CRC_MAGIC {
            return Err(FsError::InvalidMagic);
        }

        let level = buffer.read_be_u16(4)?;
        let num_recs = buffer.read_be_u16(6)?;
        let left_sibling = buffer.read_be_u64(8)?;
        let right_sibling = buffer.read_be_u64(16)?;

        let (block_no, lsn, uuid, owner, crc) = if is_v5 {
            let block_no = buffer.read_be_u64(24)?;
            let lsn = buffer.read_be_u64(32)?;
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&buffer[40..56]);
            let owner = buffer.read_be_u64(56)?;
            let crc = buffer.read_be_u32(64)?;
            (block_no, lsn, uuid, owner, crc)
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

    /// Returns `true` if this is a leaf node.
    pub fn is_leaf(&self) -> bool {
        self.level == 0
    }

    /// Returns `true` if this is a v5 block.
    pub fn is_v5(&self) -> bool {
        self.magic == XFS_BMAP_CRC_MAGIC
    }

    /// Returns the header size.
    pub fn header_size(&self) -> usize {
        if self.is_v5() {
            Self::SIZE_V5
        } else {
            Self::SIZE_V4
        }
    }

    /// Finds the child block pointer for a given file offset in an intermediate
    /// node.
    pub fn get_ptr_for_offset(&self, buffer: &[u8], file_offset: u64) -> FsResult<u64> {
        if self.level == 0 {
            return Err(FsError::InvalidBlockType);
        }

        let header_size = self.header_size();
        let keys_offset = header_size;
        let ptrs_offset = header_size + (self.num_recs as usize * BmbtKey::SIZE);

        // Validate that the buffer is large enough for all records
        let min_buffer_size = ptrs_offset + (self.num_recs as usize * BmbtPtr::SIZE);
        if buffer.len() < min_buffer_size {
            return Err(FsError::BufferTooSmall);
        }

        // Binary search for the largest key <= file_offset
        let num_recs_usize = self.num_recs as usize;

        // Handle the case where there are no records
        if num_recs_usize == 0 {
            return Err(FsError::NotFound);
        }

        let mut left = 0;
        let mut right = num_recs_usize;
        let mut result_idx = None;

        // Perform binary search - using exclusive upper bound to avoid underflow
        while left < right {
            let mid = left + (right - left) / 2;

            // Validate buffer bounds before parsing
            if keys_offset + mid * BmbtKey::SIZE + BmbtKey::SIZE > buffer.len() {
                return Err(FsError::BufferTooSmall);
            }

            let key = BmbtKey::parse(&buffer[keys_offset + mid * BmbtKey::SIZE..])?;

            if key.file_offset <= file_offset {
                result_idx = Some(mid);
                // Move to right half to find a potentially larger valid key
                left = mid + 1;
            } else {
                // Move to left half
                right = mid;
            }
        }

        match result_idx {
            Some(idx) => {
                // Validate buffer bounds before parsing pointer
                if ptrs_offset + idx * BmbtPtr::SIZE + BmbtPtr::SIZE > buffer.len() {
                    return Err(FsError::BufferTooSmall);
                }

                let ptr = BmbtPtr::parse(&buffer[ptrs_offset + idx * BmbtPtr::SIZE..])?;
                Ok(ptr.block)
            }
            None => Err(FsError::NotFound),
        }
    }

    /// Finds the extent covering a given file offset in a leaf node.
    pub fn get_extent_for_offset(
        &self,
        buffer: &[u8],
        file_offset: u64,
    ) -> FsResult<Option<crate::extent::Extent>> {
        if self.level != 0 {
            return Err(FsError::InvalidBlockType);
        }

        let header_size = self.header_size();
        for i in 0..self.num_recs as usize {
            let extent = crate::extent::Extent::parse(
                &buffer[header_size + i * crate::extent::Extent::SIZE..],
            )?;
            if extent.contains_file_block(file_offset) {
                return Ok(Some(extent));
            }
        }

        Ok(None)
    }
}

/// B+Tree block header (short format, for AG-local trees).
#[derive(Debug, Clone)]
pub struct BtreeBlockShort {
    /// Magic number.
    pub magic: u32,
    /// B+tree level (0 = leaf).
    pub level: u16,
    /// Number of records/keys.
    pub num_recs: u16,
    /// Left sibling block (AG-relative).
    pub left_sibling: u32,
    /// Right sibling block (AG-relative).
    pub right_sibling: u32,
    /// Block number (v5, AG-relative).
    pub block_no: u32,
    /// Log sequence number (v5).
    pub lsn: u64,
    /// UUID (v5).
    pub uuid: [u8; 16],
    /// Owner AG (v5).
    pub owner: u32,
    /// CRC (v5).
    pub crc: u32,
}

impl BtreeBlockShort {
    /// Size of v4 header.
    pub const SIZE_V4: usize = 16;
    /// Size of v5 header.
    pub const SIZE_V5: usize = 56;

    /// Parses a short-format B+tree block header.
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
            let block_no = buffer.read_be_u32(16)?;
            let lsn = buffer.read_be_u64(20)?;
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&buffer[28..44]);
            let owner = buffer.read_be_u32(44)?;
            let crc = buffer.read_be_u32(48)?;
            (block_no, lsn, uuid, owner, crc)
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

    /// Returns `true` if this is a leaf node.
    pub fn is_leaf(&self) -> bool {
        self.level == 0
    }
}

/// BMBT (Block Map B+Tree) key structure.
#[derive(Debug, Clone, Copy)]
pub struct BmbtKey {
    /// Starting file offset.
    pub file_offset: u64,
}

impl BmbtKey {
    /// Size of a BMBT key.
    pub const SIZE: usize = 8;

    /// Parses a BMBT key.
    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }
        Ok(Self {
            file_offset: buffer.read_be_u64(0)?,
        })
    }
}

/// BMBT pointer structure (block number).
#[derive(Debug, Clone, Copy)]
pub struct BmbtPtr {
    /// Block number.
    pub block: u64,
}

impl BmbtPtr {
    /// Size of a BMBT pointer.
    pub const SIZE: usize = 8;

    /// Parses a BMBT pointer.
    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }
        Ok(Self {
            block: buffer.read_be_u64(0)?,
        })
    }
}

/// BMBT record (same as extent, 128 bits).
pub type BmbtRec = crate::extent::Extent;

/// BMBT (Block Map B+Tree) root structure stored in inode data fork.
///
/// When a file grows large enough that its extent list can't fit in the
/// inode's data fork, XFS converts it to a B+Tree structure. The root
/// of this tree is stored inline in the data fork.
///
/// Layout in data fork:
/// ```text
/// +----------+----------+------------------+------------------+
/// | level    | numrecs  | keys[numrecs]    | ptrs[numrecs]    |
/// | (2 bytes)| (2 bytes)| (8 bytes each)   | (8 bytes each)   |
/// +----------+----------+------------------+------------------+
/// ```
#[derive(Debug, Clone)]
pub struct BmbtRoot {
    /// B+tree level (0 = leaf, >0 = intermediate).
    pub level: u16,
    /// Number of keys/pointers in this root.
    pub num_recs: u16,
    /// Keys (file block offsets).
    #[cfg(feature = "alloc")]
    pub keys: alloc::vec::Vec<BmbtKey>,
    /// Pointers (disk block numbers).
    #[cfg(feature = "alloc")]
    pub ptrs: alloc::vec::Vec<BmbtPtr>,
}

impl BmbtRoot {
    /// Header size (level + numrecs).
    pub const HEADER_SIZE: usize = 4;

    /// Parses the BMBT root from an inode's data fork.
    ///
    /// # Arguments
    /// * `data` - The raw data fork bytes (after the 4-byte header in Inode
    ///   parsing)
    /// * `level` - The B+tree level from the inode
    /// * `num_recs` - The number of records from the inode
    #[cfg(feature = "alloc")]
    pub fn parse(data: &[u8], level: u16, num_recs: u16) -> FsResult<Self> {
        // Validate we have enough data for keys and pointers
        let keys_size = num_recs as usize * BmbtKey::SIZE;
        let ptrs_size = num_recs as usize * BmbtPtr::SIZE;
        let required_size = keys_size + ptrs_size;

        if data.len() < required_size {
            return Err(FsError::BufferTooSmall);
        }

        // Parse keys
        let mut keys = alloc::vec::Vec::with_capacity(num_recs as usize);
        for i in 0..num_recs as usize {
            let key = BmbtKey::parse(&data[i * BmbtKey::SIZE..])?;
            keys.push(key);
        }

        // Parse pointers (they come after all keys)
        let ptrs_offset = keys_size;
        let mut ptrs = alloc::vec::Vec::with_capacity(num_recs as usize);
        for i in 0..num_recs as usize {
            let ptr = BmbtPtr::parse(&data[ptrs_offset + i * BmbtPtr::SIZE..])?;
            ptrs.push(ptr);
        }

        Ok(Self {
            level,
            num_recs,
            keys,
            ptrs,
        })
    }

    /// Returns `true` if this root points directly to leaf nodes.
    pub fn is_leaf_parent(&self) -> bool {
        self.level == 1
    }

    /// Finds the child block pointer for a given file offset.
    ///
    /// Uses binary search to find the largest key <= file_offset,
    /// then returns the corresponding pointer.
    #[cfg(feature = "alloc")]
    pub fn find_child_ptr(&self, file_offset: u64) -> FsResult<u64> {
        if self.num_recs == 0 {
            return Err(FsError::NotFound);
        }

        // Binary search for the largest key <= file_offset
        let mut left = 0usize;
        let mut right = self.num_recs as usize;
        let mut result_idx = None;

        while left < right {
            let mid = left + (right - left) / 2;
            if self.keys[mid].file_offset <= file_offset {
                result_idx = Some(mid);
                left = mid + 1;
            } else {
                right = mid;
            }
        }

        match result_idx {
            Some(idx) => Ok(self.ptrs[idx].block),
            None => {
                // file_offset is before the first key - this shouldn't happen
                // for valid file blocks, but return the first pointer anyway
                if self.num_recs > 0 && file_offset < self.keys[0].file_offset {
                    Err(FsError::NotFound)
                } else {
                    Err(FsError::NotFound)
                }
            }
        }
    }
}

/// Trait for reading disk blocks during B+Tree traversal.
///
/// This allows the B+Tree traversal code to be used with different
/// storage backends (kernel driver, userspace, etc.).
#[cfg(feature = "alloc")]
pub trait BlockReader {
    /// Reads a disk block at the given block number.
    fn read_block(&self, block_num: u64) -> FsResult<alloc::vec::Vec<u8>>;
}

/// Result of a B+Tree extent lookup.
#[derive(Debug, Clone)]
pub struct BtreeLookupResult {
    /// The extent containing the requested file block, if found.
    pub extent: Option<crate::extent::Extent>,
    /// The physical disk block for the file block, if found.
    pub disk_block: Option<u64>,
}

/// Traverses a BMBT (Block Map B+Tree) to find the extent for a file block.
///
/// # Arguments
/// * `root` - The BMBT root from the inode
/// * `file_block` - The file block offset to look up
/// * `reader` - A block reader for reading intermediate B+tree nodes
/// * `is_v5` - Whether this is a v5 filesystem (affects header sizes)
///
/// # Returns
/// The extent containing the file block, or None if it's a hole.
#[cfg(feature = "alloc")]
pub fn btree_lookup_extent<R: BlockReader>(
    root: &BmbtRoot,
    file_block: u64,
    reader: &R,
    is_v5: bool,
) -> FsResult<Option<crate::extent::Extent>> {
    // Start with the root's child pointer for this file offset
    let mut current_block = root.find_child_ptr(file_block)?;
    let mut current_level = root.level;

    // Traverse down the tree
    while current_level > 0 {
        let block_data = reader.read_block(current_block)?;
        let header = BtreeBlockLong::parse(&block_data, is_v5)?;

        if header.is_leaf() {
            // We've reached a leaf node - search for the extent
            return header.get_extent_for_offset(&block_data, file_block);
        } else {
            // Intermediate node - find the next block to visit
            current_block = header.get_ptr_for_offset(&block_data, file_block)?;
            current_level = header.level;
        }
    }

    // If we exit the loop with level 0, something went wrong
    Err(FsError::Corrupted)
}

/// Collects all extents from a BMBT by traversing all leaf nodes.
///
/// This is useful for operations that need the complete extent list,
/// such as calculating total file blocks or validating the tree.
#[cfg(feature = "alloc")]
pub fn btree_collect_extents<R: BlockReader>(
    root: &BmbtRoot,
    reader: &R,
    is_v5: bool,
) -> FsResult<alloc::vec::Vec<crate::extent::Extent>> {
    let mut extents = alloc::vec::Vec::new();

    // We need to traverse to find the leftmost leaf, then follow sibling pointers
    if root.num_recs == 0 {
        return Ok(extents);
    }

    // Find the leftmost leaf by always taking the first pointer
    let mut current_block = root.ptrs[0].block;
    let mut current_level = root.level;

    // Traverse down to the leftmost leaf
    while current_level > 1 {
        let block_data = reader.read_block(current_block)?;
        let header = BtreeBlockLong::parse(&block_data, is_v5)?;

        if header.num_recs == 0 {
            return Err(FsError::Corrupted);
        }

        // Get the first (leftmost) pointer
        let header_size = header.header_size();
        let ptrs_offset = header_size + (header.num_recs as usize * BmbtKey::SIZE);
        let ptr = BmbtPtr::parse(&block_data[ptrs_offset..])?;

        current_block = ptr.block;
        current_level = header.level;
    }

    // Now traverse all leaves using sibling pointers
    loop {
        let block_data = reader.read_block(current_block)?;
        let header = BtreeBlockLong::parse(&block_data, is_v5)?;

        if !header.is_leaf() {
            return Err(FsError::Corrupted);
        }

        // Read all extents from this leaf
        let header_size = header.header_size();
        for i in 0..header.num_recs as usize {
            let extent_offset = header_size + i * crate::extent::Extent::SIZE;
            let extent = crate::extent::Extent::parse(&block_data[extent_offset..])?;
            extents.push(extent);
        }

        // Move to right sibling, or stop if there is none
        if header.right_sibling == u64::MAX || header.right_sibling == 0 {
            break;
        }
        current_block = header.right_sibling;
    }

    Ok(extents)
}
