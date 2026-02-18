//! XFS Extent records.
//!
//! XFS uses 128-bit extent records packed into 16 bytes.

use fs_abstraction::{
    safe_math::{CheckedOps, CheckedSliceOps},
    FsError,
    FsResult,
};

/// A parsed XFS extent record.
///
/// XFS extents are 128-bit packed records with the following layout:
/// - Bit 127: Unwritten flag
/// - Bits 126-73: File offset (54 bits)
/// - Bits 72-21: Start block (52 bits)
/// - Bits 20-0: Block count (21 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    /// File offset in blocks (where this extent starts in the file).
    pub file_offset: u64,
    /// Absolute start block on disk.
    pub start_block: u64,
    /// Number of blocks in this extent.
    pub block_count: u32,
    /// True if this extent is unwritten (preallocated but not written).
    pub is_unwritten: bool,
}

impl Extent {
    /// Size of a packed extent record in bytes.
    pub const SIZE: usize = 16;

    /// Parses an extent from a 16-byte packed record.
    ///
    /// XFS extent format (128 bits, big-endian):
    /// ```text
    /// +-------+------------------+------------------+---------------+
    /// | 1 bit | 54 bits          | 52 bits          | 21 bits       |
    /// +-------+------------------+------------------+---------------+
    /// | flag  | file offset      | start block      | block count   |
    /// +-------+------------------+------------------+---------------+
    /// ```
    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }

        // Read as two 64-bit big-endian values
        let hi = buffer.read_be_u64(0)?;
        let lo = buffer.read_be_u64(8)?;

        // Parse fields
        // Bit 127 (MSB of hi) = unwritten flag
        let is_unwritten = (hi >> 63) != 0;

        // Bits 126-73 = file offset (54 bits)
        // Shift hi left 1 to remove flag, then right to extract 54 bits
        let file_offset = ((hi & 0x7FFF_FFFF_FFFF_FFFF) >> 9) & 0x003F_FFFF_FFFF_FFFF;

        // Bits 72-21 = start block (52 bits)
        // Low 9 bits from hi, high 43 bits from top of lo
        let start_block = ((hi & 0x1FF) << 43) | ((lo >> 21) & 0x7FF_FFFF_FFFF);

        // Bits 20-0 = block count (21 bits)
        let block_count = (lo & 0x1F_FFFF) as u32;

        Ok(Self {
            file_offset,
            start_block,
            block_count,
            is_unwritten,
        })
    }

    /// Returns `true` if this is an empty/hole extent.
    pub fn is_hole(&self) -> bool {
        self.start_block == 0 && self.block_count == 0
    }

    /// Serialize the extent to a 16-byte packed record.
    ///
    /// This is the inverse of `parse()`.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buffer = [0u8; Self::SIZE];

        // Build the 128-bit packed format
        // hi contains: flag (1 bit) | file_offset (54 bits) | start_block high (9 bits)
        // lo contains: start_block low (43 bits) | block_count (21 bits)

        let flag_bit: u64 = if self.is_unwritten { 1 << 63 } else { 0 };
        let file_offset_bits = (self.file_offset & 0x003F_FFFF_FFFF_FFFF) << 9;
        let start_block_hi = (self.start_block >> 43) & 0x1FF;

        let hi = flag_bit | file_offset_bits | start_block_hi;

        let start_block_lo = (self.start_block & 0x7FF_FFFF_FFFF) << 21;
        let block_count_bits = (self.block_count as u64) & 0x1F_FFFF;

        let lo = start_block_lo | block_count_bits;

        // Write as big-endian
        buffer[0..8].copy_from_slice(&hi.to_be_bytes());
        buffer[8..16].copy_from_slice(&lo.to_be_bytes());

        buffer
    }

    /// Returns the end file offset (exclusive).
    pub fn file_end(&self) -> FsResult<u64> {
        self.file_offset.checked_add_offset(self.block_count as u64)
    }

    /// Returns the end block on disk (exclusive).
    pub fn disk_end(&self) -> FsResult<u64> {
        self.start_block.checked_add_offset(self.block_count as u64)
    }

    /// Checks if the given file block is within this extent.
    pub fn contains_file_block(&self, block: u64) -> bool {
        block >= self.file_offset
            && block < self.file_offset.saturating_add(self.block_count as u64)
    }

    /// Translates a file block to a disk block.
    pub fn translate(&self, file_block: u64) -> FsResult<u64> {
        if !self.contains_file_block(file_block) {
            return Err(FsError::InvalidBlockAddress);
        }
        let offset = file_block
            .checked_sub(self.file_offset)
            .ok_or(FsError::ArithmeticOverflow)?;
        self.start_block
            .checked_add(offset)
            .ok_or(FsError::ArithmeticOverflow)
    }
}

/// Iterator over packed extent records.
pub struct ExtentIter<'a> {
    buffer: &'a [u8],
    offset: usize,
    count: u32,
    current: u32,
}

impl<'a> ExtentIter<'a> {
    /// Creates a new extent iterator.
    ///
    /// # Arguments
    /// * `buffer` - Buffer containing packed extent records
    /// * `count` - Number of extents in the buffer
    pub fn new(buffer: &'a [u8], count: u32) -> Self {
        Self {
            buffer,
            offset: 0,
            count,
            current: 0,
        }
    }
}

impl<'a> Iterator for ExtentIter<'a> {
    type Item = FsResult<Extent>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.count {
            return None;
        }

        if self.offset + Extent::SIZE > self.buffer.len() {
            return Some(Err(FsError::BufferTooSmall));
        }

        let extent = Extent::parse(&self.buffer[self.offset..]);
        self.offset += Extent::SIZE;
        self.current += 1;
        Some(extent)
    }
}

/// Finds an extent containing the given file block.
pub fn find_extent_for_block(
    buffer: &[u8],
    count: u32,
    file_block: u64,
) -> FsResult<Option<Extent>> {
    for result in ExtentIter::new(buffer, count) {
        let extent = result?;
        if extent.contains_file_block(file_block) {
            return Ok(Some(extent));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    #[test]
    fn test_extent_parse() {
        // Create a simple test extent with known values
        // file_offset = 100, start_block = 200, block_count = 50, not unwritten
        let mut buffer = [0u8; 16];

        // Pack the values according to XFS format
        // Bits 126-73: file offset (54 bits)
        // 100 << 9 = 51200 (0xC800) in the 64-bit high part
        buffer[6] = 0xC8;
        buffer[7] = 0x00;

        // Bits 20-0: block count (21 bits)
        // 50 (0x32) in the 64-bit low part
        buffer[15] = 0x32;

        let extent = Extent::parse(&buffer).unwrap();
        assert_eq!(extent.file_offset, 100);
        assert_eq!(extent.block_count, 50);
        assert!(!extent.is_unwritten);
    }

    #[test]
    fn test_extent_buffer_too_small() {
        let buffer = [0u8; 8];
        assert!(matches!(
            Extent::parse(&buffer),
            Err(FsError::BufferTooSmall)
        ));
    }

    #[test]
    fn test_extent_contains_file_block() {
        let extent = Extent {
            file_offset: 100,
            start_block: 200,
            block_count: 10,
            is_unwritten: false,
        };

        // Test block inside extent
        assert!(extent.contains_file_block(105));
        // Test block at start
        assert!(extent.contains_file_block(100));
        // Test block at end (exclusive)
        assert!(!extent.contains_file_block(110));
        // Test block before
        assert!(!extent.contains_file_block(99));
        // Test block after
        assert!(!extent.contains_file_block(111));
    }

    #[test]
    fn test_extent_translate() {
        let extent = Extent {
            file_offset: 100,
            start_block: 200,
            block_count: 10,
            is_unwritten: false,
        };

        // Translate a valid block
        assert_eq!(extent.translate(105).unwrap(), 205);
        // Try to translate an invalid block
        assert!(extent.translate(150).is_err());
    }

    #[test]
    fn test_extent_file_and_disk_end() {
        let extent = Extent {
            file_offset: 100,
            start_block: 200,
            block_count: 10,
            is_unwritten: false,
        };

        assert_eq!(extent.file_end().unwrap(), 110);
        assert_eq!(extent.disk_end().unwrap(), 210);
    }

    #[test]
    fn test_extent_iter() {
        let buffer = [0u8; 32]; // Two extents
                                // Fill with dummy data
        let iter = ExtentIter::new(&buffer, 2);
        let extents: Result<Vec<_>, _> = iter.collect();
        assert!(extents.is_ok());
        assert_eq!(extents.unwrap().len(), 2);
    }
}
