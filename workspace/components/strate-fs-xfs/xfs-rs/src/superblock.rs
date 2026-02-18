//! XFS Superblock parser.
//!
//! The superblock is the primary metadata structure of an XFS filesystem.
//! It's located at the beginning of each Allocation Group (AG), with the
//! primary copy in AG 0.

use fs_abstraction::{safe_math::CheckedSliceOps, FsError, FsResult};

use crate::constants::*;

/// Parsed XFS superblock.
///
/// Contains all filesystem-level metadata including sizes, counts, and
/// feature flags.
#[derive(Debug, Clone)]
pub struct Superblock {
    // ─── Basic Info (offset 0x000-0x007) ──────────────────────────────
    /// Magic number (must be XFS_SB_MAGIC).
    pub magic: u32,
    /// Block size in bytes (e.g., 4096).
    pub block_size: u32,

    // ─── Block Counts (offset 0x008-0x01F) ────────────────────────────
    /// Total data blocks in filesystem.
    pub total_blocks: u64,
    /// Total realtime blocks.
    pub realtime_blocks: u64,
    /// Total realtime extents.
    pub realtime_extents: u64,

    // ─── UUID (offset 0x020-0x02F) ────────────────────────────────────
    /// Filesystem UUID.
    pub uuid: [u8; 16],

    // ─── Log and Root (offset 0x030-0x04F) ────────────────────────────
    /// First block of internal log (0 if external).
    pub log_start: u64,
    /// Root directory inode number.
    pub root_inode: u64,
    /// Realtime bitmap inode.
    pub realtime_bitmap_inode: u64,
    /// Realtime summary inode.
    pub realtime_summary_inode: u64,

    // ─── Sizes (offset 0x050-0x06B) ───────────────────────────────────
    /// Realtime extent size in blocks.
    pub realtime_extent_size: u32,
    /// AG size in blocks.
    pub ag_blocks: u32,
    /// Number of AGs.
    pub ag_count: u32,
    /// Realtime bitmap blocks.
    pub realtime_bitmap_blocks: u32,
    /// Log size in blocks.
    pub log_blocks: u32,
    /// Version number (4 or 5).
    pub version: u16,
    /// Sector size in bytes.
    pub sector_size: u16,
    /// Inode size in bytes.
    pub inode_size: u16,
    /// Inodes per block.
    pub inodes_per_block: u16,
    /// Filesystem name (12 bytes, may not be null-terminated).
    pub name: [u8; 12],

    // ─── Log2 Values (offset 0x078-0x07F) ─────────────────────────────
    /// log2(block_size).
    pub block_log: u8,
    /// log2(sector_size).
    pub sector_log: u8,
    /// log2(inode_size).
    pub inode_log: u8,
    /// log2(inodes_per_block).
    pub inode_per_block_log: u8,
    /// log2(ag_blocks).
    pub ag_block_log: u8,
    /// log2(realtime_extents).
    pub realtime_extent_log: u8,
    /// Set to 1 during mkfs.
    pub in_progress: u8,
    /// Maximum percentage of inodes.
    pub inode_max_percent: u8,

    // ─── Inode/Block Stats (offset 0x080-0x09F) ───────────────────────
    /// Allocated inode count.
    pub inode_count: u64,
    /// Free inode count.
    pub free_inodes: u64,
    /// Free data block count.
    pub free_blocks: u64,
    /// Free realtime extent count.
    pub free_realtime_extents: u64,

    // ─── V5 Fields (offset 0x0D0-0x107) ───────────────────────────────
    /// Compatible features.
    pub features_compat: u32,
    /// Read-only compatible features.
    pub features_ro_compat: u32,
    /// Incompatible features.
    pub features_incompat: u32,
    /// Log incompatible features.
    pub features_log_incompat: u32,
    /// CRC32c of superblock.
    pub crc: u32,
    /// Sparse inode alignment.
    pub sparse_inode_align: u32,
    /// Project quota inode.
    pub project_quota_inode: u64,
    /// Last write sequence number.
    pub lsn: u64,
    /// Metadata UUID.
    pub meta_uuid: [u8; 16],
}

impl Superblock {
    /// Parses a superblock from a byte buffer.
    ///
    /// # Arguments
    /// * `buffer` - Raw bytes from disk (at least XFS_SB_SIZE_V4 bytes)
    ///
    /// # Returns
    /// * `Ok(Superblock)` - Parsed superblock
    /// * `Err(FsError)` - Parse error (buffer too small, invalid magic, etc.)
    ///
    /// # Security
    /// This function performs a local copy of metadata before validation
    /// to prevent TOCTOU attacks.
    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < XFS_SB_SIZE_V4 {
            return Err(FsError::BufferTooSmall);
        }

        // Local copy to prevent TOCTOU
        let mut local = [0u8; XFS_SB_SIZE_V5];
        let copy_len = buffer.len().min(XFS_SB_SIZE_V5);
        local[..copy_len].copy_from_slice(&buffer[..copy_len]);

        // Convert to slice to use CheckedSliceOps
        let local_slice = &local[..];

        // Check magic
        let magic = local_slice.read_be_u32(0x000)?;
        if magic != XFS_SB_MAGIC {
            return Err(FsError::InvalidMagic);
        }

        // Parse common fields (v4/v5)
        let block_size = local_slice.read_be_u32(0x004)?;
        let total_blocks = local_slice.read_be_u64(0x008)?;
        let realtime_blocks = local_slice.read_be_u64(0x010)?;
        let realtime_extents = local_slice.read_be_u64(0x018)?;

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&local[0x020..0x030]);

        let log_start = local_slice.read_be_u64(0x030)?;
        let root_inode = local_slice.read_be_u64(0x038)?;
        let realtime_bitmap_inode = local_slice.read_be_u64(0x040)?;
        let realtime_summary_inode = local_slice.read_be_u64(0x048)?;

        let realtime_extent_size = local_slice.read_be_u32(0x050)?;
        let ag_blocks = local_slice.read_be_u32(0x054)?;
        let ag_count = local_slice.read_be_u32(0x058)?;
        let realtime_bitmap_blocks = local_slice.read_be_u32(0x05C)?;
        let log_blocks = local_slice.read_be_u32(0x060)?;
        let version = local_slice.read_be_u16(0x064)?;
        let sector_size = local_slice.read_be_u16(0x066)?;
        let inode_size = local_slice.read_be_u16(0x068)?;
        let inodes_per_block = local_slice.read_be_u16(0x06A)?;

        let mut name = [0u8; 12];
        name.copy_from_slice(&local[0x06C..0x078]);

        let block_log = local[0x078];
        let sector_log = local[0x079];
        let inode_log = local[0x07A];
        let inode_per_block_log = local[0x07B];
        let ag_block_log = local[0x07C];
        let realtime_extent_log = local[0x07D];
        let in_progress = local[0x07E];
        let inode_max_percent = local[0x07F];

        let inode_count = local_slice.read_be_u64(0x080)?;
        let free_inodes = local_slice.read_be_u64(0x088)?;
        let free_blocks = local_slice.read_be_u64(0x090)?;
        let free_realtime_extents = local_slice.read_be_u64(0x098)?;

        // Parse v5 fields if present
        let (features_compat, features_ro_compat, features_incompat, features_log_incompat) =
            if version >= XFS_SB_VERSION_5 && buffer.len() >= XFS_SB_SIZE_V5 {
                (
                    local_slice.read_be_u32(0x0D0)?,
                    local_slice.read_be_u32(0x0D4)?,
                    local_slice.read_be_u32(0x0D8)?,
                    local_slice.read_be_u32(0x0DC)?,
                )
            } else {
                (0, 0, 0, 0)
            };

        let crc = if version >= XFS_SB_VERSION_5 && buffer.len() >= XFS_SB_SIZE_V5 {
            local_slice.read_be_u32(0x0E0)?
        } else {
            0
        };

        let sparse_inode_align = if version >= XFS_SB_VERSION_5 && buffer.len() >= XFS_SB_SIZE_V5 {
            local_slice.read_be_u32(0x0E4)?
        } else {
            0
        };

        let project_quota_inode = if version >= XFS_SB_VERSION_5 && buffer.len() >= XFS_SB_SIZE_V5 {
            local_slice.read_be_u64(0x0E8)?
        } else {
            0
        };

        let lsn = if version >= XFS_SB_VERSION_5 && buffer.len() >= XFS_SB_SIZE_V5 {
            local_slice.read_be_u64(0x0F0)?
        } else {
            0
        };

        let mut meta_uuid = [0u8; 16];
        if version >= XFS_SB_VERSION_5 && buffer.len() >= XFS_SB_SIZE_V5 {
            meta_uuid.copy_from_slice(&local[0x0F8..0x108]);
        }

        let sb = Self {
            magic,
            block_size,
            total_blocks,
            realtime_blocks,
            realtime_extents,
            uuid,
            log_start,
            root_inode,
            realtime_bitmap_inode,
            realtime_summary_inode,
            realtime_extent_size,
            ag_blocks,
            ag_count,
            realtime_bitmap_blocks,
            log_blocks,
            version,
            sector_size,
            inode_size,
            inodes_per_block,
            name,
            block_log,
            sector_log,
            inode_log,
            inode_per_block_log,
            ag_block_log,
            realtime_extent_log,
            in_progress,
            inode_max_percent,
            inode_count,
            free_inodes,
            free_blocks,
            free_realtime_extents,
            features_compat,
            features_ro_compat,
            features_incompat,
            features_log_incompat,
            crc,
            sparse_inode_align,
            project_quota_inode,
            lsn,
            meta_uuid,
        };

        // Validate parsed values
        sb.validate()?;

        Ok(sb)
    }

    /// Validates superblock consistency.
    fn validate(&self) -> FsResult<()> {
        // Check block size is power of 2 and reasonable
        if !self.block_size.is_power_of_two() || self.block_size < 512 || self.block_size > 65536 {
            return Err(FsError::Corrupted);
        }

        // Check block_log matches block_size
        if (1u32 << self.block_log) != self.block_size {
            return Err(FsError::Corrupted);
        }

        // Check sector size
        if !self.sector_size.is_power_of_two()
            || self.sector_size < 512
            || self.sector_size > self.block_size as u16
        {
            return Err(FsError::Corrupted);
        }

        // Check inode size
        if !self.inode_size.is_power_of_two()
            || (self.inode_size as usize) < XFS_MIN_INODE_SIZE
            || (self.inode_size as usize) > XFS_MAX_INODE_SIZE
        {
            return Err(FsError::Corrupted);
        }

        // Check AG count
        if self.ag_count == 0 {
            return Err(FsError::Corrupted);
        }

        // Verify total blocks doesn't overflow
        let _total = (self.ag_blocks as u64)
            .checked_mul(self.ag_count as u64)
            .ok_or(FsError::ArithmeticOverflow)?;

        // Check version
        let version_num = self.version & 0x000F;
        if version_num != XFS_SB_VERSION_4 && version_num != XFS_SB_VERSION_5 {
            return Err(FsError::UnsupportedVersion);
        }

        Ok(())
    }

    /// Returns `true` if this is a v5 filesystem.
    pub fn is_v5(&self) -> bool {
        (self.version & 0x000F) >= XFS_SB_VERSION_5
    }

    /// Returns `true` if the filesystem has file type in directory entries.
    pub fn has_ftype(&self) -> bool {
        self.is_v5() && (self.features_incompat & XFS_SB_FEAT_INCOMPAT_FTYPE) != 0
    }

    /// Returns `true` if the filesystem supports sparse inodes.
    pub fn has_sparse_inodes(&self) -> bool {
        self.is_v5() && (self.features_incompat & XFS_SB_FEAT_INCOMPAT_SPINODES) != 0
    }

    /// Returns `true` if the filesystem has big timestamps.
    pub fn has_bigtime(&self) -> bool {
        self.is_v5() && (self.features_incompat & XFS_SB_FEAT_INCOMPAT_BIGTIME) != 0
    }

    /// Gets the filesystem name as a string slice.
    pub fn name_str(&self) -> &str {
        // Find null terminator or end
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(12);
        core::str::from_utf8(&self.name[..end]).unwrap_or("")
    }

    /// Calculates the byte offset of an AG.
    pub fn ag_offset(&self, ag_number: u32) -> FsResult<u64> {
        if ag_number >= self.ag_count {
            return Err(FsError::InvalidBlockAddress);
        }
        (ag_number as u64)
            .checked_mul(self.ag_blocks as u64)
            .ok_or(FsError::ArithmeticOverflow)?
            .checked_mul(self.block_size as u64)
            .ok_or(FsError::ArithmeticOverflow)
    }

    /// Calculates the block number from an AG-relative address.
    pub fn ag_to_absolute_block(&self, ag: u32, ag_block: u32) -> FsResult<u64> {
        if ag >= self.ag_count || ag_block >= self.ag_blocks {
            return Err(FsError::InvalidBlockAddress);
        }
        (ag as u64)
            .checked_mul(self.ag_blocks as u64)
            .ok_or(FsError::ArithmeticOverflow)?
            .checked_add(ag_block as u64)
            .ok_or(FsError::ArithmeticOverflow)
    }

    /// Calculates the byte offset for a given block number.
    pub fn block_to_byte_offset(&self, block: u64) -> FsResult<u64> {
        block
            .checked_mul(self.block_size as u64)
            .ok_or(FsError::ArithmeticOverflow)
    }

    /// Calculates which AG contains a given block.
    pub fn block_to_ag(&self, block: u64) -> FsResult<(u32, u32)> {
        let ag = (block / self.ag_blocks as u64) as u32;
        let ag_block = (block % self.ag_blocks as u64) as u32;
        if ag >= self.ag_count {
            return Err(FsError::InvalidBlockAddress);
        }
        Ok((ag, ag_block))
    }

    /// Gets filesystem size in bytes.
    pub fn size_bytes(&self) -> FsResult<u64> {
        self.total_blocks
            .checked_mul(self.block_size as u64)
            .ok_or(FsError::ArithmeticOverflow)
    }

    /// Serialize the superblock to bytes (without CRC - caller should
    /// recalculate).
    ///
    /// Returns XFS_SB_SIZE_V5 bytes for v5 or XFS_SB_SIZE_V4 bytes for v4.
    pub fn to_bytes(&self) -> [u8; XFS_SB_SIZE_V5] {
        let mut buf = [0u8; XFS_SB_SIZE_V5];

        // Basic info
        buf[0x000..0x004].copy_from_slice(&self.magic.to_be_bytes());
        buf[0x004..0x008].copy_from_slice(&self.block_size.to_be_bytes());

        // Block counts
        buf[0x008..0x010].copy_from_slice(&self.total_blocks.to_be_bytes());
        buf[0x010..0x018].copy_from_slice(&self.realtime_blocks.to_be_bytes());
        buf[0x018..0x020].copy_from_slice(&self.realtime_extents.to_be_bytes());

        // UUID
        buf[0x020..0x030].copy_from_slice(&self.uuid);

        // Log and root
        buf[0x030..0x038].copy_from_slice(&self.log_start.to_be_bytes());
        buf[0x038..0x040].copy_from_slice(&self.root_inode.to_be_bytes());
        buf[0x040..0x048].copy_from_slice(&self.realtime_bitmap_inode.to_be_bytes());
        buf[0x048..0x050].copy_from_slice(&self.realtime_summary_inode.to_be_bytes());

        // Sizes
        buf[0x050..0x054].copy_from_slice(&self.realtime_extent_size.to_be_bytes());
        buf[0x054..0x058].copy_from_slice(&self.ag_blocks.to_be_bytes());
        buf[0x058..0x05C].copy_from_slice(&self.ag_count.to_be_bytes());
        buf[0x05C..0x060].copy_from_slice(&self.realtime_bitmap_blocks.to_be_bytes());
        buf[0x060..0x064].copy_from_slice(&self.log_blocks.to_be_bytes());
        buf[0x064..0x066].copy_from_slice(&self.version.to_be_bytes());
        buf[0x066..0x068].copy_from_slice(&self.sector_size.to_be_bytes());
        buf[0x068..0x06A].copy_from_slice(&self.inode_size.to_be_bytes());
        buf[0x06A..0x06C].copy_from_slice(&self.inodes_per_block.to_be_bytes());
        buf[0x06C..0x078].copy_from_slice(&self.name);

        // Log2 values
        buf[0x078] = self.block_log;
        buf[0x079] = self.sector_log;
        buf[0x07A] = self.inode_log;
        buf[0x07B] = self.inode_per_block_log;
        buf[0x07C] = self.ag_block_log;
        buf[0x07D] = self.realtime_extent_log;
        buf[0x07E] = self.in_progress;
        buf[0x07F] = self.inode_max_percent;

        // Inode/block stats
        buf[0x080..0x088].copy_from_slice(&self.inode_count.to_be_bytes());
        buf[0x088..0x090].copy_from_slice(&self.free_inodes.to_be_bytes());
        buf[0x090..0x098].copy_from_slice(&self.free_blocks.to_be_bytes());
        buf[0x098..0x0A0].copy_from_slice(&self.free_realtime_extents.to_be_bytes());

        // Skip some v4 fields at 0xA0-0xCF that we didn't parse

        // V5 fields
        if self.is_v5() {
            buf[0x0D0..0x0D4].copy_from_slice(&self.features_compat.to_be_bytes());
            buf[0x0D4..0x0D8].copy_from_slice(&self.features_ro_compat.to_be_bytes());
            buf[0x0D8..0x0DC].copy_from_slice(&self.features_incompat.to_be_bytes());
            buf[0x0DC..0x0E0].copy_from_slice(&self.features_log_incompat.to_be_bytes());
            buf[0x0E0..0x0E4].copy_from_slice(&self.crc.to_be_bytes());
            buf[0x0E4..0x0E8].copy_from_slice(&self.sparse_inode_align.to_be_bytes());
            buf[0x0E8..0x0F0].copy_from_slice(&self.project_quota_inode.to_be_bytes());
            buf[0x0F0..0x0F8].copy_from_slice(&self.lsn.to_be_bytes());
            buf[0x0F8..0x108].copy_from_slice(&self.meta_uuid);
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_too_small() {
        let buf = [0u8; 100];
        assert!(matches!(
            Superblock::parse(&buf),
            Err(FsError::BufferTooSmall)
        ));
    }

    #[test]
    fn test_parse_invalid_magic() {
        let mut buf = [0u8; XFS_SB_SIZE_V4];
        // Wrong magic
        buf[0..4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(matches!(
            Superblock::parse(&buf),
            Err(FsError::InvalidMagic)
        ));
    }

    #[test]
    fn test_parse_valid_v4() {
        let mut buf = [0u8; XFS_SB_SIZE_V4];
        // Set valid magic
        buf[0..4].copy_from_slice(&XFS_SB_MAGIC.to_be_bytes());
        // Set block size to 4096
        buf[4..8].copy_from_slice(&4096u32.to_be_bytes());
        // Set total blocks to 1024
        buf[0x008..0x010].copy_from_slice(&1024u64.to_be_bytes());
        // Set AG blocks to 1024
        buf[0x054..0x058].copy_from_slice(&1024u32.to_be_bytes());
        // Set AG count to 1
        buf[0x058..0x05C].copy_from_slice(&1u32.to_be_bytes());
        // Set version
        buf[0x064..0x066].copy_from_slice(&4u16.to_be_bytes());
        // Set sector size
        buf[0x066..0x068].copy_from_slice(&512u16.to_be_bytes());
        // Set inode size
        buf[0x068..0x06A].copy_from_slice(&256u16.to_be_bytes());

        // Logs
        buf[0x078] = 12; // block_log
        buf[0x079] = 9; // sector_log
        buf[0x07A] = 8; // inode_log
        buf[0x07C] = 10; // ag_block_log

        let sb = Superblock::parse(&buf).expect("Valid v4 superblock should parse");
        assert_eq!(sb.magic, XFS_SB_MAGIC);
        assert_eq!(sb.block_size, 4096);
        assert_eq!(sb.ag_count, 1);
        assert_eq!(sb.ag_blocks, 1024);
    }

    #[test]
    fn test_is_v5() {
        let mut buf = [0u8; XFS_SB_SIZE_V4];
        buf[0..4].copy_from_slice(&XFS_SB_MAGIC.to_be_bytes());
        buf[4..8].copy_from_slice(&4096u32.to_be_bytes());
        buf[0x008..0x010].copy_from_slice(&1024u64.to_be_bytes());
        buf[0x054..0x058].copy_from_slice(&1024u32.to_be_bytes());
        buf[0x058..0x05C].copy_from_slice(&1u32.to_be_bytes());
        buf[0x066..0x068].copy_from_slice(&512u16.to_be_bytes());
        buf[0x068..0x06A].copy_from_slice(&256u16.to_be_bytes());
        buf[0x078] = 12; // block_log
        buf[0x079] = 9; // sector_log
        buf[0x07A] = 8; // inode_log
        buf[0x07C] = 10; // ag_block_log

        // Version 4
        buf[0x064..0x066].copy_from_slice(&4u16.to_be_bytes());
        let sb = Superblock::parse(&buf).unwrap();
        assert!(!sb.is_v5());

        // Version 5
        let mut buf5 = [0u8; XFS_SB_SIZE_V5];
        buf5[..XFS_SB_SIZE_V4].copy_from_slice(&buf);
        buf5[0x064..0x066].copy_from_slice(&5u16.to_be_bytes());
        let sb = Superblock::parse(&buf5).unwrap();
        assert!(sb.is_v5());
    }
}
