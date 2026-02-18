//! XFS filesystem constants.
//!
//! Magic numbers, sizes, and limits for XFS structures.

/// Magic number: "XFSB" in ASCII (0x58465342).
pub const XFS_SB_MAGIC: u32 = 0x58465342;

/// Magic number for AGF (Allocation Group Free space).
pub const XFS_AGF_MAGIC: u32 = 0x58414746; // "XAGF"

/// Magic number for AGI (Allocation Group Inode).
pub const XFS_AGI_MAGIC: u32 = 0x58414749; // "XAGI"

/// Magic number for AGFL (AG Free List).
pub const XFS_AGFL_MAGIC: u32 = 0x5841464C; // "XAFL"

/// Magic number for v3 inode (on-disk).
pub const XFS_DINODE_MAGIC: u16 = 0x494E; // "IN"

/// Magic number for directory block.
pub const XFS_DIR2_BLOCK_MAGIC: u32 = 0x58443242; // "XD2B"

/// Magic number for v3 directory block.
pub const XFS_DIR3_BLOCK_MAGIC: u32 = 0x58444233; // "XDB3"

/// Magic number for directory data.
pub const XFS_DIR2_DATA_MAGIC: u32 = 0x58443244; // "XD2D"

/// Magic number for v3 directory data.
pub const XFS_DIR3_DATA_MAGIC: u32 = 0x58444433; // "XDD3"

/// Magic number for directory leaf.
pub const XFS_DIR2_LEAF_MAGIC: u16 = 0xD2F1;

/// Magic number for v3 directory leaf.
pub const XFS_DIR3_LEAF_MAGIC: u16 = 0x3DF1;

/// Magic number for directory free index.
pub const XFS_DIR2_FREE_MAGIC: u32 = 0x58443246; // "XD2F"

/// Magic number for v3 directory free index.
pub const XFS_DIR3_FREE_MAGIC: u32 = 0x58444633; // "XDF3"

/// Magic number for B+tree block (long form).
pub const XFS_BMAP_MAGIC: u32 = 0x424D4150; // "BMAP"

/// Magic number for v5 B+tree block (long form).
pub const XFS_BMAP_CRC_MAGIC: u32 = 0x424D4133; // "BMA3"

/// Magic number for BNO B+tree (free space by block number).
pub const XFS_ABTB_MAGIC: u32 = 0x41425442; // "ABTB"

/// Magic number for v5 BNO B+tree.
pub const XFS_ABTB_CRC_MAGIC: u32 = 0x41423342; // "AB3B"

/// Magic number for CNT B+tree (free space by count).
pub const XFS_ABTC_MAGIC: u32 = 0x41425443; // "ABTC"

/// Magic number for v5 CNT B+tree.
pub const XFS_ABTC_CRC_MAGIC: u32 = 0x41423343; // "AB3C"

/// Magic number for inode B+tree.
pub const XFS_IBT_MAGIC: u32 = 0x49414254; // "IABT"

/// Magic number for v5 inode B+tree.
pub const XFS_IBT_CRC_MAGIC: u32 = 0x49414233; // "IAB3"

/// Magic number for free inode B+tree.
pub const XFS_FIBT_MAGIC: u32 = 0x46494254; // "FIBT"

/// Magic number for v5 free inode B+tree.
pub const XFS_FIBT_CRC_MAGIC: u32 = 0x46494233; // "FIB3"

// ─── Sizes ────────────────────────────────────────────────────────────────

/// Minimum superblock size (v4).
pub const XFS_SB_SIZE_V4: usize = 208;

/// Superblock size (v5).
pub const XFS_SB_SIZE_V5: usize = 264;

/// Minimum inode size.
pub const XFS_MIN_INODE_SIZE: usize = 256;

/// Maximum inode size.
pub const XFS_MAX_INODE_SIZE: usize = 2048;

/// Directory entry header size (without name).
pub const XFS_DIR2_DATA_ENTRY_HDR_SIZE: usize = 8;

/// Size of an extent record (128 bits = 16 bytes).
pub const XFS_EXTENT_SIZE: usize = 16;

// ─── Inode Numbers ────────────────────────────────────────────────────────

/// Root inode number (default).
pub const XFS_ROOT_INO: u64 = 128;

// ─── Version Flags ────────────────────────────────────────────────────────

/// Version 4 filesystem.
pub const XFS_SB_VERSION_4: u16 = 4;

/// Version 5 filesystem (CRC enabled).
pub const XFS_SB_VERSION_5: u16 = 5;

/// Version flag: has attributes.
pub const XFS_SB_VERSION_ATTRBIT: u16 = 0x0010;

/// Version flag: has quotas.
pub const XFS_SB_VERSION_QUOTABIT: u16 = 0x0040;

/// Version flag: has extended attributes.
pub const XFS_SB_VERSION_MOREBITSBIT: u16 = 0x8000;

// ─── Feature Flags (v5) ───────────────────────────────────────────────────

/// Feature: File type in directory entries.
pub const XFS_SB_FEAT_INCOMPAT_FTYPE: u32 = 1 << 0;

/// Feature: Sparse inodes.
pub const XFS_SB_FEAT_INCOMPAT_SPINODES: u32 = 1 << 1;

/// Feature: Metadata UUID.
pub const XFS_SB_FEAT_INCOMPAT_META_UUID: u32 = 1 << 2;

/// Feature: Big timestamps.
pub const XFS_SB_FEAT_INCOMPAT_BIGTIME: u32 = 1 << 3;

/// Feature: Large extent counters.
pub const XFS_SB_FEAT_INCOMPAT_NREXT64: u32 = 1 << 5;

// ─── Inode Format Types ───────────────────────────────────────────────────

/// Inode format: device.
pub const XFS_DINODE_FMT_DEV: u8 = 0;

/// Inode format: local (inline data).
pub const XFS_DINODE_FMT_LOCAL: u8 = 1;

/// Inode format: extents (data fork has extent list).
pub const XFS_DINODE_FMT_EXTENTS: u8 = 2;

/// Inode format: btree (data fork has btree root).
pub const XFS_DINODE_FMT_BTREE: u8 = 3;

/// Inode format: UUID (extended attribute fork).
pub const XFS_DINODE_FMT_UUID: u8 = 4;

// ─── File Types ───────────────────────────────────────────────────────────

/// File type: FIFO.
pub const S_IFIFO: u16 = 0o010000;

/// File type: character device.
pub const S_IFCHR: u16 = 0o020000;

/// File type: directory.
pub const S_IFDIR: u16 = 0o040000;

/// File type: block device.
pub const S_IFBLK: u16 = 0o060000;

/// File type: regular file.
pub const S_IFREG: u16 = 0o100000;

/// File type: symbolic link.
pub const S_IFLNK: u16 = 0o120000;

/// File type: socket.
pub const S_IFSOCK: u16 = 0o140000;

/// File type mask.
pub const S_IFMT: u16 = 0o170000;

// ─── Extent Flags ─────────────────────────────────────────────────────────

/// Extent is unwritten (preallocated but not written).
pub const XFS_EXT_UNWRITTEN: u8 = 1;

// ─── Limits ───────────────────────────────────────────────────────────────

/// Maximum name length in a directory entry.
pub const XFS_NAME_MAX: usize = 255;

/// Maximum inline data size.
pub const XFS_MAX_INLINE_DATA: usize = 160;

/// Maximum symlink length that can be inline.
pub const XFS_MAX_INLINE_SYMLINK: usize = 1024;
