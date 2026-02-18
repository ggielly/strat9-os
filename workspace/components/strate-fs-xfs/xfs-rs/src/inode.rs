//! XFS Inode parser.
//!
//! Inodes store file metadata including type, permissions, timestamps,
//! and data fork (file contents or extent list).

use fs_abstraction::{safe_math::CheckedSliceOps, FsError, FsResult};

use crate::constants::*;
#[cfg(feature = "alloc")]
use crate::extent::Extent;

/// Inode data fork format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeFormat {
    /// Device special file.
    Device,
    /// Data is inline in the inode.
    Local,
    /// Data is in an extent list.
    Extents,
    /// Data is in a B+tree.
    Btree,
    /// UUID (for extended attributes).
    Uuid,
}

impl InodeFormat {
    fn from_u8(v: u8) -> FsResult<Self> {
        match v {
            XFS_DINODE_FMT_DEV => Ok(Self::Device),
            XFS_DINODE_FMT_LOCAL => Ok(Self::Local),
            XFS_DINODE_FMT_EXTENTS => Ok(Self::Extents),
            XFS_DINODE_FMT_BTREE => Ok(Self::Btree),
            XFS_DINODE_FMT_UUID => Ok(Self::Uuid),
            _ => Err(FsError::Corrupted),
        }
    }

    /// Convert format back to the byte representation.
    pub fn to_u8(&self) -> u8 {
        match self {
            Self::Device => XFS_DINODE_FMT_DEV,
            Self::Local => XFS_DINODE_FMT_LOCAL,
            Self::Extents => XFS_DINODE_FMT_EXTENTS,
            Self::Btree => XFS_DINODE_FMT_BTREE,
            Self::Uuid => XFS_DINODE_FMT_UUID,
        }
    }
}

/// File type (from mode field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Fifo,
    CharDevice,
    Directory,
    BlockDevice,
    RegularFile,
    SymbolicLink,
    Socket,
    Unknown,
}

impl FileType {
    fn from_mode(mode: u16) -> Self {
        match mode & S_IFMT {
            S_IFIFO => Self::Fifo,
            S_IFCHR => Self::CharDevice,
            S_IFDIR => Self::Directory,
            S_IFBLK => Self::BlockDevice,
            S_IFREG => Self::RegularFile,
            S_IFLNK => Self::SymbolicLink,
            S_IFSOCK => Self::Socket,
            _ => Self::Unknown,
        }
    }

    /// Returns `true` if this is a directory.
    pub fn is_dir(&self) -> bool {
        matches!(self, Self::Directory)
    }

    /// Returns `true` if this is a regular file.
    pub fn is_file(&self) -> bool {
        matches!(self, Self::RegularFile)
    }

    /// Returns `true` if this is a symbolic link.
    pub fn is_symlink(&self) -> bool {
        matches!(self, Self::SymbolicLink)
    }
}

/// Inode core data (di_core).
///
/// This is the fixed-size header of every inode.
#[derive(Debug, Clone)]
pub struct InodeCore {
    /// Magic number (XFS_DINODE_MAGIC for v3).
    pub magic: u16,
    /// File mode and type.
    pub mode: u16,
    /// Version (1, 2, or 3).
    pub version: u8,
    /// Data fork format.
    pub format: InodeFormat,
    /// Link count (v1/v2) or pad (v3).
    pub onlink: u16,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Link count (v2+).
    pub nlink: u32,
    /// Project ID (low 16 bits).
    pub projid_lo: u16,
    /// Project ID (high 16 bits, v2+).
    pub projid_hi: u16,
    /// Access time (seconds).
    pub atime_sec: u32,
    /// Access time (nanoseconds).
    pub atime_nsec: u32,
    /// Modification time (seconds).
    pub mtime_sec: u32,
    /// Modification time (nanoseconds).
    pub mtime_nsec: u32,
    /// Change time (seconds).
    pub ctime_sec: u32,
    /// Change time (nanoseconds).
    pub ctime_nsec: u32,
    /// File size in bytes.
    pub size: u64,
    /// Number of data blocks.
    pub nblocks: u64,
    /// Extent size hint.
    pub extsize: u32,
    /// Number of data extents.
    pub nextents: u32,
    /// Number of attribute extents.
    pub anextents: u16,
    /// Attribute fork offset.
    pub forkoff: u8,
    /// Attribute fork format.
    pub aformat: u8,
    /// Realtime device extent size.
    pub dmevmask: u32,
    /// DMAPI event mask.
    pub dmstate: u16,
    /// Inode flags.
    pub flags: u16,
    /// Generation number.
    pub r#gen: u32,
    /// Ag block of next unlinked inode.
    pub next_unlinked: u32,
    // V3 fields
    /// CRC (v3).
    pub crc: u32,
    /// Change counter (v3).
    pub changecount: u64,
    /// Log sequence number (v3).
    pub lsn: u64,
    /// Inode flags2 (v3).
    pub flags2: u64,
    /// COW extent size hint (v3).
    pub cowextsize: u32,
    /// Creation time seconds (v3).
    pub crtime_sec: u32,
    /// Creation time nanoseconds (v3).
    pub crtime_nsec: u32,
    /// Inode number (v3).
    pub ino: u64,
    /// UUID for v3 inodes.
    pub uuid: [u8; 16],
}

/// Constant for XFS Bigtime epoch offset relative to Unix epoch (1970).
const XFS_BIGTIME_EPOCH_OFFSET: i64 = 2147483648;

impl InodeCore {
    /// Size of v2 inode core (including next_unlinked).
    pub const V2_SIZE: usize = 100;
    /// Size of v3 inode core.
    pub const V3_SIZE: usize = 176;

    /// Parses an inode core from a byte buffer.
    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        // Minimum size check
        if buffer.len() < Self::V2_SIZE {
            return Err(FsError::BufferTooSmall);
        }

        let magic = buffer.read_be_u16(0x00)?;
        let mode = buffer.read_be_u16(0x02)?;
        let version = buffer[0x04];
        let format = InodeFormat::from_u8(buffer[0x05])?;
        let onlink = buffer.read_be_u16(0x06)?;
        let uid = buffer.read_be_u32(0x08)?;
        let gid = buffer.read_be_u32(0x0C)?;
        let nlink = buffer.read_be_u32(0x10)?;
        let projid_lo = buffer.read_be_u16(0x14)?;
        let projid_hi = buffer.read_be_u16(0x16)?;
        // 8 bytes padding at 0x18
        // Back to big-endian - timestamps are big-endian in XFS
        let atime_sec = buffer.read_be_u32(0x20)?;
        let atime_nsec = buffer.read_be_u32(0x24)?;
        let mtime_sec = buffer.read_be_u32(0x28)?;
        let mtime_nsec = buffer.read_be_u32(0x2C)?;
        let ctime_sec = buffer.read_be_u32(0x30)?;
        let ctime_nsec = buffer.read_be_u32(0x34)?;
        let size = buffer.read_be_u64(0x38)?; // Fixed: was 0x3A, should be 0x38
        let nblocks = buffer.read_be_u64(0x40)?; // Fixed: was 0x42, should be 0x40
        let extsize = buffer.read_be_u32(0x48)?; // Fixed: was 0x4A, should be 0x48
        let nextents = buffer.read_be_u32(0x4C)?; // Fixed: was 0x4E, should be 0x4C
        let anextents = buffer.read_be_u16(0x50)?; // Fixed: was 0x52, should be 0x50
        let forkoff = buffer[0x52]; // Fixed: was 0x54, should be 0x52
        let aformat = buffer[0x53]; // Fixed: was 0x55, should be 0x53
        let dmevmask = buffer.read_be_u32(0x54)?; // Fixed: was 0x56, should be 0x54
        let dmstate = buffer.read_be_u16(0x58)?; // Fixed: was 0x5A, should be 0x58
        let flags = buffer.read_be_u16(0x5A)?; // Fixed: was 0x5C, should be 0x5A
        let r#gen = buffer.read_be_u32(0x5C)?; // Fixed: was 0x5E, should be 0x5C
        let next_unlinked = buffer.read_be_u32(0x60)?; // Fixed: was 0x62, should be 0x60

        // V3 fields (if magic is present and version is 3)
        let (crc, changecount, lsn, flags2, cowextsize, crtime_sec, crtime_nsec, ino, uuid) =
            if version >= 3 && buffer.len() >= Self::V3_SIZE && magic == XFS_DINODE_MAGIC {
                let crc = buffer.read_be_u32(0x64)?; // Fixed: was 0x66, should be 0x64
                let changecount = buffer.read_be_u64(0x68)?; // Fixed: was 0x6A, should be 0x68
                let lsn = buffer.read_be_u64(0x70)?; // Fixed: was 0x72, should be 0x70
                let flags2 = buffer.read_be_u64(0x78)?; // Fixed: was 0x7A, should be 0x78
                let cowextsize = buffer.read_be_u32(0x80)?;
                // 12 bytes padding
                let crtime_sec = buffer.read_be_u32(0x90)?;
                let crtime_nsec = buffer.read_be_u32(0x94)?;
                let ino = buffer.read_be_u64(0x98)?; // Fixed: was 0x9A, should be 0x98
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&buffer[0xA0..0xB0]); // Fixed: was 0xA2..0xB2, should be 0xA0..0xB0
                (
                    crc,
                    changecount,
                    lsn,
                    flags2,
                    cowextsize,
                    crtime_sec,
                    crtime_nsec,
                    ino,
                    uuid,
                )
            } else {
                (0, 0, 0, 0, 0, 0, 0, 0, [0u8; 16])
            };

        Ok(Self {
            magic,
            mode,
            version,
            format,
            onlink,
            uid,
            gid,
            nlink,
            projid_lo,
            projid_hi,
            atime_sec,
            atime_nsec,
            mtime_sec,
            mtime_nsec,
            ctime_sec,
            ctime_nsec,
            size,
            nblocks,
            extsize,
            nextents,
            anextents,
            forkoff,
            aformat,
            dmevmask,
            dmstate,
            flags,
            r#gen,
            next_unlinked,
            crc,
            changecount,
            lsn,
            flags2,
            cowextsize,
            crtime_sec,
            crtime_nsec,
            ino,
            uuid,
        })
    }

    /// Converts an XFS timestamp to Unix (seconds, nanoseconds).
    /// Handles Bigtime and v3 epoch extension.
    pub fn timestamp_to_unix(sec: u32, nsec: u32, has_bigtime: bool) -> (i64, u32) {
        if has_bigtime {
            // In Bigtime format, the timestamp is a 64-bit nanosecond counter
            // since the XFS epoch (1901-01-01 00:00:00).
            let xfs_ns = ((sec as u64) << 32) | (nsec as u64);
            let unix_ns = xfs_ns as i64 - (XFS_BIGTIME_EPOCH_OFFSET * 1_000_000_000);

            let unix_sec = unix_ns / 1_000_000_000;
            let unix_nsec = (unix_ns % 1_000_000_000) as u32;
            (unix_sec, unix_nsec)
        } else {
            // Classical v3 epoch extension
            // Top 2 bits of nsec are bits 32 and 33 of the seconds field
            let epoch_ext = (nsec >> 30) as u64;
            let unix_sec = (sec as i64) | ((epoch_ext << 32) as i64);
            let unix_nsec = nsec & 0x3FFFFFFF;
            (unix_sec, unix_nsec)
        }
    }

    /// Returns the access time as (seconds, nanoseconds).
    pub fn atime(&self, has_bigtime: bool) -> (i64, u32) {
        Self::timestamp_to_unix(self.atime_sec, self.atime_nsec, has_bigtime)
    }

    /// Returns the modification time as (seconds, nanoseconds).
    pub fn mtime(&self, has_bigtime: bool) -> (i64, u32) {
        Self::timestamp_to_unix(self.mtime_sec, self.mtime_nsec, has_bigtime)
    }

    /// Returns the change time as (seconds, nanoseconds).
    pub fn ctime(&self, has_bigtime: bool) -> (i64, u32) {
        Self::timestamp_to_unix(self.ctime_sec, self.ctime_nsec, has_bigtime)
    }

    /// Returns the creation time as (seconds, nanoseconds) (v3 inodes only).
    pub fn crtime(&self, has_bigtime: bool) -> (i64, u32) {
        if self.version >= 3 {
            Self::timestamp_to_unix(self.crtime_sec, self.crtime_nsec, has_bigtime)
        } else {
            // For v2 inodes, use ctime
            self.ctime(has_bigtime)
        }
    }

    /// Returns the file type.
    pub fn file_type(&self) -> FileType {
        FileType::from_mode(self.mode)
    }

    /// Returns `true` if this is a directory.
    pub fn is_dir(&self) -> bool {
        self.file_type().is_dir()
    }

    /// Returns `true` if this is a regular file.
    pub fn is_file(&self) -> bool {
        self.file_type().is_file()
    }

    /// Returns `true` if this is a symlink.
    pub fn is_symlink(&self) -> bool {
        self.file_type().is_symlink()
    }

    /// Returns the data fork offset from the start of the inode.
    pub fn data_fork_offset(&self) -> usize {
        if self.version >= 3 {
            Self::V3_SIZE
        } else {
            Self::V2_SIZE
        }
    }

    /// Returns the attribute fork offset (if present).
    pub fn attr_fork_offset(&self, _inode_size: usize) -> Option<usize> {
        if self.forkoff == 0 {
            None
        } else {
            // forkoff is in 8-byte units from the end of the inode core
            Some(self.data_fork_offset() + (self.forkoff as usize) * 8)
        }
    }

    /// Returns the size of the data fork.
    pub fn data_fork_size(&self, _inode_size: usize) -> usize {
        if self.forkoff == 0 {
            // No attr fork, data extends to end of inode
            _inode_size - self.data_fork_offset()
        } else {
            (self.forkoff as usize) * 8
        }
    }

    /// Returns the permission bits (lower 12 bits of mode).
    pub fn permissions(&self) -> u16 {
        self.mode & 0o7777
    }

    /// Serialize the inode core to bytes (without CRC - caller should
    /// recalculate).
    ///
    /// Returns either V2_SIZE or V3_SIZE bytes depending on version.
    #[cfg(feature = "alloc")]
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        let size = if self.version >= 3 {
            Self::V3_SIZE
        } else {
            Self::V2_SIZE
        };
        let mut buf = alloc::vec![0u8; size];

        // Write v2 fields
        buf[0x00..0x02].copy_from_slice(&self.magic.to_be_bytes());
        buf[0x02..0x04].copy_from_slice(&self.mode.to_be_bytes());
        buf[0x04] = self.version;
        buf[0x05] = self.format.to_u8();
        buf[0x06..0x08].copy_from_slice(&self.onlink.to_be_bytes());
        buf[0x08..0x0C].copy_from_slice(&self.uid.to_be_bytes());
        buf[0x0C..0x10].copy_from_slice(&self.gid.to_be_bytes());
        buf[0x10..0x14].copy_from_slice(&self.nlink.to_be_bytes());
        buf[0x14..0x16].copy_from_slice(&self.projid_lo.to_be_bytes());
        buf[0x16..0x18].copy_from_slice(&self.projid_hi.to_be_bytes());
        // 8 bytes padding at 0x18-0x1F (zeros)
        buf[0x20..0x24].copy_from_slice(&self.atime_sec.to_be_bytes());
        buf[0x24..0x28].copy_from_slice(&self.atime_nsec.to_be_bytes());
        buf[0x28..0x2C].copy_from_slice(&self.mtime_sec.to_be_bytes());
        buf[0x2C..0x30].copy_from_slice(&self.mtime_nsec.to_be_bytes());
        buf[0x30..0x34].copy_from_slice(&self.ctime_sec.to_be_bytes());
        buf[0x34..0x38].copy_from_slice(&self.ctime_nsec.to_be_bytes());
        buf[0x38..0x40].copy_from_slice(&self.size.to_be_bytes());
        buf[0x40..0x48].copy_from_slice(&self.nblocks.to_be_bytes());
        buf[0x48..0x4C].copy_from_slice(&self.extsize.to_be_bytes());
        buf[0x4C..0x50].copy_from_slice(&self.nextents.to_be_bytes());
        buf[0x50..0x52].copy_from_slice(&self.anextents.to_be_bytes());
        buf[0x52] = self.forkoff;
        buf[0x53] = self.aformat;
        buf[0x54..0x58].copy_from_slice(&self.dmevmask.to_be_bytes());
        buf[0x58..0x5A].copy_from_slice(&self.dmstate.to_be_bytes());
        buf[0x5A..0x5C].copy_from_slice(&self.flags.to_be_bytes());
        buf[0x5C..0x60].copy_from_slice(&self.r#gen.to_be_bytes());
        // next_unlinked at 0x60
        buf[0x60..0x64].copy_from_slice(&self.next_unlinked.to_be_bytes());

        // Write v3 fields
        if self.version >= 3 {
            buf[0x64..0x68].copy_from_slice(&self.crc.to_be_bytes());
            buf[0x68..0x70].copy_from_slice(&self.changecount.to_be_bytes());
            buf[0x70..0x78].copy_from_slice(&self.lsn.to_be_bytes());
            buf[0x78..0x80].copy_from_slice(&self.flags2.to_be_bytes());
            buf[0x80..0x84].copy_from_slice(&self.cowextsize.to_be_bytes());
            // 12 bytes padding at 0x84-0x8F (zeros)
            buf[0x90..0x94].copy_from_slice(&self.crtime_sec.to_be_bytes());
            buf[0x94..0x98].copy_from_slice(&self.crtime_nsec.to_be_bytes());
            buf[0x98..0xA0].copy_from_slice(&self.ino.to_be_bytes());
            buf[0xA0..0xB0].copy_from_slice(&self.uuid);
        }

        buf
    }
}

/// Full inode with data fork.
#[derive(Debug, Clone)]
pub struct Inode {
    /// Core inode metadata.
    pub core: InodeCore,
    /// Raw data fork bytes (interpretation depends on format).
    pub data_fork: DataFork,
}

/// Inode data fork contents.
#[derive(Debug, Clone)]
pub enum DataFork {
    /// Device numbers for special files.
    Device { major: u32, minor: u32 },
    /// Inline data (for small files/symlinks/directories).
    #[cfg(not(feature = "alloc"))]
    Local { data: [u8; 160], len: usize },
    #[cfg(feature = "alloc")]
    Local(alloc::vec::Vec<u8>),
    /// Extent list.
    #[cfg(not(feature = "alloc"))]
    Extents { count: u32 },
    #[cfg(feature = "alloc")]
    Extents(alloc::vec::Vec<Extent>),
    /// B+tree root.
    Btree {
        level: u16,
        num_recs: u16,
        #[cfg(feature = "alloc")]
        data: alloc::vec::Vec<u8>,
    },
    /// Empty (for special cases).
    Empty,
}

impl Inode {
    /// Parses a full inode from a byte buffer.
    pub fn parse(buffer: &[u8], inode_size: usize) -> FsResult<Self> {
        if buffer.len() < inode_size {
            return Err(FsError::BufferTooSmall);
        }

        let core = InodeCore::parse(buffer)?;
        let data_fork_offset = core.data_fork_offset();
        let data_fork_size = core.data_fork_size(inode_size);

        if data_fork_offset + data_fork_size > buffer.len() {
            return Err(FsError::BufferTooSmall);
        }

        let data_fork_raw = &buffer[data_fork_offset..data_fork_offset + data_fork_size];

        let data_fork = match core.format {
            InodeFormat::Device => {
                let dev = buffer.read_be_u32(data_fork_offset)?;
                DataFork::Device {
                    major: (dev >> 8) & 0xFF,
                    minor: dev & 0xFF,
                }
            }
            InodeFormat::Local => {
                let len = (core.size as usize).min(data_fork_size);
                #[cfg(feature = "alloc")]
                {
                    DataFork::Local(alloc::vec::Vec::from(&data_fork_raw[..len]))
                }
                #[cfg(not(feature = "alloc"))]
                {
                    let mut data = [0u8; 160];
                    let actual_len = len.min(160);
                    data[..actual_len].copy_from_slice(&data_fork_raw[..actual_len]);
                    DataFork::Local {
                        data,
                        len: actual_len,
                    }
                }
            }
            InodeFormat::Extents => {
                #[cfg(feature = "alloc")]
                {
                    use crate::extent::{Extent, ExtentIter};
                    // Limit number of extents to what can fit in the data fork
                    // Each extent is 16 bytes
                    let max_extents = data_fork_size / Extent::SIZE;
                    let actual_extents = (core.nextents as usize).min(max_extents);
                    let mut extents = alloc::vec::Vec::with_capacity(actual_extents);
                    let iter = ExtentIter::new(data_fork_raw, actual_extents as u32);
                    for res in iter {
                        extents.push(res?);
                    }
                    DataFork::Extents(extents)
                }
                #[cfg(not(feature = "alloc"))]
                {
                    DataFork::Extents {
                        count: core.nextents,
                    }
                }
            }
            InodeFormat::Btree => {
                let level = buffer.read_be_u16(data_fork_offset)?;
                let num_recs = buffer.read_be_u16(data_fork_offset + 2)?;
                #[cfg(feature = "alloc")]
                {
                    DataFork::Btree {
                        level,
                        num_recs,
                        data: alloc::vec::Vec::from(&data_fork_raw[4..]),
                    }
                }
                #[cfg(not(feature = "alloc"))]
                {
                    DataFork::Btree { level, num_recs }
                }
            }
            InodeFormat::Uuid => DataFork::Empty,
        };

        Ok(Self { core, data_fork })
    }

    /// Returns `true` if data is inline in the inode.
    pub fn is_inline(&self) -> bool {
        matches!(self.core.format, InodeFormat::Local)
    }

    /// Returns inline data if present.
    pub fn inline_data(&self) -> Option<&[u8]> {
        match &self.data_fork {
            #[cfg(feature = "alloc")]
            DataFork::Local(v) => Some(v.as_slice()),
            #[cfg(not(feature = "alloc"))]
            DataFork::Local { data, len } => Some(&data[..*len]),
            _ => None,
        }
    }

    /// Finds a named entry in this inode (if it's a directory).
    pub fn find_entry(&self, name: &[u8], is_v5: bool) -> FsResult<u64> {
        if !self.core.is_dir() {
            return Err(FsError::NotADirectory);
        }

        match self.core.format {
            InodeFormat::Local => {
                let data = self.inline_data().ok_or(FsError::Corrupted)?;
                let entry = crate::directory::find_entry_shortform(data, name, is_v5)?;
                Ok(entry.inode)
            }
            InodeFormat::Extents | InodeFormat::Btree => {
                // Large directories require a block reader for lookup.
                // Use find_entry_with_reader instead.
                Err(FsError::NotImplemented)
            }
            _ => Err(FsError::NotImplemented),
        }
    }

    /// Finds a named entry in this directory inode using a block reader.
    #[cfg(feature = "alloc")]
    pub fn find_entry_with_reader<R: crate::btree::BlockReader>(
        &self,
        name: &[u8],
        reader: &R,
        is_v5: bool,
        block_size: u32,
        has_ftype: bool,
    ) -> FsResult<u64> {
        if !self.core.is_dir() {
            return Err(FsError::NotADirectory);
        }

        match self.core.format {
            InodeFormat::Local => self.find_entry(name, is_v5),
            InodeFormat::Extents | InodeFormat::Btree => {
                let extents = self.collect_extents(reader, is_v5)?;
                for extent in extents {
                    // Only search DATA blocks (ignoring leaf/free blocks for now as we don't use
                    // hash lookup yet) XFS directory data blocks are at logical
                    // offsets < 32GB
                    if extent.file_offset >= (1 << (31 - 9)) {
                        continue;
                    }

                    for b in 0..extent.block_count {
                        let disk_block = extent.start_block + b as u64;
                        let buffer = reader.read_block(disk_block)?;
                        let magic = buffer.read_be_u32(0)?;

                        if crate::directory::validate_dir_block_magic(magic) {
                            let is_block_format = magic == crate::constants::XFS_DIR2_BLOCK_MAGIC
                                || magic == crate::constants::XFS_DIR3_BLOCK_MAGIC;

                            let res = crate::directory::find_entry_block(
                                &buffer, name, block_size, has_ftype, is_v5,
                            );

                            if let Ok(entry) = res {
                                return Ok(entry.inode);
                            }
                        }
                    }
                }
                Err(FsError::NotFound)
            }
            _ => Err(FsError::NotImplemented),
        }
    }

    /// Translates a file block offset to a physical disk block number.
    ///
    /// This method only works for extent-based inodes. For B+Tree inodes,
    /// use `map_block_btree` instead, which requires a block reader.
    #[allow(unused_variables)]
    pub fn map_block(&self, file_block: u64) -> FsResult<Option<u64>> {
        match &self.data_fork {
            #[cfg(feature = "alloc")]
            DataFork::Extents(extents) => {
                for extent in extents {
                    if extent.contains_file_block(file_block) {
                        return Ok(Some(extent.translate(file_block)?));
                    }
                }
                Ok(None)
            }
            #[cfg(feature = "alloc")]
            DataFork::Btree { .. } => {
                // B+Tree requires external block reading - use map_block_btree instead
                Err(FsError::NotImplemented)
            }
            _ => Err(FsError::NotImplemented),
        }
    }

    /// Translates a file block offset to a physical disk block number for
    /// B+Tree inodes.
    ///
    /// This method handles B+Tree structured inodes by traversing the tree
    /// using the provided block reader.
    ///
    /// # Arguments
    /// * `file_block` - The file block offset to translate
    /// * `reader` - A block reader implementation for reading B+tree nodes
    /// * `is_v5` - Whether this is a v5 filesystem
    ///
    /// # Returns
    /// The physical disk block number, or `None` if the file block is a hole.
    #[cfg(feature = "alloc")]
    pub fn map_block_btree<R: crate::btree::BlockReader>(
        &self,
        file_block: u64,
        reader: &R,
        is_v5: bool,
    ) -> FsResult<Option<u64>> {
        match &self.data_fork {
            DataFork::Extents(extents) => {
                // For extent-based, just search the list
                for extent in extents {
                    if extent.contains_file_block(file_block) {
                        return Ok(Some(extent.translate(file_block)?));
                    }
                }
                Ok(None)
            }
            DataFork::Btree {
                level,
                num_recs,
                data,
            } => {
                // Parse the B+tree root from the data fork
                let root = crate::btree::BmbtRoot::parse(data, *level, *num_recs)?;

                // Use the B+tree lookup
                match crate::btree::btree_lookup_extent(&root, file_block, reader, is_v5)? {
                    Some(extent) => Ok(Some(extent.translate(file_block)?)),
                    None => Ok(None),
                }
            }
            DataFork::Local { .. } => Err(FsError::InvalidBlockType),
            _ => Err(FsError::NotImplemented),
        }
    }

    /// Gets the B+Tree root for this inode, if it uses B+Tree format.
    ///
    /// This is useful when you need to perform multiple operations on
    /// the B+tree without re-parsing the root each time.
    #[cfg(feature = "alloc")]
    pub fn btree_root(&self) -> FsResult<Option<crate::btree::BmbtRoot>> {
        match &self.data_fork {
            DataFork::Btree {
                level,
                num_recs,
                data,
            } => {
                let root = crate::btree::BmbtRoot::parse(data, *level, *num_recs)?;
                Ok(Some(root))
            }
            _ => Ok(None),
        }
    }

    /// Collects all extents from this inode.
    ///
    /// For extent-based inodes, returns the extent list directly.
    /// For B+Tree inodes, traverses the tree to collect all extents.
    #[cfg(feature = "alloc")]
    pub fn collect_extents<R: crate::btree::BlockReader>(
        &self,
        reader: &R,
        is_v5: bool,
    ) -> FsResult<alloc::vec::Vec<Extent>> {
        match &self.data_fork {
            DataFork::Extents(extents) => Ok(extents.clone()),
            DataFork::Btree {
                level,
                num_recs,
                data,
            } => {
                let root = crate::btree::BmbtRoot::parse(data, *level, *num_recs)?;
                crate::btree::btree_collect_extents(&root, reader, is_v5)
            }
            _ => Err(FsError::NotImplemented),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;

    #[test]
    fn test_inode_core_parse_minimal() {
        let mut buffer = [0u8; InodeCore::V2_SIZE];
        // Set magic number
        buffer[0..2].copy_from_slice(&XFS_DINODE_MAGIC.to_be_bytes());
        // Set mode to regular file
        buffer[2..4].copy_from_slice(&0x81A4u16.to_be_bytes()); // Regular file with permissions
                                                                // Set version to 2
        buffer[4] = 2;
        // Set format to local
        buffer[5] = XFS_DINODE_FMT_LOCAL;

        let core = InodeCore::parse(&buffer).expect("Should parse minimal inode core");
        assert_eq!(core.magic, XFS_DINODE_MAGIC);
        assert_eq!(core.version, 2);
        assert_eq!(core.format, InodeFormat::Local);
        assert_eq!(core.file_type(), FileType::RegularFile);
    }

    #[test]
    fn test_inode_core_parse_too_small() {
        let buffer = [0u8; 96]; // Less than V2_SIZE (100)
        assert!(matches!(
            InodeCore::parse(&buffer),
            Err(FsError::BufferTooSmall)
        ));
    }

    #[test]
    fn test_inode_parse() {
        let mut buffer = vec![0u8; 256]; // Common inode size
                                         // Set magic number
        buffer[0..2].copy_from_slice(&XFS_DINODE_MAGIC.to_be_bytes());
        // Set mode to regular file
        buffer[2..4].copy_from_slice(&0x81A4u16.to_be_bytes());
        // Set version to 2
        buffer[4] = 2;
        // Set format to local
        buffer[5] = XFS_DINODE_FMT_LOCAL;
        // Set size to 100 bytes
        buffer[0x38..0x40].copy_from_slice(&100u64.to_be_bytes());

        let inode = Inode::parse(&buffer, 256).expect("Should parse inode");
        assert_eq!(inode.core.magic, XFS_DINODE_MAGIC);
        assert_eq!(inode.core.file_type(), FileType::RegularFile);
        assert!(inode.is_inline());
    }

    #[test]
    fn test_file_type_detection() {
        assert_eq!(FileType::from_mode(0x4000), FileType::Directory); // S_IFDIR
        assert_eq!(FileType::from_mode(0x8000), FileType::RegularFile); // S_IFREG
        assert_eq!(FileType::from_mode(0xA000), FileType::SymbolicLink); // S_IFLNK
        assert_eq!(FileType::from_mode(0x2000), FileType::CharDevice); // S_IFCHR
        assert_eq!(FileType::from_mode(0x6000), FileType::BlockDevice); // S_IFBLK
        assert_eq!(FileType::from_mode(0x1000), FileType::Fifo); // S_IFIFO
        assert_eq!(FileType::from_mode(0xC000), FileType::Socket); // S_IFSOCK
    }

    #[test]
    fn test_permissions_extraction() {
        let mut buffer = [0u8; InodeCore::V2_SIZE];
        buffer[0..2].copy_from_slice(&XFS_DINODE_MAGIC.to_be_bytes());
        buffer[2..4].copy_from_slice(&0x81A4u16.to_be_bytes()); // Mode with 0644 permissions
        buffer[4] = 2;
        buffer[5] = XFS_DINODE_FMT_LOCAL;

        let core = InodeCore::parse(&buffer).unwrap();
        assert_eq!(core.permissions(), 0o644); // 0x1A4 = 420 decimal = 0644
                                               // octal
    }

    #[test]
    fn test_timestamp_to_unix_bigtime() {
        // Values from user logs: 0x365D4214 C637B335
        let sec = 0x365D4214;
        let nsec = 0xC637B335;

        let (u_sec, u_nsec) = InodeCore::timestamp_to_unix(sec, nsec, true);

        // 0x365D4214 << 32 | 0xC637B335 = 3917349194387597109
        // u_sec: 1769876259, u_nsec: 874517813
        assert_eq!(u_sec, 1769876259);
        assert_eq!(u_nsec, 874517813);
    }

    #[test]
    fn test_timestamp_to_unix_v3_extension() {
        // Test epoch extension: sec = 1, nsec = (3 << 30) | 123
        let sec = 1;
        let nsec = (3 << 30) | 123;

        let (u_sec, u_nsec) = InodeCore::timestamp_to_unix(sec, nsec, false);

        // sec = 1 | (3 << 32) = 1 + 12884901888 = 12884901889
        assert_eq!(u_sec, 12884901889);
        assert_eq!(u_nsec, 123);
    }
}
