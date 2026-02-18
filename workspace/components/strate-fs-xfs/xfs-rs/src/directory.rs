//! XFS Directory parsing.
//!
//! XFS has multiple directory formats depending on size:
//! - Shortform (inline in inode) for small directories
//! - Block format for medium directories
//! - Leaf/Node format for large directories

use fs_abstraction::{safe_math::CheckedSliceOps, FsError, FsResult};

use crate::constants::*;

/// Calculate XFS directory hash for a name.
pub fn dir2_hash(name: &[u8]) -> u32 {
    let mut hash = 0u32;
    for &c in name {
        hash = (c as u32).wrapping_add(hash.rotate_left(7) ^ hash);
    }
    hash
}

/// Block directory data bestfree entry.
#[derive(Debug, Clone, Copy)]
pub struct DataFree {
    pub offset: u16,
    pub length: u16,
}

impl DataFree {
    pub fn parse(buffer: &[u8], offset: usize) -> FsResult<Self> {
        Ok(Self {
            offset: buffer.read_be_u16(offset)?,
            length: buffer.read_be_u16(offset + 2)?,
        })
    }
}

/// Directory entry file type (from di_ftype field in v5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DirFileType {
    Unknown = 0,
    RegularFile = 1,
    Directory = 2,
    CharDevice = 3,
    BlockDevice = 4,
    Fifo = 5,
    Socket = 6,
    SymbolicLink = 7,
}

impl DirFileType {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::RegularFile,
            2 => Self::Directory,
            3 => Self::CharDevice,
            4 => Self::BlockDevice,
            5 => Self::Fifo,
            6 => Self::Socket,
            7 => Self::SymbolicLink,
            _ => Self::Unknown,
        }
    }

    /// Returns `true` if this is a directory.
    pub fn is_dir(&self) -> bool {
        matches!(self, Self::Directory)
    }
}

/// A parsed directory entry.
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Inode number of the entry.
    pub inode: u64,
    /// File type (v5 only, Unknown for v4).
    pub file_type: DirFileType,
    /// Name of the entry.
    pub name: [u8; 256],
    /// Length of the name.
    pub name_len: u8,
}

impl DirEntry {
    /// Returns the name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Returns the name as a string (if valid UTF-8).
    pub fn name_str(&self) -> Option<&str> {
        core::str::from_utf8(self.name_bytes()).ok()
    }

    /// Returns `true` if this is "." or "..".
    pub fn is_dot_entry(&self) -> bool {
        let name = self.name_bytes();
        name == b"." || name == b".."
    }
}

/// Shortform directory header.
#[derive(Debug, Clone)]
pub struct ShortformHeader {
    /// Number of entries.
    pub count: u8,
    /// Number of entries with 8-byte inodes (if i8count is used).
    pub i8count: u8,
    /// Parent inode number.
    pub parent: u64,
}

impl ShortformHeader {
    /// Size with 4-byte parent inode.
    pub const SIZE_4: usize = 6;
    /// Size with 8-byte parent inode.
    pub const SIZE_8: usize = 10;

    /// Parses a shortform header.
    ///
    /// # Arguments
    /// * `buffer` - Raw data fork bytes
    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < 2 {
            return Err(FsError::BufferTooSmall);
        }

        let count = buffer[0];
        let i8count = buffer[1];
        let use_64bit = i8count > 0;

        let size = if use_64bit {
            Self::SIZE_8
        } else {
            Self::SIZE_4
        };
        if buffer.len() < size {
            return Err(FsError::BufferTooSmall);
        }

        let parent = if use_64bit {
            buffer.read_be_u64(2)?
        } else {
            buffer.read_be_u32(2)? as u64
        };

        Ok(Self {
            count,
            i8count,
            parent,
        })
    }
}

/// Iterator for shortform directory entries.
pub struct ShortformDirIter<'a> {
    buffer: &'a [u8],
    offset: usize,
    count: u8,
    current: u8,
    use_64bit: bool,
    has_ftype: bool,
}

impl<'a> ShortformDirIter<'a> {
    /// Creates a new iterator.
    pub fn new(buffer: &'a [u8], count: u8, use_64bit: bool, has_ftype: bool) -> Self {
        // Skip header
        let header_size = if use_64bit {
            ShortformHeader::SIZE_8
        } else {
            ShortformHeader::SIZE_4
        };
        Self {
            buffer,
            offset: header_size,
            count,
            current: 0,
            use_64bit,
            has_ftype,
        }
    }
}

impl<'a> Iterator for ShortformDirIter<'a> {
    type Item = FsResult<DirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.count {
            return None;
        }

        // Shortform entry layout (XFS on-disk format):
        // 1 byte: name length
        // 2 bytes: offset (unused for reading)
        // N bytes: name
        // 1 byte: ftype (v5 only, comes BEFORE inode)
        // 4 or 8 bytes: inode

        if self.offset >= self.buffer.len() {
            return Some(Err(FsError::BufferTooSmall));
        }

        let name_len = self.buffer[self.offset];
        self.offset += 1;

        // Skip 2-byte offset field
        self.offset += 2;

        // Read name
        if self.offset + name_len as usize > self.buffer.len() {
            return Some(Err(FsError::BufferTooSmall));
        }

        let mut name = [0u8; 256];
        name[..name_len as usize]
            .copy_from_slice(&self.buffer[self.offset..self.offset + name_len as usize]);
        self.offset += name_len as usize;

        // Read ftype if present (comes BEFORE inode in XFS format)
        let file_type = if self.has_ftype {
            if self.offset >= self.buffer.len() {
                return Some(Err(FsError::BufferTooSmall));
            }
            let ft = DirFileType::from_u8(self.buffer[self.offset]);
            self.offset += 1;
            ft
        } else {
            DirFileType::Unknown
        };

        // Read inode (after ftype)
        let inode_size = if self.use_64bit { 8 } else { 4 };
        if self.offset + inode_size > self.buffer.len() {
            return Some(Err(FsError::BufferTooSmall));
        }

        let inode = if self.use_64bit {
            match self.buffer.read_be_u64(self.offset) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            }
        } else {
            match self.buffer.read_be_u32(self.offset) {
                Ok(v) => v as u64,
                Err(e) => return Some(Err(e)),
            }
        };
        self.offset += inode_size;

        self.current += 1;

        Some(Ok(DirEntry {
            inode,
            file_type,
            name,
            name_len,
        }))
    }
}

/// Parses shortform directory entries from an inode's data fork.
pub fn parse_shortform_directory<'a>(
    data: &'a [u8],
    has_ftype: bool,
) -> FsResult<(ShortformHeader, ShortformDirIter<'a>)> {
    let header = ShortformHeader::parse(data)?;
    let iter = ShortformDirIter::new(data, header.count, header.i8count > 0, has_ftype);
    Ok((header, iter))
}

/// Finds an entry by name in a shortform directory.
pub fn find_entry_shortform(data: &[u8], name: &[u8], has_ftype: bool) -> FsResult<DirEntry> {
    let (_, iter) = parse_shortform_directory(data, has_ftype)?;
    for entry_res in iter {
        let entry: DirEntry = entry_res?;
        if entry.name_bytes() == name {
            return Ok(entry);
        }
    }
    Err(FsError::NotFound)
}

/// Directory data block header (v4).
#[derive(Debug, Clone)]
pub struct DataHeaderV4 {
    pub magic: u32,
    pub best_free: [DataFree; 3],
}

impl DataHeaderV4 {
    pub const SIZE: usize = 16;

    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        let magic = buffer.read_be_u32(0)?;
        let best_free = [
            DataFree::parse(buffer, 4)?,
            DataFree::parse(buffer, 8)?,
            DataFree::parse(buffer, 12)?,
        ];
        Ok(Self { magic, best_free })
    }
}

/// Directory data block header (v5).
#[derive(Debug, Clone)]
pub struct DataHeaderV5 {
    pub magic: u32,
    pub crc: u32,
    pub block_no: u64,
    pub lsn: u64,
    pub uuid: [u8; 16],
    pub owner: u64,
    pub best_free: [DataFree; 3],
}

impl DataHeaderV5 {
    pub const SIZE: usize = 64;

    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        let magic = buffer.read_be_u32(0)?;
        let crc = buffer.read_be_u32(4)?;
        let block_no = buffer.read_be_u64(8)?;
        let lsn = buffer.read_be_u64(16)?;
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buffer[24..40]);
        let owner = buffer.read_be_u64(40)?;
        let best_free = [
            DataFree::parse(buffer, 48)?,
            DataFree::parse(buffer, 52)?,
            DataFree::parse(buffer, 56)?,
        ];
        Ok(Self {
            magic,
            crc,
            block_no,
            lsn,
            uuid,
            owner,
            best_free,
        })
    }
}

/// A leaf entry in a block or leaf directory.
#[derive(Debug, Clone, Copy)]
pub struct LeafEntry {
    /// Hash value of the name.
    pub hashval: u32,
    /// Address of the data entry (8-byte units).
    pub address: u32,
}

impl LeafEntry {
    pub const SIZE: usize = 8;

    pub fn parse(buffer: &[u8], offset: usize) -> FsResult<Self> {
        Ok(Self {
            hashval: buffer.read_be_u32(offset)?,
            address: buffer.read_be_u32(offset + 4)?,
        })
    }
}

/// Tail of a block-format directory block.
#[derive(Debug, Clone, Copy)]
pub struct BlockTail {
    /// Number of leaf entries.
    pub count: u32,
    /// Number of stale leaf entries.
    pub stale: u32,
}

impl BlockTail {
    pub const SIZE: usize = 8;

    pub fn parse(buffer: &[u8], offset: usize) -> FsResult<Self> {
        Ok(Self {
            count: buffer.read_be_u32(offset)?,
            stale: buffer.read_be_u32(offset + 4)?,
        })
    }
}

/// Header of a directory leaf block (v4).
#[derive(Debug, Clone)]
pub struct LeafHeaderV4 {
    pub info: BlockInfoV4,
    pub count: u16,
    pub stale: u16,
}

/// Header of a directory leaf block (v5).
#[derive(Debug, Clone)]
pub struct LeafHeaderV5 {
    pub info: BlockInfoV5,
    pub count: u16,
    pub stale: u16,
}

/// Generic block info for v4.
#[derive(Debug, Clone)]
pub struct BlockInfoV4 {
    pub forw: u32,
    pub back: u32,
    pub magic: u16,
}

/// Generic block info for v5.
#[derive(Debug, Clone)]
pub struct BlockInfoV5 {
    pub forw: u32,
    pub back: u32,
    pub magic: u16,
    pub crc: u32,
    pub block_no: u64,
    pub lsn: u64,
    pub uuid: [u8; 16],
    pub owner: u64,
}

impl BlockInfoV4 {
    pub const SIZE: usize = 10;

    pub fn parse(buffer: &[u8], offset: usize) -> FsResult<Self> {
        Ok(Self {
            forw: buffer.read_be_u32(offset)?,
            back: buffer.read_be_u32(offset + 4)?,
            magic: buffer.read_be_u16(offset + 8)?,
        })
    }
}

impl BlockInfoV5 {
    pub const SIZE: usize = 56;

    pub fn parse(buffer: &[u8], offset: usize) -> FsResult<Self> {
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buffer[offset + 32..offset + 48]);
        Ok(Self {
            forw: buffer.read_be_u32(offset)?,
            back: buffer.read_be_u32(offset + 4)?,
            magic: buffer.read_be_u16(offset + 8)?,
            crc: buffer.read_be_u32(offset + 12)?,
            block_no: buffer.read_be_u64(offset + 16)?,
            lsn: buffer.read_be_u64(offset + 24)?,
            uuid,
            owner: buffer.read_be_u64(offset + 48)?,
        })
    }
}

/// Iterator for directory data blocks (used in Block and Leaf formats).
pub struct DataDirIter<'a> {
    buffer: &'a [u8],
    offset: usize,
    end_offset: usize,
    has_ftype: bool,
}

impl<'a> DataDirIter<'a> {
    pub fn new(buffer: &'a [u8], header_size: usize, end_offset: usize, has_ftype: bool) -> Self {
        Self {
            buffer,
            offset: header_size,
            end_offset,
            has_ftype,
        }
    }
}

impl<'a> Iterator for DataDirIter<'a> {
    type Item = FsResult<DirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.offset < self.end_offset {
            // Check for unused entry (freetag = 0xFFFF)
            let freetag = match self.buffer.read_be_u16(self.offset) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };

            if freetag == 0xFFFF {
                // Free space entry
                let length = match self.buffer.read_be_u16(self.offset + 2) {
                    Ok(v) => v,
                    Err(e) => return Some(Err(e)),
                };
                if length == 0 {
                    return Some(Err(FsError::Corrupted));
                }
                self.offset += length as usize;
                continue;
            }

            // Data entry
            let inode = match self.buffer.read_be_u64(self.offset) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };
            let name_len = self.buffer[self.offset + 8];
            let name_offset = self.offset + 9;

            if name_offset + name_len as usize > self.buffer.len() {
                return Some(Err(FsError::BufferTooSmall));
            }

            let mut name = [0u8; 256];
            name[..name_len as usize]
                .copy_from_slice(&self.buffer[name_offset..name_offset + name_len as usize]);

            let file_type = if self.has_ftype {
                let ft_offset = name_offset + name_len as usize;
                if ft_offset >= self.buffer.len() {
                    return Some(Err(FsError::BufferTooSmall));
                }
                DirFileType::from_u8(self.buffer[ft_offset])
            } else {
                DirFileType::Unknown
            };

            // Calculate aligned size: inumber(8) + namelen(1) + name + ftype?(1) + tag(2)
            let entry_size = 8 + 1 + name_len as usize + if self.has_ftype { 1 } else { 0 } + 2;
            let aligned_size = (entry_size + 7) & !7;

            self.offset += aligned_size;

            return Some(Ok(DirEntry {
                inode,
                file_type,
                name,
                name_len,
            }));
        }
        None
    }
}

/// Finds an entry in a block-format directory block.
pub fn find_entry_block(
    buffer: &[u8],
    name: &[u8],
    block_size: u32,
    has_ftype: bool,
    is_v5: bool,
) -> FsResult<DirEntry> {
    let tail_offset = block_size as usize - BlockTail::SIZE;
    if buffer.len() < block_size as usize {
        return Err(FsError::BufferTooSmall);
    }
    let tail = BlockTail::parse(buffer, tail_offset)?;

    let header_size = if is_v5 {
        DataHeaderV5::SIZE
    } else {
        DataHeaderV4::SIZE
    };

    // End offset for entries is start of leaf entries
    let end_offset = tail_offset - (tail.count as usize * LeafEntry::SIZE);
    if end_offset < header_size {
        return Err(FsError::Corrupted);
    }

    let iter = DataDirIter::new(buffer, header_size, end_offset, has_ftype);
    for entry_res in iter {
        let entry = entry_res?;
        if entry.name_bytes() == name {
            return Ok(entry);
        }
    }
    Err(FsError::NotFound)
}

/// Parses a directory data block and returns an iterator over its entries.
pub fn parse_data_block<'a>(
    buffer: &'a [u8],
    has_ftype: bool,
    is_v5: bool,
    is_block_format: bool,
    block_size: u32,
) -> FsResult<DataDirIter<'a>> {
    let header_size = if is_v5 {
        DataHeaderV5::SIZE
    } else {
        DataHeaderV4::SIZE
    };

    let end_offset = if is_block_format {
        let tail_offset = block_size as usize - BlockTail::SIZE;
        let tail = BlockTail::parse(buffer, tail_offset)?;
        tail_offset - (tail.count as usize * LeafEntry::SIZE)
    } else {
        buffer.len()
    };

    Ok(DataDirIter::new(buffer, header_size, end_offset, has_ftype))
}

/// Check if a directory data block is valid.
pub fn validate_dir_block_magic(magic: u32) -> bool {
    matches!(
        magic,
        XFS_DIR2_BLOCK_MAGIC | XFS_DIR3_BLOCK_MAGIC | XFS_DIR2_DATA_MAGIC | XFS_DIR3_DATA_MAGIC
    )
}
