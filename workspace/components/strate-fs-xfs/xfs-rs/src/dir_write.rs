//! Directory write operations for XFS.
//!
//! This module provides functions to add and remove entries from XFS
//! directories. It handles shortform, block, and (TODO) leaf/node directory
//! formats.

extern crate alloc;

use alloc::vec::Vec;

use fs_abstraction::{FsError, FsResult};

use crate::{
    constants::*,
    directory::{parse_shortform_directory, DirFileType, ShortformHeader},
};

/// Maximum entries in a shortform directory before conversion to block format.
/// This depends on inode size, but typically around 4-10 entries.
pub const SHORTFORM_MAX_ENTRIES: u8 = 10;

/// Entry to add to a directory.
#[derive(Debug, Clone)]
pub struct NewDirEntry {
    /// Name of the entry (max 255 bytes).
    pub name: Vec<u8>,
    /// Inode number.
    pub inode: u64,
    /// File type.
    pub file_type: DirFileType,
}

impl NewDirEntry {
    /// Create a new directory entry.
    pub fn new(name: &[u8], inode: u64, file_type: DirFileType) -> Self {
        Self {
            name: name.to_vec(),
            inode,
            file_type,
        }
    }

    /// Calculate the size of this entry in shortform format.
    pub fn shortform_size(&self, use_64bit: bool, has_ftype: bool) -> usize {
        let mut size = 1 + 2 + self.name.len(); // namelen + offset + name
        if has_ftype {
            size += 1; // ftype
        }
        size += if use_64bit { 8 } else { 4 }; // inode
        size
    }
}

/// Serialize a shortform directory header.
pub fn serialize_shortform_header(header: &ShortformHeader, use_64bit: bool) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(header.count);
    buf.push(header.i8count);

    if use_64bit {
        buf.extend_from_slice(&header.parent.to_be_bytes());
    } else {
        buf.extend_from_slice(&(header.parent as u32).to_be_bytes());
    }

    buf
}

/// Serialize a shortform directory entry.
pub fn serialize_shortform_entry(
    entry: &NewDirEntry,
    offset: u16,
    use_64bit: bool,
    has_ftype: bool,
) -> Vec<u8> {
    let mut buf = Vec::new();

    // Name length
    buf.push(entry.name.len() as u8);

    // Offset (2 bytes)
    buf.extend_from_slice(&offset.to_be_bytes());

    // Name
    buf.extend_from_slice(&entry.name);

    // File type (before inode in XFS format)
    if has_ftype {
        buf.push(entry.file_type as u8);
    }

    // Inode
    if use_64bit {
        buf.extend_from_slice(&entry.inode.to_be_bytes());
    } else {
        buf.extend_from_slice(&(entry.inode as u32).to_be_bytes());
    }

    buf
}

/// Add an entry to a shortform directory.
///
/// Returns the new directory data, or an error if the directory is full
/// and needs to be converted to block format.
pub fn add_shortform_entry(
    current_data: &[u8],
    entry: &NewDirEntry,
    parent_ino: u64,
    has_ftype: bool,
    max_size: usize,
) -> FsResult<Vec<u8>> {
    // 1. Determine current state
    let mut header = if current_data.len() >= 6 {
        ShortformHeader::parse(current_data)?
    } else {
        // Initial empty directory
        ShortformHeader {
            count: 0,
            i8count: 0,
            parent: parent_ino,
        }
    };

    // 2. Check if we have room
    let current_is_64 = header.i8count > 0;
    let new_needs_64 = entry.inode > 0xFFFFFFFF || header.parent > 0xFFFFFFFF;
    let target_is_64 = current_is_64 || new_needs_64;

    let entry_size = entry.shortform_size(target_is_64, has_ftype);
    let header_size = if target_is_64 {
        ShortformHeader::SIZE_8
    } else {
        ShortformHeader::SIZE_4
    };

    // If we transition 32 -> 64, we need to account for existing entries growing
    let mut total_size = header_size + entry_size;
    if target_is_64 && !current_is_64 && current_data.len() >= 6 {
        let (_, iter) = crate::directory::parse_shortform_directory(current_data, has_ftype)?;
        for e in iter {
            let e: crate::directory::DirEntry = e?;
            let ne = NewDirEntry::new(e.name_bytes(), e.inode, e.file_type);
            total_size += ne.shortform_size(true, has_ftype);
        }
    } else if current_data.len() > (if current_is_64 { 10 } else { 6 }) {
        total_size += current_data.len() - (if current_is_64 { 10 } else { 6 });
    }

    if total_size > max_size {
        return Err(FsError::NoSpace);
    }

    if header.count >= SHORTFORM_MAX_ENTRIES {
        return Err(FsError::NoSpace);
    }

    // 3. Build new data
    let mut new_data = Vec::with_capacity(total_size);

    // Update header
    header.count += 1;
    if entry.inode > 0xFFFFFFFF {
        header.i8count += 1;
    } else if target_is_64 && !current_is_64 {
        // We are moving to 64-bit but this entry is small.
        // If parent was the reason, i8count should be initialized or handled.
        // In XFS, i8count is purely for ENTRIES.
        // If no entries are 64-bit but parent is, i8count is still 1? No, let's check.
        // Actually, let's just make sure i8count > 0 if we need 64-bit parent.
        if header.i8count == 0 && target_is_64 {
            header.i8count = 1; // Signal 64-bit format
        }
    }

    new_data.extend(serialize_shortform_header(&header, target_is_64));

    // Track offset cookie - XFS shortform offsets start at 3 (0=., 1=..,
    // 2=reserved)
    let mut next_offset: u16 = 3;

    // 4. Add existing entries (with conversion if needed)
    if current_data.len() > (if current_is_64 { 10 } else { 6 }) {
        if target_is_64 && !current_is_64 && current_data.len() >= 6 {
            // Convert existing entries to 64-bit with sequential offsets
            let (_, iter) = crate::directory::parse_shortform_directory(current_data, has_ftype)?;
            for e in iter {
                let e: crate::directory::DirEntry = e?;
                let ne = NewDirEntry::new(e.name_bytes(), e.inode, e.file_type);
                new_data.extend(serialize_shortform_entry(&ne, next_offset, true, has_ftype));
                next_offset += 1;
            }
        } else {
            // Copy existing entries - count them for next offset
            let old_header_size = if current_is_64 { 10 } else { 6 };
            new_data.extend_from_slice(&current_data[old_header_size..]);
            // Calculate next offset from existing entry count
            next_offset = 3 + (header.count - 1) as u16;
        }
    }

    // 5. Add new entry with sequential offset
    new_data.extend(serialize_shortform_entry(
        entry,
        next_offset,
        target_is_64,
        has_ftype,
    ));

    Ok(new_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::DirFileType;

    #[test]
    fn test_add_shortform_entry_empty() {
        let entry = NewDirEntry::new(b"test", 123, DirFileType::RegularFile);
        let result = add_shortform_entry(&[], &entry, 456, true, 256).unwrap();

        let header = ShortformHeader::parse(&result).unwrap();
        assert_eq!(header.count, 1);
        assert_eq!(header.parent, 456);
        assert_eq!(header.i8count, 0); // Both fit in 32-bit
    }

    #[test]
    fn test_add_shortform_entry_64bit() {
        let entry = NewDirEntry::new(b"test", 0x1_0000_0000, DirFileType::RegularFile);
        let result = add_shortform_entry(&[], &entry, 456, true, 256).unwrap();

        let header = ShortformHeader::parse(&result).unwrap();
        assert_eq!(header.count, 1);
        assert_eq!(header.i8count, 1);
        assert_eq!(header.parent, 456);
    }
}

/// Remove an entry from a shortform directory by name.
pub fn remove_shortform_entry(
    current_data: &[u8],
    name: &[u8],
    has_ftype: bool,
) -> FsResult<Vec<u8>> {
    let header = ShortformHeader::parse(current_data)?;
    let use_64bit = header.i8count > 0;
    let header_size = if use_64bit {
        ShortformHeader::SIZE_8
    } else {
        ShortformHeader::SIZE_4
    };

    // Build new directory skipping the entry to remove
    let mut new_data = Vec::new();
    let mut new_count = 0u8;
    let mut found = false;

    // We'll rebuild the header later
    new_data.resize(header_size, 0);

    // Track offset cookie - XFS shortform offsets start at 3 (0=., 1=..,
    // 2=reserved)
    let mut next_offset: u16 = 3;

    // Parse and copy entries, skipping the one to remove
    let mut offset = header_size;
    for _ in 0..header.count {
        if offset >= current_data.len() {
            break;
        }

        let name_len = current_data[offset] as usize;
        offset += 1;

        // Read original offset cookie (we'll ignore and regenerate)
        let _original_offset = u16::from_be_bytes([current_data[offset], current_data[offset + 1]]);
        offset += 2;

        // Read name
        if offset + name_len > current_data.len() {
            return Err(FsError::Corrupted);
        }
        let entry_name = &current_data[offset..offset + name_len];
        offset += name_len;

        // Read ftype if present
        let ftype = if has_ftype {
            if offset >= current_data.len() {
                return Err(FsError::Corrupted);
            }
            let ft = current_data[offset];
            offset += 1;
            ft
        } else {
            0
        };

        // Read inode
        let inode_size = if use_64bit { 8 } else { 4 };
        if offset + inode_size > current_data.len() {
            return Err(FsError::Corrupted);
        }
        let inode = if use_64bit {
            u64::from_be_bytes(current_data[offset..offset + 8].try_into().unwrap())
        } else {
            u32::from_be_bytes(current_data[offset..offset + 4].try_into().unwrap()) as u64
        };
        offset += inode_size;

        // Skip if this is the entry to remove
        if entry_name == name {
            found = true;
            continue;
        }

        // Re-add this entry with the correct sequential offset cookie
        let entry = NewDirEntry {
            name: entry_name.to_vec(),
            inode,
            file_type: DirFileType::from(ftype),
        };
        new_data.extend(serialize_shortform_entry(
            &entry,
            next_offset,
            use_64bit,
            has_ftype,
        ));
        next_offset += 1;
        new_count += 1;
    }

    if !found {
        return Err(FsError::NotFound);
    }

    // Update header
    let new_header = ShortformHeader {
        count: new_count,
        i8count: if use_64bit { new_count } else { 0 },
        parent: header.parent,
    };
    let header_bytes = serialize_shortform_header(&new_header, use_64bit);
    new_data[..header_size].copy_from_slice(&header_bytes);

    Ok(new_data)
}

/// Check if a name exists in a shortform directory.
pub fn shortform_contains(data: &[u8], name: &[u8], has_ftype: bool) -> FsResult<bool> {
    match crate::directory::find_entry_shortform(data, name, has_ftype) {
        Ok(_) => Ok(true),
        Err(FsError::NotFound) => Ok(false),
        Err(e) => Err(e),
    }
}

impl From<u8> for DirFileType {
    fn from(v: u8) -> Self {
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
}

// ─── Block Directory Operations ───────────────────────────────────────────

/// Block directory data entry header.
#[derive(Debug, Clone)]
pub struct BlockDirEntry {
    /// Inode number.
    pub inode: u64,
    /// Name length.
    pub name_len: u8,
    /// Name bytes.
    pub name: Vec<u8>,
    /// File type (v5).
    pub file_type: DirFileType,
    /// Entry tag (offset from start of block).
    pub tag: u16,
}

impl BlockDirEntry {
    /// Calculate the on-disk size of this entry (8-byte aligned).
    pub fn disk_size(&self, has_ftype: bool) -> usize {
        // inumber (8) + namelen (1) + name + ftype? + tag (2)
        let base_size = 8 + 1 + self.name.len() + if has_ftype { 1 } else { 0 } + 2;
        // Round up to 8-byte alignment
        (base_size + 7) & !7
    }
}

/// Free space entry in a block directory.
#[derive(Debug, Clone, Copy)]
pub struct BlockDirFree {
    /// Offset of this free entry.
    pub offset: u16,
    /// Length of free space (8-byte aligned).
    pub length: u16,
}

impl BlockDirFree {
    /// Minimum usable free space (for smallest possible entry).
    pub const MIN_USEFUL: u16 = 16;
    pub const SIZE: usize = 4; // 8 + 1 + 1 + 2 = 12, aligned to 16
}

/// Parse a block directory and return entries and free spaces.
pub fn parse_block_directory(
    data: &[u8],
    has_ftype: bool,
) -> FsResult<(Vec<BlockDirEntry>, Vec<BlockDirFree>)> {
    // Check magic
    if data.len() < 16 {
        return Err(FsError::BufferTooSmall);
    }

    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if !crate::directory::validate_dir_block_magic(magic) {
        return Err(FsError::InvalidMagic);
    }

    let is_v5 = magic == XFS_DIR3_BLOCK_MAGIC || magic == XFS_DIR3_DATA_MAGIC;
    let header_size = if is_v5 { 64 } else { 16 };
    let mut entries = Vec::new();
    let mut frees = Vec::new();

    let mut offset = header_size;

    while offset + 8 < data.len() - 8 {
        // Leave room for tail
        // Check for unused entry (freetag = 0xFFFF)
        let freetag = u16::from_be_bytes([data[offset], data[offset + 1]]);

        if freetag == 0xFFFF {
            // Free space entry
            let length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            frees.push(BlockDirFree {
                offset: offset as u16,
                length,
            });
            offset += length as usize;
        } else {
            // Data entry
            let inode = u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
            let name_len = data[offset + 8] as usize;

            if offset + 9 + name_len > data.len() {
                break;
            }

            let name = data[offset + 9..offset + 9 + name_len].to_vec();

            let file_type = if has_ftype && offset + 9 + name_len < data.len() {
                DirFileType::from(data[offset + 9 + name_len])
            } else {
                DirFileType::Unknown
            };

            let entry_size = 8 + 1 + name_len + if has_ftype { 1 } else { 0 } + 2;
            let aligned_size = (entry_size + 7) & !7;

            // Tag is at end of aligned entry
            let tag_offset = offset + aligned_size - 2;
            let tag = if tag_offset + 2 <= data.len() {
                u16::from_be_bytes([data[tag_offset], data[tag_offset + 1]])
            } else {
                offset as u16
            };

            entries.push(BlockDirEntry {
                inode,
                name_len: name_len as u8,
                name,
                file_type,
                tag,
            });

            offset += aligned_size;
        }
    }

    Ok((entries, frees))
}
