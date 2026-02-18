#![no_std]

extern crate alloc;

use alloc::sync::Arc;
use fs_abstraction::{VfsDirEntry, VfsFileInfo, VfsFileSystem};
use spin::Mutex;
use strat9_components_api::{
    BlockDevice, FileHandle, FileStat, FileSystem, FileType, FsError, FsResult,
};
use strat9_kernel::ipc::IpcMessage;
use xfs_rs::{
    extent::{Extent, ExtentIter},
    Inode, Superblock,
};

pub struct XfsDriver {
    device: Arc<dyn BlockDevice>,
    superblock: Superblock,
    root_inode: u64,
    // Add caching mechanism if needed
}

impl XfsDriver {
    pub fn new(device: Arc<dyn BlockDevice>) -> FsResult<Self> {
        // Read superblock from device
        let mut sb_buf = [0u8; 512];
        device
            .read_at(0, &mut sb_buf)
            .map_err(|_| FsError::IoError)?;

        // Validate XFS magic number
        if &sb_buf[0..4] != b"XFSB" {
            return Err(FsError::InvalidFormat);
        }

        // Parse superblock
        let superblock = Superblock::parse(&sb_buf).map_err(|_| FsError::Corrupted)?;

        Ok(Self {
            device,
            superblock,
            root_inode: superblock.root_inode,
            // Initialize cache if needed
        })
    }

    fn read_inode(&self, ino: u64) -> FsResult<Inode> {
        // Calculate inode location based on XFS layout
        let inode_size = self.superblock.inode_size as usize;
        let inode_offset = self.calculate_inode_offset(ino)?;

        let mut buf = alloc::vec![0u8; inode_size];
        self.device
            .read_at(inode_offset, &mut buf)
            .map_err(|_| FsError::IoError)?;

        Inode::parse(&buf, inode_size).map_err(|_| FsError::Corrupted)
    }

    fn calculate_inode_offset(&self, ino: u64) -> FsResult<u64> {
        let sb = &self.superblock;

        // Calculate AG number and inode within AG
        let ag_number = ino >> (sb.ag_block_log + sb.inode_per_block_log);
        let inode_in_ag = ino & ((1 << (sb.ag_block_log + sb.inode_per_block_log)) - 1);

        // AG start offset
        let ag_start = ag_number * (sb.ag_blocks as u64) * (sb.block_size as u64);

        // Inode offset within AG
        let block_in_ag = inode_in_ag >> sb.inode_per_block_log;
        let inode_in_block = inode_in_ag & ((1 << sb.inode_per_block_log) - 1);

        let offset = ag_start
            + block_in_ag * (sb.block_size as u64)
            + inode_in_block * (sb.inode_size as u64);

        Ok(offset)
    }

    fn read_file_data(&self, inode: &Inode, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        match &inode.data_fork {
            xfs_rs::DataFork::Local(data) => {
                // Handle inline data (stored directly in inode)
                let start = offset as usize;
                if start >= data.len() {
                    return Ok(0); // EOF
                }

                let end = ((offset + buf.len() as u64) as usize).min(data.len());
                let read_len = end - start;

                buf[..read_len].copy_from_slice(&data[start..end]);
                Ok(read_len)
            }
            xfs_rs::DataFork::Extents(extents) => {
                // Handle file with extent list
                self.read_from_extents(inode, extents, offset, buf)
            }
            xfs_rs::DataFork::Btree { .. } => {
                // Handle file with B+tree (large files)
                Err(FsError::NotImplemented)
            }
            xfs_rs::DataFork::Device { .. } | xfs_rs::DataFork::Empty => {
                // Special files or empty files
                Ok(0)
            }
        }
    }

    fn read_from_extents(
        &self,
        _inode: &Inode,
        extents: &alloc::vec::Vec<Extent>,
        offset: u64,
        buf: &mut [u8],
    ) -> FsResult<usize> {
        let block_size = self.superblock.block_size as u64;
        let start_block = offset / block_size;
        let start_block_offset = offset % block_size;

        let mut bytes_read = 0;
        let mut current_offset = offset;

        for extent in extents {
            if extent.contains_file_block(start_block) {
                // Calculate the physical block to read
                let physical_block = extent
                    .translate(start_block)
                    .map_err(|_| FsError::InvalidArgument)?;
                let block_offset = physical_block * block_size;

                // Read the block
                let mut block_buf = alloc::vec![0u8; block_size as usize];
                self.device
                    .read_at(block_offset, &mut block_buf)
                    .map_err(|_| FsError::IoError)?;

                // Copy the relevant portion to the output buffer
                let copy_start = start_block_offset as usize;
                let copy_len = (block_size - start_block_offset).min(buf.len() as u64) as usize;

                if copy_len > 0 {
                    buf[0..copy_len].copy_from_slice(&block_buf[copy_start..copy_start + copy_len]);
                    bytes_read += copy_len;
                }

                break; // For simplicity, only read from the first matching extent
            }
        }

        Ok(bytes_read)
    }
}

impl FileSystem for XfsDriver {
    fn mount(&mut self, device: Arc<dyn BlockDevice>) -> FsResult<()> {
        // Already handled in new() but can be extended if needed
        Ok(())
    }

    fn unmount(&mut self) -> FsResult<()> {
        // Perform any cleanup needed
        Ok(())
    }

    fn lookup(&self, path: &str) -> FsResult<u64> {
        // Implementation for looking up inodes by path
        // This would involve traversing the directory structure
        todo!("Implement path lookup for XFS")
    }

    fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        let inode = self.read_inode(ino)?;

        // Check if it's a directory
        if inode.core.is_dir() {
            return Err(FsError::IsADirectory);
        }

        self.read_file_data(&inode, offset, buf)
    }

    fn write(&mut self, ino: u64, offset: u64, buf: &[u8]) -> FsResult<usize> {
        // XFS implementation for write operations
        // For now, return error as write is complex and requires journaling
        Err(FsError::NotImplemented)
    }

    fn create(&mut self, parent: u64, name: &str, file_type: FileType) -> FsResult<u64> {
        // XFS implementation for file/directory creation
        // For now, return error as creation is complex and requires journaling
        Err(FsError::NotImplemented)
    }

    fn remove(&mut self, parent: u64, name: &str) -> FsResult<()> {
        // XFS implementation for file/directory removal
        // For now, return error as removal is complex and requires journaling
        Err(FsError::NotImplemented)
    }

    fn stat(&self, ino: u64) -> FsResult<FileStat> {
        let inode = self.read_inode(ino)?;

        Ok(FileStat {
            size: inode.core.size,
            file_type: if inode.core.is_dir() {
                FileType::Directory
            } else if inode.core.is_file() {
                FileType::Regular
            } else if inode.core.is_symlink() {
                FileType::Symlink
            } else {
                FileType::Other
            },
            permissions: inode.core.permissions() as u8,
            modified: inode.core.mtime_sec as u64,
        })
    }

    fn readdir(&self, ino: u64) -> FsResult<alloc::vec::Vec<(alloc::string::String, u64)>> {
        let inode = self.read_inode(ino)?;

        if !inode.core.is_dir() {
            return Err(FsError::NotADirectory);
        }

        // Handle directory reading based on inode format
        match inode.core.format {
            xfs_rs::InodeFormat::Local => {
                // For small directories stored inline in the inode
                let data = inode.inline_data().ok_or(FsError::Corrupted)?;
                self.parse_directory_entries(ino, data)
            }
            xfs_rs::InodeFormat::Extents | xfs_rs::InodeFormat::Btree => {
                // For larger directories stored in extents or btree
                // This requires reading directory blocks from disk
                self.read_large_directory(ino, &inode)
            }
            _ => Err(FsError::NotImplemented),
        }
    }

    fn parse_directory_entries(
        &self,
        _parent_ino: u64,
        data: &[u8],
    ) -> FsResult<alloc::vec::Vec<(alloc::string::String, u64)>> {
        // Simplified directory parsing - in a real implementation,
        // this would parse XFS directory format
        let mut entries = alloc::vec::Vec::new();

        // Placeholder implementation - would need to properly parse XFS directory format
        // This is a simplified approach for demonstration purposes
        if data.len() >= 2 {
            // If there's data, add a placeholder entry for now
            entries.push((alloc::string::String::from("."), _parent_ino));
        }

        Ok(entries)
    }

    fn read_large_directory(
        &self,
        ino: u64,
        inode: &Inode,
    ) -> FsResult<alloc::vec::Vec<(alloc::string::String, u64)>> {
        // For directories stored in extents or btree
        // This is a simplified implementation
        let mut entries = alloc::vec::Vec::new();

        match &inode.data_fork {
            xfs_rs::DataFork::Extents(extents) => {
                // Read directory data from extents
                for extent in extents {
                    let block_size = self.superblock.block_size as u64;

                    for block_offset in 0..extent.block_count {
                        let file_block = extent.file_offset + block_offset as u64;
                        let disk_block = extent.start_block + block_offset as u64;

                        let block_offset_bytes = disk_block * block_size;
                        let mut block_data = alloc::vec![0u8; block_size as usize];

                        self.device
                            .read_at(block_offset_bytes, &mut block_data)
                            .map_err(|_| FsError::IoError)?;

                        // Parse directory block - simplified
                        // In a real implementation, this would parse XFS directory format
                        entries.push((alloc::string::String::from("placeholder"), ino));
                    }
                }
            }
            _ => return Err(FsError::NotImplemented),
        }

        Ok(entries)
    }
}
