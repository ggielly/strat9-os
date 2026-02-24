#![no_std]

extern crate alloc;

use alloc::sync::Arc;
use strate_fs_abstraction::{VfsDirEntry, VfsFileInfo, VfsFileSystem};
use strat9_components_api::{
    BlockDevice, FileHandle, FileStat, FileSystem, FileType, FsError, FsResult,
};
use xfs_rs::{
    extent::{Extent, ExtentIter},
    Inode, Superblock,
};

pub struct XfsDriver {
    device: Arc<dyn BlockDevice>,
    superblock: Superblock,
    root_inode: u64,
}

impl XfsDriver {
    pub fn new(device: Arc<dyn BlockDevice>) -> FsResult<Self> {
        let mut sb_buf = [0u8; 512];
        device
            .read_at(0, &mut sb_buf)
            .map_err(|_| FsError::DiskError)?;

        if &sb_buf[0..4] != b"XFSB" {
            return Err(FsError::InvalidMagic);
        }

        let superblock = Superblock::parse(&sb_buf).map_err(|_| FsError::Corrupted)?;

        Ok(Self {
            device,
            superblock,
            root_inode: superblock.root_inode,
        })
    }

    fn read_inode(&self, ino: u64) -> FsResult<Inode> {
        let inode_size = self.superblock.inode_size as usize;
        let inode_offset = self.calculate_inode_offset(ino)?;

        let mut buf = alloc::vec![0u8; inode_size];
        self.device
            .read_at(inode_offset, &mut buf)
            .map_err(|_| FsError::DiskError)?;

        Inode::parse(&buf, inode_size).map_err(|_| FsError::Corrupted)
    }

    fn calculate_inode_offset(&self, ino: u64) -> FsResult<u64> {
        let sb = &self.superblock;

        let ag_number = ino >> (sb.ag_block_log + sb.inode_per_block_log);
        let inode_in_ag = ino & ((1 << (sb.ag_block_log + sb.inode_per_block_log)) - 1);

        let ag_start = ag_number * (sb.ag_blocks as u64) * (sb.block_size as u64);

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
                let start = offset as usize;
                if start >= data.len() {
                    return Ok(0);
                }

                let end = ((offset + buf.len() as u64) as usize).min(data.len());
                let read_len = end - start;

                buf[..read_len].copy_from_slice(&data[start..end]);
                Ok(read_len)
            }
            xfs_rs::DataFork::Extents(extents) => {
                self.read_from_extents(inode, extents, offset, buf)
            }
            xfs_rs::DataFork::Btree { .. } => {
                // TODO: implement B+tree extent reading for large files
                Err(FsError::NotImplemented)
            }
            xfs_rs::DataFork::Device { .. } | xfs_rs::DataFork::Empty => Ok(0),
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

        for extent in extents {
            if extent.contains_file_block(start_block) {
                let physical_block = extent
                    .translate(start_block)
                    .map_err(|_| FsError::InvalidBlockAddress)?;
                let block_offset = physical_block * block_size;

                let mut block_buf = alloc::vec![0u8; block_size as usize];
                self.device
                    .read_at(block_offset, &mut block_buf)
                    .map_err(|_| FsError::DiskError)?;

                let copy_start = start_block_offset as usize;
                let copy_len = (block_size - start_block_offset).min(buf.len() as u64) as usize;

                if copy_len > 0 {
                    buf[0..copy_len].copy_from_slice(&block_buf[copy_start..copy_start + copy_len]);
                    bytes_read += copy_len;
                }

                // TODO: read across multiple extents for large reads
                break;
            }
        }

        Ok(bytes_read)
    }
}

impl FileSystem for XfsDriver {
    fn mount(&mut self, _device: Arc<dyn BlockDevice>) -> FsResult<()> {
        Ok(())
    }

    fn unmount(&mut self) -> FsResult<()> {
        Ok(())
    }

    fn lookup(&self, _path: &str) -> FsResult<u64> {
        // TODO: implement path lookup traversing directory structure
        Err(FsError::NotImplemented)
    }

    fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        let inode = self.read_inode(ino)?;

        if inode.core.is_dir() {
            return Err(FsError::IsADirectory);
        }

        self.read_file_data(&inode, offset, buf)
    }

    fn write(&mut self, _ino: u64, _offset: u64, _buf: &[u8]) -> FsResult<usize> {
        // TODO: implement write (requires XFS journaling)
        Err(FsError::NotImplemented)
    }

    fn create(&mut self, _parent: u64, _name: &str, _file_type: FileType) -> FsResult<u64> {
        // TODO: implement create (requires XFS journaling)
        Err(FsError::NotImplemented)
    }

    fn remove(&mut self, _parent: u64, _name: &str) -> FsResult<()> {
        // TODO: implement remove (requires XFS journaling)
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

        match inode.core.format {
            xfs_rs::InodeFormat::Local => {
                let data = inode.inline_data().ok_or(FsError::Corrupted)?;
                self.parse_directory_entries(ino, data)
            }
            xfs_rs::InodeFormat::Extents | xfs_rs::InodeFormat::Btree => {
                self.read_large_directory(ino, &inode)
            }
            // TODO: handle other inode formats
            _ => Err(FsError::NotSupported),
        }
    }

    fn parse_directory_entries(
        &self,
        parent_ino: u64,
        data: &[u8],
    ) -> FsResult<alloc::vec::Vec<(alloc::string::String, u64)>> {
        // TODO: properly parse XFS short-form directory entries
        let mut entries = alloc::vec::Vec::new();

        if data.len() >= 2 {
            entries.push((alloc::string::String::from("."), parent_ino));
        }

        Ok(entries)
    }

    fn read_large_directory(
        &self,
        ino: u64,
        inode: &Inode,
    ) -> FsResult<alloc::vec::Vec<(alloc::string::String, u64)>> {
        // TODO: properly parse XFS block/leaf/node directory formats
        let mut entries = alloc::vec::Vec::new();

        match &inode.data_fork {
            xfs_rs::DataFork::Extents(extents) => {
                for extent in extents {
                    let block_size = self.superblock.block_size as u64;

                    for block_offset in 0..extent.block_count {
                        let disk_block = extent.start_block + block_offset as u64;

                        let block_offset_bytes = disk_block * block_size;
                        let mut block_data = alloc::vec![0u8; block_size as usize];

                        self.device
                            .read_at(block_offset_bytes, &mut block_data)
                            .map_err(|_| FsError::DiskError)?;

                        entries.push((alloc::string::String::from("placeholder"), ino));
                    }
                }
            }
            // TODO: handle btree directories
            _ => return Err(FsError::NotSupported),
        }

        Ok(entries)
    }
}
