//! RAM Filesystem implementation for Strat9-OS
//!
//! Stores all file data and directory structure in memory.
//! Compliant with VfsFileSystem trait from strate-fs-abstraction.

#![no_std]

extern crate alloc;

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use strate_fs_abstraction::{
    FsCapabilities, FsError, FsResult, VfsDirEntry, VfsFileInfo, VfsFileType, VfsFileSystem,
    VfsVolumeInfo,
};

/// Internal node type for RamFS
enum RamNode {
    File {
        data: Vec<u8>,
    },
    Directory {
        entries: BTreeMap<String, u64>, // Maps name to Inode ID
    },
}

pub struct RamFileSystem {
    inodes: Mutex<BTreeMap<u64, Arc<Mutex<RamNode>>>>,
    next_inode: AtomicU64,
    capabilities: FsCapabilities,
}

impl RamFileSystem {
    pub fn new() -> Self {
        let root = Arc::new(Mutex::new(RamNode::Directory {
            entries: BTreeMap::new(),
        }));
        let mut inodes = BTreeMap::new();
        inodes.insert(2, root); // Standard root inode is 2

        Self {
            inodes: Mutex::new(inodes),
            next_inode: AtomicU64::new(10), // Start user inodes at 10
            capabilities: FsCapabilities::writable_linux(), 
        }
    }

    fn get_node(&self, ino: u64) -> FsResult<Arc<Mutex<RamNode>>> {
        self.inodes
            .lock()
            .get(&ino)
            .cloned()
            .ok_or(FsError::InodeNotFound)
    }

    fn allocate_inode(&self, node: RamNode) -> u64 {
        let id = self.next_inode.fetch_add(1, Ordering::SeqCst);
        self.inodes.lock().insert(id, Arc::new(Mutex::new(node)));
        id
    }

    /// Internal helper to resolve path to Inode (used by IPC server)
    pub fn resolve_path(&self, path: &str) -> FsResult<u64> {
        let mut current_ino = self.root_inode();
        for part in path.split('/').filter(|s| !s.is_empty()) {
            let info = self.lookup(current_ino, part)?;
            current_ino = info.ino;
        }
        Ok(current_ino)
    }
}

impl VfsFileSystem for RamFileSystem {
    fn fs_type(&self) -> &'static str {
        "ramfs"
    }

    fn capabilities(&self) -> &FsCapabilities {
        &self.capabilities
    }

    fn root_inode(&self) -> u64 {
        2
    }

    fn get_volume_info(&self) -> FsResult<VfsVolumeInfo> {
        Ok(VfsVolumeInfo {
            fs_type: String::from("ramfs"),
            block_size: 4096,
            ..VfsVolumeInfo::default()
        })
    }

    fn stat(&self, ino: u64) -> FsResult<VfsFileInfo> {
        let node = self.get_node(ino)?;
        let guard = node.lock();
        let mut info = VfsFileInfo::default();
        info.ino = ino;
        match &*guard {
            RamNode::File { data } => {
                info.size = data.len() as u64;
                info.file_type = VfsFileType::RegularFile;
                info.mode = 0o100644;
            }
            RamNode::Directory { .. } => {
                info.size = 0;
                info.file_type = VfsFileType::Directory;
                info.mode = 0o040755;
            }
        }
        Ok(info)
    }

    fn lookup(&self, parent_ino: u64, name: &str) -> FsResult<VfsFileInfo> {
        let parent = self.get_node(parent_ino)?;
        let guard = parent.lock();
        match &*guard {
            RamNode::Directory { entries } => {
                let ino = *entries.get(name).ok_or(FsError::NotFound)?;
                drop(guard);
                self.stat(ino)
            }
            _ => Err(FsError::NotADirectory),
        }
    }

    fn resolve_path(&self, path: &str) -> FsResult<u64> {
        self.resolve_path(path)
    }

    fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        let node = self.get_node(ino)?;
        let guard = node.lock();
        match &*guard {
            RamNode::File { data } => {
                if offset >= data.len() as u64 {
                    return Ok(0);
                }
                let start = offset as usize;
                let end = (start + buf.len()).min(data.len());
                let count = end - start;
                buf[..count].copy_from_slice(&data[start..end]);
                Ok(count)
            }
            _ => Err(FsError::IsADirectory),
        }
    }

    fn write(&self, ino: u64, offset: u64, data: &[u8]) -> FsResult<usize> {
        let node = self.get_node(ino)?;
        let mut guard = node.lock();
        match &mut *guard {
            RamNode::File { data: file_data } => {
                let start = offset as usize;
                let end = start + data.len();
                if end > file_data.len() {
                    file_data.resize(end, 0);
                }
                file_data[start..end].copy_from_slice(data);
                Ok(data.len())
            }
            _ => Err(FsError::IsADirectory),
        }
    }

    fn readdir(&self, ino: u64) -> FsResult<Vec<VfsDirEntry>> {
        let node = self.get_node(ino)?;
        let guard = node.lock();
        match &*guard {
            RamNode::Directory { entries } => {
                let mut result = Vec::new();
                for (name, &child_ino) in entries {
                    let info = self.stat(child_ino)?;
                    result.push(VfsDirEntry {
                        name: name.clone(),
                        ino: child_ino,
                        file_type: info.file_type,
                        offset: 0,
                    });
                }
                Ok(result)
            }
            _ => Err(FsError::NotADirectory),
        }
    }

    fn create_file(&self, parent_ino: u64, name: &str, _mode: u32) -> FsResult<VfsFileInfo> {
        let parent = self.get_node(parent_ino)?;
        let mut guard = parent.lock();
        match &mut *guard {
            RamNode::Directory { entries } => {
                if entries.contains_key(name) {
                    return Err(FsError::AlreadyExists);
                }
                let new_ino = self.allocate_inode(RamNode::File { data: Vec::new() });
                entries.insert(name.to_string(), new_ino);
                drop(guard);
                self.stat(new_ino)
            }
            _ => Err(FsError::NotADirectory),
        }
    }

    fn create_directory(&self, parent_ino: u64, name: &str, _mode: u32) -> FsResult<VfsFileInfo> {
        let parent = self.get_node(parent_ino)?;
        let mut guard = parent.lock();
        match &mut *guard {
            RamNode::Directory { entries } => {
                if entries.contains_key(name) {
                    return Err(FsError::AlreadyExists);
                }
                let new_ino = self.allocate_inode(RamNode::Directory {
                    entries: BTreeMap::new(),
                });
                entries.insert(name.to_string(), new_ino);
                drop(guard);
                self.stat(new_ino)
            }
            _ => Err(FsError::NotADirectory),
        }
    }

    fn unlink(&self, parent_ino: u64, name: &str, target_ino: u64) -> FsResult<()> {
        let parent = self.get_node(parent_ino)?;
        let mut guard = parent.lock();
        match &mut *guard {
            RamNode::Directory { entries } => {
                let ino = *entries.get(name).ok_or(FsError::NotFound)?;
                if ino != target_ino {
                    return Err(FsError::InvalidArgument);
                }
                
                let node = self.get_node(ino)?;
                let node_guard = node.lock();
                
                if let RamNode::Directory { entries: child_entries } = &*node_guard {
                    if !child_entries.is_empty() {
                        return Err(FsError::NotEmpty);
                    }
                }
                
                drop(node_guard);
                entries.remove(name);
                drop(guard);
                self.inodes.lock().remove(&ino);
                Ok(())
            }
            _ => Err(FsError::NotADirectory),
        }
    }

    fn readlink(&self, _ino: u64) -> FsResult<String> {
        Err(FsError::NotSupported)
    }

    fn invalidate_inode(&self, _ino: u64) {}
    fn invalidate_all_caches(&self) {}
}

pub fn split_path(path: &str) -> (&str, &str) {
    let path = path.trim_end_matches('/');
    if let Some(idx) = path.rfind('/') {
        if idx == 0 {
            ("/", &path[1..])
        } else {
            (&path[..idx], &path[idx + 1..])
        }
    } else {
        ("/", path)
    }
}
