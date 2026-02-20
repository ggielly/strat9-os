//! RAM Filesystem implementation for Strat9-OS
//!
//! Stores all file data and directory structure in memory.

#![no_std]

extern crate alloc;

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use spin::Mutex;
use strate_fs_abstraction::{
    FsError, FsResult, OpenFlags, VfsDirEntry, VfsFileInfo, VfsFileType, VfsFileSystem, VfsTimestamp,
};

/// Internal node type for RamFS
enum RamNode {
    File {
        data: Vec<u8>,
    },
    Directory {
        entries: BTreeMap<String, Arc<Mutex<RamNode>>>,
    },
}

impl RamNode {
    fn info(&self) -> VfsFileInfo {
        match self {
            RamNode::File { data } => VfsFileInfo {
                size: data.len() as u64,
                file_type: VfsFileType::Regular,
                permissions: 0o644,
                created: VfsTimestamp::default(),
                modified: VfsTimestamp::default(),
                accessed: VfsTimestamp::default(),
            },
            RamNode::Directory { .. } => VfsFileInfo {
                size: 0,
                file_type: VfsFileType::Directory,
                permissions: 0o755,
                created: VfsTimestamp::default(),
                modified: VfsTimestamp::default(),
                accessed: VfsTimestamp::default(),
            },
        }
    }
}

pub struct RamFileSystem {
    root: Arc<Mutex<RamNode>>,
}

impl RamFileSystem {
    pub fn new() -> Self {
        Self {
            root: Arc::new(Mutex::new(RamNode::Directory {
                entries: BTreeMap::new(),
            })),
        }
    }

    fn resolve(&self, path: &str) -> FsResult<Arc<Mutex<RamNode>>> {
        let mut current = self.root.clone();
        
        for part in path.split('/').filter(|s| !s.is_empty()) {
            let next = {
                let guard = current.lock();
                match &*guard {
                    RamNode::Directory { entries } => {
                        entries.get(part).cloned().ok_or(FsError::NotFound)?
                    }
                    _ => return Err(FsError::NotADirectory),
                }
            };
            current = next;
        }
        
        Ok(current)
    }
}

impl VfsFileSystem for RamFileSystem {
    fn open(&self, path: &str, flags: OpenFlags) -> FsResult<VfsFileInfo> {
        match self.resolve(path) {
            Ok(node) => {
                if flags.contains(OpenFlags::CREATE) && flags.contains(OpenFlags::EXCLUSIVE) {
                    return Err(FsError::AlreadyExists);
                }
                Ok(node.lock().info())
            }
            Err(FsError::NotFound) if flags.contains(OpenFlags::CREATE) => {
                // Create file logic would go here, simplified for now
                // In a real impl, we need the parent directory
                Err(FsError::NotImplemented)
            }
            Err(e) => Err(e),
        }
    }

    fn read(&self, path: &str, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        let node = self.resolve(path)?;
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

    fn write(&self, path: &str, offset: u64, buf: &[u8]) -> FsResult<usize> {
        let node = self.resolve(path)?;
        let mut guard = node.lock();
        match &mut *guard {
            RamNode::File { data } => {
                let start = offset as usize;
                let end = start + buf.len();
                if end > data.len() {
                    data.resize(end, 0);
                }
                data[start..end].copy_from_slice(buf);
                Ok(buf.len())
            }
            _ => Err(FsError::IsADirectory),
        }
    }

    fn read_dir(&self, path: &str) -> FsResult<Vec<VfsDirEntry>> {
        let node = self.resolve(path)?;
        let guard = node.lock();
        match &*guard {
            RamNode::Directory { entries } => {
                let mut result = Vec::new();
                for (name, child) in entries {
                    let info = child.lock().info();
                    result.push(VfsDirEntry {
                        name: name.clone(),
                        info,
                    });
                }
                Ok(result)
            }
            _ => Err(FsError::NotADirectory),
        }
    }

    // Other methods (mkdir, unlink, etc.)
    fn create_dir(&self, path: &str) -> FsResult<()> {
        // Implementation for mkdir
        let (parent_path, name) = split_path(path);
        let parent_node = self.resolve(parent_path)?;
        let mut guard = parent_node.lock();
        match &mut *guard {
            RamNode::Directory { entries } => {
                if entries.contains_key(name) {
                    return Err(FsError::AlreadyExists);
                }
                entries.insert(name.to_string(), Arc::new(Mutex::new(RamNode::Directory {
                    entries: BTreeMap::new(),
                })));
                Ok(())
            }
            _ => Err(FsError::NotADirectory),
        }
    }
}

fn split_path(path: &str) -> (&str, &str) {
    let path = path.trim_end_matches('/');
    if let Some(idx) = path.rfind('/') {
        (&path[..idx], &path[idx+1..])
    } else {
        ("/", path)
    }
}
