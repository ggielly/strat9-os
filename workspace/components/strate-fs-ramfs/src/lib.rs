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
    FsCapabilities, FsError, FsResult, RenameFlags, VfsDirEntry, VfsFileInfo, VfsFileSystem,
    VfsFileType, VfsTimestamp, VfsVolumeInfo,
};

/// Internal node type for RamFS
enum RamNode {
    File {
        data: Vec<u8>,
        mode: u32,
    },
    Directory {
        entries: BTreeMap<String, u64>, // Maps name to Inode ID
        mode: u32,
    },
}

pub struct RamFileSystem {
    inodes: Mutex<BTreeMap<u64, Arc<Mutex<RamNode>>>>,
    open_counts: Mutex<BTreeMap<u64, u32>>,
    next_inode: AtomicU64,
    capabilities: FsCapabilities,
}

impl RamFileSystem {
    pub fn new() -> Self {
        let root = Arc::new(Mutex::new(RamNode::Directory {
            entries: BTreeMap::new(),
            mode: 0o040755,
        }));
        let mut inodes = BTreeMap::new();
        inodes.insert(2, root); // Standard root inode is 2

        Self {
            inodes: Mutex::new(inodes),
            open_counts: Mutex::new(BTreeMap::new()),
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

    fn lookup_child_inode(&self, parent_ino: u64, name: &str) -> FsResult<u64> {
        let parent = self.get_node(parent_ino)?;
        let guard = parent.lock();
        match &*guard {
            RamNode::Directory { entries, .. } => entries.get(name).copied().ok_or(FsError::NotFound),
            _ => Err(FsError::NotADirectory),
        }
    }

    /// Internal helper to resolve path to inode (used by IPC server)
    pub fn resolve_path_internal(&self, path: &str) -> FsResult<u64> {
        let mut current_ino = self.root_inode();
        for part in path.split('/').filter(|s| !s.is_empty()) {
            current_ino = self.lookup_child_inode(current_ino, part)?;
        }
        Ok(current_ino)
    }

    fn to_file_mode(mode: u32) -> u32 {
        0o100000 | (mode & 0o7777)
    }

    fn to_dir_mode(mode: u32) -> u32 {
        0o040000 | (mode & 0o7777)
    }

    pub fn register_open(&self, ino: u64) -> FsResult<()> {
        let mut counts = self.open_counts.lock();
        if !self.inodes.lock().contains_key(&ino) {
            return Err(FsError::InodeNotFound);
        }
        let count = counts.entry(ino).or_insert(0);
        *count = count.saturating_add(1);
        Ok(())
    }

    pub fn unregister_open(&self, ino: u64) -> FsResult<()> {
        let mut counts = self.open_counts.lock();
        let removed_last = match counts.get_mut(&ino) {
            Some(count) if *count > 1 => {
                *count -= 1;
                false
            }
            Some(_) => {
                counts.remove(&ino);
                true
            }
            None => return Err(FsError::InodeNotFound),
        };
        drop(counts);

        if removed_last {
            self.collect_if_detached(ino)?;
        }
        Ok(())
    }

    fn is_open(&self, ino: u64) -> bool {
        self.open_counts.lock().get(&ino).copied().unwrap_or(0) > 0
    }

    fn directory_contains_inode(&self, root_dir_ino: u64, target_ino: u64) -> FsResult<bool> {
        let mut stack = Vec::new();
        stack.push(root_dir_ino);

        while let Some(current) = stack.pop() {
            if current == target_ino {
                return Ok(true);
            }

            let node = self.get_node(current)?;
            let guard = node.lock();
            if let RamNode::Directory { entries, .. } = &*guard {
                for &child in entries.values() {
                    stack.push(child);
                }
            }
        }

        Ok(false)
    }

    fn collect_if_detached(&self, ino: u64) -> FsResult<()> {
        if ino == self.root_inode() || self.is_open(ino) {
            return Ok(());
        }
        if self.directory_contains_inode(self.root_inode(), ino)? {
            return Ok(());
        }
        self.collect_detached_subtree(ino)
    }

    fn collect_detached_subtree(&self, ino: u64) -> FsResult<()> {
        if self.is_open(ino) {
            return Ok(());
        }

        let children = match self.get_node(ino) {
            Ok(node) => {
                let guard = node.lock();
                match &*guard {
                    RamNode::Directory { entries, .. } => {
                        let mut out = Vec::new();
                        for &child in entries.values() {
                            out.push(child);
                        }
                        out
                    }
                    RamNode::File { .. } => Vec::new(),
                }
            }
            Err(_) => return Ok(()),
        };

        for child in children {
            self.collect_detached_subtree(child)?;
        }

        if !self.is_open(ino) {
            self.open_counts.lock().remove(&ino);
            self.inodes.lock().remove(&ino);
        }
        Ok(())
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
            RamNode::File { data, mode } => {
                info.size = data.len() as u64;
                info.file_type = VfsFileType::RegularFile;
                info.mode = *mode;
            }
            RamNode::Directory { mode, .. } => {
                info.size = 0;
                info.file_type = VfsFileType::Directory;
                info.mode = *mode;
            }
        }
        Ok(info)
    }

    fn lookup(&self, parent_ino: u64, name: &str) -> FsResult<VfsFileInfo> {
        let ino = self.lookup_child_inode(parent_ino, name)?;
        self.stat(ino)
    }

    fn resolve_path(&self, path: &str) -> FsResult<u64> {
        self.resolve_path_internal(path)
    }

    fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        let node = self.get_node(ino)?;
        let guard = node.lock();
        match &*guard {
            RamNode::File { data, .. } => {
                let start = usize::try_from(offset).map_err(|_| FsError::InvalidArgument)?;
                if offset >= data.len() as u64 {
                    return Ok(0);
                }
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
            RamNode::File {
                data: file_data, ..
            } => {
                let start = usize::try_from(offset).map_err(|_| FsError::InvalidArgument)?;
                let end = start
                    .checked_add(data.len())
                    .ok_or(FsError::FileTooLarge)?;
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
            RamNode::Directory { entries, .. } => {
                let children: Vec<(String, u64)> =
                    entries.iter().map(|(name, &ino)| (name.clone(), ino)).collect();
                drop(guard);

                let mut result = Vec::new();
                for (name, child_ino) in children {
                    let child_node = self.get_node(child_ino)?;
                    let child_guard = child_node.lock();
                    let file_type = match &*child_guard {
                        RamNode::File { .. } => VfsFileType::RegularFile,
                        RamNode::Directory { .. } => VfsFileType::Directory,
                    };
                    result.push(VfsDirEntry {
                        name,
                        ino: child_ino,
                        file_type,
                        offset: 0,
                    });
                }
                Ok(result)
            }
            _ => Err(FsError::NotADirectory),
        }
    }

    fn create_file(&self, parent_ino: u64, name: &str, mode: u32) -> FsResult<VfsFileInfo> {
        let parent = self.get_node(parent_ino)?;
        {
            let guard = parent.lock();
            match &*guard {
                RamNode::Directory { entries, .. } => {
                    if entries.contains_key(name) {
                        return Err(FsError::AlreadyExists);
                    }
                }
                _ => return Err(FsError::NotADirectory),
            }
        }

        let new_ino = self.allocate_inode(RamNode::File {
            data: Vec::new(),
            mode: Self::to_file_mode(mode),
        });

        let mut guard = parent.lock();
        match &mut *guard {
            RamNode::Directory { entries, .. } => {
                if entries.contains_key(name) {
                    self.inodes.lock().remove(&new_ino);
                    return Err(FsError::AlreadyExists);
                }
                entries.insert(name.to_string(), new_ino);
                drop(guard);
                self.stat(new_ino)
            }
            _ => {
                self.inodes.lock().remove(&new_ino);
                Err(FsError::NotADirectory)
            }
        }
    }

    fn create_directory(&self, parent_ino: u64, name: &str, mode: u32) -> FsResult<VfsFileInfo> {
        let parent = self.get_node(parent_ino)?;
        {
            let guard = parent.lock();
            match &*guard {
                RamNode::Directory { entries, .. } => {
                    if entries.contains_key(name) {
                        return Err(FsError::AlreadyExists);
                    }
                }
                _ => return Err(FsError::NotADirectory),
            }
        }

        let new_ino = self.allocate_inode(RamNode::Directory {
            entries: BTreeMap::new(),
            mode: Self::to_dir_mode(mode),
        });

        let mut guard = parent.lock();
        match &mut *guard {
            RamNode::Directory { entries, .. } => {
                if entries.contains_key(name) {
                    self.inodes.lock().remove(&new_ino);
                    return Err(FsError::AlreadyExists);
                }
                entries.insert(name.to_string(), new_ino);
                drop(guard);
                self.stat(new_ino)
            }
            _ => {
                self.inodes.lock().remove(&new_ino);
                Err(FsError::NotADirectory)
            }
        }
    }

    fn unlink(&self, parent_ino: u64, name: &str, target_ino: u64) -> FsResult<()> {
        let parent = self.get_node(parent_ino)?;
        let child_ino = {
            let guard = parent.lock();
            match &*guard {
                RamNode::Directory { entries, .. } => *entries.get(name).ok_or(FsError::NotFound)?,
                _ => return Err(FsError::NotADirectory),
            }
        };

        if child_ino != target_ino {
            return Err(FsError::InvalidArgument);
        }

        let node = self.get_node(child_ino)?;
        {
            let node_guard = node.lock();
            if let RamNode::Directory {
                entries: child_entries,
                ..
            } = &*node_guard
            {
                if !child_entries.is_empty() {
                    return Err(FsError::NotEmpty);
                }
            }
        }

        let mut guard = parent.lock();
        match &mut *guard {
            RamNode::Directory { entries, .. } => {
                let current = *entries.get(name).ok_or(FsError::NotFound)?;
                if current != child_ino {
                    return Err(FsError::InvalidArgument);
                }
                entries.remove(name);
                drop(guard);
                self.collect_if_detached(child_ino)?;
                Ok(())
            }
            _ => Err(FsError::NotADirectory),
        }
    }

    fn rename(
        &self,
        old_parent: u64,
        old_name: &str,
        new_parent: u64,
        new_name: &str,
        flags: RenameFlags,
    ) -> FsResult<()> {
        if old_parent == new_parent && old_name == new_name {
            return Ok(());
        }
        if flags.exchange {
            return Err(FsError::NotSupported);
        }
        if flags.no_replace && flags.replace_if_exists {
            return Err(FsError::InvalidArgument);
        }

        let old_parent_node = self.get_node(old_parent)?;
        let moved_ino = {
            let guard = old_parent_node.lock();
            match &*guard {
                RamNode::Directory { entries, .. } => *entries.get(old_name).ok_or(FsError::NotFound)?,
                _ => return Err(FsError::NotADirectory),
            }
        };

        {
            let moved_node = self.get_node(moved_ino)?;
            let moved_guard = moved_node.lock();
            if let RamNode::Directory { .. } = &*moved_guard {
                if self.directory_contains_inode(moved_ino, new_parent)? {
                    return Err(FsError::InvalidArgument);
                }
            }
        }

        let new_parent_node = self.get_node(new_parent)?;
        let mut new_guard = new_parent_node.lock();
        let replaced_ino = match &mut *new_guard {
            RamNode::Directory { entries, .. } => {
                if let Some(&existing) = entries.get(new_name) {
                    if flags.no_replace {
                        return Err(FsError::AlreadyExists);
                    }
                    if !flags.replace_if_exists && existing != moved_ino {
                        return Err(FsError::AlreadyExists);
                    }
                    Some(existing)
                } else {
                    None
                }
            }
            _ => return Err(FsError::NotADirectory),
        };
        drop(new_guard);

        if let Some(existing_ino) = replaced_ino {
            let existing_node = self.get_node(existing_ino)?;
            let existing_guard = existing_node.lock();
            if let RamNode::Directory {
                entries: child_entries,
                ..
            } = &*existing_guard
            {
                if !child_entries.is_empty() {
                    return Err(FsError::NotEmpty);
                }
            }
        }

        {
            let mut guard = old_parent_node.lock();
            match &mut *guard {
                RamNode::Directory { entries, .. } => {
                    let current = *entries.get(old_name).ok_or(FsError::NotFound)?;
                    if current != moved_ino {
                        return Err(FsError::InvalidArgument);
                    }
                    entries.remove(old_name);
                }
                _ => return Err(FsError::NotADirectory),
            }
        }

        let mut guard = new_parent_node.lock();
        match &mut *guard {
            RamNode::Directory { entries, .. } => {
                let mut replaced_for_gc: Option<u64> = None;
                if let Some(existing_ino) = entries.insert(new_name.to_string(), moved_ino) {
                    if existing_ino != moved_ino {
                        replaced_for_gc = Some(existing_ino);
                    }
                }
                drop(guard);
                if let Some(existing_ino) = replaced_for_gc {
                    self.collect_if_detached(existing_ino)?;
                }
                Ok(())
            }
            _ => Err(FsError::NotADirectory),
        }
    }

    fn set_size(&self, ino: u64, size: u64) -> FsResult<()> {
        let node = self.get_node(ino)?;
        let mut guard = node.lock();
        match &mut *guard {
            RamNode::File { data, .. } => {
                let new_size = usize::try_from(size).map_err(|_| FsError::FileTooLarge)?;
                data.resize(new_size, 0);
                Ok(())
            }
            _ => Err(FsError::IsADirectory),
        }
    }

    fn set_times(
        &self,
        ino: u64,
        _atime: Option<VfsTimestamp>,
        _mtime: Option<VfsTimestamp>,
    ) -> FsResult<()> {
        let _ = self.get_node(ino)?;
        Ok(())
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
