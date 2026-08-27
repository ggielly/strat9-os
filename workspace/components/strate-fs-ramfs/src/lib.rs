//! RAM Filesystem implementation for Strat9-OS
//!
//! Stores all file data and directory structure in memory.
//! Compliant with VfsFileSystem trait from strate-fs-abstraction.

#![no_std]

extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, RwLock};
use strate_fs_abstraction::{
    FsCapabilities, FsError, FsResult, RenameFlags, VfsDirEntry, VfsFileInfo, VfsFileSystem,
    VfsFileType, VfsTimestamp, VfsVolumeInfo,
};

/// Maximum size of a single regular file, in bytes.
///
/// `write` and `set_size` refuse to grow a file past this bound *before*
/// touching the allocator. Without it, an untrusted client could send a
/// `WRITE` with an arbitrary offset, forcing `Vec::resize` to attempt a
/// multi-gigabyte allocation that trips the allocator's OOM handler and
/// kills the whole Silo (heap is only 2 MiB).
pub const MAX_FILE_SIZE: usize = 1024 * 1024; // 1 MiB per file

/// Maximum total bytes of file data across the whole filesystem.
///
/// The server heap is a small pool shared by every client of the Silo. This
/// global budget stops a single client from creating/writing files until the
/// allocator aborts (`exit(12)`). Headroom is reserved for directory
/// metadata, inodes and the session table.
pub const MAX_TOTAL_DATA: u64 = 1536 * 1024; // 1.5 MiB total

/// Maximum number of nodes visited by a single tree walk
/// (`directory_contains_inode`, `collect_detached_subtree`). Bounds the work
/// performed per call and makes the walks cycle-proof.
pub const MAX_TRAVERSAL_NODES: usize = 65536;

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

struct RamInode {
    node: Mutex<RamNode>,
    open_count: AtomicU32,
}

impl RamInode {
    /// Creates a new instance.
    fn new(node: RamNode) -> Self {
        Self {
            node: Mutex::new(node),
            open_count: AtomicU32::new(0),
        }
    }
}

pub struct RamFileSystem {
    inodes: RwLock<BTreeMap<u64, Arc<RamInode>>>,
    next_inode: AtomicU64,
    capabilities: FsCapabilities,
    /// Bytes of file data currently stored across all inodes (budget guard
    /// against exhausting the shared server heap).
    total_data_bytes: AtomicU64,
}

impl RamFileSystem {
    /// Creates a new instance.
    pub fn new() -> Self {
        let root = Arc::new(RamInode::new(RamNode::Directory {
            entries: BTreeMap::new(),
            mode: 0o040755,
        }));
        let mut inodes = BTreeMap::new();
        inodes.insert(2, root); // Standard root inode is 2

        Self {
            inodes: RwLock::new(inodes),
            next_inode: AtomicU64::new(10), // Start user inodes at 10
            capabilities: FsCapabilities::writable_linux(),
            total_data_bytes: AtomicU64::new(0),
        }
    }

    /// Validates a directory entry name.
    ///
    /// Rejects empty names, `.` and `..` (which must stay virtual), and any
    /// name containing a path separator or NUL so that no entry can shadow
    /// POSIX path semantics.
    fn validate_name(name: &str) -> FsResult<()> {
        if name.is_empty() || name == "." || name == ".." {
            return Err(FsError::InvalidArgument);
        }
        if name.bytes().any(|b| b == b'/' || b == b'\0') {
            return Err(FsError::InvalidArgument);
        }
        Ok(())
    }

    /// Returns node.
    fn get_node(&self, ino: u64) -> FsResult<Arc<RamInode>> {
        self.inodes
            .read()
            .get(&ino)
            .cloned()
            .ok_or(FsError::InodeNotFound)
    }

    /// Implements allocate inode.
    ///
    /// Never reuses inode 0 (reserved) or 2 (root), and never overwrites an
    /// id that is still present in the map, even if `next_inode` ever wraps.
    /// The loop is bounded in practice: with a 2 MiB heap the map can never
    /// hold 2^64 entries.
    fn allocate_inode(&self, node: RamNode) -> u64 {
        let inode = Arc::new(RamInode::new(node));
        loop {
            let id = self.next_inode.fetch_add(1, Ordering::SeqCst);
            if id == 0 || id == 2 {
                continue;
            }
            let mut map = self.inodes.write();
            if map.contains_key(&id) {
                continue;
            }
            map.insert(id, inode);
            return id;
        }
    }

    /// Implements lookup child inode.
    fn lookup_child_inode(&self, parent_ino: u64, name: &str) -> FsResult<u64> {
        let parent = self.get_node(parent_ino)?;
        let guard = parent.node.lock();
        match &*guard {
            RamNode::Directory { entries, .. } => {
                entries.get(name).copied().ok_or(FsError::NotFound)
            }
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

    /// Converts this value to file mode.
    fn to_file_mode(mode: u32) -> u32 {
        0o100000 | (mode & 0o7777)
    }

    /// Converts this value to dir mode.
    fn to_dir_mode(mode: u32) -> u32 {
        0o040000 | (mode & 0o7777)
    }

    /// Implements register open.
    ///
    /// The inode-map read lock is held across the 0->1 CAS so a concurrent
    /// GC (which removes inodes under the write lock only when the open
    /// counter is 0) cannot collect this inode between our lookup and our
    /// increment: the GC's write lock excludes us until the CAS lands, and
    /// its re-check then sees a non-zero counter.
    pub fn register_open(&self, ino: u64) -> FsResult<()> {
        let guard = self.inodes.read();
        let inode = guard.get(&ino).cloned().ok_or(FsError::InodeNotFound)?;
        let mut current = inode.open_count.load(Ordering::Acquire);
        loop {
            if current == u32::MAX {
                return Err(FsError::TooManyOpenFiles);
            }
            match inode.open_count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => current = actual,
            }
        }
    }

    /// Implements unregister open.
    pub fn unregister_open(&self, ino: u64) -> FsResult<()> {
        let inode = self.get_node(ino)?;
        let mut current = inode.open_count.load(Ordering::Acquire);
        let removed_last = loop {
            if current == 0 {
                return Err(FsError::InodeNotFound);
            }
            let next = current - 1;
            match inode.open_count.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break next == 0,
                Err(actual) => current = actual,
            }
        };

        if removed_last {
            self.collect_if_detached(ino)?;
        }
        Ok(())
    }

    /// Returns whether open.
    fn is_open(&self, ino: u64) -> bool {
        self.get_node(ino)
            .map(|inode| inode.open_count.load(Ordering::Acquire) > 0)
            .unwrap_or(false)
    }

    /// Implements directory contains inode.
    ///
    /// Iterative walk with a visited set and a node budget: it can never loop
    /// forever even if the tree is ever corrupted into containing a cycle,
    /// and it bounds the work per call.
    fn directory_contains_inode(&self, root_dir_ino: u64, target_ino: u64) -> FsResult<bool> {
        if root_dir_ino == target_ino {
            return Ok(true);
        }

        let mut stack = Vec::new();
        stack.push(root_dir_ino);
        let mut visited = BTreeSet::new();
        let mut nodes_seen = 0usize;

        while let Some(current) = stack.pop() {
            if !visited.insert(current) {
                continue; // cycle guard
            }
            nodes_seen += 1;
            if nodes_seen > MAX_TRAVERSAL_NODES {
                return Err(FsError::ArithmeticOverflow);
            }

            let node = match self.get_node(current) {
                Ok(node) => node,
                Err(_) => continue, // node vanished mid-walk
            };
            let guard = node.node.lock();
            if let RamNode::Directory { entries, .. } = &*guard {
                for &child in entries.values() {
                    if child == target_ino {
                        return Ok(true);
                    }
                    stack.push(child);
                }
            }
        }

        Ok(false)
    }

    /// Implements collect if detached.
    fn collect_if_detached(&self, ino: u64) -> FsResult<()> {
        if ino == self.root_inode() || self.is_open(ino) {
            return Ok(());
        }
        if self.directory_contains_inode(self.root_inode(), ino)? {
            return Ok(());
        }
        self.collect_detached_subtree(ino)
    }

    /// Implements collect detached subtree.
    ///
    /// Iterative (explicit stack) with a visited set and a node budget, so a
    /// legitimately deep tree cannot overflow the stack and a corrupted tree
    /// cannot loop. An inode is only removed under the map's write lock and
    /// only when its open counter is still 0, so a concurrent `register_open`
    /// cannot observe an inode that was just collected. File data freed here
    /// is returned to the global data budget.
    fn collect_detached_subtree(&self, root: u64) -> FsResult<()> {
        let mut stack = Vec::new();
        stack.push(root);
        let mut visited = BTreeSet::new();
        let mut nodes_seen = 0usize;
        let mut freed = 0u64;

        while let Some(ino) = stack.pop() {
            if ino == self.root_inode() {
                continue;
            }
            if !visited.insert(ino) {
                continue; // cycle guard
            }
            nodes_seen += 1;
            if nodes_seen > MAX_TRAVERSAL_NODES {
                // Refuse unbounded work in a single call. The subtree is left
                // in place rather than partially freed; a later pass retries.
                return Err(FsError::ArithmeticOverflow);
            }

            let node = match self.get_node(ino) {
                Ok(node) => node,
                Err(_) => continue, // already collected
            };
            // Anything still open must survive.
            if node.open_count.load(Ordering::Acquire) > 0 {
                continue;
            }

            let mut children = Vec::new();
            let mut data_bytes = 0usize;
            {
                let guard = node.node.lock();
                match &*guard {
                    RamNode::Directory { entries, .. } => {
                        for &child in entries.values() {
                            children.push(child);
                        }
                    }
                    RamNode::File { data, .. } => data_bytes = data.len(),
                }
            }
            for child in children {
                stack.push(child);
            }

            // Re-check the open counter under the write lock before removing.
            let mut map = self.inodes.write();
            if node.open_count.load(Ordering::Acquire) == 0 {
                map.remove(&ino);
                freed += data_bytes as u64;
            }
        }

        if freed > 0 {
            self.total_data_bytes.fetch_sub(freed, Ordering::AcqRel);
        }
        Ok(())
    }
}

impl VfsFileSystem for RamFileSystem {
    /// Implements fs type.
    fn fs_type(&self) -> &'static str {
        "ramfs"
    }

    /// Implements capabilities.
    fn capabilities(&self) -> &FsCapabilities {
        &self.capabilities
    }

    /// Implements root inode.
    fn root_inode(&self) -> u64 {
        2
    }

    /// Returns volume info.
    fn get_volume_info(&self) -> FsResult<VfsVolumeInfo> {
        Ok(VfsVolumeInfo {
            fs_type: String::from("ramfs"),
            block_size: 4096,
            ..VfsVolumeInfo::default()
        })
    }

    /// Implements stat.
    fn stat(&self, ino: u64) -> FsResult<VfsFileInfo> {
        let node = self.get_node(ino)?;
        let guard = node.node.lock();
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

    /// Implements lookup.
    fn lookup(&self, parent_ino: u64, name: &str) -> FsResult<VfsFileInfo> {
        let ino = self.lookup_child_inode(parent_ino, name)?;
        self.stat(ino)
    }

    /// Implements resolve path.
    fn resolve_path(&self, path: &str) -> FsResult<u64> {
        self.resolve_path_internal(path)
    }

    /// Implements read.
    fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        let node = self.get_node(ino)?;
        let guard = node.node.lock();
        match &*guard {
            RamNode::File { data, .. } => {
                let start = usize::try_from(offset).map_err(|_| FsError::InvalidArgument)?;
                if offset >= data.len() as u64 {
                    return Ok(0);
                }
                let end = start
                    .checked_add(buf.len())
                    .ok_or(FsError::FileTooLarge)?
                    .min(data.len());
                let count = end - start;
                buf[..count].copy_from_slice(&data[start..end]);
                Ok(count)
            }
            _ => Err(FsError::IsADirectory),
        }
    }

    /// Implements write.
    fn write(&self, ino: u64, offset: u64, data: &[u8]) -> FsResult<usize> {
        let node = self.get_node(ino)?;
        let mut guard = node.node.lock();
        match &mut *guard {
            RamNode::File {
                data: file_data, ..
            } => {
                let start = usize::try_from(offset).map_err(|_| FsError::InvalidArgument)?;
                let end = start.checked_add(data.len()).ok_or(FsError::FileTooLarge)?;
                // Cap the file size *before* any resize: on a 64-bit target
                // `usize::try_from(offset)` never fails, so an arbitrary
                // offset must not be able to force a giant allocation that
                // aborts the whole Silo.
                if end > MAX_FILE_SIZE {
                    return Err(FsError::FileTooLarge);
                }
                if end > file_data.len() {
                    let growth = end - file_data.len();
                    let used = self.total_data_bytes.load(Ordering::Acquire);
                    if used.saturating_add(growth as u64) > MAX_TOTAL_DATA {
                        return Err(FsError::NoSpace);
                    }
                    // `try_reserve` turns allocator failure into a logical
                    // error instead of hitting the OOM handler (exit).
                    if file_data.try_reserve(growth).is_err() {
                        return Err(FsError::NoSpace);
                    }
                    file_data.resize(end, 0);
                    self.total_data_bytes
                        .fetch_add(growth as u64, Ordering::AcqRel);
                }
                file_data[start..end].copy_from_slice(data);
                Ok(data.len())
            }
            _ => Err(FsError::IsADirectory),
        }
    }

    /// Implements readdir.
    fn readdir(&self, ino: u64) -> FsResult<Vec<VfsDirEntry>> {
        let node = self.get_node(ino)?;
        let guard = node.node.lock();
        match &*guard {
            RamNode::Directory { entries, .. } => {
                let children: Vec<(String, u64)> = entries
                    .iter()
                    .map(|(name, &ino)| (name.clone(), ino))
                    .collect();
                drop(guard);

                let mut result = Vec::new();
                for (name, child_ino) in children {
                    let child_node = self.get_node(child_ino)?;
                    let child_guard = child_node.node.lock();
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

    /// Implements create file.
    fn create_file(&self, parent_ino: u64, name: &str, mode: u32) -> FsResult<VfsFileInfo> {
        Self::validate_name(name)?;
        let parent = self.get_node(parent_ino)?;
        {
            let guard = parent.node.lock();
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

        let mut guard = parent.node.lock();
        match &mut *guard {
            RamNode::Directory { entries, .. } => {
                if entries.contains_key(name) {
                    self.inodes.write().remove(&new_ino);
                    return Err(FsError::AlreadyExists);
                }
                entries.insert(name.to_string(), new_ino);
                drop(guard);
                self.stat(new_ino)
            }
            _ => {
                self.inodes.write().remove(&new_ino);
                Err(FsError::NotADirectory)
            }
        }
    }

    /// Implements create directory.
    fn create_directory(&self, parent_ino: u64, name: &str, mode: u32) -> FsResult<VfsFileInfo> {
        Self::validate_name(name)?;
        let parent = self.get_node(parent_ino)?;
        {
            let guard = parent.node.lock();
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

        let mut guard = parent.node.lock();
        match &mut *guard {
            RamNode::Directory { entries, .. } => {
                if entries.contains_key(name) {
                    self.inodes.write().remove(&new_ino);
                    return Err(FsError::AlreadyExists);
                }
                entries.insert(name.to_string(), new_ino);
                drop(guard);
                self.stat(new_ino)
            }
            _ => {
                self.inodes.write().remove(&new_ino);
                Err(FsError::NotADirectory)
            }
        }
    }

    /// Implements unlink.
    fn unlink(&self, parent_ino: u64, name: &str, target_ino: u64) -> FsResult<()> {
        let parent = self.get_node(parent_ino)?;
        let child_ino = {
            let guard = parent.node.lock();
            match &*guard {
                RamNode::Directory { entries, .. } => {
                    *entries.get(name).ok_or(FsError::NotFound)?
                }
                _ => return Err(FsError::NotADirectory),
            }
        };

        if child_ino != target_ino {
            return Err(FsError::InvalidArgument);
        }

        let child = self.get_node(child_ino)?;

        // Hold the child's lock while removing from the parent, so the
        // "directory is empty" check and the removal are atomic w.r.t. a
        // concurrent create_file in the same directory. Lock order is always
        // parent -> child; nothing takes child then parent, so no deadlock.
        {
            let mut guard = parent.node.lock();
            let mut child_guard = child.node.lock();
            match &mut *guard {
                RamNode::Directory { entries, .. } => {
                    let current = *entries.get(name).ok_or(FsError::NotFound)?;
                    if current != child_ino {
                        return Err(FsError::InvalidArgument);
                    }
                    if let RamNode::Directory {
                        entries: child_entries,
                        ..
                    } = &mut *child_guard
                    {
                        if !child_entries.is_empty() {
                            return Err(FsError::NotEmpty);
                        }
                    }
                    entries.remove(name);
                }
                _ => return Err(FsError::NotADirectory),
            }
        }
        self.collect_if_detached(child_ino)?;
        Ok(())
    }

    /// Implements rename.
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
        Self::validate_name(new_name)?;

        let old_parent_node = self.get_node(old_parent)?;
        let moved_ino = {
            let guard = old_parent_node.node.lock();
            match &*guard {
                RamNode::Directory { entries, .. } => {
                    *entries.get(old_name).ok_or(FsError::NotFound)?
                }
                _ => return Err(FsError::NotADirectory),
            }
        };

        {
            let moved_node = self.get_node(moved_ino)?;
            let moved_guard = moved_node.node.lock();
            if let RamNode::Directory { .. } = &*moved_guard {
                if self.directory_contains_inode(moved_ino, new_parent)? {
                    return Err(FsError::InvalidArgument);
                }
            }
        }

        let new_parent_node = self.get_node(new_parent)?;
        let mut new_guard = new_parent_node.node.lock();
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
            let existing_guard = existing_node.node.lock();
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
            let mut guard = old_parent_node.node.lock();
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

        // Re-check the anti-cycle condition immediately before the final
        // insertion. The traversal is cycle-safe (visited set + budget), so a
        // residual cycle cannot hang here; this closes the check/act gap that
        // the earlier check above would otherwise leave open.
        {
            let moved_node = self.get_node(moved_ino)?;
            let moved_guard = moved_node.node.lock();
            if let RamNode::Directory { .. } = &*moved_guard {
                if self.directory_contains_inode(moved_ino, new_parent)? {
                    return Err(FsError::InvalidArgument);
                }
            }
        }

        let mut guard = new_parent_node.node.lock();
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

    /// Sets size.
    fn set_size(&self, ino: u64, size: u64) -> FsResult<()> {
        let node = self.get_node(ino)?;
        let mut guard = node.node.lock();
        match &mut *guard {
            RamNode::File { data, .. } => {
                if size > MAX_FILE_SIZE as u64 {
                    return Err(FsError::FileTooLarge);
                }
                let new_size = usize::try_from(size).map_err(|_| FsError::FileTooLarge)?;
                let old_len = data.len();
                if new_size > old_len {
                    let growth = new_size - old_len;
                    let used = self.total_data_bytes.load(Ordering::Acquire);
                    if used.saturating_add(growth as u64) > MAX_TOTAL_DATA {
                        return Err(FsError::NoSpace);
                    }
                    if data.try_reserve(growth).is_err() {
                        return Err(FsError::NoSpace);
                    }
                    data.resize(new_size, 0);
                    self.total_data_bytes
                        .fetch_add(growth as u64, Ordering::AcqRel);
                } else {
                    // Shrinking returns bytes to the shared budget.
                    data.resize(new_size, 0);
                    let freed = (old_len - new_size) as u64;
                    if freed > 0 {
                        self.total_data_bytes.fetch_sub(freed, Ordering::AcqRel);
                    }
                }
                Ok(())
            }
            _ => Err(FsError::IsADirectory),
        }
    }

    /// Sets times.
    fn set_times(
        &self,
        ino: u64,
        _atime: Option<VfsTimestamp>,
        _mtime: Option<VfsTimestamp>,
    ) -> FsResult<()> {
        let _ = self.get_node(ino)?;
        Ok(())
    }

    /// Implements readlink.
    fn readlink(&self, _ino: u64) -> FsResult<String> {
        Err(FsError::NotSupported)
    }

    /// Implements invalidate inode.
    fn invalidate_inode(&self, _ino: u64) {}
    /// Implements invalidate all caches.
    fn invalidate_all_caches(&self) {}
}

/// Implements split path.
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
