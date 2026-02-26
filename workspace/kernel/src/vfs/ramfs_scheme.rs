//! In-kernel RAM filesystem — mounts on `/` to provide a writable root.
//!
//! ## Design
//!
//! A single `SpinLock<RamState>` protects all state.  The lock is held only
//! for the duration of each scheme call (no blocking I/O inside), so lock
//! contention is negligible.
//!
//! Inodes are stored in a flat `BTreeMap<u64, RamInode>` keyed by inode number.
//! Directories hold a `BTreeMap<String, u64>` of `(name → ino)` children.
//! Files hold their content in a heap-allocated `Vec<u8>`.
//!
//! Inode 1 is always the root directory (`/`).
//!
//! ## Path convention
//!
//! `path` arguments arrive **relative to the mount point** (i.e. the leading
//! `/` has already been stripped by the mount table resolver).  An empty
//! string therefore means the root directory.

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::{
    sync::SpinLock,
    syscall::error::SyscallError,
    vfs::scheme::{
        DT_DIR, DT_REG, DirEntry, FileFlags, FileStat, OpenFlags, OpenResult, Scheme,
    },
};

// ─── Inode numbering ─────────────────────────────────────────────────────────

const INO_ROOT: u64 = 1;
const INO_FIRST: u64 = 2;

// ─── Inode types ─────────────────────────────────────────────────────────────

enum RamKind {
    /// Regular file with byte-addressable content.
    File { data: Vec<u8> },
    /// Directory with an ordered map of child names to inode numbers.
    Dir { children: BTreeMap<String, u64> },
}

struct RamInode {
    ino: u64,
    kind: RamKind,
    /// Unix permission bits including file-type high bits (e.g. `0o100_644`).
    mode: u32,
}

impl RamInode {
    fn is_dir(&self) -> bool {
        matches!(self.kind, RamKind::Dir { .. })
    }

    fn byte_size(&self) -> u64 {
        match &self.kind {
            RamKind::File { data } => data.len() as u64,
            RamKind::Dir { .. } => 0,
        }
    }
}

// ─── Filesystem state ────────────────────────────────────────────────────────

struct RamState {
    inodes: BTreeMap<u64, RamInode>,
}

impl RamState {
    fn new() -> Self {
        let mut inodes = BTreeMap::new();
        inodes.insert(
            INO_ROOT,
            RamInode {
                ino: INO_ROOT,
                kind: RamKind::Dir {
                    children: BTreeMap::new(),
                },
                mode: 0o040_755, // drwxr-xr-x
            },
        );
        RamState { inodes }
    }

    /// Resolve a relative path to its inode number.
    ///
    /// An empty (or all-slash) `path` resolves to the root directory.
    fn lookup(&self, path: &str) -> Option<u64> {
        let path = path.trim_matches('/');
        if path.is_empty() {
            return Some(INO_ROOT);
        }
        let mut cur = INO_ROOT;
        for part in path.split('/') {
            if part.is_empty() {
                continue;
            }
            let inode = self.inodes.get(&cur)?;
            match &inode.kind {
                RamKind::Dir { children } => {
                    cur = *children.get(part)?;
                }
                _ => return None,
            }
        }
        Some(cur)
    }

    /// Return `(parent_ino, final_component)` for a path.
    ///
    /// Returns `None` if the parent directory does not exist.
    fn lookup_parent<'a>(&self, path: &'a str) -> Option<(u64, &'a str)> {
        let path = path.trim_matches('/');
        let (parent_path, name) = match path.rfind('/') {
            Some(pos) => (&path[..pos], &path[pos + 1..]),
            None => ("", path),
        };
        let parent_ino = self.lookup(parent_path)?;
        Some((parent_ino, name))
    }
}

// ─── RamfsScheme ─────────────────────────────────────────────────────────────

/// Kernel-resident RAM filesystem implementing the `Scheme` trait.
pub struct RamfsScheme {
    state: SpinLock<RamState>,
    next_ino: AtomicU64,
}

impl RamfsScheme {
    pub fn new() -> Self {
        RamfsScheme {
            state: SpinLock::new(RamState::new()),
            next_ino: AtomicU64::new(INO_FIRST),
        }
    }

    fn alloc_ino(&self) -> u64 {
        self.next_ino.fetch_add(1, Ordering::Relaxed)
    }

    /// Ensure that `path` (relative to mount root) exists as a directory.
    ///
    /// Silently succeeds if the directory already exists.
    pub fn ensure_dir(&self, path: &str) {
        let _ = self.create_directory(path.trim_matches('/'), 0o755);
    }

    /// Insert a read-only file into the root.
    ///
    /// Convenience helper used during `vfs::init()` to pre-populate files.
    pub fn insert_file(&self, name: &str, content: &[u8]) {
        let ino = self.alloc_ino();
        let mut st = self.state.lock();
        st.inodes.insert(
            ino,
            RamInode {
                ino,
                kind: RamKind::File {
                    data: content.to_vec(),
                },
                mode: 0o100_444, // -r--r--r--
            },
        );
        if let Some(root) = st.inodes.get_mut(&INO_ROOT) {
            if let RamKind::Dir { ref mut children } = root.kind {
                children.insert(String::from(name), ino);
            }
        }
    }
}

impl Scheme for RamfsScheme {
    // ── open ─────────────────────────────────────────────────────────────────

    fn open(&self, path: &str, flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        let path = path.trim_matches('/');

        if flags.contains(OpenFlags::CREATE) {
            let mut st = self.state.lock();

            if let Some(ino) = st.lookup(path) {
                // Entry already exists — succeed (POSIX O_CREAT without O_EXCL).
                let inode = st.inodes.get_mut(&ino).unwrap();
                if inode.is_dir() {
                    return Ok(OpenResult {
                        file_id: ino,
                        size: Some(0),
                        flags: FileFlags::DIRECTORY,
                    });
                }
                if flags.contains(OpenFlags::TRUNCATE) {
                    if let RamKind::File { ref mut data } = inode.kind {
                        data.clear();
                    }
                }
                let size = inode.byte_size();
                return Ok(OpenResult {
                    file_id: ino,
                    size: Some(size),
                    flags: FileFlags::empty(),
                });
            }

            // Create the new file.
            let (parent_ino, name) =
                st.lookup_parent(path).ok_or(SyscallError::NotFound)?;
            if name.is_empty() {
                return Err(SyscallError::InvalidArgument);
            }
            let new_ino = self.next_ino.fetch_add(1, Ordering::Relaxed);
            st.inodes.insert(
                new_ino,
                RamInode {
                    ino: new_ino,
                    kind: RamKind::File { data: Vec::new() },
                    mode: 0o100_644,
                },
            );
            if let Some(parent) = st.inodes.get_mut(&parent_ino) {
                if let RamKind::Dir { ref mut children } = parent.kind {
                    children.insert(String::from(name), new_ino);
                }
            }
            return Ok(OpenResult {
                file_id: new_ino,
                size: Some(0),
                flags: FileFlags::empty(),
            });
        }

        // Normal open (no O_CREAT).
        let st = self.state.lock();
        let ino = st.lookup(path).ok_or(SyscallError::NotFound)?;
        let inode = st.inodes.get(&ino).unwrap();

        if inode.is_dir() {
            Ok(OpenResult {
                file_id: ino,
                size: Some(0),
                flags: FileFlags::DIRECTORY,
            })
        } else {
            Ok(OpenResult {
                file_id: ino,
                size: Some(inode.byte_size()),
                flags: FileFlags::empty(),
            })
        }
    }

    // ── read ─────────────────────────────────────────────────────────────────

    fn read(&self, file_id: u64, offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        let st = self.state.lock();
        let inode = st.inodes.get(&file_id).ok_or(SyscallError::BadHandle)?;
        match &inode.kind {
            RamKind::File { data } => {
                let start = offset as usize;
                if start >= data.len() {
                    return Ok(0);
                }
                let n = (data.len() - start).min(buf.len());
                buf[..n].copy_from_slice(&data[start..start + n]);
                Ok(n)
            }
            RamKind::Dir { .. } => Err(SyscallError::InvalidArgument),
        }
    }

    // ── write ────────────────────────────────────────────────────────────────

    fn write(&self, file_id: u64, offset: u64, buf: &[u8]) -> Result<usize, SyscallError> {
        let mut st = self.state.lock();
        let inode = st.inodes.get_mut(&file_id).ok_or(SyscallError::BadHandle)?;
        match &mut inode.kind {
            RamKind::File { ref mut data } => {
                let start = offset as usize;
                let end = start + buf.len();
                if end > data.len() {
                    data.resize(end, 0);
                }
                data[start..end].copy_from_slice(buf);
                Ok(buf.len())
            }
            RamKind::Dir { .. } => Err(SyscallError::InvalidArgument),
        }
    }

    // ── close ────────────────────────────────────────────────────────────────

    fn close(&self, _file_id: u64) -> Result<(), SyscallError> {
        Ok(()) // stateless — nothing to clean up
    }

    // ── size ─────────────────────────────────────────────────────────────────

    fn size(&self, file_id: u64) -> Result<u64, SyscallError> {
        let st = self.state.lock();
        let inode = st.inodes.get(&file_id).ok_or(SyscallError::BadHandle)?;
        Ok(inode.byte_size())
    }

    // ── truncate ─────────────────────────────────────────────────────────────

    fn truncate(&self, file_id: u64, new_size: u64) -> Result<(), SyscallError> {
        let mut st = self.state.lock();
        let inode = st.inodes.get_mut(&file_id).ok_or(SyscallError::BadHandle)?;
        match &mut inode.kind {
            RamKind::File { ref mut data } => {
                data.resize(new_size as usize, 0);
                Ok(())
            }
            RamKind::Dir { .. } => Err(SyscallError::InvalidArgument),
        }
    }

    // ── create_file ──────────────────────────────────────────────────────────

    fn create_file(&self, path: &str, mode: u32) -> Result<OpenResult, SyscallError> {
        let path = path.trim_matches('/');
        let mut st = self.state.lock();

        if st.lookup(path).is_some() {
            return Err(SyscallError::AlreadyExists);
        }

        let (parent_ino, name) = st.lookup_parent(path).ok_or(SyscallError::NotFound)?;
        if name.is_empty() {
            return Err(SyscallError::InvalidArgument);
        }

        let new_ino = self.next_ino.fetch_add(1, Ordering::Relaxed);
        // Ensure the mode has the regular-file type bits set.
        let file_mode = (mode & 0o7777) | 0o100_000;
        st.inodes.insert(
            new_ino,
            RamInode {
                ino: new_ino,
                kind: RamKind::File { data: Vec::new() },
                mode: file_mode,
            },
        );
        if let Some(parent) = st.inodes.get_mut(&parent_ino) {
            if let RamKind::Dir { ref mut children } = parent.kind {
                children.insert(String::from(name), new_ino);
            }
        }

        Ok(OpenResult {
            file_id: new_ino,
            size: Some(0),
            flags: FileFlags::empty(),
        })
    }

    // ── create_directory ─────────────────────────────────────────────────────

    fn create_directory(&self, path: &str, mode: u32) -> Result<OpenResult, SyscallError> {
        let path = path.trim_matches('/');
        let mut st = self.state.lock();

        // Idempotent: return Ok if it already exists as a directory.
        if let Some(ino) = st.lookup(path) {
            let inode = st.inodes.get(&ino).unwrap();
            if inode.is_dir() {
                return Ok(OpenResult {
                    file_id: ino,
                    size: Some(0),
                    flags: FileFlags::DIRECTORY,
                });
            }
            return Err(SyscallError::AlreadyExists);
        }

        let (parent_ino, name) = st.lookup_parent(path).ok_or(SyscallError::NotFound)?;
        if name.is_empty() {
            return Err(SyscallError::InvalidArgument);
        }

        let new_ino = self.next_ino.fetch_add(1, Ordering::Relaxed);
        let dir_mode = (mode & 0o7777) | 0o040_000;
        st.inodes.insert(
            new_ino,
            RamInode {
                ino: new_ino,
                kind: RamKind::Dir {
                    children: BTreeMap::new(),
                },
                mode: dir_mode,
            },
        );
        if let Some(parent) = st.inodes.get_mut(&parent_ino) {
            if let RamKind::Dir { ref mut children } = parent.kind {
                children.insert(String::from(name), new_ino);
            }
        }

        Ok(OpenResult {
            file_id: new_ino,
            size: Some(0),
            flags: FileFlags::DIRECTORY,
        })
    }

    // ── unlink ───────────────────────────────────────────────────────────────

    fn unlink(&self, path: &str) -> Result<(), SyscallError> {
        let path = path.trim_matches('/');
        if path.is_empty() {
            return Err(SyscallError::PermissionDenied); // cannot remove root
        }

        let mut st = self.state.lock();
        let ino = st.lookup(path).ok_or(SyscallError::NotFound)?;

        // Refuse to remove a non-empty directory.
        if let Some(inode) = st.inodes.get(&ino) {
            if let RamKind::Dir { children } = &inode.kind {
                if !children.is_empty() {
                    return Err(SyscallError::NotSupported);
                }
            }
        }

        let (parent_ino, name) = st.lookup_parent(path).ok_or(SyscallError::NotFound)?;
        if let Some(parent) = st.inodes.get_mut(&parent_ino) {
            if let RamKind::Dir { ref mut children } = parent.kind {
                children.remove(name);
            }
        }
        st.inodes.remove(&ino);

        Ok(())
    }

    // ── stat ─────────────────────────────────────────────────────────────────

    fn stat(&self, file_id: u64) -> Result<FileStat, SyscallError> {
        let st = self.state.lock();
        let inode = st.inodes.get(&file_id).ok_or(SyscallError::BadHandle)?;

        let (st_mode, st_size, st_nlink) = match &inode.kind {
            RamKind::Dir { children } => (inode.mode, 0u64, 2 + children.len() as u32),
            RamKind::File { data } => (inode.mode, data.len() as u64, 1u32),
        };

        Ok(FileStat {
            st_ino: file_id,
            st_mode,
            st_nlink,
            st_size,
            st_blksize: 4096,
            st_blocks: (st_size + 511) / 512,
        })
    }

    // ── readdir ──────────────────────────────────────────────────────────────

    fn readdir(&self, file_id: u64) -> Result<Vec<DirEntry>, SyscallError> {
        let st = self.state.lock();
        let inode = st.inodes.get(&file_id).ok_or(SyscallError::BadHandle)?;

        match &inode.kind {
            RamKind::Dir { children } => {
                let mut entries = Vec::with_capacity(children.len());
                for (name, &child_ino) in children.iter() {
                    let file_type = match st.inodes.get(&child_ino).map(|c| &c.kind) {
                        Some(RamKind::Dir { .. }) => DT_DIR,
                        _ => DT_REG,
                    };
                    entries.push(DirEntry {
                        ino: child_ino,
                        file_type,
                        name: name.clone(),
                    });
                }
                Ok(entries)
            }
            RamKind::File { .. } => Err(SyscallError::InvalidArgument),
        }
    }
}
