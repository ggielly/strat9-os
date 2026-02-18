//! File Descriptor Table (per-process).
//!
//! Each process has its own FD table mapping integers (0, 1, 2...) to open files.

use super::file::OpenFile;
use crate::syscall::error::SyscallError;
use alloc::{collections::BTreeMap, sync::Arc};

/// Standard file descriptor numbers.
pub const STDIN: u32 = 0;
pub const STDOUT: u32 = 1;
pub const STDERR: u32 = 2;

/// Per-process file descriptor table.
pub struct FileDescriptorTable {
    fds: BTreeMap<u32, Arc<OpenFile>>,
    next_fd: u32,
}

impl FileDescriptorTable {
    /// Create a new empty FD table.
    pub fn new() -> Self {
        FileDescriptorTable {
            fds: BTreeMap::new(),
            next_fd: 3, // Start after stdin/stdout/stderr
        }
    }

    /// Insert an open file and return its FD number.
    pub fn insert(&mut self, file: Arc<OpenFile>) -> u32 {
        let fd = self.next_fd;
        self.fds.insert(fd, file);
        self.next_fd += 1;
        fd
    }

    /// Insert a file at a specific FD (for stdin/stdout/stderr).
    pub fn insert_at(&mut self, fd: u32, file: Arc<OpenFile>) {
        self.fds.insert(fd, file);
        if fd >= self.next_fd {
            self.next_fd = fd + 1;
        }
    }

    /// Get an open file by FD.
    pub fn get(&self, fd: u32) -> Result<Arc<OpenFile>, SyscallError> {
        self.fds.get(&fd).cloned().ok_or(SyscallError::BadHandle)
    }

    /// Remove an FD and return the file.
    pub fn remove(&mut self, fd: u32) -> Result<Arc<OpenFile>, SyscallError> {
        self.fds.remove(&fd).ok_or(SyscallError::BadHandle)
    }

    /// Check if an FD exists.
    pub fn contains(&self, fd: u32) -> bool {
        self.fds.contains_key(&fd)
    }

    /// Duplicate an FD (fork/dup semantics).
    pub fn duplicate(&mut self, old_fd: u32) -> Result<u32, SyscallError> {
        let file = self.get(old_fd)?;
        Ok(self.insert(file))
    }

    /// Close all file descriptors (process exit).
    pub fn close_all(&mut self) {
        self.fds.clear();
    }

    /// Clone this FD table (fork semantics).
    pub fn clone_for_fork(&self) -> Self {
        FileDescriptorTable {
            fds: self.fds.clone(),
            next_fd: self.next_fd,
        }
    }
}

impl Default for FileDescriptorTable {
    fn default() -> Self {
        Self::new()
    }
}
