//! File Descriptor Table (per-process).
//!
//! Each process has its own FD table mapping integers (0, 1, 2...) to open files.

use super::file::OpenFile;
use crate::syscall::error::SyscallError;
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

/// Standard file descriptor numbers.
pub const STDIN: u32 = 0;
pub const STDOUT: u32 = 1;
pub const STDERR: u32 = 2;

/// Wrapper for a file descriptor with FD-level flags (CLOEXEC).
#[derive(Clone)]
pub struct FileDescriptor {
    /// The open file handle.
    pub file: Arc<OpenFile>,
    /// Close-on-exec flag (FD_CLOEXEC).
    pub cloexec: bool,
}

impl FileDescriptor {
    /// Create a new file descriptor without CLOEXEC.
    pub fn new(file: Arc<OpenFile>) -> Self {
        FileDescriptor {
            file,
            cloexec: false,
        }
    }

    /// Create a new file descriptor with CLOEXEC flag.
    pub fn new_cloexec(file: Arc<OpenFile>, cloexec: bool) -> Self {
        FileDescriptor { file, cloexec }
    }
}

/// Per-process file descriptor table.
pub struct FileDescriptorTable {
    fds: BTreeMap<u32, FileDescriptor>,
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
        self.fds.insert(fd, FileDescriptor::new(file));
        self.next_fd += 1;
        fd
    }

    /// Insert a file at a specific FD (for stdin/stdout/stderr).
    pub fn insert_at(&mut self, fd: u32, file: Arc<OpenFile>) {
        self.fds.insert(fd, FileDescriptor::new(file));
        if fd >= self.next_fd {
            self.next_fd = fd + 1;
        }
    }

    /// Insert a file with explicit CLOEXEC flag.
    pub fn insert_with_flags(&mut self, file: Arc<OpenFile>, cloexec: bool) -> u32 {
        let fd = self.next_fd;
        self.fds.insert(fd, FileDescriptor::new_cloexec(file, cloexec));
        self.next_fd += 1;
        fd
    }

    /// Get an open file by FD.
    pub fn get(&self, fd: u32) -> Result<Arc<OpenFile>, SyscallError> {
        self.fds
            .get(&fd)
            .map(|desc| desc.file.clone())
            .ok_or(SyscallError::BadHandle)
    }

    /// Get the CLOEXEC flag for a file descriptor.
    pub fn get_cloexec(&self, fd: u32) -> Result<bool, SyscallError> {
        self.fds
            .get(&fd)
            .map(|desc| desc.cloexec)
            .ok_or(SyscallError::BadHandle)
    }

    /// Set the CLOEXEC flag for a file descriptor.
    pub fn set_cloexec(&mut self, fd: u32, cloexec: bool) -> Result<(), SyscallError> {
        self.fds
            .get_mut(&fd)
            .map(|desc| desc.cloexec = cloexec)
            .ok_or(SyscallError::BadHandle)
    }

    /// Remove an FD and return the file.
    pub fn remove(&mut self, fd: u32) -> Result<Arc<OpenFile>, SyscallError> {
        self.fds
            .remove(&fd)
            .map(|desc| desc.file)
            .ok_or(SyscallError::BadHandle)
    }

    /// Check if an FD exists.
    pub fn contains(&self, fd: u32) -> bool {
        self.fds.contains_key(&fd)
    }

    /// Duplicate an FD (fork/dup semantics).
    pub fn duplicate(&mut self, old_fd: u32) -> Result<u32, SyscallError> {
        let desc = self.fds.get(&old_fd).ok_or(SyscallError::BadHandle)?;
        let new_desc = FileDescriptor::new(desc.file.clone());
        let new_fd = self.next_fd;
        self.fds.insert(new_fd, new_desc);
        self.next_fd += 1;
        Ok(new_fd)
    }

    /// Close all file descriptors (process exit).
    pub fn close_all(&mut self) {
        self.fds.clear();
    }

    /// Close all file descriptors with CLOEXEC flag (execve cleanup).
    pub fn close_cloexec(&mut self) {
        let fds_to_close: Vec<u32> = self
            .fds
            .iter()
            .filter_map(|(fd, desc)| if desc.cloexec { Some(*fd) } else { None })
            .collect();

        for fd in fds_to_close {
            let _ = self.remove(fd);
        }
    }

    /// Clone this FD table (fork semantics), excluding CLOEXEC descriptors.
    pub fn clone_for_fork(&self) -> Self {
        let mut new_table = FileDescriptorTable {
            fds: BTreeMap::new(),
            next_fd: self.next_fd,
        };

        // Copy only non-CLOEXEC descriptors
        for (fd, desc) in &self.fds {
            if !desc.cloexec {
                new_table.fds.insert(*fd, desc.clone());
            }
        }

        new_table
    }
}

impl Default for FileDescriptorTable {
    fn default() -> Self {
        Self::new()
    }
}
