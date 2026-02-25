//! File Descriptor Table (per-process).
//!
//! Each process has its own FD table mapping integers (0, 1, 2...) to open files.

use super::file::OpenFile;
use crate::syscall::error::SyscallError;
use alloc::{sync::Arc, vec::Vec};

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
    fds: Vec<Option<FileDescriptor>>,
}

impl FileDescriptorTable {
    /// Create a new empty FD table.
    pub fn new() -> Self {
        let mut fds = Vec::with_capacity(64);
        fds.resize(3, None); // Reserve 0, 1, 2
        FileDescriptorTable { fds }
    }

    /// Find the lowest available file descriptor number.
    fn find_free_fd(&self) -> u32 {
        for (i, fd) in self.fds.iter().enumerate() {
            if fd.is_none() {
                return i as u32;
            }
        }
        self.fds.len() as u32
    }

    /// Insert an open file and return its FD number.
    pub fn insert(&mut self, file: Arc<OpenFile>) -> u32 {
        self.insert_with_flags(file, false)
    }

    /// Insert a file at a specific FD (for stdin/stdout/stderr).
    pub fn insert_at(&mut self, fd: u32, file: Arc<OpenFile>) {
        let fd_usize = fd as usize;
        if fd_usize >= self.fds.len() {
            self.fds.resize(fd_usize + 1, None);
        }
        self.fds[fd_usize] = Some(FileDescriptor::new(file));
    }

    /// Insert a file with explicit CLOEXEC flag.
    pub fn insert_with_flags(&mut self, file: Arc<OpenFile>, cloexec: bool) -> u32 {
        let fd = self.find_free_fd();
        let fd_usize = fd as usize;
        if fd_usize >= self.fds.len() {
            self.fds.resize(fd_usize + 1, None);
        }
        self.fds[fd_usize] = Some(FileDescriptor::new_cloexec(file, cloexec));
        fd
    }

    /// Get an open file by FD.
    pub fn get(&self, fd: u32) -> Result<Arc<OpenFile>, SyscallError> {
        let fd_usize = fd as usize;
        if fd_usize < self.fds.len() {
            if let Some(desc) = &self.fds[fd_usize] {
                return Ok(desc.file.clone());
            }
        }
        Err(SyscallError::BadHandle)
    }

    /// Get the CLOEXEC flag for a file descriptor.
    pub fn get_cloexec(&self, fd: u32) -> Result<bool, SyscallError> {
        let fd_usize = fd as usize;
        if fd_usize < self.fds.len() {
            if let Some(desc) = &self.fds[fd_usize] {
                return Ok(desc.cloexec);
            }
        }
        Err(SyscallError::BadHandle)
    }

    /// Set the CLOEXEC flag for a file descriptor.
    pub fn set_cloexec(&mut self, fd: u32, cloexec: bool) -> Result<(), SyscallError> {
        let fd_usize = fd as usize;
        if fd_usize < self.fds.len() {
            if let Some(desc) = &mut self.fds[fd_usize] {
                desc.cloexec = cloexec;
                return Ok(());
            }
        }
        Err(SyscallError::BadHandle)
    }

    /// Remove an FD and return the file.
    pub fn remove(&mut self, fd: u32) -> Result<Arc<OpenFile>, SyscallError> {
        let fd_usize = fd as usize;
        if fd_usize < self.fds.len() {
            if let Some(desc) = self.fds[fd_usize].take() {
                return Ok(desc.file);
            }
        }
        Err(SyscallError::BadHandle)
    }

    /// Check if an FD exists.
    pub fn contains(&self, fd: u32) -> bool {
        let fd_usize = fd as usize;
        fd_usize < self.fds.len() && self.fds[fd_usize].is_some()
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

    /// Close all file descriptors with CLOEXEC flag (execve cleanup).
    pub fn close_cloexec(&mut self) {
        for fd in &mut self.fds {
            if let Some(desc) = fd {
                if desc.cloexec {
                    *fd = None;
                }
            }
        }
    }

    /// Clone this FD table (fork semantics), excluding CLOEXEC descriptors.
    pub fn clone_for_fork(&self) -> Self {
        let mut new_table = FileDescriptorTable {
            fds: Vec::with_capacity(self.fds.len()),
        };

        for fd in &self.fds {
            if let Some(desc) = fd {
                if !desc.cloexec {
                    new_table.fds.push(Some(desc.clone()));
                } else {
                    new_table.fds.push(None);
                }
            } else {
                new_table.fds.push(None);
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
