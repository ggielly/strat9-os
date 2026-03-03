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
    next_fd_hint: usize,
}

impl FileDescriptorTable {
    /// Performs the advance next fd hint operation.
    fn advance_next_fd_hint(&mut self) {
        while self.next_fd_hint < self.fds.len() && self.fds[self.next_fd_hint].is_some() {
            self.next_fd_hint = self.next_fd_hint.saturating_add(1);
        }
    }

    /// Create a new empty FD table.
    pub fn new() -> Self {
        let mut fds = Vec::with_capacity(64);
        fds.resize(3, None); // Reserve 0, 1, 2
        FileDescriptorTable {
            fds,
            next_fd_hint: 3,
        }
    }

    /// Find the lowest available file descriptor number.
    fn find_free_fd(&mut self) -> u32 {
        for i in self.next_fd_hint..self.fds.len() {
            if self.fds[i].is_none() {
                self.next_fd_hint = i.saturating_add(1);
                self.advance_next_fd_hint();
                return i as u32;
            }
        }
        for i in 0..self.next_fd_hint.min(self.fds.len()) {
            if self.fds[i].is_none() {
                self.next_fd_hint = i.saturating_add(1);
                self.advance_next_fd_hint();
                return i as u32;
            }
        }
        self.next_fd_hint = self.fds.len().saturating_add(1);
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
        if fd_usize == self.next_fd_hint {
            self.next_fd_hint = self.next_fd_hint.saturating_add(1);
            self.advance_next_fd_hint();
        }
    }

    /// Insert a file with explicit CLOEXEC flag.
    pub fn insert_with_flags(&mut self, file: Arc<OpenFile>, cloexec: bool) -> u32 {
        let fd = self.find_free_fd();
        let fd_usize = fd as usize;
        if fd_usize >= self.fds.len() {
            self.fds.resize(fd_usize + 1, None);
        }
        self.fds[fd_usize] = Some(FileDescriptor::new_cloexec(file, cloexec));
        if fd_usize == self.next_fd_hint {
            self.next_fd_hint = self.next_fd_hint.saturating_add(1);
            self.advance_next_fd_hint();
        }
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
                if fd_usize < self.next_fd_hint {
                    self.next_fd_hint = fd_usize;
                }
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

    /// Duplicate an FD with a minimum target FD number (F_DUPFD semantics).
    pub fn duplicate_from(&mut self, old_fd: u32, min_fd: u32) -> Result<u32, SyscallError> {
        let file = self.get(old_fd)?;
        let min = min_fd as usize;
        if min >= self.fds.len() {
            self.fds.resize(min + 1, None);
        }
        let start = core::cmp::max(min, self.next_fd_hint);
        for i in start..self.fds.len() {
            if self.fds[i].is_none() {
                self.fds[i] = Some(FileDescriptor::new(file));
                if i == self.next_fd_hint {
                    self.next_fd_hint = self.next_fd_hint.saturating_add(1);
                    self.advance_next_fd_hint();
                }
                return Ok(i as u32);
            }
        }
        for i in min..start.min(self.fds.len()) {
            if self.fds[i].is_none() {
                self.fds[i] = Some(FileDescriptor::new(file));
                if i == self.next_fd_hint {
                    self.next_fd_hint = self.next_fd_hint.saturating_add(1);
                    self.advance_next_fd_hint();
                }
                return Ok(i as u32);
            }
        }
        let fd = self.fds.len() as u32;
        self.fds.push(Some(FileDescriptor::new(file)));
        if (fd as usize) == self.next_fd_hint {
            self.next_fd_hint = self.next_fd_hint.saturating_add(1);
            self.advance_next_fd_hint();
        }
        Ok(fd)
    }

    /// Duplicate `old_fd` onto `new_fd` (dup2 semantics).
    pub fn duplicate_to(&mut self, old_fd: u32, new_fd: u32) -> Result<u32, SyscallError> {
        let file = self.get(old_fd)?;
        if old_fd == new_fd {
            return Ok(new_fd);
        }
        let new_idx = new_fd as usize;
        if new_idx >= self.fds.len() {
            self.fds.resize(new_idx + 1, None);
        }
        self.fds[new_idx] = Some(FileDescriptor::new(file));
        if new_idx == self.next_fd_hint {
            self.next_fd_hint = self.next_fd_hint.saturating_add(1);
            self.advance_next_fd_hint();
        }
        Ok(new_fd)
    }

    /// Close all file descriptors (process exit).
    pub fn close_all(&mut self) {
        self.fds.clear();
        self.next_fd_hint = 0;
    }

    /// Close all file descriptors with CLOEXEC flag (execve cleanup).
    pub fn close_cloexec(&mut self) {
        for (i, fd) in self.fds.iter_mut().enumerate() {
            if let Some(desc) = fd {
                if desc.cloexec {
                    *fd = None;
                    if i < self.next_fd_hint {
                        self.next_fd_hint = i;
                    }
                }
            }
        }
    }

    /// Clone this FD table (fork semantics).
    ///
    /// All descriptors are copied, including those with CLOEXEC.
    /// CLOEXEC only takes effect at exec-time via `close_cloexec()`.
    pub fn clone_for_fork(&self) -> Self {
        FileDescriptorTable {
            fds: self.fds.clone(),
            next_fd_hint: self.next_fd_hint,
        }
    }
}

impl Default for FileDescriptorTable {
    /// Builds a default instance.
    fn default() -> Self {
        Self::new()
    }
}
