//! Kernel pipe implementation.
//!
//! A pipe is a unidirectional byte stream between two file descriptors.
//! The read end blocks when empty; the write end returns EPIPE when
//! the read end is closed.

use crate::{sync::SpinLock, syscall::error::SyscallError};
use alloc::sync::Arc;

const PIPE_BUF_SIZE: usize = 4096;

/// Shared state for one pipe instance.
struct PipeInner {
    buf: [u8; PIPE_BUF_SIZE],
    read_pos: usize,
    write_pos: usize,
    /// Number of bytes currently buffered.
    len: usize,
    read_closed: bool,
    write_closed: bool,
    /// Number of open file-descriptions referencing the read end.
    /// The end is marked closed only when this reaches zero.
    read_refs: usize,
    /// Number of open file-descriptions referencing the write end.
    write_refs: usize,
}

impl PipeInner {
    fn new() -> Self {
        PipeInner {
            buf: [0u8; PIPE_BUF_SIZE],
            read_pos: 0,
            write_pos: 0,
            len: 0,
            read_closed: false,
            write_closed: false,
            read_refs: 1,
            write_refs: 1,
        }
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn is_full(&self) -> bool {
        self.len >= PIPE_BUF_SIZE
    }

    fn available_read(&self) -> usize {
        self.len
    }

    fn available_write(&self) -> usize {
        PIPE_BUF_SIZE - self.len
    }
}

/// Shared pipe handle.
pub struct Pipe {
    inner: SpinLock<PipeInner>,
}

impl Pipe {
    pub fn new() -> Arc<Self> {
        Arc::new(Pipe {
            inner: SpinLock::new(PipeInner::new()),
        })
    }

    /// Read from the pipe. Returns 0 on EOF (write end closed + empty).
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, SyscallError> {
        loop {
            {
                let mut inner = self.inner.lock();

                if inner.available_read() > 0 {
                    let to_read = core::cmp::min(buf.len(), inner.available_read());
                    for i in 0..to_read {
                        buf[i] = inner.buf[inner.read_pos];
                        inner.read_pos = (inner.read_pos + 1) % PIPE_BUF_SIZE;
                    }
                    inner.len -= to_read;
                    return Ok(to_read);
                }

                if inner.write_closed {
                    return Ok(0); // EOF
                }
            }
            // Yield and retry (simple polling — could be improved with wait queues)
            crate::process::yield_task();
        }
    }

    /// Write to the pipe. Returns EPIPE if read end is closed.
    pub fn write(&self, buf: &[u8]) -> Result<usize, SyscallError> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut total = 0;
        while total < buf.len() {
            {
                let mut inner = self.inner.lock();

                if inner.read_closed {
                    if total > 0 {
                        return Ok(total);
                    }
                    return Err(SyscallError::Pipe);
                }

                if inner.available_write() > 0 {
                    let to_write = core::cmp::min(buf.len() - total, inner.available_write());
                    for i in 0..to_write {
                        let wp = inner.write_pos;
                        inner.buf[wp] = buf[total + i];
                        inner.write_pos = (wp + 1) % PIPE_BUF_SIZE;
                    }
                    inner.len += to_write;
                    total += to_write;
                    continue;
                }
            }
            // Buffer full — yield and retry
            crate::process::yield_task();
        }

        Ok(total)
    }

    /// Increment the read-end refcount (called on dup/fork).
    pub fn dup_read(&self) {
        self.inner.lock().read_refs += 1;
    }

    /// Increment the write-end refcount (called on dup/fork).
    pub fn dup_write(&self) {
        self.inner.lock().write_refs += 1;
    }

    /// Decrement the read-end refcount; marks the end closed only when it
    /// reaches zero.  Returns true if the end was actually closed.
    pub fn close_read(&self) -> bool {
        let mut inner = self.inner.lock();
        if inner.read_refs == 0 {
            return false;
        }
        inner.read_refs -= 1;
        if inner.read_refs == 0 {
            inner.read_closed = true;
            true
        } else {
            false
        }
    }

    /// Decrement the write-end refcount; marks the end closed only when it
    /// reaches zero.  Returns true if the end was actually closed.
    pub fn close_write(&self) -> bool {
        let mut inner = self.inner.lock();
        if inner.write_refs == 0 {
            return false;
        }
        inner.write_refs -= 1;
        if inner.write_refs == 0 {
            inner.write_closed = true;
            true
        } else {
            false
        }
    }
}

// ============================================================================
// Pipe as a VFS Scheme
// ============================================================================

use super::scheme::{DirEntry, FileFlags, FileStat, OpenFlags, OpenResult, Scheme};
use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

/// A scheme that manages kernel pipes.
///
/// Each pipe gets two file_ids: even = read end, odd = write end.
pub struct PipeScheme {
    pipes: SpinLock<BTreeMap<u64, Arc<Pipe>>>,
}

static NEXT_PIPE_ID: AtomicU64 = AtomicU64::new(2); // Start at 2 (even numbers)

impl PipeScheme {
    pub fn new() -> Self {
        PipeScheme {
            pipes: SpinLock::new(BTreeMap::new()),
        }
    }

    /// Create a new pipe pair. Returns (read_file_id, write_file_id).
    pub fn create_pipe(&self) -> (u64, Arc<Pipe>) {
        let base_id = NEXT_PIPE_ID.fetch_add(2, Ordering::SeqCst);
        let pipe = Pipe::new();
        self.pipes.lock().insert(base_id, pipe.clone());
        (base_id, pipe)
    }

    fn get_pipe(&self, file_id: u64) -> Result<Arc<Pipe>, SyscallError> {
        let base = file_id & !1; // Even = base
        self.pipes
            .lock()
            .get(&base)
            .cloned()
            .ok_or(SyscallError::BadHandle)
    }

    fn is_read_end(file_id: u64) -> bool {
        file_id & 1 == 0
    }
}

impl Scheme for PipeScheme {
    fn open(&self, _path: &str, _flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        Err(SyscallError::NotSupported) // Pipes are created via sys_pipe, not open()
    }

    fn read(&self, file_id: u64, _offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        if !Self::is_read_end(file_id) {
            return Err(SyscallError::PermissionDenied);
        }
        let pipe = self.get_pipe(file_id)?;
        pipe.read(buf)
    }

    fn write(&self, file_id: u64, _offset: u64, buf: &[u8]) -> Result<usize, SyscallError> {
        if Self::is_read_end(file_id) {
            return Err(SyscallError::PermissionDenied);
        }
        let pipe = self.get_pipe(file_id)?;
        pipe.write(buf)
    }

    fn close(&self, file_id: u64) -> Result<(), SyscallError> {
        let pipe = self.get_pipe(file_id)?;
        if Self::is_read_end(file_id) {
            pipe.close_read();
        } else {
            pipe.close_write();
        }

        // Remove the shared Pipe entry only when both ends are fully closed
        // (both refcounts have reached zero).
        let base = file_id & !1;
        let inner = pipe.inner.lock();
        if inner.read_closed && inner.write_closed {
            drop(inner);
            self.pipes.lock().remove(&base);
        }
        Ok(())
    }

    fn stat(&self, file_id: u64) -> Result<FileStat, SyscallError> {
        let pipe = self.get_pipe(file_id)?;
        let inner = pipe.inner.lock();
        Ok(FileStat {
            st_ino: file_id,
            st_mode: 0o010600, // S_IFIFO | rw-------
            st_nlink: 1,
            st_size: inner.len as u64,
            st_blksize: PIPE_BUF_SIZE as u64,
            st_blocks: 0,
        })
    }

    fn readdir(&self, _file_id: u64) -> Result<Vec<DirEntry>, SyscallError> {
        Err(SyscallError::InvalidArgument)
    }

    fn size(&self, file_id: u64) -> Result<u64, SyscallError> {
        let pipe = self.get_pipe(file_id)?;
        let len = pipe.inner.lock().len;
        Ok(len as u64)
    }
}
