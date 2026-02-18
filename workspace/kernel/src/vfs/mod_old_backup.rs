//! Minimal in-kernel VFS/namespace (temporary).
//!
//! Provides a tiny path -> memory file mapping used by SYS_OPEN and SYS_READ
//! until the full userspace VFS/IPC stack is implemented.

use crate::syscall::error::SyscallError;
use crate::sync::SpinLock;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use core::sync::atomic::{AtomicU64, Ordering};

/// A wrapper around a raw pointer that implements Send and Sync.
/// This is safe because we only store kernel-static addresses that are valid
/// for the entire lifetime of the kernel.
#[derive(Clone, Copy)]
struct SafePtr(*const u8);

// SAFETY: SafePtr is safe to send between threads because it points to
// kernel-static data that remains valid for the entire kernel lifetime.
unsafe impl Send for SafePtr {}
unsafe impl Sync for SafePtr {}

#[derive(Clone)]
struct KernelFile {
    id: u64,
    path: String,
    base: SafePtr,
    len: usize,
}

struct OpenFile {
    id: u64,
    base: SafePtr,
    len: usize,
    offset: usize,
}

struct VfsState {
    files: BTreeMap<String, KernelFile>,
    open_files: BTreeMap<u64, OpenFile>,
}

impl VfsState {
    const fn new() -> Self {
        VfsState {
            files: BTreeMap::new(),
            open_files: BTreeMap::new(),
        }
    }
}

static VFS: SpinLock<VfsState> = SpinLock::new(VfsState::new());
static NEXT_FILE_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_OPEN_ID: AtomicU64 = AtomicU64::new(1);

/// Register a static, memory-backed file at the given path.
///
/// The data pointer must remain valid for the lifetime of the kernel.
pub fn register_static_file(path: &str, base: *const u8, len: usize) -> Result<u64, SyscallError> {
    if path.is_empty() {
        return Err(SyscallError::InvalidArgument);
    }
    let id = NEXT_FILE_ID.fetch_add(1, Ordering::SeqCst);
    let mut vfs = VFS.lock();
    let file = KernelFile {
        id,
        path: path.to_string(),
        base: SafePtr(base),
        len,
    };
    vfs.files.insert(path.to_string(), file);
    Ok(id)
}

/// Open a path and return an open-file id.
pub fn open_path(path: &str) -> Result<u64, SyscallError> {
    let mut vfs = VFS.lock();
    let file = vfs
        .files
        .get(path)
        .ok_or(SyscallError::BadHandle)?
        .clone();
    let open_id = NEXT_OPEN_ID.fetch_add(1, Ordering::SeqCst);
    vfs.open_files.insert(
        open_id,
        OpenFile {
            id: open_id,
            base: file.base,
            len: file.len,
            offset: 0,
        },
    );
    Ok(open_id)
}

/// Read from an open file into `dest`, advancing the file offset.
pub fn read_open_file(open_id: u64, dest: &mut [u8]) -> Result<usize, SyscallError> {
    let mut vfs = VFS.lock();
    let file = vfs
        .open_files
        .get_mut(&open_id)
        .ok_or(SyscallError::BadHandle)?;
    if file.offset >= file.len || dest.is_empty() {
        return Ok(0);
    }
    let remaining = file.len - file.offset;
    let to_copy = core::cmp::min(remaining, dest.len());
    // SAFETY: base is a kernel pointer registered as static, bounds checked above.
    unsafe {
        let src = (file.base.0).add(file.offset);
        core::ptr::copy_nonoverlapping(src, dest.as_mut_ptr(), to_copy);
    }
    file.offset += to_copy;
    Ok(to_copy)
}

/// Read the entire remaining content of an open file into a Vec.
pub fn read_open_file_all(open_id: u64) -> Result<alloc::vec::Vec<u8>, SyscallError> {
    let mut vfs = VFS.lock();
    let file = vfs
        .open_files
        .get_mut(&open_id)
        .ok_or(SyscallError::BadHandle)?;
    if file.offset >= file.len {
        return Ok(alloc::vec::Vec::new());
    }
    let remaining = file.len - file.offset;
    let mut buf = alloc::vec![0u8; remaining];
    // SAFETY: base is a kernel pointer registered as static, bounds checked above.
    unsafe {
        let src = (file.base.0).add(file.offset);
        core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), remaining);
    }
    file.offset = file.len;
    Ok(buf)
}

/// Close an open file handle.
pub fn close_open_file(open_id: u64) -> Result<(), SyscallError> {
    let mut vfs = VFS.lock();
    vfs.open_files
        .remove(&open_id)
        .ok_or(SyscallError::BadHandle)?;
    Ok(())
}
