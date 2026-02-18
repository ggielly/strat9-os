//! Virtual File System (VFS) - Plan 9-inspired namespace.
//!
//! The VFS provides:
//! - Scheme abstraction: Pluggable backends (IPC, kernel, devices)
//! - Mount table: Map path prefixes to schemes
//! - File descriptors: Per-process FD tables
//! - Path resolution: Navigate the namespace hierarchy
//!
//! ## Architecture
//!
//! ```text
//! User syscall (open "/net/tcp/0")
//!      ↓
//! VFS::open() — path resolution
//!      ↓
//! MountTable::resolve() → ("/net" → IpcScheme, "tcp/0")
//!      ↓
//! IpcScheme::open("tcp/0") → IPC message to network stack
//!      ↓
//! OpenFile created with scheme reference + file_id
//!      ↓
//! FD allocated in process FD table
//!      ↓
//! Returns FD to userspace
//! ```

pub mod fd;
pub mod file;
pub mod mount;
pub mod scheme;
pub mod scheme_router;
pub mod procfs;

use crate::{process::current_task_clone, syscall::error::SyscallError};
use alloc::{string::String, sync::Arc};

pub use fd::{FileDescriptorTable, STDERR, STDIN, STDOUT};
pub use file::OpenFile;
pub use mount::{mount, resolve, unmount, Namespace};
pub use scheme::{DynScheme, FileFlags, IpcScheme, KernelScheme, OpenFlags, Scheme};
pub use scheme_router::{register_scheme, mount_scheme, init_builtin_schemes, list_schemes};
pub use procfs::ProcScheme;

use crate::memory::{UserSliceRead, UserSliceWrite};

// ============================================================================
// High-level VFS API
// ============================================================================

/// Open a file and return a file descriptor.
///
/// This is the main entry point for opening files from userspace.
pub fn open(path: &str, flags: OpenFlags) -> Result<u32, SyscallError> {
    // Resolve path to (scheme, relative_path)
    let (scheme, relative_path) = mount::resolve(path)?;

    // Open the file via the scheme
    let open_result = scheme.open(&relative_path, flags)?;

    // Create OpenFile wrapper
    let open_file = Arc::new(OpenFile::new(
        scheme,
        open_result.file_id,
        String::from(path),
        flags,
        open_result.flags,
        open_result.size,
    ));

    // Insert into current task's FD table
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: We're in syscall context, have exclusive access to FD table
    let fd = unsafe { (&mut *task.fd_table.get()).insert(open_file) };

    Ok(fd)
}

/// Read from a file descriptor.
pub fn read(fd: u32, buf: &mut [u8]) -> Result<usize, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: Syscall context
    let fd_table = unsafe { &*task.fd_table.get() };
    let file = fd_table.get(fd)?;
    file.read(buf)
}

/// Write to a file descriptor.
pub fn write(fd: u32, buf: &[u8]) -> Result<usize, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: Syscall context
    let fd_table = unsafe { &*task.fd_table.get() };
    let file = fd_table.get(fd)?;
    file.write(buf)
}

/// Close a file descriptor.
pub fn close(fd: u32) -> Result<(), SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: Syscall context
    let fd_table = unsafe { &mut *task.fd_table.get() };
    let file = fd_table.remove(fd)?;
    file.close()
}

/// Seek within a file.
pub fn seek(fd: u32, offset: u64) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: Syscall context
    let fd_table = unsafe { &*task.fd_table.get() };
    let file = fd_table.get(fd)?;
    file.seek(offset)
}

/// Get current offset in a file.
pub fn tell(fd: u32) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: Syscall context
    let fd_table = unsafe { &*task.fd_table.get() };
    let file = fd_table.get(fd)?;
    Ok(file.tell())
}

/// Get file size.
pub fn fsize(fd: u32) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: Syscall context
    let fd_table = unsafe { &*task.fd_table.get() };
    let file = fd_table.get(fd)?;
    file.size()
}

/// Sync file to storage.
pub fn fsync(fd: u32) -> Result<(), SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: Syscall context
    let fd_table = unsafe { &*task.fd_table.get() };
    let file = fd_table.get(fd)?;
    file.sync()
}

// ============================================================================
// Syscall Handlers (Native ABI)
// ============================================================================

/// Syscall handler for opening a file.
pub fn sys_open(path_ptr: u64, path_len: u64, flags: u64) -> Result<u64, SyscallError> {
    const MAX_PATH_LEN: usize = 4096;
    if path_len == 0 || path_len as usize > MAX_PATH_LEN {
        return Err(SyscallError::InvalidArgument);
    }

    let user = UserSliceRead::new(path_ptr, path_len as usize)?;
    let bytes = user.read_to_vec();
    let path = core::str::from_utf8(&bytes).map_err(|_| SyscallError::InvalidArgument)?;

    // Convert flags to OpenFlags
    let mut open_flags = OpenFlags::empty();
    if flags & 0x1 != 0 {
        open_flags |= OpenFlags::READ;
    }
    if flags & 0x2 != 0 {
        open_flags |= OpenFlags::WRITE;
    }
    if flags & 0x4 != 0 {
        open_flags |= OpenFlags::CREATE;
    }
    if flags & 0x8 != 0 {
        open_flags |= OpenFlags::TRUNCATE;
    }
    if flags & 0x10 != 0 {
        open_flags |= OpenFlags::APPEND;
    }
    if flags & 0x20 != 0 {
        open_flags |= OpenFlags::DIRECTORY;
    }

    let fd = open(path, open_flags)?;
    Ok(fd as u64)
}

/// Syscall handler for reading from a file.
pub fn sys_read(fd: u32, buf_ptr: u64, buf_len: u64) -> Result<u64, SyscallError> {
    if buf_len == 0 {
        return Ok(0);
    }

    // Read directly into chunks to avoid large kernel allocations
    let mut kbuf = [0u8; 4096];
    let mut total_read = 0;

    while total_read < buf_len as usize {
        let to_read = core::cmp::min(kbuf.len(), buf_len as usize - total_read);
        let n = read(fd, &mut kbuf[..to_read])?;
        if n == 0 {
            break;
        }

        let chunk_user = UserSliceWrite::new(buf_ptr + total_read as u64, n)?;
        chunk_user.copy_from(&kbuf[..n]);

        total_read += n;
        if n < to_read {
            break;
        }
    }

    Ok(total_read as u64)
}

/// Syscall handler for writing to a file.
pub fn sys_write(fd: u32, buf_ptr: u64, buf_len: u64) -> Result<u64, SyscallError> {
    // Special case for stdout/stderr (legacy redirect for bootstrap)
    if fd == 1 || fd == 2 {
        crate::silo::enforce_console_access()?;

        if buf_len == 0 {
            return Ok(0);
        }

        let len = core::cmp::min(buf_len as usize, 16 * 1024); // Cap at 16KB for console
        let user_buf = UserSliceRead::new(buf_ptr, len)?;
        let mut kbuf = [0u8; 4096];
        let mut total_written = 0;

        while total_written < len {
            let to_write = core::cmp::min(kbuf.len(), len - total_written);
            let n = user_buf.copy_to(&mut kbuf[..to_write]);

            for &byte in &kbuf[..n] {
                crate::serial_print!("{}", byte as char);
            }
            total_written += n;
        }

        return Ok(total_written as u64);
    }

    if buf_len == 0 {
        return Ok(0);
    }

    let mut kbuf = [0u8; 4096];
    let mut total_written = 0;

    while total_written < buf_len as usize {
        let to_write = core::cmp::min(kbuf.len(), buf_len as usize - total_written);
        let chunk_user = UserSliceRead::new(buf_ptr + total_written as u64, to_write)?;
        chunk_user.copy_to(&mut kbuf[..to_write]);

        let n = write(fd, &kbuf[..to_write])?;
        total_written += n;
        if n < to_write {
            break;
        }
    }

    Ok(total_written as u64)
}

/// Syscall handler for closing a file.
pub fn sys_close(fd: u32) -> Result<u64, SyscallError> {
    close(fd)?;
    Ok(0)
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the VFS with default mounts.
pub fn init() {
    log::info!("[VFS] Initializing virtual file system");

    // Initialize scheme router
    if let Err(e) = scheme_router::init_builtin_schemes() {
        log::error!("[VFS] Failed to init builtin schemes: {:?}", e);
    }

    // Create and mount kernel scheme for /sys
    let mut kernel_scheme = KernelScheme::new();

    // Register some basic kernel files
    static VERSION: &[u8] = b"Strat9-OS v0.1.0 (Bedrock)\n";
    kernel_scheme.register("version", VERSION.as_ptr(), VERSION.len());

    static CMDLINE: &[u8] = b"quiet loglevel=debug\n";
    kernel_scheme.register("cmdline", CMDLINE.as_ptr(), CMDLINE.len());

    let kernel_scheme = Arc::new(kernel_scheme);
    
    // Mount /sys
    if let Err(e) = mount::mount("/sys", kernel_scheme.clone()) {
        log::error!("[VFS] Failed to mount /sys: {:?}", e);
    } else {
        log::info!("[VFS] Mounted /sys (kernel scheme)");
    }

    // Register and mount procfs
    let proc_scheme = Arc::new(ProcScheme::new());
    if let Err(e) = register_scheme("proc", proc_scheme.clone()) {
        log::error!("[VFS] Failed to register proc scheme: {:?}", e);
    } else {
        log::info!("[VFS] Registered proc scheme");
    }
    
    if let Err(e) = mount::mount("/proc", proc_scheme) {
        log::error!("[VFS] Failed to mount /proc: {:?}", e);
    } else {
        log::info!("[VFS] Mounted /proc (procfs)");
    }

    log::info!("[VFS] VFS ready");
}

// ============================================================================
// Legacy compatibility (temporary)
// ============================================================================

/// Open a path using the old VFS API (for backwards compatibility).
///
/// DEPRECATED: Use vfs::open() instead.
pub fn open_path(path: &str) -> Result<u64, SyscallError> {
    // Try new VFS first
    if let Ok(fd) = open(path, OpenFlags::READ) {
        return Ok(fd as u64);
    }

    // Fallback to old static file table
    old_vfs::open_path(path)
}

/// Read from an old-style open file ID.
///
/// DEPRECATED: Use vfs::read() instead.
pub fn read_open_file(open_id: u64, dest: &mut [u8]) -> Result<usize, SyscallError> {
    // Try as FD first
    if open_id <= u32::MAX as u64 {
        if let Ok(bytes) = read(open_id as u32, dest) {
            return Ok(bytes);
        }
    }

    // Fallback to old VFS
    old_vfs::read_open_file(open_id, dest)
}

/// Read entire file (old API).
///
/// DEPRECATED: Use vfs::open() + vfs::read() in a loop.
pub fn read_open_file_all(open_id: u64) -> Result<alloc::vec::Vec<u8>, SyscallError> {
    old_vfs::read_open_file_all(open_id)
}

/// Close old-style open file.
///
/// DEPRECATED: Use vfs::close() instead.
pub fn close_open_file(open_id: u64) -> Result<(), SyscallError> {
    // Try as FD first
    if open_id <= u32::MAX as u64 {
        if close(open_id as u32).is_ok() {
            return Ok(());
        }
    }

    // Fallback to old VFS
    old_vfs::close_open_file(open_id)
}

/// Register a static file (old API).
///
/// DEPRECATED: Use KernelScheme::register() and mount it.
pub fn register_static_file(path: &str, base: *const u8, len: usize) -> Result<u64, SyscallError> {
    old_vfs::register_static_file(path, base, len)
}

// ============================================================================
// Old VFS (to be removed)
// ============================================================================

mod old_vfs {
    use super::*;
    use crate::sync::SpinLock;
    use alloc::{collections::BTreeMap, string::ToString, vec::Vec};
    use core::sync::atomic::{AtomicU64, Ordering};

    #[derive(Clone, Copy)]
    struct SafePtr(*const u8);
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
    static NEXT_OPEN_ID: AtomicU64 = AtomicU64::new(1000); // Start at 1000 to avoid FD collision

    pub fn register_static_file(
        path: &str,
        base: *const u8,
        len: usize,
    ) -> Result<u64, SyscallError> {
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

    pub fn open_path(path: &str) -> Result<u64, SyscallError> {
        let mut vfs = VFS.lock();
        let file = vfs.files.get(path).ok_or(SyscallError::BadHandle)?.clone();
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
        unsafe {
            let src = (file.base.0).add(file.offset);
            core::ptr::copy_nonoverlapping(src, dest.as_mut_ptr(), to_copy);
        }
        file.offset += to_copy;
        Ok(to_copy)
    }

    pub fn read_open_file_all(open_id: u64) -> Result<Vec<u8>, SyscallError> {
        let mut vfs = VFS.lock();
        let file = vfs
            .open_files
            .get_mut(&open_id)
            .ok_or(SyscallError::BadHandle)?;
        if file.offset >= file.len {
            return Ok(Vec::new());
        }
        let remaining = file.len - file.offset;
        let mut buf = alloc::vec![0u8; remaining];
        unsafe {
            let src = (file.base.0).add(file.offset);
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), remaining);
        }
        file.offset = file.len;
        Ok(buf)
    }

    pub fn close_open_file(open_id: u64) -> Result<(), SyscallError> {
        let mut vfs = VFS.lock();
        vfs.open_files
            .remove(&open_id)
            .ok_or(SyscallError::BadHandle)?;
        Ok(())
    }
}
