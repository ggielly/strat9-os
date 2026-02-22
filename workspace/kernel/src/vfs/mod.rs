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
pub mod procfs;
pub mod scheme;
pub mod scheme_router;

use crate::{process::current_task_clone, syscall::error::SyscallError};
use alloc::{string::String, sync::Arc};

pub use fd::{FileDescriptorTable, STDERR, STDIN, STDOUT};
pub use file::OpenFile;
pub use mount::{list_mounts, mount, resolve, unmount, Namespace};
pub use procfs::ProcScheme;
pub use scheme::{DynScheme, FileFlags, IpcScheme, KernelScheme, OpenFlags, Scheme};
pub use scheme_router::{
    init_builtin_schemes, list_schemes, mount_scheme, register_initfs_file, register_scheme,
};

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

/// Create a directory.
pub fn mkdir(path: &str, mode: u32) -> Result<(), SyscallError> {
    let (scheme, relative_path) = mount::resolve(path)?;
    scheme.create_directory(&relative_path, mode)?;
    Ok(())
}

/// Create an empty regular file.
pub fn create_file(path: &str, mode: u32) -> Result<(), SyscallError> {
    let (scheme, relative_path) = mount::resolve(path)?;
    scheme.create_file(&relative_path, mode)?;
    Ok(())
}

/// Remove a file or directory.
pub fn unlink(path: &str) -> Result<(), SyscallError> {
    let (scheme, relative_path) = mount::resolve(path)?;
    scheme.unlink(&relative_path)?;
    Ok(())
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

/// Read all remaining bytes from a file descriptor.
pub fn read_all(fd: u32) -> Result<alloc::vec::Vec<u8>, SyscallError> {
    let mut out = alloc::vec::Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = read(fd, &mut buf)?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
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
    let kernel_scheme = KernelScheme::new();

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
