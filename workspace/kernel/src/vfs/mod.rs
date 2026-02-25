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
pub mod pipe;
pub mod procfs;
pub mod scheme;
pub mod scheme_router;

use crate::{process::current_task_clone, sync::SpinLock, syscall::error::SyscallError};
use alloc::{string::String, sync::Arc};

pub use fd::{FileDescriptorTable, STDERR, STDIN, STDOUT};
pub use file::OpenFile;
pub use mount::{list_mounts, mount, resolve, unmount, Namespace};
pub use procfs::ProcScheme;
pub use pipe::PipeScheme;
pub use scheme::{DirEntry, DynScheme, FileFlags, FileStat, IpcScheme, KernelScheme, OpenFlags, Scheme};
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
///
/// Removes the fd from the table.  If this was the last Arc<OpenFile> reference
/// (no dup'd / fork'd copies remain) the Drop impl will call scheme.close().
pub fn close(fd: u32) -> Result<(), SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: Syscall context
    let fd_table = unsafe { &mut *task.fd_table.get() };
    let _file = fd_table.remove(fd)?;
    Ok(())
    // _file (Arc<OpenFile>) is dropped here; if refcount → 0, Drop fires → scheme.close()
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

/// POSIX lseek on a file descriptor.
pub fn lseek(fd: u32, offset: i64, whence: u32) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let fd_table = unsafe { &*task.fd_table.get() };
    let file = fd_table.get(fd)?;
    file.lseek(offset, whence)
}

/// fstat on an open file descriptor.
pub fn fstat(fd: u32) -> Result<FileStat, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let fd_table = unsafe { &*task.fd_table.get() };
    let file = fd_table.get(fd)?;
    file.stat()
}

/// stat by path (opens, stats, closes).
pub fn stat_path(path: &str) -> Result<FileStat, SyscallError> {
    let (scheme, relative_path) = mount::resolve(path)?;
    let open_result = scheme.open(&relative_path, OpenFlags::READ)?;
    let result = scheme.stat(open_result.file_id);
    let _ = scheme.close(open_result.file_id);
    result
}

/// Read directory entries from an open directory fd.
pub fn getdents(fd: u32) -> Result<alloc::vec::Vec<DirEntry>, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let fd_table = unsafe { &*task.fd_table.get() };
    let file = fd_table.get(fd)?;
    file.readdir()
}

/// Create a background stdin: a pipe read-end whose write end is immediately
/// closed.  Any `read()` on the returned file will return 0 (EOF) at once,
/// preventing processes launched in the background from blocking on stdin or
/// spinning on EBADF.
pub fn create_background_stdin() -> Arc<OpenFile> {
    let pipe_scheme = get_pipe_scheme();
    let (base_id, pipe) = pipe_scheme.create_pipe();

    // Close write end now (refcount → 0 → write_closed = true).
    // Subsequent reads on the read end will return EOF immediately.
    pipe.close_write();

    let dyn_scheme: DynScheme = pipe_scheme as Arc<dyn Scheme>;
    Arc::new(OpenFile::new(
        dyn_scheme,
        base_id, // even = read end
        String::from("pipe:[bg-stdin]"),
        OpenFlags::READ,
        FileFlags::PIPE,
        None,
    ))
}

/// Create a pipe, returning (read_fd, write_fd).
pub fn pipe() -> Result<(u32, u32), SyscallError> {
    let pipe_scheme = get_pipe_scheme();
    let (base_id, _pipe) = pipe_scheme.create_pipe();

    let dyn_scheme: DynScheme = pipe_scheme as Arc<dyn Scheme>;

    let read_file = Arc::new(OpenFile::new(
        dyn_scheme.clone(),
        base_id,
        String::from("pipe:[read]"),
        OpenFlags::READ,
        FileFlags::PIPE,
        None,
    ));
    let write_file = Arc::new(OpenFile::new(
        dyn_scheme.clone(),
        base_id + 1,
        String::from("pipe:[write]"),
        OpenFlags::WRITE,
        FileFlags::PIPE,
        None,
    ));

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let fd_table = unsafe { &mut *task.fd_table.get() };
    let read_fd = fd_table.insert(read_file);
    let write_fd = fd_table.insert(write_file);

    Ok((read_fd, write_fd))
}

/// Duplicate a file descriptor (POSIX dup).
pub fn dup(old_fd: u32) -> Result<u32, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let fd_table = unsafe { &mut *task.fd_table.get() };
    fd_table.duplicate(old_fd)
}

/// Duplicate a file descriptor to a specific number (POSIX dup2).
pub fn dup2(old_fd: u32, new_fd: u32) -> Result<u32, SyscallError> {
    if old_fd == new_fd {
        let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
        let fd_table = unsafe { &*task.fd_table.get() };
        fd_table.get(old_fd)?;
        return Ok(new_fd);
    }
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let fd_table = unsafe { &mut *task.fd_table.get() };

    // Close new_fd if it exists (silently ignore errors)
    let _ = fd_table.remove(new_fd);

    // Get the file from old_fd and insert at new_fd
    let file = fd_table.get(old_fd)?;
    fd_table.insert_at(new_fd, file);
    Ok(new_fd)
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

            if crate::arch::x86_64::vga::is_available() {
                if let Ok(s) = core::str::from_utf8(&kbuf[..n]) {
                    crate::serial_print!("{}", s);
                    crate::vga_print!("{}", s);
                } else {
                    for &byte in &kbuf[..n] {
                        crate::serial_print!("{}", byte as char);
                    }
                }
            } else {
                for &byte in &kbuf[..n] {
                    crate::serial_print!("{}", byte as char);
                }
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

/// Syscall handler for lseek.
pub fn sys_lseek(fd: u32, offset: i64, whence: u32) -> Result<u64, SyscallError> {
    lseek(fd, offset, whence)
}

/// Syscall handler for fstat.
pub fn sys_fstat(fd: u32, stat_ptr: u64) -> Result<u64, SyscallError> {
    let st = fstat(fd)?;
    let user = UserSliceWrite::new(stat_ptr, core::mem::size_of::<FileStat>())?;
    let bytes = unsafe {
        core::slice::from_raw_parts(&st as *const FileStat as *const u8, core::mem::size_of::<FileStat>())
    };
    user.copy_from(bytes);
    Ok(0)
}

/// Syscall handler for stat (by path).
pub fn sys_stat(path_ptr: u64, path_len: u64, stat_ptr: u64) -> Result<u64, SyscallError> {
    const MAX_PATH_LEN: usize = 4096;
    if path_len == 0 || path_len as usize > MAX_PATH_LEN {
        return Err(SyscallError::InvalidArgument);
    }
    let user = UserSliceRead::new(path_ptr, path_len as usize)?;
    let bytes = user.read_to_vec();
    let path = core::str::from_utf8(&bytes).map_err(|_| SyscallError::InvalidArgument)?;

    let st = stat_path(path)?;
    let user_out = UserSliceWrite::new(stat_ptr, core::mem::size_of::<FileStat>())?;
    let out_bytes = unsafe {
        core::slice::from_raw_parts(&st as *const FileStat as *const u8, core::mem::size_of::<FileStat>())
    };
    user_out.copy_from(out_bytes);
    Ok(0)
}

/// Syscall handler for getdents.
///
/// Writes a packed array of `KernelDirent` entries into the user buffer.
/// Returns the number of bytes written.
pub fn sys_getdents(fd: u32, buf_ptr: u64, buf_len: u64) -> Result<u64, SyscallError> {
    let entries = getdents(fd)?;

    let mut offset: usize = 0;
    let buf_size = buf_len as usize;

    for entry in &entries {
        let name_bytes = entry.name.as_bytes();
        let name_len = core::cmp::min(name_bytes.len(), 255);
        let entry_size = 8 + 1 + 2 + name_len + 1; // ino(8) + type(1) + name_len(2) + name + nul

        if offset + entry_size > buf_size {
            break;
        }

        let user = UserSliceWrite::new(buf_ptr + offset as u64, entry_size)?;
        let mut kbuf = [0u8; 268]; // max entry
        kbuf[0..8].copy_from_slice(&entry.ino.to_le_bytes());
        kbuf[8] = entry.file_type;
        kbuf[9..11].copy_from_slice(&(name_len as u16).to_le_bytes());
        kbuf[11..11 + name_len].copy_from_slice(&name_bytes[..name_len]);
        kbuf[11 + name_len] = 0; // nul-terminator
        user.copy_from(&kbuf[..entry_size]);

        offset += entry_size;
    }

    Ok(offset as u64)
}

/// Syscall handler for pipe.
pub fn sys_pipe(fds_ptr: u64) -> Result<u64, SyscallError> {
    let (read_fd, write_fd) = pipe()?;
    let user = UserSliceWrite::new(fds_ptr, 8)?; // 2 x u32
    let mut buf = [0u8; 8];
    buf[0..4].copy_from_slice(&read_fd.to_le_bytes());
    buf[4..8].copy_from_slice(&write_fd.to_le_bytes());
    user.copy_from(&buf);
    Ok(0)
}

/// Syscall handler for dup.
pub fn sys_dup(old_fd: u32) -> Result<u64, SyscallError> {
    let new_fd = dup(old_fd)?;
    Ok(new_fd as u64)
}

/// Syscall handler for dup2.
pub fn sys_dup2(old_fd: u32, new_fd: u32) -> Result<u64, SyscallError> {
    let fd = dup2(old_fd, new_fd)?;
    Ok(fd as u64)
}

// ============================================================================
// Global PipeScheme singleton
// ============================================================================

static PIPE_SCHEME: SpinLock<Option<Arc<PipeScheme>>> = SpinLock::new(None);

fn get_pipe_scheme() -> Arc<PipeScheme> {
    let mut guard = PIPE_SCHEME.lock();
    if let Some(ref scheme) = *guard {
        return scheme.clone();
    }
    let scheme = Arc::new(PipeScheme::new());
    *guard = Some(scheme.clone());
    scheme
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
