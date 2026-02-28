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

pub mod blkdev_scheme;
pub mod fd;
pub mod file;
pub mod ipcfs;
pub mod mount;
pub mod pipe;
pub mod procfs;
pub mod ramfs_scheme;
pub mod scheme;
pub mod scheme_router;

use crate::{process::current_task_clone, sync::SpinLock, syscall::error::SyscallError};
use alloc::{string::String, sync::Arc};

pub use blkdev_scheme::BlkDevScheme;
pub use fd::{FileDescriptorTable, STDERR, STDIN, STDOUT};
pub use file::OpenFile;
pub use mount::{list_mounts, mount, resolve, unmount, Namespace};
pub use pipe::PipeScheme;
pub use procfs::ProcScheme;
pub use ramfs_scheme::RamfsScheme;
pub use scheme::{
    DirEntry, DynScheme, FileFlags, FileStat, IpcScheme, KernelScheme, OpenFlags, Scheme,
};
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
    let fd = unsafe { (&mut *task.process.fd_table.get()).insert(open_file) };

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
    let fd_table = unsafe { &*task.process.fd_table.get() };
    let file = fd_table.get(fd)?;
    file.read(buf)
}

/// Write to a file descriptor.
pub fn write(fd: u32, buf: &[u8]) -> Result<usize, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: Syscall context
    let fd_table = unsafe { &*task.process.fd_table.get() };
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
    let fd_table = unsafe { &mut *task.process.fd_table.get() };
    let _file = fd_table.remove(fd)?;
    Ok(())
    // _file (Arc<OpenFile>) is dropped here; if refcount → 0, Drop fires → scheme.close()
}

/// Seek within a file.
pub fn seek(fd: u32, offset: u64) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: Syscall context
    let fd_table = unsafe { &*task.process.fd_table.get() };
    let file = fd_table.get(fd)?;
    file.seek(offset)
}

/// Get current offset in a file.
pub fn tell(fd: u32) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: Syscall context
    let fd_table = unsafe { &*task.process.fd_table.get() };
    let file = fd_table.get(fd)?;
    Ok(file.tell())
}

/// Get file size.
pub fn fsize(fd: u32) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: Syscall context
    let fd_table = unsafe { &*task.process.fd_table.get() };
    let file = fd_table.get(fd)?;
    file.size()
}

/// Sync file to storage.
pub fn fsync(fd: u32) -> Result<(), SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    // SAFETY: Syscall context
    let fd_table = unsafe { &*task.process.fd_table.get() };
    let file = fd_table.get(fd)?;
    file.sync()
}

/// POSIX lseek on a file descriptor.
pub fn lseek(fd: u32, offset: i64, whence: u32) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let fd_table = unsafe { &*task.process.fd_table.get() };
    let file = fd_table.get(fd)?;
    file.lseek(offset, whence)
}

/// fstat on an open file descriptor.
pub fn fstat(fd: u32) -> Result<FileStat, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let fd_table = unsafe { &*task.process.fd_table.get() };
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
    let fd_table = unsafe { &*task.process.fd_table.get() };
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
    let fd_table = unsafe { &mut *task.process.fd_table.get() };
    let read_fd = fd_table.insert(read_file);
    let write_fd = fd_table.insert(write_file);

    Ok((read_fd, write_fd))
}

/// Duplicate a file descriptor (POSIX dup).
pub fn dup(old_fd: u32) -> Result<u32, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let fd_table = unsafe { &mut *task.process.fd_table.get() };
    fd_table.duplicate(old_fd)
}

/// Duplicate a file descriptor to a specific number (POSIX dup2).
pub fn dup2(old_fd: u32, new_fd: u32) -> Result<u32, SyscallError> {
    if old_fd == new_fd {
        let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
        let fd_table = unsafe { &*task.process.fd_table.get() };
        fd_table.get(old_fd)?;
        return Ok(new_fd);
    }
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let fd_table = unsafe { &mut *task.process.fd_table.get() };

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

    let raw = read_user_path(path_ptr, path_len)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let cwd = unsafe { (&*task.process.cwd.get()).clone() };
    let path = resolve_path(&raw, &cwd);

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

    let want_read =
        open_flags.contains(OpenFlags::READ) || open_flags.contains(OpenFlags::DIRECTORY);
    let want_write = open_flags.contains(OpenFlags::WRITE)
        || open_flags.contains(OpenFlags::CREATE)
        || open_flags.contains(OpenFlags::TRUNCATE)
        || open_flags.contains(OpenFlags::APPEND);
    crate::silo::enforce_path_for_current_task(&path, want_read, want_write, false)?;

    let fd = open(&path, open_flags)?;
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
    if buf_len == 0 {
        return Ok(0);
    }

    // For stdout/stderr, fall back to direct console output only when no
    // FD entry exists (early boot).  Once the FD table is populated (or
    // after dup2 redirection) the normal VFS path is used.
    if fd == 1 || fd == 2 {
        let use_console = match current_task_clone() {
            Some(t) => {
                let fd_table = unsafe { &*t.process.fd_table.get() };
                !fd_table.contains(fd)
            }
            None => true,
        };
        if use_console {
            crate::silo::enforce_console_access()?;
            let len = core::cmp::min(buf_len as usize, 16 * 1024);
            let mut kbuf = [0u8; 4096];
            let mut total_written = 0;
            while total_written < len {
                let to_write = core::cmp::min(kbuf.len(), len - total_written);
                let chunk = UserSliceRead::new(buf_ptr + total_written as u64, to_write)?;
                let n = chunk.copy_to(&mut kbuf[..to_write]);
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
        core::slice::from_raw_parts(
            &st as *const FileStat as *const u8,
            core::mem::size_of::<FileStat>(),
        )
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
    let raw = read_user_path(path_ptr, path_len)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let cwd = unsafe { (&*task.process.cwd.get()).clone() };
    let path = resolve_path(&raw, &cwd);
    crate::silo::enforce_path_for_current_task(&path, true, false, false)?;

    let st = stat_path(&path)?;
    let user_out = UserSliceWrite::new(stat_ptr, core::mem::size_of::<FileStat>())?;
    let out_bytes = unsafe {
        core::slice::from_raw_parts(
            &st as *const FileStat as *const u8,
            core::mem::size_of::<FileStat>(),
        )
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

// ─── Path helpers ─────────────────────────────────────────────────────────────

/// Read a NUL-terminated or length-bounded path from user space.
///
/// `path_ptr` and `path_len` come directly from syscall arguments.
/// If `path_len` is 0 the string is assumed to be NUL-terminated up to 4096 bytes.
fn read_user_path(path_ptr: u64, path_len: u64) -> Result<alloc::string::String, SyscallError> {
    const MAX_PATH: usize = 4096;
    let len = if path_len == 0 || path_len as usize > MAX_PATH {
        MAX_PATH
    } else {
        path_len as usize
    };
    let user = UserSliceRead::new(path_ptr, len)?;
    let bytes = user.read_to_vec();
    // Trim at first NUL byte if present.
    let trimmed = bytes.split(|&b| b == 0).next().unwrap_or(&bytes);
    if trimmed.is_empty() {
        return Err(SyscallError::InvalidArgument);
    }
    core::str::from_utf8(trimmed)
        .map(|s| alloc::string::String::from(s))
        .map_err(|_| SyscallError::InvalidArgument)
}

/// Resolve `path` relative to the current working directory when it is not
/// absolute. Returns the normalized absolute path.
fn resolve_path(path: &str, cwd: &str) -> alloc::string::String {
    let raw = if path.starts_with('/') {
        alloc::string::String::from(path)
    } else if cwd.ends_with('/') {
        alloc::format!("{}{}", cwd, path)
    } else {
        alloc::format!("{}/{}", cwd, path)
    };
    normalize_path(&raw)
}

/// Collapse `.`, `..` and duplicate `/` in an absolute path.
fn normalize_path(path: &str) -> alloc::string::String {
    let mut parts: alloc::vec::Vec<&str> = alloc::vec::Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => { parts.pop(); }
            other => parts.push(other),
        }
    }
    let mut out = alloc::string::String::with_capacity(path.len());
    if parts.is_empty() {
        out.push('/');
    } else {
        for p in &parts {
            out.push('/');
            out.push_str(p);
        }
    }
    out
}

// ─── New VFS syscall handlers ─────────────────────────────────────────────────

/// SYS_CHDIR (440): Change current working directory.
pub fn sys_chdir(path_ptr: u64, path_len: u64) -> Result<u64, SyscallError> {
    let raw = read_user_path(path_ptr, path_len)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let cwd = unsafe { &*task.process.cwd.get() };
    let abs = resolve_path(&raw, cwd);
    crate::silo::enforce_path_for_current_task(&abs, true, false, false)?;

    let (scheme, rel) = mount::resolve(&abs)?;
    let res = scheme.open(&rel, OpenFlags::READ | OpenFlags::DIRECTORY)?;
    let _ = scheme.close(res.file_id);

    unsafe { *task.process.cwd.get() = abs };
    Ok(0)
}

/// SYS_FCHDIR (441): Change cwd using an open file descriptor.
pub fn sys_fchdir(fd: u32) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let fd_table = unsafe { &*task.process.fd_table.get() };
    let file = fd_table.get(fd)?;
    let path = alloc::string::String::from(file.path());
    drop(fd_table);
    unsafe { *task.process.cwd.get() = path };
    Ok(0)
}

/// SYS_GETCWD (442): Write the current working directory into a user buffer.
pub fn sys_getcwd(buf_ptr: u64, buf_len: u64) -> Result<u64, SyscallError> {
    if buf_len == 0 {
        return Err(SyscallError::InvalidArgument);
    }
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let cwd = unsafe { (&*task.process.cwd.get()).clone() };
    let bytes = cwd.as_bytes();
    let needed = bytes.len() + 1; // include NUL terminator
    if needed > buf_len as usize {
        return Err(SyscallError::OutOfMemory); // ERANGE in POSIX
    }
    let out = UserSliceWrite::new(buf_ptr, needed)?;
    let mut tmp = alloc::vec![0u8; needed];
    tmp[..bytes.len()].copy_from_slice(bytes);
    tmp[bytes.len()] = 0;
    out.copy_from(&tmp);
    Ok(needed as u64) // Like Linux: returns byte count written (including NUL)
}

/// SYS_IOCTL (443): I/O control — stub.
///
/// Returns ENOTTY for all file descriptors that are not character devices.
/// Terminal / PTY support will be added when a TTY driver is implemented.
pub fn sys_ioctl(_fd: u32, _request: u64, _arg: u64) -> Result<u64, SyscallError> {
    Err(SyscallError::NotATty)
}

/// SYS_UMASK (444): Set file creation mask; return the old mask.
pub fn sys_umask(mask: u64) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let old = task
        .process
        .umask
        .swap(mask as u32 & 0o777, core::sync::atomic::Ordering::Relaxed);
    Ok(old as u64)
}

/// SYS_UNLINK (445): Remove a file.
pub fn sys_unlink(path_ptr: u64, path_len: u64) -> Result<u64, SyscallError> {
    let raw = read_user_path(path_ptr, path_len)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let cwd = unsafe { (&*task.process.cwd.get()).clone() };
    let abs = resolve_path(&raw, &cwd);
    crate::silo::enforce_path_for_current_task(&abs, false, true, false)?;
    unlink(&abs)?;
    Ok(0)
}

/// SYS_RMDIR (446): Remove an empty directory.
pub fn sys_rmdir(path_ptr: u64, path_len: u64) -> Result<u64, SyscallError> {
    let raw = read_user_path(path_ptr, path_len)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let cwd = unsafe { (&*task.process.cwd.get()).clone() };
    let abs = resolve_path(&raw, &cwd);
    crate::silo::enforce_path_for_current_task(&abs, false, true, false)?;
    unlink(&abs)?;
    Ok(0)
}

/// SYS_MKDIR (447): Create a directory.
pub fn sys_mkdir(path_ptr: u64, path_len: u64, mode: u64) -> Result<u64, SyscallError> {
    let raw = read_user_path(path_ptr, path_len)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let umask = task
        .process
        .umask
        .load(core::sync::atomic::Ordering::Relaxed);
    let cwd = unsafe { (&*task.process.cwd.get()).clone() };
    let abs = resolve_path(&raw, &cwd);
    crate::silo::enforce_path_for_current_task(&abs, false, true, false)?;
    let effective_mode = (mode as u32) & !umask;
    mkdir(&abs, effective_mode)?;
    Ok(0)
}

/// SYS_RENAME (448): Rename a file or directory.
///
/// Not yet implemented in the scheme abstraction; returns ENOSYS.
pub fn sys_rename(
    old_ptr: u64,
    old_len: u64,
    new_ptr: u64,
    new_len: u64,
) -> Result<u64, SyscallError> {
    let old = read_user_path(old_ptr, old_len)?;
    let new = read_user_path(new_ptr, new_len)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let cwd = unsafe { (&*task.process.cwd.get()).clone() };
    let old_abs = resolve_path(&old, &cwd);
    let new_abs = resolve_path(&new, &cwd);
    crate::silo::enforce_path_for_current_task(&old_abs, true, true, false)?;
    crate::silo::enforce_path_for_current_task(&new_abs, false, true, false)?;
    Err(SyscallError::NotImplemented)
}

/// SYS_LINK (449): Create a hard link — not yet implemented.
pub fn sys_link(
    _old_ptr: u64,
    _old_len: u64,
    _new_ptr: u64,
    _new_len: u64,
) -> Result<u64, SyscallError> {
    let old = read_user_path(_old_ptr, _old_len)?;
    let new = read_user_path(_new_ptr, _new_len)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let cwd = unsafe { (&*task.process.cwd.get()).clone() };
    let old_abs = resolve_path(&old, &cwd);
    let new_abs = resolve_path(&new, &cwd);
    crate::silo::enforce_path_for_current_task(&old_abs, true, false, false)?;
    crate::silo::enforce_path_for_current_task(&new_abs, false, true, false)?;
    Err(SyscallError::NotImplemented)
}

/// SYS_SYMLINK (450): Create a symbolic link — not yet implemented.
pub fn sys_symlink(
    _target_ptr: u64,
    _target_len: u64,
    _linkpath_ptr: u64,
    _linkpath_len: u64,
) -> Result<u64, SyscallError> {
    let target = read_user_path(_target_ptr, _target_len)?;
    let linkpath = read_user_path(_linkpath_ptr, _linkpath_len)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let cwd = unsafe { (&*task.process.cwd.get()).clone() };
    let target_abs = resolve_path(&target, &cwd);
    let link_abs = resolve_path(&linkpath, &cwd);
    crate::silo::enforce_path_for_current_task(&target_abs, true, false, false)?;
    crate::silo::enforce_path_for_current_task(&link_abs, false, true, false)?;
    Err(SyscallError::NotImplemented)
}

/// SYS_READLINK (451): Read a symbolic link — not yet implemented.
pub fn sys_readlink(
    _path_ptr: u64,
    _path_len: u64,
    _buf_ptr: u64,
    _buf_len: u64,
) -> Result<u64, SyscallError> {
    let path = read_user_path(_path_ptr, _path_len)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let cwd = unsafe { (&*task.process.cwd.get()).clone() };
    let abs = resolve_path(&path, &cwd);
    crate::silo::enforce_path_for_current_task(&abs, true, false, false)?;
    Err(SyscallError::NotImplemented)
}

/// SYS_CHMOD (452): Change file mode bits.
pub fn sys_chmod(path_ptr: u64, path_len: u64, _mode: u64) -> Result<u64, SyscallError> {
    let path = read_user_path(path_ptr, path_len)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let cwd = unsafe { (&*task.process.cwd.get()).clone() };
    let abs = resolve_path(&path, &cwd);
    crate::silo::enforce_path_for_current_task(&abs, false, true, false)?;
    Err(SyscallError::NotImplemented)
}

/// SYS_FCHMOD (453): Change file mode bits on open fd.
pub fn sys_fchmod(_fd: u32, _mode: u64) -> Result<u64, SyscallError> {
    Err(SyscallError::NotImplemented)
}

/// SYS_TRUNCATE (454): Truncate file to given length.
pub fn sys_truncate(path_ptr: u64, path_len: u64, _length: u64) -> Result<u64, SyscallError> {
    let path = read_user_path(path_ptr, path_len)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;
    let cwd = unsafe { (&*task.process.cwd.get()).clone() };
    let abs = resolve_path(&path, &cwd);
    crate::silo::enforce_path_for_current_task(&abs, false, true, false)?;
    Err(SyscallError::NotImplemented)
}

/// SYS_FTRUNCATE (455): Truncate open fd to given length.
pub fn sys_ftruncate(_fd: u32, _length: u64) -> Result<u64, SyscallError> {
    Err(SyscallError::NotImplemented)
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

    // ── Root filesystem (RamFS on "/") ────────────────────────────────────
    // Must be mounted before any other scheme so that longest-prefix resolution
    // falls back to "/" for paths not covered by a more specific mount point.
    let rootfs = alloc::sync::Arc::new(RamfsScheme::new());
    if let Err(e) = mount::mount("/", rootfs.clone()) {
        log::error!("[VFS] Failed to mount /: {:?}", e);
    } else {
        // Populate the standard POSIX directory skeleton.
        for dir in &[
            "bin", "sbin", "etc", "tmp", "usr", "lib", "lib64", "home", "root", "run", "var",
            "mnt", "opt", "srv", "dev", "proc", "sys",
        ] {
            rootfs.ensure_dir(dir);
        }
        // Nested standard directories
        rootfs.ensure_dir("usr/bin");
        rootfs.ensure_dir("usr/sbin");
        rootfs.ensure_dir("usr/lib");
        rootfs.ensure_dir("var/log");
        rootfs.ensure_dir("var/tmp");
        rootfs.ensure_dir("run/lock");
        log::info!("[VFS] Mounted / (ramfs) with standard directory tree");
    }

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

    let ipc_scheme = Arc::new(ipcfs::IpcControlScheme::new());
    if let Err(e) = mount::mount("/ipc", ipc_scheme) {
        log::error!("[VFS] Failed to mount /ipc: {:?}", e);
    } else {
        log::info!("[VFS] Mounted /ipc (kernel ipc control scheme)");
    }

    // Mount /dev — raw block-device scheme backed by AHCI.
    // The scheme is registered regardless of whether a disk is present:
    // device files appear dynamically when the hardware is available.
    let dev_scheme = Arc::new(BlkDevScheme::new());
    if let Err(e) = mount::mount("/dev", dev_scheme) {
        log::error!("[VFS] Failed to mount /dev: {:?}", e);
    } else {
        log::info!("[VFS] Mounted /dev (block-device scheme)");
    }

    log::info!("[VFS] VFS ready");
}
