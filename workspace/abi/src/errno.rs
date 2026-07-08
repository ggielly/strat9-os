//! Strat9 OS error codes (errno values).
//!
//! ABI convention: syscalls return `usize` in RAX.
//! - **Success**: any non-negative value.
//! - **Error**: negative errno in two's complement.
//!
//! Userspace detects errors with `if result > 0xFFFF_F000`, then converts:
//! ```ignore
//! let errno = !result + 1;  // or equivalently: -(result as isize) as usize
//! ```

/// Operation not permitted (e.g., missing capability).
pub const EPERM: usize = 1;

/// No such file or directory.
pub const ENOENT: usize = 2;

/// No such process (invalid PID/TID).
pub const ESRCH: usize = 3;

/// Interrupted system call (signal delivered during blocking op).
pub const EINTR: usize = 4;

/// Input/output error (hardware failure, bad sector, etc.).
pub const EIO: usize = 5;

/// Argument list too long (execve path or argv exceeds limit).
pub const E2BIG: usize = 7;

/// Exec format error (invalid ELF binary, wrong architecture).
pub const ENOEXEC: usize = 8;

/// Bad file descriptor (fd not open or already closed).
pub const EBADF: usize = 9;

/// No child processes (waitpid on non-existent child).
pub const ECHILD: usize = 10;

/// Resource temporarily unavailable (non-blocking would block).
pub const EAGAIN: usize = 11;

/// Cannot allocate memory (kernel heap or page allocation failed).
pub const ENOMEM: usize = 12;

/// Permission denied (capability check failed, file mode mismatch).
pub const EACCES: usize = 13;

/// Bad address (invalid pointer in syscall argument).
pub const EFAULT: usize = 14;

/// File exists (O_CREAT | O_EXCL on existing file).
pub const EEXIST: usize = 17;

/// Not a directory (expected directory, got file or device).
pub const ENOTDIR: usize = 20;

/// Is a directory (expected file, got directory).
pub const EISDIR: usize = 21;

/// Invalid argument (bad alignment, invalid flags, etc.).
pub const EINVAL: usize = 22;

/// Not a typewriter (ioctl on non-TTY device).
pub const ENOTTY: usize = 25;

/// No space left on device (disk full, inode exhaustion).
pub const ENOSPC: usize = 28;

/// Broken pipe (write to pipe with no readers).
pub const EPIPE: usize = 32;

/// Result too large (numeric overflow in math operation).
pub const ERANGE: usize = 34;

/// File name too long (path exceeds PATH_MAX).
pub const ENAMETOOLONG: usize = 36;

/// Function not implemented (syscall not supported by kernel).
pub const ENOSYS: usize = 38;

/// Directory not empty (rmdir on non-empty directory).
pub const ENOTEMPTY: usize = 39;

/// Too many levels of symbolic links (symlink loop detected).
pub const ELOOP: usize = 40;

/// Not supported (operation not supported by this filesystem/device).
pub const ENOTSUP: usize = 52;

/// Address family not supported (socket type not available).
pub const EAFNOSUPPORT: usize = 97;

/// Address already in use (socket bind to occupied port/address).
pub const EADDRINUSE: usize = 98;

/// No buffer space available (network buffer exhaustion).
pub const ENOBUFS: usize = 105;

/// Connection timed out (network or device timeout).
pub const ETIMEDOUT: usize = 110;

/// Connection refused (no listener on target port).
pub const ECONNREFUSED: usize = 111;
