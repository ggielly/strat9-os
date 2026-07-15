//! `fcntl()` syscall implementation for file descriptor control.
//!
//! Provides fcntl operations for file descriptor flags (CLOEXEC).

use crate::{process::current_task_clone, syscall::error::SyscallError};
use crate::vfs::scheme::OpenFlags;

// fcntl commands
pub const F_DUPFD: u64 = 0;
pub const F_GETFD: u64 = 1;
pub const F_SETFD: u64 = 2;
pub const F_GETFL: u64 = 3;
pub const F_SETFL: u64 = 4;

// File descriptor flags
pub const FD_CLOEXEC: u64 = 1;

/// SYS_FCNTL (313): manipulate file descriptor.
///
/// Supported commands:
/// - F_DUPFD (0): Duplicate file descriptor
/// - F_GETFD (1): Get file descriptor flags
/// - F_SETFD (2): Set file descriptor flags (FD_CLOEXEC)
/// - F_GETFL (3): Get file status flags
/// - F_SETFL (4): Set file status flags (O_APPEND, O_NONBLOCK)
pub fn sys_fcntl(fd: u64, cmd: u64, arg: u64) -> Result<u64, SyscallError> {
    if fd > u32::MAX as u64 {
        return Err(SyscallError::BadHandle);
    }
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;

    match cmd {
        F_GETFD => {
            unsafe {
                let fd_table = &*task.process.fd_table.get();
                let cloexec = fd_table.get_cloexec(fd as u32)?;
                Ok(if cloexec { FD_CLOEXEC } else { 0 })
            }
        }
        F_SETFD => {
            unsafe {
                let fd_table = &mut *task.process.fd_table.get();
                let cloexec = (arg & FD_CLOEXEC) != 0;
                fd_table.set_cloexec(fd as u32, cloexec)?;
                Ok(0)
            }
        }
        F_DUPFD => {
            if arg > u32::MAX as u64 {
                return Err(SyscallError::InvalidArgument);
            }
            unsafe {
                let fd_table = &mut *task.process.fd_table.get();
                let new_fd = fd_table.duplicate_from(fd as u32, arg as u32)?;
                Ok(new_fd as u64)
            }
        }
        F_GETFL => {
            let fd_table = unsafe { &*task.process.fd_table.get() };
            let file = fd_table.get(fd as u32)?;
            Ok(file.open_flags().bits() as u64)
        }
        F_SETFL => {
            // Only O_APPEND, O_NONBLOCK, O_ASYNC can be changed via F_SETFL
            const CHANGEABLE: u32 = OpenFlags::APPEND.bits()
                | OpenFlags::NONBLOCK.bits();
            let new_flags = OpenFlags::from_bits_truncate((arg as u32) & CHANGEABLE);
            unsafe {
                let fd_table = &mut *task.process.fd_table.get();
                fd_table.replace_open_flags(fd as u32, new_flags)?;
            }
            Ok(0)
        }
        _ => Err(SyscallError::InvalidArgument),
    }
}
