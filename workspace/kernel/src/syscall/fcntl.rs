//! `fcntl()` syscall implementation for file descriptor control.
//!
//! Provides fcntl operations for file descriptor flags (CLOEXEC).

use crate::{process::current_task_clone, syscall::error::SyscallError};

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
/// - F_GETFD (1): Get file descriptor flags
/// - F_SETFD (2): Set file descriptor flags (FD_CLOEXEC)
pub fn sys_fcntl(fd: u64, cmd: u64, arg: u64) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;

    match cmd {
        F_GETFD => {
            // Get file descriptor flags
            unsafe {
                let fd_table = &*task.process.fd_table.get();
                let cloexec = fd_table.get_cloexec(fd as u32)?;
                Ok(if cloexec { FD_CLOEXEC } else { 0 })
            }
        }
        F_SETFD => {
            // Set file descriptor flags
            unsafe {
                let fd_table = &mut *task.process.fd_table.get();
                let cloexec = (arg & FD_CLOEXEC) != 0;
                fd_table.set_cloexec(fd as u32, cloexec)?;
                Ok(0)
            }
        }
        F_DUPFD => {
            // Duplicate file descriptor (minimum FD >= arg)
            // TODO: implement proper dup with minimum FD
            unsafe {
                let fd_table = &mut *task.process.fd_table.get();
                let new_fd = fd_table.duplicate(fd as u32)?;
                Ok(new_fd as u64)
            }
        }
        F_GETFL | F_SETFL => {
            // Get/set file status flags (not implemented yet)
            Err(SyscallError::NotImplemented)
        }
        _ => Err(SyscallError::InvalidArgument),
    }
}
