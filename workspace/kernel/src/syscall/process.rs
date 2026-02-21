//! Process and thread management syscalls.
//!
//! Implements PID/TID retrieval per the Strat9-OS ABI.

use crate::process::{current_pid, current_task_id, current_tid, get_parent_pid};
use super::error::SyscallError;

/// SYS_GETPID (311): Return current process ID.
///
/// In Strat9, each task has a unique ID, so getpid returns the TaskId.
pub fn sys_getpid() -> Result<u64, SyscallError> {
    current_pid().map(|pid| pid as u64).ok_or(SyscallError::Fault)
}

/// SYS_GETTID (312): Return current thread ID.
///
/// In the current single-threaded silo model, TID == PID.
pub fn sys_gettid() -> Result<u64, SyscallError> {
    current_tid().map(|tid| tid as u64).ok_or(SyscallError::Fault)
}

/// SYS_GETPPID (313): Return parent process ID.
pub fn sys_getppid() -> Result<u64, SyscallError> {
    let child = current_task_id().ok_or(SyscallError::Fault)?;
    Ok(get_parent_pid(child).map(|p| p as u64).unwrap_or(0))
}
