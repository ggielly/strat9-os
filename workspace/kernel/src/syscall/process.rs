//! Process and thread management syscalls.
//!
//! Implements PID/TID retrieval per the Strat9-OS ABI.

use crate::process::{
    create_session, current_pgid, current_pid, current_task_id, current_tid, get_parent_pid,
    get_pgid_by_pid, get_sid_by_pid, set_process_group,
};
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

/// SYS_GETPGID (318): Return process group id for `pid` (`0` = caller).
pub fn sys_getpgid(pid: i64) -> Result<u64, SyscallError> {
    if pid < 0 {
        return Err(SyscallError::InvalidArgument);
    }
    if pid == 0 {
        return current_pgid()
            .map(|pgid| pgid as u64)
            .ok_or(SyscallError::Fault);
    }
    get_pgid_by_pid(pid as u32)
        .map(|pgid| pgid as u64)
        .ok_or(SyscallError::NotFound)
}

/// POSIX getpgrp wrapper (equivalent to getpgid(0)).
pub fn sys_getpgrp() -> Result<u64, SyscallError> {
    current_pgid()
        .map(|pgid| pgid as u64)
        .ok_or(SyscallError::Fault)
}

/// SYS_GETSID (332): Return session id for `pid` (`0` = caller).
pub fn sys_getsid(pid: i64) -> Result<u64, SyscallError> {
    if pid < 0 {
        return Err(SyscallError::InvalidArgument);
    }
    if pid == 0 {
        return crate::process::current_sid()
            .map(|sid| sid as u64)
            .ok_or(SyscallError::Fault);
    }
    get_sid_by_pid(pid as u32)
        .map(|sid| sid as u64)
        .ok_or(SyscallError::NotFound)
}

/// SYS_SETPGID (317): set process group id.
pub fn sys_setpgid(pid: i64, pgid: i64) -> Result<u64, SyscallError> {
    if pid < 0 || pgid < 0 {
        return Err(SyscallError::InvalidArgument);
    }
    let caller = current_task_id().ok_or(SyscallError::Fault)?;
    let target_pid = if pid == 0 { None } else { Some(pid as u32) };
    let new_pgid = if pgid == 0 { None } else { Some(pgid as u32) };
    let final_pgid = set_process_group(caller, target_pid, new_pgid)?;
    Ok(final_pgid as u64)
}

/// SYS_SETSID (319): create a new session.
pub fn sys_setsid() -> Result<u64, SyscallError> {
    let caller = current_task_id().ok_or(SyscallError::Fault)?;
    create_session(caller).map(|sid| sid as u64)
}
