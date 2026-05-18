//! Asynchronous I/O syscall handlers.
//!
//! Dispatches SQEs to VFS backends via `AsyncScheme`,
//! drains completions, and blocks when `min_complete > 0`.

use crate::syscall::error::SyscallError;

use super::{complete, dispatch, ring::RingError};

/// SYS_ASYNC_SETUP(entries: u32, flags: u32) → ring_id: u64
pub fn sys_async_setup(entries: u64, _flags: u64) -> Result<u64, SyscallError> {
    let Some(task) = crate::process::current_task_clone() else {
        return Err(SyscallError::PermissionDenied);
    };
    let pid = task.pid;
    let entries = entries as u32;

    super::ring::Ring::create(pid, entries).map_err(|e| match e {
        RingError::Alloc => SyscallError::OutOfMemory,
        RingError::NotFound => SyscallError::BadHandle,
        RingError::TooManyRings => SyscallError::OutOfMemory,
    })
}

/// SYS_ASYNC_ENTER(ring_id: u64, to_submit: u32, min_complete: u32, flags: u32) → completed: u64
pub fn sys_async_enter(
    ring_id: u64,
    to_submit: u64,
    min_complete: u64,
    _flags: u64,
) -> Result<u64, SyscallError> {
    let to_submit = to_submit as u32;
    let min_complete = min_complete as u32;

    // dispatch submitted SQEs to backends
    if to_submit > 0 {
        dispatch::drain_submissions(ring_id, to_submit);
    }

    // Drain available completions
    let mut completed = complete::drain_completions(ring_id, min_complete);

    // If caller asked for more completions than available, block and wait
    if completed == 0 && min_complete > 0 {
        // use ring-specific WaitQueue for efficient wakeup.
        // For now, yield and let the scheduler pick another task.
        crate::process::yield_task();

        // After rescheduling, try draining again
        completed = complete::drain_completions(ring_id, min_complete);
    }

    Ok(completed as u64)
}

/// SYS_ASYNC_CANCEL(ring_id: u64, user_data: u64, flags: u32) → result: u64
pub fn sys_async_cancel(_ring_id: u64, _user_data: u64, _flags: u64) -> Result<u64, SyscallError> {
    // lookup in-flight operation by user_data, cancel if not yet completed
    Ok(0)
}
