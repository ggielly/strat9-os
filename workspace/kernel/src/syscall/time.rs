//! Time-related syscalls: clock_gettime, nanosleep

use core::sync::atomic::Ordering;

use crate::{
    memory::userslice::{UserSliceRead, UserSliceReadWrite},
    process::{block_current_task, current_task_id, yield_task},
    syscall::error::SyscallError,
};

pub use strat9_abi::data::TimeSpec;

/// Get current monotonic time in nanoseconds since boot.
///
/// Uses the scheduler tick counter (100Hz = 10ms per tick).
#[inline]
pub fn current_time_ns() -> u64 {
    crate::process::scheduler::ticks() * 10_000_000 // 10ms = 10,000,000 ns
}

/// SYS_CLOCK_GETTIME: Get current monotonic time.
///
/// Returns the time as a u64 nanosecond count since boot.
/// For compatibility with POSIX, userspace can convert to timespec.
pub fn sys_clock_gettime() -> Result<u64, SyscallError> {
    Ok(current_time_ns())
}

/// SYS_NANOSLEEP: Sleep for a specified duration.
///
/// # Arguments
/// * `req_ptr` - Pointer to timespec structure with requested sleep duration
/// * `rem_ptr` - Optional pointer to timespec for remaining time (if interrupted)
///
/// # Returns
/// * 0 on success
/// * -EINTR if interrupted by a signal (remaining time written to rem_ptr)
/// * -EINVAL if the requested time is invalid
pub fn sys_nanosleep(req_ptr: u64, rem_ptr: u64) -> Result<u64, SyscallError> {
    // Read the requested timespec from userspace
    let req_slice = UserSliceRead::new(req_ptr, core::mem::size_of::<TimeSpec>() as usize)
        .map_err(|_| SyscallError::Fault)?; // EFAULT

    let req = req_slice
        .read_val::<TimeSpec>()
        .map_err(|_| SyscallError::Fault)?;

    // Validate the request
    if req.tv_sec < 0 || req.tv_nsec < 0 || req.tv_nsec >= 1_000_000_000 {
        return Err(SyscallError::InvalidArgument); // EINVAL
    }

    // Handle zero-duration sleep (just yield)
    if req.tv_sec == 0 && req.tv_nsec == 0 {
        yield_task();
        return Ok(0);
    }

    let sleep_duration_ns = req.to_nanos();
    let current_ns = current_time_ns();
    let wake_deadline_ns = current_ns.saturating_add(sleep_duration_ns);

    // Get current task ID
    let task_id = current_task_id().ok_or_else(|| SyscallError::PermissionDenied)?; // EPERM

    // Set the wake deadline on the task
    if let Some(task) = crate::process::get_task_by_id(task_id) {
        task.wake_deadline_ns
            .store(wake_deadline_ns, Ordering::Relaxed);
    }

    // Block the current task - it will be woken by:
    // 1. timer_tick() when the deadline expires (check_wake_deadlines)
    // 2. A signal (in which case we return EINTR)

    // Check for pending signals before blocking
    if let Some(task) = crate::process::get_task_by_id(task_id) {
        let pending = task.pending_signals.get_mask();
        let blocked = task.blocked_signals.get_mask();
        let unblocked_pending = pending & !blocked;
        if unblocked_pending != 0 {
            // Clear the deadline since we're not sleeping
            task.wake_deadline_ns.store(0, Ordering::Relaxed);
            return Err(SyscallError::Interrupted); // EINTR
        }
    }

    loop {
        block_current_task();

        if let Some(task) = crate::process::get_task_by_id(task_id) {
            let deadline = task.wake_deadline_ns.load(Ordering::Relaxed);
            let now = current_time_ns();

            if deadline == 0 || now >= deadline {
                task.wake_deadline_ns.store(0, Ordering::Relaxed);
                return Ok(0);
            }

            if crate::process::has_pending_signals() {
                task.wake_deadline_ns.store(0, Ordering::Relaxed);
                if rem_ptr != 0 {
                    let remaining_ns = deadline - now;
                    let remaining = TimeSpec::from_nanos(remaining_ns);
                    let rem_slice =
                        UserSliceReadWrite::new(rem_ptr, core::mem::size_of::<TimeSpec>() as usize)
                            .map_err(|_| SyscallError::Fault)?;
                    rem_slice
                        .write_val(&remaining)
                        .map_err(|_| SyscallError::Fault)?;
                }
                return Err(SyscallError::Interrupted);
            }
        } else {
            return Err(SyscallError::Fault);
        }
    }
}
