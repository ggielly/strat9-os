/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! Time-related syscalls: clock_gettime, nanosleep, clock_nanosleep

use core::sync::atomic::{AtomicI64, AtomicU8, Ordering};

use crate::{
    memory::userslice::{UserSliceRead, UserSliceReadWrite},
    process::{block_current_task, current_task_id, yield_task},
    syscall::error::SyscallError,
};

pub use strat9_abi::data::TimeSpec;

// SAFETY: TimeSpec is a #[repr(C)] struct with two i64 fields : all bit
// patterns are valid.  Implementing the sealed UserPod trait here allows
// read_val::<TimeSpec>() / write_val(&TimeSpec) in UserSlice.
unsafe impl crate::memory::userslice::UserPod for TimeSpec {}

/// Clock IDs for clock_gettime (POSIX-compatible subset)
pub const CLOCK_MONOTONIC: u32 = 1;
pub const CLOCK_REALTIME: u32 = 0;

/// Flag for clock_nanosleep: request is an absolute time based on the clock.
const TIMER_ABSTIME: i32 = 1;

/// Get current monotonic time in nanoseconds since boot.
///
/// Uses the scheduler tick counter (100Hz = 10ms per tick).
#[inline]
pub fn current_time_ns() -> u64 {
    crate::process::scheduler::ticks() * 10_000_000 // 10ms = 10,000,000 ns
}

// ============================================================================
// Wall clock (CLOCK_REALTIME)
// ============================================================================

/// `0` = not initialised, `1` = one CPU is reading the RTC, `2` = ready.
static WALL_STATE: AtomicU8 = AtomicU8::new(0);
/// `realtime - monotonic`, in nanoseconds (Unix epoch based).
static WALL_OFFSET_NS: AtomicI64 = AtomicI64::new(0);

/// Whether the CMOS fields describe a believable date. A never-programmed
/// CMOS reads back as zeroes / 0xFF, which `to_timestamp` happily turns into
/// an instant that *looks* valid, so the fields must be checked first.
fn rtc_plausible(dt: &crate::hardware::timer::rtc::RtcDateTime) -> bool {
    (1..=12).contains(&dt.month)
        && (1..=31).contains(&dt.day)
        && dt.hour <= 23
        && dt.minute <= 59
        && dt.second <= 60
        && (2000..=2100).contains(&dt.year)
}

/// Seed the wall clock from the RTC the first time it is needed.
fn ensure_wall_clock() {
    if WALL_STATE.load(Ordering::Acquire) == 2 {
        return;
    }
    if WALL_STATE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return; // another CPU is initialising; offset 0 until it is done
    }
    let mono = current_time_ns() as i64;
    // The first caller is usually the VFS at early boot, long before
    // `rtc::init()` runs, so read the CMOS directly rather than waiting for
    // `is_available()`: the read only needs port I/O. A CMOS that was never
    // programmed (or a platform with stubbed port I/O) fails the plausibility
    // check and leaves the clock on uptime.
    let dt = crate::hardware::timer::rtc::get_datetime();
    if rtc_plausible(&dt) {
        let unix_ns = (dt.to_timestamp() as i64).saturating_mul(1_000_000_000);
        WALL_OFFSET_NS.store(unix_ns - mono, Ordering::Release);
    }
    WALL_STATE.store(2, Ordering::Release);
}

/// Current wall-clock time in nanoseconds since the Unix epoch.
///
/// Backed by the RTC (read once, then advanced by the monotonic tick
/// counter) and adjustable with [`set_realtime_ns`] (e.g. `ntpdate`). With no
/// usable RTC it degrades to uptime, i.e. the previous behaviour.
pub fn realtime_ns() -> u64 {
    ensure_wall_clock();
    let off = WALL_OFFSET_NS.load(Ordering::Acquire);
    (current_time_ns() as i64).saturating_add(off).max(0) as u64
}

/// `realtime - monotonic` offset in nanoseconds.
fn wall_offset_ns() -> i64 {
    ensure_wall_clock();
    WALL_OFFSET_NS.load(Ordering::Acquire)
}

/// Step the wall clock to `unix_ns` nanoseconds since the Unix epoch.
pub fn set_realtime_ns(unix_ns: u64) {
    let mono = current_time_ns() as i64;
    WALL_OFFSET_NS.store((unix_ns as i64) - mono, Ordering::Release);
    WALL_STATE.store(2, Ordering::Release);
}

/// SYS_CLOCK_GETTIME: Get current time for the specified clock.
///
/// # Arguments
/// * `clock_id` - Clock identifier (CLOCK_MONOTONIC or CLOCK_REALTIME)
/// * `tp_ptr` - Pointer to userspace timespec structure to fill
///
/// # Returns
/// * 0 on success
/// * -EINVAL if clock_id is invalid
/// * -EFAULT if tp_ptr is invalid
///
/// # POSIX compatibility
/// This follows the POSIX signature: `int clock_gettime(clockid_t clock_id, struct timespec *tp)`
pub fn sys_clock_gettime(clock_id: u32, tp_ptr: u64) -> Result<u64, SyscallError> {
    if tp_ptr == 0 {
        return Err(SyscallError::Fault);
    }

    // CLOCK_MONOTONIC counts from boot; CLOCK_REALTIME is the RTC-backed
    // wall clock (Unix epoch).
    let now_ns = match clock_id {
        CLOCK_MONOTONIC => current_time_ns(),
        CLOCK_REALTIME => realtime_ns(),
        _ => return Err(SyscallError::InvalidArgument),
    };
    let ts = TimeSpec::from_nanos(now_ns);

    let user = UserSliceReadWrite::new(tp_ptr, core::mem::size_of::<TimeSpec>())?;
    user.write_val(&ts).map_err(|_| SyscallError::Fault)?;
    Ok(0)
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

/// SYS_CLOCK_NANOSLEEP: Sleep with clock selection and absolute/relative mode.
///
/// # Arguments
/// * `clock_id` - Clock identifier (CLOCK_MONOTONIC or CLOCK_REALTIME)
/// * `flags` - 0 for relative sleep, TIMER_ABSTIME (1) for absolute wake-up time
/// * `req_ptr` - Pointer to timespec (absolute time if TIMER_ABSTIME, else duration)
/// * `rem_ptr` - Optional pointer to timespec for remaining time (relative mode only)
///
/// # Returns
/// * 0 on success
/// * -EINTR if interrupted by a signal
/// * -EINVAL if clock_id or timespec is invalid
/// * -EFAULT if req_ptr is invalid
///
/// # POSIX compatibility
/// POSIX signature: `int clock_nanosleep(clockid_t clock_id, int flags,
///                                       const struct timespec *request,
///                                       struct timespec *remain)`
pub fn sys_clock_nanosleep(
    clock_id: u32,
    flags: i32,
    req_ptr: u64,
    rem_ptr: u64,
) -> Result<u64, SyscallError> {
    // Validate clock_id
    match clock_id {
        CLOCK_MONOTONIC | CLOCK_REALTIME => {}
        _ => return Err(SyscallError::InvalidArgument),
    }

    // Read the request timespec from userspace
    let req_slice = UserSliceRead::new(req_ptr, core::mem::size_of::<TimeSpec>() as usize)
        .map_err(|_| SyscallError::Fault)?;

    let req = req_slice
        .read_val::<TimeSpec>()
        .map_err(|_| SyscallError::Fault)?;

    // Validate the timespec fields
    if req.tv_sec < 0 || req.tv_nsec < 0 || req.tv_nsec >= 1_000_000_000 {
        return Err(SyscallError::InvalidArgument);
    }

    let current_ns = current_time_ns();

    // Compute the wake deadline
    let wake_deadline_ns = if (flags & TIMER_ABSTIME) != 0 {
        // Absolute mode: request value IS the deadline. Wake deadlines run on
        // the monotonic scheduler clock, so shift a wall-clock request back.
        let mut deadline = req.to_nanos();
        if clock_id == CLOCK_REALTIME {
            let off = wall_offset_ns();
            deadline = if off >= 0 {
                deadline.saturating_sub(off as u64)
            } else {
                deadline.saturating_add(off.unsigned_abs())
            };
        }
        // If the deadline is in the past, return immediately (success per POSIX)
        if deadline <= current_ns {
            return Ok(0);
        }
        deadline
    } else {
        // Relative mode: deadline = now + request duration
        let sleep_duration_ns = req.to_nanos();

        // Handle zero-duration sleep (just yield)
        if sleep_duration_ns == 0 {
            yield_task();
            return Ok(0);
        }

        current_ns.saturating_add(sleep_duration_ns)
    };

    // Get current task ID
    let task_id = current_task_id().ok_or_else(|| SyscallError::PermissionDenied)?;

    // Set the wake deadline on the task
    if let Some(task) = crate::process::get_task_by_id(task_id) {
        task.wake_deadline_ns
            .store(wake_deadline_ns, Ordering::Relaxed);
    }

    // Check for pending signals before blocking
    if let Some(task) = crate::process::get_task_by_id(task_id) {
        let pending = task.pending_signals.get_mask();
        let blocked = task.blocked_signals.get_mask();
        let unblocked_pending = pending & !blocked;
        if unblocked_pending != 0 {
            task.wake_deadline_ns.store(0, Ordering::Relaxed);
            return Err(SyscallError::Interrupted);
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

                // Write remaining time only in relative mode
                if (flags & TIMER_ABSTIME) == 0 && rem_ptr != 0 {
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
