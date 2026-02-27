//! Wait-family syscall handlers: waitpid, getpid, getppid.
//!
//! Design notes
//! ============
//!
//! The blocking loop follows the **Aero / Maestro** pattern:
//!
//! ```text
//! loop {
//!     try_wait_child()       ← O(log n) scan under scheduler lock
//!     StillRunning → block_current_task()
//!                             ↑ woken by exit_current_task → wake_task_locked(parent)
//! }
//! ```
//!
//! Lost-wakeup race: if the child exits between `try_wait_child` returning
//! `StillRunning` and `block_current_task()` reaching the scheduler lock,
//! `exit_current_task` will have already called `wake_task_locked(parent)`,
//! which sets `task.wake_pending = true`.  `block_current_task()` checks
//! this flag and aborts the block, so the parent re-runs the loop immediately
//! without sleeping.
//!
//! Signal interruption: after each sleep the pending-signal flag is checked;
//! if a signal is queued the syscall returns `-EINTR` so userspace can handle
//! it before retrying.
//!
//! ## Plan 9 flavour
//!
//! `sys_waitpid` encodes the exit status using the standard Linux `W_EXITCODE`
//! macro (`status << 8`), which musl/glibc decode correctly.  A separate
//! Plan 9-style `Waitmsg` structure (`pid + exit_code + msg[64]`) is written to
//! an optional second output pointer when the caller provides one (via the
//! `waitmsg_ptr` variant—`SYS_PROC_WAIT`).

use crate::{
    memory::UserSliceWrite,
    process::{
        block_current_task, current_task_clone, current_task_id, get_task_id_by_pid, has_pending_signals,
        scheduler::{try_wait_child, WaitChildResult},
        TaskId,
    },
    syscall::error::SyscallError,
};

// ─── Options flags ────────────────────────────────────────────────────────────

/// Do not block if no child has exited yet.
pub const WNOHANG: u32 = 1 << 0;

// ─── Plan 9-style exit message ────────────────────────────────────────────────

/// Plan 9-inspired exit message written to userspace by `SYS_PROC_WAIT`.
///
/// Layout (C-compatible, 80 bytes total):
/// ```text
/// pid       u64   — task ID of the exited child
/// exit_code i32   — numeric exit code (0 = success)
/// _pad      i32   — padding for alignment
/// msg       [u8; 64] — null-terminated exit description
/// ```
///
/// The `msg` field follows Plan 9 convention:
///   - `""` (empty, or first byte = 0)  → process exited normally (code 0)
///   - `"exit <N>"`                      → process exited with code N ≠ 0
///   - `"killed"`                        → process was killed by signal
#[repr(C)]
pub struct Waitmsg {
    pub pid: u64,
    pub exit_code: i32,
    pub _pad: i32,
    pub msg: [u8; 64],
}

impl Waitmsg {
    fn new(pid: u64, exit_code: i32) -> Self {
        let mut msg = [0u8; 64];
        if exit_code != 0 {
            // Write "exit <N>" using a stack buffer — no heap, no format!.
            let prefix = b"exit ";
            msg[..prefix.len()].copy_from_slice(prefix);
            write_decimal(exit_code, &mut msg[prefix.len()..]);
        }
        // exit_code == 0: leave msg all-zero (Plan 9: empty = clean exit)
        Waitmsg {
            pid,
            exit_code,
            _pad: 0,
            msg,
        }
    }
}

/// Write the decimal representation of `n` into `buf`, null-terminated.
///
/// Uses digit-reversal on a small stack scratch buffer — no heap allocation.
/// Handles negative values with a leading `-`.  Writes at most `buf.len()-1`
/// digits and always null-terminates `buf[0]` on empty / overflow.
fn write_decimal(n: i32, buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }

    // Collect digits into a scratch buffer (i32 is at most 11 chars: "-2147483648")
    let mut scratch = [0u8; 12];
    let mut len = 0usize;

    let negative = n < 0;
    // Work in u32 to avoid overflow on i32::MIN
    let mut v: u32 = if negative {
        (n as i64).unsigned_abs() as u32
    } else {
        n as u32
    };

    if v == 0 {
        scratch[0] = b'0';
        len = 1;
    } else {
        while v > 0 && len < scratch.len() {
            scratch[len] = b'0' + (v % 10) as u8;
            v /= 10;
            len += 1;
        }
        // scratch holds digits in reverse order — fix that in-place
        scratch[..len].reverse();
    }

    // Prepend '-' if negative
    let (digits_start, digits_len) = if negative {
        let total = len + 1;
        // Shift digits right by 1 to make room for '-'
        for i in (1..total.min(scratch.len())).rev() {
            scratch[i] = scratch[i - 1];
        }
        scratch[0] = b'-';
        (0, total.min(scratch.len()))
    } else {
        (0, len)
    };

    // Copy into buf, leaving room for null terminator
    let copy_len = digits_len.min(buf.len() - 1);
    buf[..copy_len].copy_from_slice(&scratch[digits_start..digits_start + copy_len]);
    buf[copy_len] = 0;
}

// ─── Helper ───────────────────────────────────────────────────────────────────

/// Encode `exit_code` as a Linux `wstatus` word: `W_EXITCODE(code, 0)`.
///
/// The low 7 bits are the termination signal (0 = exited normally).
/// Bits 8-15 are the exit code.
#[inline]
fn encode_wstatus(exit_code: i32) -> i32 {
    (exit_code & 0xff) << 8
}

/// Block until a matching child becomes a zombie, checking signals each cycle.
///
/// Returns `Ok(WaitChildResult::Reaped { .. })` or propagates `EINTR` /
/// `NoChildren`.
fn wait_blocking(
    parent_id: TaskId,
    target: Option<TaskId>,
) -> Result<(TaskId, u64, i32), SyscallError> {
    crate::serial_println!(
        "[wait_blocking] start: parent={:?}, target={:?}",
        parent_id,
        target
    );
    loop {
        crate::serial_println!("[wait_blocking] trying wait...");
        match try_wait_child(parent_id, target) {
            WaitChildResult::Reaped { child, pid, status } => {
                crate::serial_println!("[wait_blocking] reaped child pid={}", pid);
                return Ok((child, pid as u64, status));
            }
            WaitChildResult::NoChildren => {
                crate::serial_println!("[wait_blocking] no children");
                return Err(SyscallError::NoChildren);
            }
            WaitChildResult::StillRunning => {
                if has_pending_signals() {
                    crate::serial_println!("[wait_blocking] interrupted");
                    return Err(SyscallError::Interrupted);
                }

                crate::serial_println!("[wait_blocking] blocking current task");
                block_current_task();
                crate::serial_println!("[wait_blocking] woken up");
            }
        }
    }
}

// ─── Syscall handlers ─────────────────────────────────────────────────────────

/// SYS_PROC_WAITPID (310): wait for a child process to exit.
///
/// Arguments:
///   - `pid`        : child task ID to wait for, or `-1` (any child).
///   - `status_ptr` : userspace `*i32` to receive the encoded wait status
///                    (`W_EXITCODE`). Pass `0` to discard.
///   - `options`    : `WNOHANG (1)` — return immediately if no child ready.
///
/// Returns:
///   - child task ID on success.
///   - `0` if `WNOHANG` and no child has exited yet.
///
/// Errors:
///   - `-ECHILD (-10)` — no matching children.
///   - `-EINTR  (-4)`  — interrupted by a pending signal.
///   - `-EINVAL (-22)` — unknown option bits.
pub fn sys_waitpid(pid: i64, status_ptr: u64, options: u32) -> Result<u64, SyscallError> {
    if options & !WNOHANG != 0 {
        return Err(SyscallError::InvalidArgument);
    }
    let wnohang = options & WNOHANG != 0;

    let parent_id = current_task_id().ok_or(SyscallError::Fault)?;

    // Build child filter.
    //   pid > 0  → wait for that specific child
    //   pid == -1 → wait for any child
    //   pid == 0  → process-group semantics (not supported)
    //   pid < -1  → wait for group |pid| (not supported)
    let target: Option<TaskId> = if pid > 0 {
        match get_task_id_by_pid(pid as u32) {
            Some(t) => Some(t),
            None => return Err(SyscallError::NoChildren),
        }
    } else if pid == -1 {
        None // any child
    } else {
        // pid == 0 or pid < -1: process-group wait — not implemented.
        return Err(SyscallError::InvalidArgument);
    };

    // ── Non-blocking fast path ────────────────────────────────────────────
    if wnohang {
        return match try_wait_child(parent_id, target) {
            WaitChildResult::Reaped { pid, status, .. } => {
                write_wstatus(status_ptr, status)?;
                log::debug!("waitpid(WNOHANG): reaped pid={} status={}", pid, status);
                Ok(pid as u64)
            }
            WaitChildResult::NoChildren => Err(SyscallError::NoChildren),
            WaitChildResult::StillRunning => Ok(0), // no zombie yet
        };
    }

    // ── Blocking path ─────────────────────────────────────────────────────
    let (_child, child_pid, status) = wait_blocking(parent_id, target)?;
    write_wstatus(status_ptr, status)?;
    log::debug!("waitpid: reaped pid={} status={}", child_pid, status);
    Ok(child_pid)
}

/// SYS_PROC_WAIT (311): Plan 9-style wait — any child, writes full Waitmsg.
///
/// Arguments:
///   - `waitmsg_ptr`: userspace pointer to a `Waitmsg` struct (80 bytes).
///                    Pass `0` to discard.
///
/// Returns the child task ID on success.
///
/// Errors: `-ECHILD`, `-EINTR`.
pub fn sys_wait(waitmsg_ptr: u64) -> Result<u64, SyscallError> {
    let parent_id = current_task_id().ok_or(SyscallError::Fault)?;
    let (_child, child_pid, status) = wait_blocking(parent_id, None)?;

    if waitmsg_ptr != 0 {
        let wmsg = Waitmsg::new(child_pid, status);
        // SAFETY: Waitmsg is repr(C) and fully initialised above.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &wmsg as *const Waitmsg as *const u8,
                core::mem::size_of::<Waitmsg>(),
            )
        };
        write_user_with_cow(waitmsg_ptr, bytes)?;
    }

    log::debug!("sys_wait: reaped pid={} exit_code={}", child_pid, status);
    Ok(child_pid)
}

/// SYS_PROC_GETPID (308): return the current task's ID.
pub fn sys_getpid() -> Result<u64, SyscallError> {
    super::process::sys_getpid()
}

/// SYS_PROC_GETPPID (309): return the parent task's ID, or 0 if none.
pub fn sys_getppid() -> Result<u64, SyscallError> {
    super::process::sys_getppid()
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Write the Linux-encoded wait status to a nullable userspace pointer.
fn write_wstatus(status_ptr: u64, exit_code: i32) -> Result<(), SyscallError> {
    if status_ptr != 0 {
        let wstatus = encode_wstatus(exit_code);
        write_user_with_cow(status_ptr, &wstatus.to_ne_bytes())?;
    }
    Ok(())
}

fn resolve_cow_for_range(ptr: u64, len: usize) -> Result<(), SyscallError> {
    if len == 0 {
        return Ok(());
    }
    let task = current_task_clone().ok_or(SyscallError::Fault)?;
    let address_space = unsafe { &*task.process.address_space.get() };
    let start = ptr & !0xfff;
    let end = (ptr + (len as u64).saturating_sub(1)) & !0xfff;
    let mut page = start;
    loop {
        crate::syscall::fork::handle_cow_fault(page, address_space).map_err(|_| SyscallError::Fault)?;
        if page == end {
            break;
        }
        page = page.saturating_add(4096);
    }
    Ok(())
}

fn write_user_with_cow(ptr: u64, data: &[u8]) -> Result<(), SyscallError> {
    match UserSliceWrite::new(ptr, data.len()) {
        Ok(user) => {
            user.copy_from(data);
            Ok(())
        }
        Err(crate::memory::UserSliceError::PermissionDenied) => {
            resolve_cow_for_range(ptr, data.len())?;
            let user = UserSliceWrite::new(ptr, data.len())?;
            user.copy_from(data);
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}
