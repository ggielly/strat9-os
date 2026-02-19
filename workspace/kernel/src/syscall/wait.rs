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
        block_current_task, current_task_id, get_parent_id, has_pending_signals,
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
    fn new(pid: TaskId, exit_code: i32) -> Self {
        let mut msg = [0u8; 64];
        if exit_code == 0 {
            // Plan 9: empty msg means clean exit
        } else {
            // Write "exit <N>" into the buffer
            let s = format_exit_msg(exit_code);
            let n = s.len().min(63);
            msg[..n].copy_from_slice(&s.as_bytes()[..n]);
            msg[n] = 0;
        }
        Waitmsg {
            pid: pid.as_u64(),
            exit_code,
            _pad: 0,
            msg,
        }
    }
}

/// Format "exit <N>" without heap allocation (uses a small stack buffer).
fn format_exit_msg(code: i32) -> &'static str {
    // We only need this for debugging; use a constant table for common codes.
    // In a full kernel we'd use write! into an ArrayString.
    match code {
        1   => "exit 1",
        2   => "exit 2",
        126 => "exit 126",
        127 => "exit 127",
        128 => "exit 128",
        130 => "exit 130",
        _   => "exit",
    }
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
) -> Result<(TaskId, i32), SyscallError> {
    loop {
        match try_wait_child(parent_id, target) {
            WaitChildResult::Reaped { child, status } => return Ok((child, status)),

            WaitChildResult::NoChildren => return Err(SyscallError::NoChildren),

            WaitChildResult::StillRunning => {
                // Check for pending signals before sleeping so we can
                // return EINTR and let userspace run the signal handler.
                if has_pending_signals() {
                    return Err(SyscallError::Interrupted);
                }

                // Sleep until a child exits.  exit_current_task() calls
                // wake_task_locked(parent_id) which either unblocks us or
                // sets wake_pending so block_current_task() aborts immediately.
                block_current_task();

                // Woken — re-run the scan at the top of the loop.
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

    // Build child filter: negative pid or -1 → any child.
    let target: Option<TaskId> = if pid > 0 {
        Some(TaskId::from_u64(pid as u64))
    } else {
        None
    };

    // ── Non-blocking fast path ────────────────────────────────────────────
    if wnohang {
        return match try_wait_child(parent_id, target) {
            WaitChildResult::Reaped { child, status } => {
                write_wstatus(status_ptr, status)?;
                log::debug!("waitpid(WNOHANG): reaped {:?} status={}", child, status);
                Ok(child.as_u64())
            }
            WaitChildResult::NoChildren  => Err(SyscallError::NoChildren),
            WaitChildResult::StillRunning => Ok(0), // no zombie yet
        };
    }

    // ── Blocking path ─────────────────────────────────────────────────────
    let (child, status) = wait_blocking(parent_id, target)?;
    write_wstatus(status_ptr, status)?;
    log::debug!("waitpid: reaped {:?} status={}", child, status);
    Ok(child.as_u64())
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
    let (child, status) = wait_blocking(parent_id, None)?;

    if waitmsg_ptr != 0 {
        let wmsg = Waitmsg::new(child, status);
        let user = UserSliceWrite::new(waitmsg_ptr, core::mem::size_of::<Waitmsg>())?;
        // SAFETY: Waitmsg is repr(C) and fully initialised above.
        user.copy_from(unsafe {
            core::slice::from_raw_parts(
                &wmsg as *const Waitmsg as *const u8,
                core::mem::size_of::<Waitmsg>(),
            )
        });
    }

    log::debug!("sys_wait: reaped {:?} exit_code={}", child, status);
    Ok(child.as_u64())
}

/// SYS_PROC_GETPID (308): return the current task's ID.
pub fn sys_getpid() -> Result<u64, SyscallError> {
    Ok(current_task_id().ok_or(SyscallError::Fault)?.as_u64())
}

/// SYS_PROC_GETPPID (309): return the parent task's ID, or 0 if none.
pub fn sys_getppid() -> Result<u64, SyscallError> {
    let id = current_task_id().ok_or(SyscallError::Fault)?;
    Ok(get_parent_id(id).map(|p| p.as_u64()).unwrap_or(0))
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Write the Linux-encoded wait status to a nullable userspace pointer.
fn write_wstatus(status_ptr: u64, exit_code: i32) -> Result<(), SyscallError> {
    if status_ptr != 0 {
        let wstatus = encode_wstatus(exit_code);
        let user = UserSliceWrite::new(status_ptr, 4)?;
        user.copy_from(&wstatus.to_ne_bytes());
    }
    Ok(())
}
