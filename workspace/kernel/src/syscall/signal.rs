//! Signal-related syscall handlers for Strat9-OS.

use super::error::SyscallError;
use crate::{
    memory::{UserSliceRead, UserSliceWrite},
    process::{
        current_pgid, current_task_clone, current_task_id, get_all_tasks, get_task_id_by_pid,
        get_task_ids_in_pgid,
        signal::{SigAction, SigStack, Signal, SignalSet},
        TaskId,
    },
};

/// SYS_SIGACTION (322): set up a signal handler.
///
/// arg1 = signum, arg2 = act_ptr (new action), arg3 = oact_ptr (old action out)
pub fn sys_sigaction(signum: u64, act_ptr: u64, oact_ptr: u64) -> Result<u64, SyscallError> {
    use core::mem;

    const SA_NOCLDSTOP: u64 = 1 << 0;
    const SA_NOCLDWAIT: u64 = 1 << 1;
    const SA_SIGINFO: u64 = 1 << 2;
    const SA_RESTORER: u64 = 1 << 3;
    const SA_ONSTACK: u64 = 1 << 4;
    const SA_RESTART: u64 = 1 << 5;
    const SA_NODEFER: u64 = 1 << 6;
    const SA_RESETHAND: u64 = 1 << 7;

    let signal = Signal::from_u32(signum as u32).ok_or(SyscallError::InvalidArgument)?;

    // Cannot set handler for SIGKILL or SIGSTOP
    if signal.is_uncatchable() {
        return Err(SyscallError::InvalidArgument);
    }

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;

    // SAFETY: we have a reference to the task.
    unsafe {
        let actions = &mut *task.signal_actions.get();

        // If oact_ptr is not null, write the old action.
        if oact_ptr != 0 {
            let old_action = actions[signum as usize];
            let user = UserSliceWrite::new(oact_ptr, mem::size_of::<SigActionRaw>())?;

            // Convert SigAction to raw representation
            let raw = match old_action {
                SigAction::Default => SigActionRaw {
                    sa_handler: 0, // SIG_DFL
                    sa_flags: 0,
                    sa_restorer: 0,
                    sa_mask: 0,
                },
                SigAction::Ignore => SigActionRaw {
                    sa_handler: 1, // SIG_IGN
                    sa_flags: 0,
                    sa_restorer: 0,
                    sa_mask: 0,
                },
                SigAction::Handler(addr) => SigActionRaw {
                    sa_handler: addr,
                    sa_flags: 0,
                    sa_restorer: 0,
                    sa_mask: 0,
                },
            };
            user.copy_from(&raw.to_bytes());
        }

        // If act_ptr is not null, update the action.
        if act_ptr != 0 {
            let user = UserSliceRead::new(act_ptr, mem::size_of::<SigActionRaw>())?;
            let bytes = user.read_to_vec();
            if bytes.len() != mem::size_of::<SigActionRaw>() {
                return Err(SyscallError::InvalidArgument);
            }
            let raw = SigActionRaw::from_bytes(&bytes);

            let new_action = if raw.sa_handler == 0 {
                SigAction::Default
            } else if raw.sa_handler == 1 {
                SigAction::Ignore
            } else {
                SigAction::Handler(raw.sa_handler)
            };

            actions[signum as usize] = new_action;
        }
    }

    Ok(0)
}

/// Raw representation of struct sigaction for userspace
#[repr(C)]
struct SigActionRaw {
    sa_handler: u64,
    sa_flags: u64,
    sa_restorer: u64,
    sa_mask: u64,
}

impl SigActionRaw {
    fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&self.sa_handler.to_ne_bytes());
        bytes[8..16].copy_from_slice(&self.sa_flags.to_ne_bytes());
        bytes[16..24].copy_from_slice(&self.sa_restorer.to_ne_bytes());
        bytes[24..32].copy_from_slice(&self.sa_mask.to_ne_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            sa_handler: u64::from_ne_bytes(bytes[0..8].try_into().unwrap()),
            sa_flags: u64::from_ne_bytes(bytes[8..16].try_into().unwrap()),
            sa_restorer: u64::from_ne_bytes(bytes[16..24].try_into().unwrap()),
            sa_mask: u64::from_ne_bytes(bytes[24..32].try_into().unwrap()),
        }
    }
}

/// SYS_SIGALTSTACK (323): Set/get signal alternate stack.
///
/// arg1 = ss_ptr (new stack), arg2 = old_ss_ptr (old stack out)
pub fn sys_sigaltstack(ss_ptr: u64, old_ss_ptr: u64) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;

    // SAFETY: We have a reference to the task.
    unsafe {
        let stack = &mut *task.signal_stack.get();

        // If old_ss_ptr is not null, write the old stack.
        if old_ss_ptr != 0 {
            let user = UserSliceWrite::new(old_ss_ptr, 24)?; // sizeof(SigStack)
            let raw = match stack {
                Some(s) => SigStackRaw {
                    ss_sp: s.ss_sp,
                    ss_flags: s.ss_flags,
                    ss_size: s.ss_size,
                },
                None => SigStackRaw {
                    ss_sp: 0,
                    ss_flags: 1, // SS_DISABLE
                    ss_size: 0,
                },
            };
            user.copy_from(&raw.to_bytes());
        }

        // If ss_ptr is not null, update the stack.
        if ss_ptr != 0 {
            let user = UserSliceRead::new(ss_ptr, 24)?;
            let bytes = user.read_to_vec();
            if bytes.len() != 24 {
                return Err(SyscallError::InvalidArgument);
            }
            let raw = SigStackRaw::from_bytes(&bytes);

            if raw.ss_flags & 1 != 0 {
                // SS_DISABLE
                *stack = None;
            } else {
                *stack = Some(SigStack {
                    ss_sp: raw.ss_sp,
                    ss_flags: raw.ss_flags,
                    ss_size: raw.ss_size,
                });
            }
        }
    }

    Ok(0)
}

#[repr(C)]
struct SigStackRaw {
    ss_sp: u64,
    ss_flags: i32,
    ss_size: usize,
}

impl SigStackRaw {
    fn to_bytes(&self) -> [u8; 24] {
        let mut bytes = [0u8; 24];
        bytes[0..8].copy_from_slice(&self.ss_sp.to_ne_bytes());
        bytes[8..12].copy_from_slice(&self.ss_flags.to_ne_bytes());
        bytes[12..16].copy_from_slice(&(self.ss_size as u32).to_ne_bytes());
        bytes[16..24].copy_from_slice(&(self.ss_size >> 32).to_ne_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            ss_sp: u64::from_ne_bytes(bytes[0..8].try_into().unwrap()),
            ss_flags: i32::from_ne_bytes(bytes[8..12].try_into().unwrap()),
            ss_size: (u32::from_ne_bytes(bytes[12..16].try_into().unwrap()) as usize)
                | ((u32::from_ne_bytes(bytes[16..24].try_into().unwrap()) as usize) << 32),
        }
    }
}

/// SYS_SIGPENDING (324): Check for pending signals.
///
/// arg1 = set_ptr (output signal set)
pub fn sys_sigpending(set_ptr: u64) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;

    // SAFETY: We have a reference to the task.
    unsafe {
        let pending = &*task.pending_signals.get();
        let mask = pending.get_mask();

        if set_ptr != 0 {
            let user = UserSliceWrite::new(set_ptr, 8)?;
            user.copy_from(&mask.to_ne_bytes());
        }
    }

    Ok(0)
}

/// SYS_SIGSUSPEND (325): Wait for signals.
///
/// arg1 = mask_ptr (temporary signal mask)
/// Returns EINTR if a signal was caught
pub fn sys_sigsuspend(mask_ptr: u64) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;

    // SAFETY: We have a reference to the task.
    unsafe {
        // Save the old mask
        let blocked = &*task.blocked_signals.get();
        let old_mask = blocked.get_mask();

        // Set the new mask
        if mask_ptr != 0 {
            let user = UserSliceRead::new(mask_ptr, 8)?;
            let mut buf = [0u8; 8];
            user.copy_to(&mut buf);
            let new_mask = u64::from_ne_bytes(buf);
            blocked.set_mask(new_mask);
        }

        // Block the task until a signal arrives
        // The task will be woken by send_signal() if an unblocked signal is pending
        crate::process::block_current_task();

        // Restore the old mask
        blocked.set_mask(old_mask);
    }

    // If we get here, we were woken by a signal
    Err(SyscallError::Interrupted)
}

/// SYS_SIGTIMEDWAIT (326): Wait for signals with timeout.
///
/// arg1 = set_ptr (signal set to wait for), arg2 = siginfo_ptr (output), arg3 = timeout_ptr
pub fn sys_sigtimedwait(
    set_ptr: u64,
    _siginfo_ptr: u64,
    timeout_ptr: u64,
) -> Result<u64, SyscallError> {
    // TODO: Implement proper timed wait
    // For now, just check if any signal in the set is pending

    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;

    // SAFETY: We have a reference to the task.
    unsafe {
        let pending = &*task.pending_signals.get();
        let blocked = &*task.blocked_signals.get();

        // Read the signal set to wait for
        if set_ptr != 0 {
            let user = UserSliceRead::new(set_ptr, 8)?;
            let mut buf = [0u8; 8];
            user.copy_to(&mut buf);
            let wait_mask = u64::from_ne_bytes(buf);

            // Check if any signal in wait_mask is pending and not blocked
            let pending_mask = pending.get_mask();
            let blocked_mask = blocked.get_mask();
            let deliverable = pending_mask & wait_mask & !blocked_mask;

            if deliverable != 0 {
                // Return the lowest signal number
                let signal_num = deliverable.trailing_zeros() + 1;
                pending.remove(Signal::from_u32(signal_num).unwrap());
                return Ok(signal_num as u64);
            }
        }
    }

    // No signal pending - would need to implement timeout wait
    Err(SyscallError::Interrupted)
}

/// SYS_SIGQUEUE (327): Send signal with value to a task.
///
/// arg1 = pid, arg2 = signum, arg3 = sigval_ptr
pub fn sys_sigqueue(pid: i64, signum: u32, _sigval_ptr: u64) -> Result<u64, SyscallError> {
    // TODO: store sigval with the pending signal record.
    sys_kill(pid, signum)
}

/// SYS_KILLPG (328): Send signal to process group.
///
/// arg1 = pgrp, arg2 = signum
pub fn sys_killpg(pgrp: u64, signum: u32) -> Result<u64, SyscallError> {
    if pgrp == 0 {
        return Err(SyscallError::InvalidArgument);
    }
    sys_kill(-(pgrp as i64), signum)
}

/// SYS_KILL (320): POSIX kill semantics by pid/group.
pub fn sys_kill(pid: i64, signum: u32) -> Result<u64, SyscallError> {
    let targets = resolve_kill_targets(pid)?;
    if signum == 0 {
        return Ok(0);
    }

    let signal = Signal::from_u32(signum).ok_or(SyscallError::InvalidArgument)?;
    for target in targets {
        crate::process::send_signal(target, signal)?;
    }
    Ok(0)
}

fn resolve_kill_targets(pid: i64) -> Result<alloc::vec::Vec<TaskId>, SyscallError> {
    use alloc::vec::Vec;

    let mut targets = Vec::new();
    match pid {
        p if p > 0 => {
            let target = get_task_id_by_pid(p as u32).ok_or(SyscallError::NotFound)?;
            targets.push(target);
        }
        0 => {
            let pgid = current_pgid().ok_or(SyscallError::Fault)?;
            targets = get_task_ids_in_pgid(pgid);
        }
        -1 => {
            let me = current_task_id();
            if let Some(tasks) = get_all_tasks() {
                for task in tasks {
                    if task.is_kernel() {
                        continue;
                    }
                    if Some(task.id) == me {
                        continue;
                    }
                    targets.push(task.id);
                }
            }
        }
        p => {
            let pgid = (-p) as u32;
            targets = get_task_ids_in_pgid(pgid);
        }
    }

    if targets.is_empty() {
        return Err(SyscallError::NotFound);
    }
    Ok(targets)
}

/// SYS_GETITIMER (329): Get interval timer value.
///
/// arg1 = which (ITIMER_REAL/VIRTUAL/PROF), arg2 = value_ptr (output)
pub fn sys_getitimer(which: u32, value_ptr: u64) -> Result<u64, SyscallError> {
    use crate::process::timer::{ITimerVal, ITimerWhich};
    use core::mem;

    let which = ITimerWhich::from_u32(which).ok_or(SyscallError::InvalidArgument)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;

    // Get current monotonic time (stub for now - returns 0)
    // TODO: Implement proper time source
    let current_time_ns = 0u64;

    let timer = task.itimers.get(which);
    let value = timer.get(current_time_ns);

    if value_ptr != 0 {
        let user = UserSliceWrite::new(value_ptr, mem::size_of::<ITimerVal>())?;
        user.copy_from(&itimerval_to_bytes(&value));
    }

    Ok(0)
}

/// SYS_SETITIMER (330): Set interval timer value.
///
/// arg1 = which (ITIMER_REAL/VIRTUAL/PROF), arg2 = new_value_ptr, arg3 = old_value_ptr (output)
pub fn sys_setitimer(
    which: u32,
    new_value_ptr: u64,
    old_value_ptr: u64,
) -> Result<u64, SyscallError> {
    use crate::process::timer::{ITimerVal, ITimerWhich};
    use core::mem;

    let which = ITimerWhich::from_u32(which).ok_or(SyscallError::InvalidArgument)?;
    let task = current_task_clone().ok_or(SyscallError::PermissionDenied)?;

    // Get current monotonic time (stub for now - returns 0)
    // TODO: Implement proper time source
    let current_time_ns = 0u64;

    let timer = task.itimers.get(which);

    // Get old value if requested
    if old_value_ptr != 0 {
        let old_value = timer.get(current_time_ns);
        let user = UserSliceWrite::new(old_value_ptr, mem::size_of::<ITimerVal>())?;
        user.copy_from(&itimerval_to_bytes(&old_value));
    }

    // Set new value if provided
    if new_value_ptr != 0 {
        let user = UserSliceRead::new(new_value_ptr, mem::size_of::<ITimerVal>())?;
        let bytes = user.read_to_vec();
        if bytes.len() != mem::size_of::<ITimerVal>() {
            return Err(SyscallError::InvalidArgument);
        }
        let new_value = itimerval_from_bytes(&bytes);
        timer.set(&new_value, current_time_ns);
    }

    Ok(0)
}

/// Convert ITimerVal to bytes
fn itimerval_to_bytes(val: &crate::process::timer::ITimerVal) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    // it_interval
    bytes[0..8].copy_from_slice(&val.it_interval.tv_sec.to_ne_bytes());
    bytes[8..16].copy_from_slice(&val.it_interval.tv_usec.to_ne_bytes());
    // it_value
    bytes[16..24].copy_from_slice(&val.it_value.tv_sec.to_ne_bytes());
    bytes[24..32].copy_from_slice(&val.it_value.tv_usec.to_ne_bytes());
    bytes
}

/// Convert bytes to ITimerVal
fn itimerval_from_bytes(bytes: &[u8]) -> crate::process::timer::ITimerVal {
    use crate::process::timer::{ITimerVal, TimeVal};
    ITimerVal {
        it_interval: TimeVal {
            tv_sec: i64::from_ne_bytes(bytes[0..8].try_into().unwrap()),
            tv_usec: i64::from_ne_bytes(bytes[8..16].try_into().unwrap()),
        },
        it_value: TimeVal {
            tv_sec: i64::from_ne_bytes(bytes[16..24].try_into().unwrap()),
            tv_usec: i64::from_ne_bytes(bytes[24..32].try_into().unwrap()),
        },
    }
}
