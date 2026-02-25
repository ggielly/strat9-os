//! Process and thread management syscalls.
//!
//! Implements PID/TID retrieval per the Strat9-OS ABI.

use super::error::SyscallError;
use crate::process::{
    create_session, current_pgid, current_pid, current_task_clone, current_task_id, current_tid,
    get_parent_pid, get_pgid_by_pid, get_sid_by_pid, set_process_group,
};
use core::sync::atomic::Ordering;

/// SYS_GETPID (311): Return current process ID.
///
/// In Strat9, each task has a unique ID, so getpid returns the TaskId.
pub fn sys_getpid() -> Result<u64, SyscallError> {
    current_pid()
        .map(|pid| pid as u64)
        .ok_or(SyscallError::Fault)
}

/// SYS_GETTID (312): Return current thread ID.
///
/// In the current single-threaded silo model, TID == PID.
pub fn sys_gettid() -> Result<u64, SyscallError> {
    current_tid()
        .map(|tid| tid as u64)
        .ok_or(SyscallError::Fault)
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

// ─── Credentials ─────────────────────────────────────────────────────────────

/// SYS_GETUID (335): Return real user id.
pub fn sys_getuid() -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::Fault)?;
    Ok(task.uid.load(Ordering::Relaxed) as u64)
}

/// SYS_GETEUID (336): Return effective user id.
pub fn sys_geteuid() -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::Fault)?;
    Ok(task.euid.load(Ordering::Relaxed) as u64)
}

/// SYS_GETGID (337): Return real group id.
pub fn sys_getgid() -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::Fault)?;
    Ok(task.gid.load(Ordering::Relaxed) as u64)
}

/// SYS_GETEGID (338): Return effective group id.
pub fn sys_getegid() -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::Fault)?;
    Ok(task.egid.load(Ordering::Relaxed) as u64)
}

/// SYS_SETUID (339): Set real and effective user id (simplified: no capabilities check).
pub fn sys_setuid(uid: u64) -> Result<u64, SyscallError> {
    if uid > u32::MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    let task = current_task_clone().ok_or(SyscallError::Fault)?;
    // Privileged (uid==0) can set anything; unprivileged can only set to current uid/euid.
    let euid = task.euid.load(Ordering::Relaxed);
    let cur_uid = task.uid.load(Ordering::Relaxed);
    if euid != 0 && uid as u32 != cur_uid && uid as u32 != euid {
        return Err(SyscallError::PermissionDenied);
    }
    task.uid.store(uid as u32, Ordering::Relaxed);
    task.euid.store(uid as u32, Ordering::Relaxed);
    Ok(0)
}

/// SYS_SETGID (340): Set real and effective group id (simplified).
pub fn sys_setgid(gid: u64) -> Result<u64, SyscallError> {
    if gid > u32::MAX as u64 {
        return Err(SyscallError::InvalidArgument);
    }
    let task = current_task_clone().ok_or(SyscallError::Fault)?;
    let euid = task.euid.load(Ordering::Relaxed);
    let cur_gid = task.gid.load(Ordering::Relaxed);
    let egid = task.egid.load(Ordering::Relaxed);
    if euid != 0 && gid as u32 != cur_gid && gid as u32 != egid {
        return Err(SyscallError::PermissionDenied);
    }
    task.gid.store(gid as u32, Ordering::Relaxed);
    task.egid.store(gid as u32, Ordering::Relaxed);
    Ok(0)
}

// ─── Thread lifecycle helpers ─────────────────────────────────────────────────

/// SYS_SET_TID_ADDRESS (333): Store `tidptr` in the task; return current TID.
///
/// The kernel will write 0 to `tidptr` and call futex_wake when the thread
/// exits. This is the mechanism used by pthreads for thread join.
pub fn sys_set_tid_address(tidptr: u64) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::Fault)?;
    task.clear_child_tid.store(tidptr, Ordering::Relaxed);
    Ok(task.tid as u64)
}

/// SYS_EXIT_GROUP (334): Exit all threads in the thread group.
///
/// In the current single-threaded model this is identical to SYS_PROC_EXIT.
/// When multi-threading is added, this must kill every task sharing the same TGID.
pub fn sys_exit_group(exit_code: u64) -> Result<u64, SyscallError> {
    // Diverges — never returns.
    crate::process::scheduler::exit_current_task(exit_code as i32)
}

// ─── Architecture-specific ────────────────────────────────────────────────────

/// x86_64 arch_prctl operation codes (Linux-compatible).
const ARCH_SET_GS: u64 = 0x1001;
const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;
const ARCH_GET_GS: u64 = 0x1004;

/// MSR addresses for FS/GS base.
const MSR_FS_BASE: u32 = 0xC000_0100;
const MSR_GS_BASE: u32 = 0xC000_0101;

/// SYS_ARCH_PRCTL (350): Architecture-specific process settings.
///
/// Supported operations:
/// - `ARCH_SET_FS` (0x1002): Set user-space FS.base (Thread Local Storage).
/// - `ARCH_GET_FS` (0x1003): Read current FS.base into *arg.
pub fn sys_arch_prctl(code: u64, addr: u64) -> Result<u64, SyscallError> {
    let task = current_task_clone().ok_or(SyscallError::Fault)?;
    match code {
        ARCH_SET_FS => {
            // Store in task struct (so it survives context switches).
            task.user_fs_base.store(addr, Ordering::Relaxed);
            // Write to MSR immediately — we are the current task.
            unsafe { wrmsr(MSR_FS_BASE, addr) };
            Ok(0)
        }
        ARCH_GET_FS => {
            let base = task.user_fs_base.load(Ordering::Relaxed);
            // Write the 8-byte value back to the provided user pointer.
            use crate::memory::UserSliceWrite;
            let out = UserSliceWrite::new(addr, 8).map_err(|_| SyscallError::Fault)?;
            out.copy_from(&base.to_ne_bytes());
            Ok(0)
        }
        ARCH_SET_GS => {
            // GS slot not separately stored for now.
            unsafe { wrmsr(MSR_GS_BASE, addr) };
            Ok(0)
        }
        ARCH_GET_GS => {
            let base = unsafe { rdmsr(MSR_GS_BASE) };
            use crate::memory::UserSliceWrite;
            let out = UserSliceWrite::new(addr, 8).map_err(|_| SyscallError::Fault)?;
            out.copy_from(&base.to_ne_bytes());
            Ok(0)
        }
        _ => Err(SyscallError::InvalidArgument),
    }
}

/// Write a 64-bit value to an MSR.
///
/// # Safety
/// Must only be called with valid MSR addresses. Misuse causes a #GP.
#[inline]
unsafe fn wrmsr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nostack, preserves_flags),
        );
    }
}

/// Read a 64-bit value from an MSR.
///
/// # Safety
/// Must only be called with valid MSR addresses.
#[inline]
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags),
        );
    }
    lo as u64 | ((hi as u64) << 32)
}

// ─── tgkill ───────────────────────────────────────────────────────────────────

/// SYS_TGKILL (352): Send a signal to a specific thread in a thread group.
///
/// In the current single-threaded model, tgid and tid both map to a single
/// task (pid == tid == tgid). We verify both match before delivering.
pub fn sys_tgkill(tgid: u64, tid: u64, signum: u64) -> Result<u64, SyscallError> {
    use crate::process::{get_task_by_pid, send_signal, Signal};

    // Sanity check.
    if signum as u32 >= 64 {
        return Err(SyscallError::InvalidArgument);
    }

    // Resolve tgid → task.
    let task = get_task_by_pid(tgid as u32).ok_or(SyscallError::NotFound)?;

    // Verify the tid matches (single-threaded: task.tid == task.pid).
    if task.tid as u64 != tid && task.pid as u64 != tid {
        return Err(SyscallError::NotFound);
    }

    if signum == 0 {
        return Ok(0); // existence check only
    }

    let sig = Signal::from_u32(signum as u32).ok_or(SyscallError::InvalidArgument)?;
    send_signal(task.id, sig)?;
    Ok(0)
}
