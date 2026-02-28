//! Process and thread management syscalls.
//!
//! Implements PID/TID retrieval per the Strat9-OS ABI.

use super::{error::SyscallError, SyscallFrame};
use crate::process::scheduler::add_task_with_parent;
use crate::process::{
    block_current_task, create_session, current_pgid, current_task_clone,
    current_task_id, current_tid, get_parent_id, get_parent_pid, get_pgid_by_pid,
    get_sid_by_pid, get_task_id_by_tid, set_process_group,
    task::{CpuContext, FpuState, KernelStack, SyncUnsafeCell, Task},
    WaitChildResult,
};
use alloc::{boxed::Box, sync::Arc};
use core::mem::offset_of;
use core::sync::atomic::Ordering;

#[repr(C)]
#[derive(Clone, Copy)]
struct ThreadUserContext {
    entry: u64,
    stack_top: u64,
    arg0: u64,
    user_cs: u64,
    user_rflags: u64,
    user_ss: u64,
}

const THREAD_OFF_ENTRY: usize = offset_of!(ThreadUserContext, entry);
const THREAD_OFF_STACK_TOP: usize = offset_of!(ThreadUserContext, stack_top);
const THREAD_OFF_ARG0: usize = offset_of!(ThreadUserContext, arg0);
const THREAD_OFF_USER_CS: usize = offset_of!(ThreadUserContext, user_cs);
const THREAD_OFF_USER_RFLAGS: usize = offset_of!(ThreadUserContext, user_rflags);
const THREAD_OFF_USER_SS: usize = offset_of!(ThreadUserContext, user_ss);

extern "C" fn thread_child_start(ctx_ptr: u64) -> ! {
    // SAFETY: `ctx_ptr` is allocated with Box::into_raw in `build_user_thread_task`
    // and passed as immutable bootstrap data for this task only.
    let boxed = unsafe { Box::from_raw(ctx_ptr as *mut ThreadUserContext) };
    let ctx = *boxed;
    // SAFETY: Assembly routine performs an iretq into userspace with validated context.
    unsafe { thread_iret_from_ctx(&ctx as *const ThreadUserContext) }
}

#[unsafe(naked)]
unsafe extern "C" fn thread_iret_from_ctx(_ctx: *const ThreadUserContext) -> ! {
    core::arch::naked_asm!(
        "mov rsi, rdi",
        // Build iret frame: SS, RSP, RFLAGS, CS, RIP
        "mov r8, [rsi + {off_user_ss}]",
        "push r8",
        "mov r8, [rsi + {off_stack_top}]",
        "push r8",
        "mov r8, [rsi + {off_user_rflags}]",
        "push r8",
        "mov r8, [rsi + {off_user_cs}]",
        "push r8",
        "mov r8, [rsi + {off_entry}]",
        "push r8",
        // Argument convention for userspace entry: rdi = arg0
        "mov rdi, [rsi + {off_arg0}]",
        // Child thread returns 0 if entry routine ever reads rax.
        "xor rax, rax",
        "iretq",
        off_entry = const THREAD_OFF_ENTRY,
        off_stack_top = const THREAD_OFF_STACK_TOP,
        off_arg0 = const THREAD_OFF_ARG0,
        off_user_cs = const THREAD_OFF_USER_CS,
        off_user_rflags = const THREAD_OFF_USER_RFLAGS,
        off_user_ss = const THREAD_OFF_USER_SS,
    );
}

fn build_user_thread_task(
    parent: &Arc<Task>,
    bootstrap_ctx: Box<ThreadUserContext>,
    tls_base: u64,
) -> Result<Arc<Task>, SyscallError> {
    let kernel_stack =
        KernelStack::allocate(Task::DEFAULT_STACK_SIZE).map_err(|_| SyscallError::OutOfMemory)?;
    let context = CpuContext::new(thread_child_start as *const () as u64, &kernel_stack);
    let (pid, tid, _) = Task::allocate_process_ids();

    let parent_fpu = unsafe { &*parent.fpu_state.get() };
    let mut child_fpu = FpuState::new();
    child_fpu.data.copy_from_slice(&parent_fpu.data);

    let task = Arc::new(Task {
        id: crate::process::TaskId::new(),
        pid,
        tid,
        tgid: parent.tgid,
        pgid: core::sync::atomic::AtomicU32::new(parent.pgid.load(Ordering::Relaxed)),
        sid: core::sync::atomic::AtomicU32::new(parent.sid.load(Ordering::Relaxed)),
        uid: core::sync::atomic::AtomicU32::new(parent.uid.load(Ordering::Relaxed)),
        euid: core::sync::atomic::AtomicU32::new(parent.euid.load(Ordering::Relaxed)),
        gid: core::sync::atomic::AtomicU32::new(parent.gid.load(Ordering::Relaxed)),
        egid: core::sync::atomic::AtomicU32::new(parent.egid.load(Ordering::Relaxed)),
        state: SyncUnsafeCell::new(crate::process::TaskState::Ready),
        priority: parent.priority,
        context: SyncUnsafeCell::new(context),
        kernel_stack,
        user_stack: None,
        name: "user-thread",
        process: parent.process.clone(),
        pending_signals: crate::process::signal::SignalSet::new(),
        blocked_signals: parent.blocked_signals.clone(),
        signal_stack: SyncUnsafeCell::new(None),
        itimers: crate::process::timer::ITimers::new(),
        wake_pending: core::sync::atomic::AtomicBool::new(false),
        wake_deadline_ns: core::sync::atomic::AtomicU64::new(0),
        trampoline_entry: core::sync::atomic::AtomicU64::new(0),
        trampoline_stack_top: core::sync::atomic::AtomicU64::new(0),
        trampoline_arg0: core::sync::atomic::AtomicU64::new(0),
        ticks: core::sync::atomic::AtomicU64::new(0),
        sched_policy: SyncUnsafeCell::new(parent.sched_policy()),
        vruntime: core::sync::atomic::AtomicU64::new(parent.vruntime()),
        clear_child_tid: core::sync::atomic::AtomicU64::new(0),
        user_fs_base: core::sync::atomic::AtomicU64::new(tls_base),
        fpu_state: SyncUnsafeCell::new(child_fpu),
    });

    // CpuContext initial stack layout: r15, r14, r13(arg), r12(entry), rbp, rbx, ret
    // Seed r13 with bootstrap context pointer for `thread_child_start`.
    unsafe {
        let ctx = &mut *task.context.get();
        let frame = ctx.saved_rsp as *mut u64;
        *frame.add(2) = Box::into_raw(bootstrap_ctx) as u64;
    }

    Ok(task)
}

/// SYS_GETPID (311): Return current process ID.
///
/// In Strat9, each task has a unique ID, so getpid returns the TaskId.
pub fn sys_getpid() -> Result<u64, SyscallError> {
    current_task_clone()
        .map(|task| task.tgid as u64)
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

/// SYS_THREAD_CREATE (341): create a userspace thread sharing current process resources.
pub fn sys_thread_create(
    frame: &SyscallFrame,
    entry: u64,
    stack_top: u64,
    arg0: u64,
    flags: u64,
    tls_base: u64,
) -> Result<u64, SyscallError> {
    const USER_TOP_EXCLUSIVE: u64 = 0x0000_8000_0000_0000;

    if flags != 0 {
        return Err(SyscallError::InvalidArgument);
    }

    if entry == 0
        || stack_top == 0
        || entry >= USER_TOP_EXCLUSIVE
        || stack_top >= USER_TOP_EXCLUSIVE
        || (stack_top & 0xF) != 0
    {
        return Err(SyscallError::InvalidArgument);
    }

    let parent = current_task_clone().ok_or(SyscallError::Fault)?;
    if parent.is_kernel() {
        return Err(SyscallError::PermissionDenied);
    }

    let user_ctx = Box::new(ThreadUserContext {
        entry,
        stack_top,
        arg0,
        user_cs: frame.iret_cs,
        user_rflags: frame.iret_rflags | (1 << 9),
        user_ss: frame.iret_ss,
    });

    let child = build_user_thread_task(&parent, user_ctx, tls_base)?;
    let tid = child.tid as u64;
    add_task_with_parent(child, parent.id);
    Ok(tid)
}

/// SYS_THREAD_JOIN (342): wait for a thread created by the current task.
pub fn sys_thread_join(tid: u64, status_ptr: u64, flags: u64) -> Result<u64, SyscallError> {
    if flags != 0 {
        return Err(SyscallError::InvalidArgument);
    }

    let wait_tid = u32::try_from(tid).map_err(|_| SyscallError::InvalidArgument)?;
    let current = current_task_clone().ok_or(SyscallError::Fault)?;
    if wait_tid == current.tid {
        return Err(SyscallError::InvalidArgument);
    }

    let parent_id = current_task_id().ok_or(SyscallError::Fault)?;
    let child_id = get_task_id_by_tid(wait_tid).ok_or(SyscallError::NotFound)?;
    if get_parent_id(child_id) != Some(parent_id) {
        return Err(SyscallError::NotFound);
    }

    loop {
        match crate::process::try_wait_child(parent_id, Some(child_id)) {
            WaitChildResult::Reaped { status, .. } => {
                if status_ptr != 0 {
                    let out =
                        crate::memory::UserSliceWrite::new(status_ptr, 4).map_err(|_| SyscallError::Fault)?;
                    out.copy_from(&(status as i32).to_ne_bytes());
                }
                return Ok(wait_tid as u64);
            }
            WaitChildResult::NoChildren => return Err(SyscallError::NotFound),
            WaitChildResult::StillRunning => block_current_task(),
        }
    }
}

/// SYS_THREAD_EXIT (343): exit only the current thread.
pub fn sys_thread_exit(exit_code: u64) -> Result<u64, SyscallError> {
    let code = i32::try_from(exit_code).map_err(|_| SyscallError::InvalidArgument)?;
    crate::process::scheduler::exit_current_task(code)
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
