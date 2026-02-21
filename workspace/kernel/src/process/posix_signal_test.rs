//! runtime self-tests for posix process-group/session/signal behavior.
//!
//! runs only in test iso (`feature = "selftest"`).

use crate::{
    process::{
        add_task, current_pgid, current_sid, current_task_clone, current_task_id, get_task_by_id,
        kill_task, suspend_task, Task, TaskPriority,
    },
    syscall::{self, error::SyscallError},
};
use core::sync::atomic::Ordering;

extern "C" fn parked_task() -> ! {
    loop {
        crate::process::yield_task();
    }
}

fn test_groups_and_sessions() -> bool {
    let pgid = current_pgid().unwrap_or(0) as u64;
    let sid = current_sid().unwrap_or(0) as u64;
    if pgid == 0 || sid == 0 {
        return false;
    }

    match syscall::process::sys_getpgid(0) {
        Ok(v) if v == pgid => {}
        _ => return false,
    }
    match syscall::process::sys_getpgrp() {
        Ok(v) if v == pgid => {}
        _ => return false,
    }
    match syscall::process::sys_getsid(0) {
        Ok(v) if v == sid => {}
        _ => return false,
    }

    // session leader cannot change its process group.
    matches!(
        syscall::process::sys_setpgid(0, 0),
        Err(SyscallError::PermissionDenied)
    )
}

fn test_kill_permissions() -> bool {
    let caller = match current_task_clone() {
        Some(t) => t,
        None => return false,
    };

    let target = match Task::new_kernel_task(parked_task, "posix-signal-target", TaskPriority::Low) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let target_pid = target.pid as i64;
    let target_id = target.id;
    add_task(target.clone());
    let _ = suspend_task(target_id);

    // same uid: allowed
    caller.uid.store(1000, Ordering::Relaxed);
    caller.euid.store(1000, Ordering::Relaxed);
    target.uid.store(1000, Ordering::Relaxed);
    target.euid.store(1000, Ordering::Relaxed);
    if syscall::signal::sys_kill(target_pid, crate::process::Signal::SIGUSR1 as u32).is_err() {
        let _ = kill_task(target_id);
        return false;
    }
    {
        let pending = unsafe { &*target.pending_signals.get() };
        if !pending.contains(crate::process::Signal::SIGUSR1) {
            let _ = kill_task(target_id);
            return false;
        }
        pending.remove(crate::process::Signal::SIGUSR1);
    }

    // different uid: denied
    caller.uid.store(1000, Ordering::Relaxed);
    caller.euid.store(1000, Ordering::Relaxed);
    target.uid.store(2000, Ordering::Relaxed);
    target.euid.store(2000, Ordering::Relaxed);
    if !matches!(
        syscall::signal::sys_kill(target_pid, crate::process::Signal::SIGUSR1 as u32),
        Err(SyscallError::PermissionDenied)
    ) {
        let _ = kill_task(target_id);
        return false;
    }

    // root-like euid bypass.
    caller.euid.store(0, Ordering::Relaxed);
    if syscall::signal::sys_kill(target_pid, crate::process::Signal::SIGUSR2 as u32).is_err() {
        let _ = kill_task(target_id);
        return false;
    }

    // cleanup
    let _ = kill_task(target_id);
    true
}

extern "C" fn posix_signal_test_main() -> ! {
    crate::serial_println!("[posix-test] start");

    let s1 = test_groups_and_sessions();
    crate::serial_println!(
        "[posix-test] groups/session: {}",
        if s1 { "ok" } else { "FAIL" }
    );

    let s2 = test_kill_permissions();
    crate::serial_println!(
        "[posix-test] kill permissions: {}",
        if s2 { "ok" } else { "FAIL" }
    );

    crate::serial_println!(
        "[posix-test] summary: {}",
        if s1 && s2 { "PASS" } else { "FAIL" }
    );

    if let Some(me) = current_task_id().and_then(get_task_by_id) {
        me.uid.store(0, Ordering::Relaxed);
        me.euid.store(0, Ordering::Relaxed);
    }
    crate::process::scheduler::exit_current_task(0);
}

pub fn create_posix_signal_test_task() {
    if let Ok(task) =
        Task::new_kernel_task(posix_signal_test_main, "posix-signal-test", TaskPriority::Normal)
    {
        add_task(task);
    } else {
        crate::serial_println!("[posix-test] failed to create task");
    }
}
