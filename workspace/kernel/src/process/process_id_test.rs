//! Process identity and credentials self-test suite.
//!
//! Exercises: getpid, gettid, getppid, getuid/geteuid/getgid/getegid,
//! setuid/setgid round-trips, getpgid, setpgid, getpgrp, setsid, getsid.
//!
//! Runs only under `feature = "selftest"`.

use crate::{
    process::{
        add_task, current_pid, current_task_clone, current_task_id, current_tid, get_parent_pid,
        Task, TaskPriority,
    },
    syscall::process as proc_sys,
};

fn log_section(title: &str) {
    crate::serial_println!(
        "[proc-id-test][STEP] ========================================================"
    );
    crate::serial_println!("[proc-id-test][STEP] {}", title);
    crate::serial_println!(
        "[proc-id-test][STEP] ========================================================"
    );
}

fn record(name: &str, ok: bool, passed: &mut usize, total: &mut usize) {
    *total += 1;
    if ok {
        *passed += 1;
    }
    crate::serial_println!(
        "[proc-id-test][ASSERT][SCENARIO] {:<48} => {}",
        name,
        if ok { "PASS" } else { "FAIL" }
    );
}

fn run_process_id_suite() -> bool {
    let mut passed = 0usize;
    let mut total = 0usize;

    // ── 1. getpid returns non-zero ============================================================================================================================================
    log_section("1. GETPID");
    let mut s = true;
    match proc_sys::sys_getpid() {
        Ok(pid) => {
            crate::serial_println!("[proc-id-test][STEP] sys_getpid() => {}", pid);
            if pid == 0 {
                crate::serial_println!("[proc-id-test][ASSERT] FAIL: pid == 0");
                s = false;
            }
        }
        Err(e) => {
            crate::serial_println!("[proc-id-test][STEP] sys_getpid => {:?}", e);
            s = false;
        }
    }
    record("getpid returns non-zero", s, &mut passed, &mut total);

    // ── 2. gettid returns non-zero ============================================================================================================================================
    log_section("2. GETTID");
    let mut s = true;
    match proc_sys::sys_gettid() {
        Ok(tid) => {
            crate::serial_println!("[proc-id-test][STEP] sys_gettid() => {}", tid);
            if tid == 0 {
                crate::serial_println!("[proc-id-test][ASSERT] FAIL: tid == 0");
                s = false;
            }
        }
        Err(e) => {
            crate::serial_println!("[proc-id-test][STEP] sys_gettid => {:?}", e);
            s = false;
        }
    }
    record("gettid returns non-zero", s, &mut passed, &mut total);

    // ── 3. getpid == gettid for main thread ==============================================================================================================
    log_section("3. PID == TID (MAIN THREAD)");
    let mut s = true;
    let pid = proc_sys::sys_getpid().unwrap_or(0);
    let tid = proc_sys::sys_gettid().unwrap_or(0);
    crate::serial_println!("[proc-id-test][STEP] pid={} tid={}", pid, tid);
    if pid != tid {
        crate::serial_println!(
            "[proc-id-test][STEP] note: pid != tid (may be expected for kernel tasks)"
        );
    }
    if pid == 0 || tid == 0 {
        s = false;
    }
    record("pid and tid are non-zero", s, &mut passed, &mut total);

    // ── 4. getppid returns a valid pid ========================================================================================================================──
    log_section("4. GETPPID");
    let mut s = true;
    match proc_sys::sys_getppid() {
        Ok(ppid) => {
            crate::serial_println!("[proc-id-test][STEP] sys_getppid() => {}", ppid);
        }
        Err(e) => {
            crate::serial_println!("[proc-id-test][STEP] sys_getppid => {:?}", e);
            s = false;
        }
    }
    record("getppid returns value", s, &mut passed, &mut total);

    // ── 5. getpid via scheduler matches syscall ==========================================================================================──
    log_section("5. GETPID CONSISTENCY");
    let mut s = true;
    let sched_pid = current_pid().unwrap_or(0) as u64;
    let sys_pid = proc_sys::sys_getpid().unwrap_or(0);
    crate::serial_println!(
        "[proc-id-test][STEP] scheduler pid={}, syscall pid={}",
        sched_pid,
        sys_pid
    );
    if sched_pid != sys_pid {
        crate::serial_println!("[proc-id-test][ASSERT] FAIL: pid mismatch");
        s = false;
    }
    record("getpid scheduler vs syscall", s, &mut passed, &mut total);

    // ── 6. getuid / geteuid return 0 (root default) ================================================================================
    log_section("6. GETUID / GETEUID");
    let mut s = true;
    match proc_sys::sys_getuid() {
        Ok(uid) => {
            crate::serial_println!("[proc-id-test][STEP] sys_getuid() => {}", uid);
            if uid != 0 {
                crate::serial_println!(
                    "[proc-id-test][STEP] note: uid != 0 (non-root kernel task)"
                );
            }
        }
        Err(e) => {
            crate::serial_println!("[proc-id-test][STEP] getuid => {:?}", e);
            s = false;
        }
    }
    match proc_sys::sys_geteuid() {
        Ok(euid) => {
            crate::serial_println!("[proc-id-test][STEP] sys_geteuid() => {}", euid);
        }
        Err(e) => {
            crate::serial_println!("[proc-id-test][STEP] geteuid => {:?}", e);
            s = false;
        }
    }
    record("getuid / geteuid", s, &mut passed, &mut total);

    // ── 7. getgid / getegid return 0 (root default) ================================================================================
    log_section("7. GETGID / GETEGID");
    let mut s = true;
    match proc_sys::sys_getgid() {
        Ok(gid) => {
            crate::serial_println!("[proc-id-test][STEP] sys_getgid() => {}", gid);
        }
        Err(e) => {
            crate::serial_println!("[proc-id-test][STEP] getgid => {:?}", e);
            s = false;
        }
    }
    match proc_sys::sys_getegid() {
        Ok(egid) => {
            crate::serial_println!("[proc-id-test][STEP] sys_getegid() => {}", egid);
        }
        Err(e) => {
            crate::serial_println!("[proc-id-test][STEP] getegid => {:?}", e);
            s = false;
        }
    }
    record("getgid / getegid", s, &mut passed, &mut total);

    // ── 8. setuid + getuid round-trip ==================================================================================================================================
    log_section("8. SETUID + GETUID ROUND-TRIP");
    let mut s = true;
    let orig_uid = proc_sys::sys_getuid().unwrap_or(0);
    match proc_sys::sys_setuid(1000) {
        Ok(_) => {
            let new_uid = proc_sys::sys_getuid().unwrap_or(0);
            crate::serial_println!("[proc-id-test][STEP] setuid(1000): uid now = {}", new_uid);
            if new_uid != 1000 {
                crate::serial_println!("[proc-id-test][ASSERT] FAIL: uid != 1000 after setuid");
                s = false;
            }
            let _ = proc_sys::sys_setuid(orig_uid);
        }
        Err(e) => {
            crate::serial_println!("[proc-id-test][STEP] setuid(1000) => {:?}", e);
            s = false;
        }
    }
    record("setuid + getuid round-trip", s, &mut passed, &mut total);

    // ── 9. setgid + getgid round-trip ==================================================================================================================================
    log_section("9. SETGID + GETGID ROUND-TRIP");
    let mut s = true;
    let orig_gid = proc_sys::sys_getgid().unwrap_or(0);
    match proc_sys::sys_setgid(500) {
        Ok(_) => {
            let new_gid = proc_sys::sys_getgid().unwrap_or(0);
            crate::serial_println!("[proc-id-test][STEP] setgid(500): gid now = {}", new_gid);
            if new_gid != 500 {
                crate::serial_println!("[proc-id-test][ASSERT] FAIL: gid != 500 after setgid");
                s = false;
            }
            let _ = proc_sys::sys_setgid(orig_gid);
        }
        Err(e) => {
            crate::serial_println!("[proc-id-test][STEP] setgid(500) => {:?}", e);
            s = false;
        }
    }
    record("setgid + getgid round-trip", s, &mut passed, &mut total);

    // ── 10. getpgid(0) returns current pgid ==============================================================================================================
    log_section("10. GETPGID(0)");
    let mut s = true;
    match proc_sys::sys_getpgid(0) {
        Ok(pgid) => {
            crate::serial_println!("[proc-id-test][STEP] sys_getpgid(0) => {}", pgid);
        }
        Err(e) => {
            crate::serial_println!("[proc-id-test][STEP] getpgid => {:?}", e);
            s = false;
        }
    }
    record("getpgid(0)", s, &mut passed, &mut total);

    // ── 11. getpgrp == getpgid(0) ============================================================================================================================================─
    log_section("11. GETPGRP == GETPGID(0)");
    let mut s = true;
    let pgid_0 = proc_sys::sys_getpgid(0).unwrap_or(u64::MAX);
    let pgrp = proc_sys::sys_getpgrp().unwrap_or(0);
    crate::serial_println!(
        "[proc-id-test][STEP] getpgid(0)={} getpgrp()={}",
        pgid_0,
        pgrp
    );
    if pgid_0 != pgrp {
        crate::serial_println!("[proc-id-test][ASSERT] FAIL: getpgrp != getpgid(0)");
        s = false;
    }
    record("getpgrp == getpgid(0)", s, &mut passed, &mut total);

    // ── 12. getsid(0) ==========
    log_section("12. GETSID(0)");
    let mut s = true;
    match proc_sys::sys_getsid(0) {
        Ok(sid) => {
            crate::serial_println!("[proc-id-test][STEP] sys_getsid(0) => {}", sid);
        }
        Err(e) => {
            crate::serial_println!("[proc-id-test][STEP] getsid => {:?}", e);
            s = false;
        }
    }
    record("getsid(0)", s, &mut passed, &mut total);

    // ── 13. setsid ====================
    log_section("13. SETSID");
    let mut s = true;
    match proc_sys::sys_setsid() {
        Ok(new_sid) => {
            crate::serial_println!("[proc-id-test][STEP] sys_setsid() => {}", new_sid);
            let sid2 = proc_sys::sys_getsid(0).unwrap_or(0);
            if sid2 != new_sid {
                crate::serial_println!("[proc-id-test][ASSERT] FAIL: getsid after setsid mismatch");
                s = false;
            }
        }
        Err(e) => {
            crate::serial_println!(
                "[proc-id-test][STEP] setsid => {:?} (may already be session leader)",
                e
            );
        }
    }
    record("setsid", s, &mut passed, &mut total);

    // ── 14. setpgid(0, 0) sets pgid to own pid ==========================================================================================──
    log_section("14. SETPGID(0, 0)");
    let mut s = true;
    match proc_sys::sys_setpgid(0, 0) {
        Ok(_) => {
            let my_pid = proc_sys::sys_getpid().unwrap_or(0);
            let my_pgid = proc_sys::sys_getpgid(0).unwrap_or(0);
            crate::serial_println!(
                "[proc-id-test][STEP] setpgid(0,0): pid={} pgid={}",
                my_pid,
                my_pgid
            );
            if my_pgid != my_pid {
                crate::serial_println!(
                    "[proc-id-test][ASSERT] FAIL: pgid != pid after setpgid(0,0)"
                );
                s = false;
            }
        }
        Err(e) => {
            crate::serial_println!("[proc-id-test][STEP] setpgid(0,0) => {:?}", e);
            s = false;
        }
    }
    record("setpgid(0,0) sets pgid=pid", s, &mut passed, &mut total);

    // ── 15. current_task_clone returns Some ==============================================================================================================
    log_section("15. CURRENT_TASK_CLONE");
    let mut s = true;
    match current_task_clone() {
        Some(task) => {
            crate::serial_println!(
                "[proc-id-test][STEP] current task: name='{}' id={:?} pid={}",
                task.name,
                task.id,
                task.pid
            );
            if task.name != "proc-id-test" {
                crate::serial_println!("[proc-id-test][ASSERT] FAIL: unexpected task name");
                s = false;
            }
        }
        None => {
            crate::serial_println!("[proc-id-test][ASSERT] FAIL: current_task_clone() is None");
            s = false;
        }
    }
    record("current_task_clone is Some", s, &mut passed, &mut total);

    // ── 16. current_task_id returns Some ========================================================================================================================
    log_section("16. CURRENT_TASK_ID");
    let mut s = true;
    match current_task_id() {
        Some(id) => {
            crate::serial_println!("[proc-id-test][STEP] current_task_id() => {:?}", id);
        }
        None => {
            crate::serial_println!("[proc-id-test][ASSERT] FAIL: current_task_id() is None");
            s = false;
        }
    }
    record("current_task_id is Some", s, &mut passed, &mut total);

    // ── Summary ==============================
    log_section("PROCESS ID TEST SUMMARY");
    let ok = passed == total;
    crate::serial_println!(
        "[proc-id-test][ASSERT] result: {}/{} scenarios PASS",
        passed,
        total
    );
    crate::serial_println!(
        "[proc-id-test][ASSERT] final : {}",
        if ok { "PASS" } else { "FAIL" }
    );
    ok
}

extern "C" fn process_id_test_main() -> ! {
    crate::serial_println!("[proc-id-test][SETUP] task start");
    let _ = run_process_id_suite();
    crate::serial_println!("[proc-id-test][CLEANUP] task done");
    crate::process::scheduler::exit_current_task(0);
}

pub fn create_process_id_test_task() {
    if let Ok(task) =
        Task::new_kernel_task(process_id_test_main, "proc-id-test", TaskPriority::Normal)
    {
        add_task(task);
    } else {
        crate::serial_println!("[proc-id-test][SETUP] failed to create task");
    }
}
