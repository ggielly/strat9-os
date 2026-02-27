//! Kernel self-test orchestrator.

use crate::{
    process::{add_task, get_all_tasks, scheduler::ticks, Task, TaskPriority},
    silo,
    syscall::error::SyscallError,
    vfs,
};
use alloc::vec::Vec;

fn wait_task_exit(name: &'static str, timeout_ticks: u64) -> bool {
    let start = ticks();
    loop {
        let mut alive = false;
        if let Some(tasks) = get_all_tasks() {
            alive = tasks.iter().any(|t| t.name == name);
        }
        if !alive {
            return true;
        }
        if ticks().saturating_sub(start) > timeout_ticks {
            crate::serial_println!("[selftest] timeout waiting '{}'", name);
            return false;
        }
        crate::process::yield_task();
    }
}

fn wait_until(timeout_ticks: u64, mut cond: impl FnMut() -> bool) -> bool {
    let start = ticks();
    loop {
        if cond() {
            return true;
        }
        if ticks().saturating_sub(start) > timeout_ticks {
            return false;
        }
        crate::process::yield_task();
    }
}

fn read_initfs(path: &str) -> Option<Vec<u8>> {
    let fd = vfs::open(path, vfs::OpenFlags::READ).ok()?;
    let data = vfs::read_all(fd).ok();
    let _ = vfs::close(fd);
    data
}

fn run_strate_lifecycle_e2e() -> bool {
    crate::serial_println!("[selftest][strate] start");
    let ram = match read_initfs("/initfs/strate-fs-ramfs") {
        Some(v) => v,
        None => {
            crate::serial_println!("[selftest][strate] FAIL: missing /initfs/strate-fs-ramfs");
            return false;
        }
    };

    let sid = match silo::kernel_spawn_strate(&ram, Some("e2e-ram-a"), None) {
        Ok(id) => id,
        Err(e) => {
            crate::serial_println!("[selftest][strate] FAIL: spawn: {:?}", e);
            return false;
        }
    };
    crate::serial_println!("[selftest][strate] spawn ok: silo_id={}", sid);

    let mounted = wait_until(3_000, || {
        vfs::list_mounts()
            .iter()
            .any(|m| m == "/srv/strate-fs-ramfs/e2e-ram-a")
    });
    if !mounted {
        crate::serial_println!("[selftest][strate] FAIL: alias mount not observed");
        let _ = silo::kernel_stop_silo("e2e-ram-a", true);
        let _ = silo::kernel_destroy_silo("e2e-ram-a");
        return false;
    }
    crate::serial_println!("[selftest][strate] alias mount ok");

    match silo::kernel_spawn_strate(&ram, Some("e2e-ram-a"), None) {
        Err(SyscallError::AlreadyExists) => {
            crate::serial_println!("[selftest][strate] duplicate label protection ok")
        }
        other => {
            crate::serial_println!(
                "[selftest][strate] FAIL: duplicate label check: {:?}",
                other
            );
            let _ = silo::kernel_stop_silo("e2e-ram-a", true);
            let _ = silo::kernel_destroy_silo("e2e-ram-a");
            return false;
        }
    }

    if silo::kernel_rename_silo_label("e2e-ram-a", "e2e-ram-b").is_ok() {
        crate::serial_println!("[selftest][strate] FAIL: rename should fail while running");
        let _ = silo::kernel_stop_silo("e2e-ram-a", true);
        let _ = silo::kernel_destroy_silo("e2e-ram-a");
        return false;
    }

    if silo::kernel_stop_silo("e2e-ram-a", false).is_err() {
        crate::serial_println!("[selftest][strate] FAIL: stop");
        let _ = silo::kernel_stop_silo("e2e-ram-a", true);
        let _ = silo::kernel_destroy_silo("e2e-ram-a");
        return false;
    }
    crate::serial_println!("[selftest][strate] stop ok");

    if silo::kernel_rename_silo_label("e2e-ram-a", "e2e-ram-b").is_err() {
        crate::serial_println!("[selftest][strate] FAIL: rename after stop");
        let _ = silo::kernel_destroy_silo("e2e-ram-a");
        return false;
    }
    crate::serial_println!("[selftest][strate] rename ok");

    if silo::kernel_destroy_silo("e2e-ram-b").is_err() {
        crate::serial_println!("[selftest][strate] FAIL: destroy");
        return false;
    }
    crate::serial_println!("[selftest][strate] destroy ok");
    true
}

extern "C" fn selftest_orchestrator() -> ! {
    crate::serial_println!("[selftest] orchestrator start");

    crate::process::demand_paging_test::create_demand_paging_test_task();
    let _ = wait_task_exit("demand-paging-test", 2_000);

    crate::process::scheduler_test::create_scheduler_test_task();
    let _ = wait_task_exit("scheduler-test", 6_000);

    crate::process::fork_test::create_fork_test_task();
    let _ = wait_task_exit("fork-test", 4_000);

    crate::process::posix_signal_test::create_posix_signal_test_task();
    let _ = wait_task_exit("posix-signal-test", 2_000);

    crate::ipc::test::create_ipc_test_tasks();
    let _ = wait_task_exit("ipc-sender", 2_000);
    let _ = wait_task_exit("ipc-recv", 2_000);

    crate::ipc::test::create_channel_test_tasks();
    let _ = wait_task_exit("chan-prod-1", 2_000);
    let _ = wait_task_exit("chan-prod-2", 2_000);
    let _ = wait_task_exit("chan-consumer", 3_000);

    crate::ipc::test::create_ipc_04_05_test_task();
    let _ = wait_task_exit("ipc-sem-poster", 2_000);
    let _ = wait_task_exit("ipc-04-05-test", 3_000);

    let strate_ok = run_strate_lifecycle_e2e();
    if strate_ok {
        crate::serial_println!("[selftest][strate] PASS");
    } else {
        crate::serial_println!("[selftest][strate] FAIL");
    }

    crate::serial_println!("[selftest] orchestrator done");
    crate::process::scheduler::exit_current_task(0);
}

pub fn create_selftest_tasks() {
    match Task::new_kernel_task(
        selftest_orchestrator,
        "selftest-orchestrator",
        TaskPriority::High,
    ) {
        Ok(task) => add_task(task),
        Err(_) => crate::serial_println!("[selftest] failed to create orchestrator task"),
    }
}
