//! Kernel self-test orchestrator.

use crate::process::{add_task, get_all_tasks, scheduler::ticks, Task, TaskPriority};

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

extern "C" fn selftest_orchestrator() -> ! {
    crate::serial_println!("[selftest] orchestrator start");

    crate::process::demand_paging_test::create_demand_paging_test_task();
    let _ = wait_task_exit("demand-paging-test", 2_000);

    crate::process::fork_test::create_fork_test_task();
    let _ = wait_task_exit("fork-test", 4_000);

    crate::process::posix_signal_test::create_posix_signal_test_task();
    let _ = wait_task_exit("posix-signal-test", 2_000);

    crate::serial_println!("[selftest] orchestrator done");
    crate::process::scheduler::exit_current_task(0);
}

pub fn create_selftest_tasks() {
    match Task::new_kernel_task(selftest_orchestrator, "selftest-orchestrator", TaskPriority::High)
    {
        Ok(task) => add_task(task),
        Err(_) => crate::serial_println!("[selftest] failed to create orchestrator task"),
    }
}
