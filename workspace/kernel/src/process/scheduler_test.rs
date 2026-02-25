//! runtime self-tests for scheduler classes and tracing hooks.
//!
//! runs only in test iso (`feature = "selftest"`).

use crate::process::{
    add_task, get_task_by_id, kill_task, log_scheduler_state, scheduler::ticks,
    set_scheduler_verbose, set_task_sched_policy, Task, TaskId, TaskPriority,
};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static RT_HITS: AtomicU64 = AtomicU64::new(0);
static FAIR_HITS: AtomicU64 = AtomicU64::new(0);
static SWITCH_WORKER_HITS: AtomicU64 = AtomicU64::new(0);
static SWITCH_WORKER_DONE: AtomicBool = AtomicBool::new(false);

fn wait_exit(id: TaskId, timeout_ticks: u64) -> bool {
    let start = ticks();
    loop {
        if get_task_by_id(id).is_none() {
            return true;
        }
        if ticks().saturating_sub(start) > timeout_ticks {
            let _ = kill_task(id);
            return false;
        }
        crate::process::yield_task();
    }
}

extern "C" fn rt_probe_main() -> ! {
    let start = ticks();
    while ticks().saturating_sub(start) < 40 {
        RT_HITS.fetch_add(1, Ordering::Relaxed);
    }
    crate::process::scheduler::exit_current_task(0);
}

extern "C" fn fair_probe_main() -> ! {
    let start = ticks();
    while ticks().saturating_sub(start) < 40 {
        FAIR_HITS.fetch_add(1, Ordering::Relaxed);
        crate::process::yield_task();
    }
    crate::process::scheduler::exit_current_task(0);
}

extern "C" fn switch_probe_main() -> ! {
    while !SWITCH_WORKER_DONE.load(Ordering::Relaxed) {
        SWITCH_WORKER_HITS.fetch_add(1, Ordering::Relaxed);
        crate::process::yield_task();
    }
    crate::process::scheduler::exit_current_task(0);
}

fn test_rt_preempts_fair() -> bool {
    RT_HITS.store(0, Ordering::Relaxed);
    FAIR_HITS.store(0, Ordering::Relaxed);

    let fair =
        match Task::new_kernel_task(fair_probe_main, "sched-fair-probe", TaskPriority::Normal) {
            Ok(t) => t,
            Err(_) => return false,
        };
    let fair_id = fair.id;
    let rt = match Task::new_kernel_task(rt_probe_main, "sched-rt-probe", TaskPriority::Realtime) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let rt_id = rt.id;

    add_task(fair);
    add_task(rt);
    log_scheduler_state("rt-preempt-start");

    let fair_ok = wait_exit(fair_id, 1500);
    let rt_ok = wait_exit(rt_id, 1500);
    let rt_hits = RT_HITS.load(Ordering::Relaxed);
    let fair_hits = FAIR_HITS.load(Ordering::Relaxed);

    fair_ok && rt_ok && rt_hits > fair_hits
}

fn test_dynamic_policy_switch() -> bool {
    SWITCH_WORKER_HITS.store(0, Ordering::Relaxed);
    SWITCH_WORKER_DONE.store(false, Ordering::Relaxed);

    let worker = match Task::new_kernel_task(
        switch_probe_main,
        "sched-switch-probe",
        TaskPriority::Normal,
    ) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let id = worker.id;
    add_task(worker);

    let p1 = set_task_sched_policy(
        id,
        crate::process::sched::SchedPolicy::RealTimeRR {
            prio: crate::process::sched::real_time::RealTimePriority::new(70),
        },
    );
    let p2 = set_task_sched_policy(
        id,
        crate::process::sched::SchedPolicy::Fair(crate::process::sched::nice::Nice::new(-5)),
    );
    let p3 = set_task_sched_policy(
        id,
        crate::process::sched::SchedPolicy::Fair(crate::process::sched::nice::Nice::new(10)),
    );

    let start = ticks();
    while SWITCH_WORKER_HITS.load(Ordering::Relaxed) < 200 && ticks().saturating_sub(start) < 800 {
        crate::process::yield_task();
    }
    SWITCH_WORKER_DONE.store(true, Ordering::Relaxed);
    let done = wait_exit(id, 800);
    p1 && p2 && p3 && done && SWITCH_WORKER_HITS.load(Ordering::Relaxed) > 0
}

extern "C" fn scheduler_test_main() -> ! {
    crate::serial_println!("[sched-test] start");
    set_scheduler_verbose(true);
    log_scheduler_state("start");

    let s1 = test_rt_preempts_fair();
    crate::serial_println!(
        "[sched-test] rt-preempts-fair: {}",
        if s1 { "ok" } else { "FAIL" }
    );

    let s2 = test_dynamic_policy_switch();
    crate::serial_println!(
        "[sched-test] dynamic-policy-switch: {}",
        if s2 { "ok" } else { "FAIL" }
    );

    log_scheduler_state("end");
    set_scheduler_verbose(false);
    crate::serial_println!(
        "[sched-test] summary: {}",
        if s1 && s2 { "PASS" } else { "FAIL" }
    );
    crate::process::scheduler::exit_current_task(0);
}

pub fn create_scheduler_test_task() {
    if let Ok(task) = Task::new_kernel_task_with_stack(
        scheduler_test_main,
        "scheduler-test",
        TaskPriority::High,
        64 * 1024,
    ) {
        add_task(task);
    } else {
        crate::serial_println!("[sched-test] failed to create task");
    }
}
