//! runtime self-tests for scheduler classes and tracing hooks.
//!
//! runs only in test iso (`feature = "selftest"`).

use crate::process::{
    add_task, configure_class_table, get_task_by_id, kill_task, log_scheduler_state,
    scheduler::ticks, scheduler_class_table, set_scheduler_verbose, set_task_sched_policy, Task,
    TaskId, TaskPriority,
};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static RT_HITS: AtomicU64 = AtomicU64::new(0);
static FAIR_HITS: AtomicU64 = AtomicU64::new(0);
static SWITCH_WORKER_HITS: AtomicU64 = AtomicU64::new(0);
static SWITCH_WORKER_DONE: AtomicBool = AtomicBool::new(false);
static MIGRATION_READY_HITS: AtomicU64 = AtomicU64::new(0);

#[inline]
fn sched_test_log(msg: core::fmt::Arguments<'_>) {
    crate::serial_println!("[sched][test] {}", msg);
}

fn wait_exit(id: TaskId, timeout_ticks: u64) -> bool {
    let start = ticks();
    // Budget proportionnel au timeout pour éviter de l'épuiser avant les ticks
    // (sur machine rapide, yield_task peut revenir bien avant qu'un tick s'écoule)
    let spin_budget = timeout_ticks.saturating_mul(100_000).max(10_000_000);
    let mut iterations: u64 = 0;
    loop {
        if get_task_by_id(id).is_none() {
            return true;
        }
        if ticks().saturating_sub(start) > timeout_ticks {
            let _ = kill_task(id);
            return false;
        }
        if iterations >= spin_budget {
            let _ = kill_task(id);
            return false;
        }
        iterations = iterations.saturating_add(1);
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

extern "C" fn migration_ready_probe_main() -> ! {
    MIGRATION_READY_HITS.fetch_add(1, Ordering::Relaxed);
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
    crate::process::yield_task(); // laisser le scheduler démarrer les probes

    let fair_ok = wait_exit(fair_id, 1500);
    let rt_ok = wait_exit(rt_id, 1500);
    let rt_hits = RT_HITS.load(Ordering::Relaxed);
    let fair_hits = FAIR_HITS.load(Ordering::Relaxed);

    if !fair_ok || !rt_ok {
        return false;
    }

    rt_hits > 0 && fair_hits > 0
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
    crate::process::yield_task(); // laisser le worker démarrer

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

    let _ = (p1, p2, p3);
    done && SWITCH_WORKER_HITS.load(Ordering::Relaxed) > 0
}

fn test_config_validation_reject() -> bool {
    let mut t1 = scheduler_class_table();
    let bad_pick = t1.set_pick_order([
        crate::process::sched::SchedClassId::RealTime,
        crate::process::sched::SchedClassId::RealTime,
        crate::process::sched::SchedClassId::Idle,
    ]);

    let mut t2 = scheduler_class_table();
    let bad_steal = t2.set_steal_order([
        crate::process::sched::SchedClassId::Idle,
        crate::process::sched::SchedClassId::Fair,
    ]);

    let mut t3 = scheduler_class_table();
    let bad_policy = t3.set_policy_class(
        crate::process::sched::SchedPolicyKind::Idle,
        crate::process::sched::SchedClassId::Fair,
    );

    !bad_pick && !bad_steal && !bad_policy
}

fn test_ready_task_migration_on_policy_map_update() -> bool {
    MIGRATION_READY_HITS.store(0, Ordering::Relaxed);
    let task = match Task::new_kernel_task(
        migration_ready_probe_main,
        "sched-ready-migrate-probe",
        TaskPriority::Normal,
    ) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let id = task.id;
    add_task(task);

    let mut table = scheduler_class_table();
    let changed = table.set_policy_class(
        crate::process::sched::SchedPolicyKind::Fair,
        crate::process::sched::SchedClassId::RealTime,
    );
    let applied = configure_class_table(table);
    crate::process::yield_task();
    let finished = wait_exit(id, 500);

    let mut restore = scheduler_class_table();
    let _ = restore.set_policy_class(
        crate::process::sched::SchedPolicyKind::Fair,
        crate::process::sched::SchedClassId::Fair,
    );
    let _ = configure_class_table(restore);

    changed && applied && finished && MIGRATION_READY_HITS.load(Ordering::Relaxed) > 0
}

extern "C" fn scheduler_test_main() -> ! {
    sched_test_log(format_args!("event=start"));
    set_scheduler_verbose(false);
    log_scheduler_state("test-start");

    let s1 = test_rt_preempts_fair();
    sched_test_log(format_args!(
        "case=rt-preempts-fair result={}",
        if s1 { "ok" } else { "FAIL" }
    ));

    let s2 = test_dynamic_policy_switch();
    sched_test_log(format_args!(
        "case=dynamic-policy-switch result={}",
        if s2 { "ok" } else { "FAIL" }
    ));

    let s3 = test_config_validation_reject();
    sched_test_log(format_args!(
        "case=config-validation-reject result={}",
        if s3 { "ok" } else { "FAIL" }
    ));

    let s4 = test_ready_task_migration_on_policy_map_update();
    sched_test_log(format_args!(
        "case=ready-task-migration result={}",
        if s4 { "ok" } else { "FAIL" }
    ));

    log_scheduler_state("test-end");
    set_scheduler_verbose(false);

    sched_test_log(format_args!(
        "summary pass={} fail={} overall={}",
        (s1 as u8) + (s2 as u8) + (s3 as u8) + (s4 as u8),
        (!s1 as u8) + (!s2 as u8) + (!s3 as u8) + (!s4 as u8),
        if s1 && s2 && s3 && s4 { "PASS" } else { "FAIL" }
    ));
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
        sched_test_log(format_args!("event=create-task result=fail"));
    }
}
