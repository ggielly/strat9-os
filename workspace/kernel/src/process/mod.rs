//! Process and Task Management
//!
//! Implements the core structures for process management in Strat9-OS:
//! - Task structure with state management
//! - Process abstraction
//! - Basic scheduler functionality

#[cfg(feature = "selftest")]
pub mod abi_layout_test;
#[cfg(feature = "selftest")]
pub mod demand_paging_test;
pub mod elf;
#[cfg(feature = "selftest")]
pub mod errno_test;
#[cfg(feature = "selftest")]
pub mod fork_test;
#[cfg(feature = "selftest")]
pub mod futex_test;
#[cfg(feature = "selftest")]
pub mod mmap_test;
#[cfg(feature = "selftest")]
pub mod pipe_test;
#[cfg(feature = "selftest")]
pub mod posix_signal_test;
pub mod process;
#[cfg(feature = "selftest")]
pub mod process_id_test;
pub mod sched_classes;
pub mod scheduler;
#[cfg(feature = "selftest")]
pub mod scheduler_test;
#[cfg(feature = "selftest")]
pub mod selftest;
pub mod signal;
pub mod task;
pub mod test;
#[cfg(feature = "selftest")]
pub mod time_test;
pub mod timer;
pub mod usertest;
#[cfg(feature = "selftest")]
pub mod vfs_ops_test;
#[cfg(feature = "selftest")]
pub mod vfs_stat_test;

// Backward-compatible alias while references migrate from `sched` to `sched_classes`.
pub use sched_classes as sched;

pub use scheduler::{
    add_task, block_current_task, class_table as scheduler_class_table, clear_task_wake_deadline,
    configure_class_table, cpu_usage_snapshot, create_session, current_pgid, current_pid,
    current_sid, current_task_clone, current_task_clone_try, current_task_id, current_tid,
    get_all_tasks, get_child_task_id_by_pid, get_child_task_id_by_tid, get_parent_id,
    get_parent_pid, get_pgid_by_pid, get_sid_by_pid, get_task_by_id, get_task_by_pid,
    get_task_id_by_pid, get_task_id_by_tid, get_task_ids_in_pgid, get_task_ids_in_tgid,
    init_scheduler, kill_task, log_state as log_scheduler_state, note_try_lock_fail,
    reset_scheduler_metrics, resume_task, schedule, schedule_on_cpu, scheduler_metrics_snapshot,
    set_process_group, set_task_sched_policy, set_task_wake_deadline,
    set_verbose as set_scheduler_verbose, state_snapshot as scheduler_state_snapshot, suspend_task,
    try_wait_child, verbose_enabled as scheduler_verbose_enabled, wake_task, yield_task,
    CpuUsageSnapshot, SchedulerMetricsSnapshot, SchedulerStateSnapshot, WaitChildResult,
};
pub use signal::{has_pending_signals, send_signal, Signal, SignalSet};
pub use task::{Pid, Task, TaskId, TaskPriority, TaskState, Tid};
