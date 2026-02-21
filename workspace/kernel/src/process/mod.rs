//! Process and Task Management
//!
//! Implements the core structures for process management in Strat9-OS:
//! - Task structure with state management
//! - Process abstraction
//! - Basic scheduler functionality

#[cfg(feature = "selftest")]
pub mod demand_paging_test;
pub mod elf;
#[cfg(feature = "selftest")]
pub mod fork_test;
#[cfg(feature = "selftest")]
pub mod futex_test;
#[cfg(feature = "selftest")]
pub mod mmap_test;
#[cfg(feature = "selftest")]
pub mod posix_signal_test;
pub mod scheduler;
#[cfg(feature = "selftest")]
pub mod selftest;
pub mod signal;
pub mod task;
pub mod test;
pub mod timer;
pub mod usertest;

pub use scheduler::{
    add_task, block_current_task, current_task_clone, current_task_id, get_all_tasks,
    current_pgid, current_pid, current_sid, current_tid, create_session, get_parent_id,
    get_parent_pid, get_pgid_by_pid, get_sid_by_pid, get_task_by_id, get_task_by_pid,
    get_task_id_by_pid,
    get_task_ids_in_pgid, init_scheduler, kill_task, resume_task, schedule, schedule_on_cpu,
    set_process_group, suspend_task, try_wait_child, wake_task, yield_task, WaitChildResult,
};
pub use signal::{has_pending_signals, send_signal, Signal, SignalSet};
pub use task::{Pid, Task, TaskId, TaskPriority, TaskState, Tid};
