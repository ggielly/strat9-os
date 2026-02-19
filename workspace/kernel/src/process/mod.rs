//! Process and Task Management
//!
//! Implements the core structures for process management in Strat9-OS:
//! - Task structure with state management
//! - Process abstraction
//! - Basic scheduler functionality

pub mod elf;
#[cfg(feature = "selftest")]
pub mod futex_test;
#[cfg(feature = "selftest")]
pub mod mmap_test;
#[cfg(feature = "selftest")]
pub mod selftest;
pub mod scheduler;
pub mod signal;
pub mod task;
pub mod test;
pub mod timer;
pub mod usertest;

pub use scheduler::{
    add_task, block_current_task, current_task_clone, current_task_id, get_all_tasks,
    get_parent_id, get_task_by_id, init_scheduler, kill_task, resume_task, schedule,
    schedule_on_cpu, suspend_task, try_wait_child, wake_task, yield_task, WaitChildResult,
};
pub use signal::{has_pending_signals, send_signal, Signal, SignalSet};
pub use task::{Task, TaskId, TaskPriority, TaskState};
