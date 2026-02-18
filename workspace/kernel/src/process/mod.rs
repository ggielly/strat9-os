//! Process and Task Management
//!
//! Implements the core structures for process management in Strat9-OS:
//! - Task structure with state management
//! - Process abstraction
//! - Basic scheduler functionality

pub mod elf;
pub mod scheduler;
pub mod signal;
pub mod task;
pub mod test;
pub mod timer;
pub mod usertest;

pub use scheduler::{
    add_task, block_current_task, current_task_clone, current_task_id, get_all_tasks,
    get_task_by_id, init_scheduler, kill_task, resume_task, schedule, schedule_on_cpu,
    suspend_task, wake_task, yield_task,
};
pub use signal::{has_pending_signals, send_signal, Signal, SignalSet};
pub use task::{Task, TaskId, TaskPriority, TaskState};
