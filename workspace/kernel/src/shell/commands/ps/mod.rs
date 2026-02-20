//! Process management commands
use crate::shell_println;
use crate::shell::ShellError;
use alloc::string::String;

/// List all tasks
pub fn cmd_ps(_args: &[String]) -> Result<(), ShellError> {
    shell_println!("PID    Name              State      Priority");
    shell_println!("────────────────────────────────────────────────");

    if let Some(tasks) = crate::process::get_all_tasks() {
        for task in tasks {
            let state = unsafe { *task.state.get() };
            let state_str = match state {
                crate::process::TaskState::Ready => "Ready",
                crate::process::TaskState::Running => "Running",
                crate::process::TaskState::Blocked => "Blocked",
                crate::process::TaskState::Dead => "Dead",
            };

            let priority_str = match task.priority {
                crate::process::TaskPriority::Idle => "Idle",
                crate::process::TaskPriority::Low => "Low",
                crate::process::TaskPriority::Normal => "Normal",
                crate::process::TaskPriority::High => "High",
                crate::process::TaskPriority::Realtime => "Realtime",
            };

            shell_println!(
                "{:<6} {:<17} {:<10} {:?}",
                task.id.as_u64(),
                task.name,
                state_str,
                task.priority
            );
        }
    } else {
        shell_println!("  No tasks available");
    }

    shell_println!("");
    Ok(())
}
