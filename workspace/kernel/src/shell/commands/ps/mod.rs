//! Process management commands
use crate::{
    shell::{output::task_state_str, ShellError},
    shell_println,
};
use alloc::string::String;

/// List all tasks
///
/// `PID` is the userspace pid, which is what `kill <pid>` takes. The kernel task
/// id is shown as `TID` for disambiguation: reporting the task id under the
/// `PID` header used to hand users a number `kill` rejects with
/// "no task with pid N".
pub fn cmd_ps(args: &[String]) -> Result<(), ShellError> {
    if let Some(unknown) = args.iter().find(|a| a.starts_with('-')) {
        shell_println!("ps: unknown option '{}'", unknown);
        return Err(ShellError::InvalidArguments);
    }

    const COLS: [usize; 5] = [6, 6, 18, 10, 8];
    shell_println!(
        "{:<6} {:<6} {:<18} {:<10} {}",
        "PID",
        "TID",
        "Name",
        "State",
        "Prio"
    );
    shell_println!("{}", "-".repeat(COLS.iter().sum::<usize>()));

    let Some(tasks) = crate::process::get_all_tasks() else {
        shell_println!("  (no tasks available)");
        return Ok(());
    };
    let count = tasks.len();

    for task in tasks {
        shell_println!(
            "{:<6} {:<6} {:<18} {:<10} {:?}",
            task.pid,
            task.id.as_u64(),
            task.name,
            task_state_str(task.get_state()),
            task.priority
        );
    }
    shell_println!("");
    shell_println!("{} task(s)", count);
    Ok(())
}
