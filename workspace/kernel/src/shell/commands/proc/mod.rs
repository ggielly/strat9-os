//! Process management commands (kill)
use crate::{shell::ShellError, shell_println};
use alloc::string::String;

pub fn cmd_kill(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: kill <pid>");
        return Err(ShellError::InvalidArguments);
    }
    let pid_val: u32 = args[0].parse().map_err(|_| {
        shell_println!("kill: invalid pid '{}'", args[0]);
        ShellError::InvalidArguments
    })?;

    let task_id = match crate::process::get_task_id_by_pid(pid_val) {
        Some(tid) => tid,
        None => {
            shell_println!("kill: no task with pid {}", pid_val);
            return Err(ShellError::ExecutionFailed);
        }
    };

    if crate::process::kill_task(task_id) {
        shell_println!("kill: terminated pid {} (tid={})", pid_val, task_id.as_u64());
        Ok(())
    } else {
        shell_println!("kill: failed to terminate pid {}", pid_val);
        Err(ShellError::ExecutionFailed)
    }
}
