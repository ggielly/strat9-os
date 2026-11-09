/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

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
        shell_println!(
            "kill: terminated pid {} (tid={})",
            pid_val,
            task_id.as_u64()
        );
        Ok(())
    } else {
        shell_println!("kill: failed to terminate pid {}", pid_val);
        Err(ShellError::ExecutionFailed)
    }
}
