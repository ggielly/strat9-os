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

use super::*;

/// Launch a userspace GUI audit binary from initfs by name.
fn launch_gui_audit(name: &'static str) -> Result<(), ShellError> {
    let path = match name {
        "test_gui_mem" => "/initfs/test_gui_mem",
        "test_gui_authority" => "/initfs/test_gui_authority",
        "test_gui_display" => "/initfs/test_gui_display",
        _ => return Err(ShellError::ExecutionFailed),
    };
    shell_println!("Launching {} ...", path);

    let fd = match vfs::open(path, vfs::OpenFlags::READ) {
        Ok(fd) => fd,
        Err(e) => {
            shell_println!("open failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };

    let data = match vfs::read_all(fd) {
        Ok(d) => d,
        Err(e) => {
            let _ = vfs::close(fd);
            shell_println!("read failed: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };
    let _ = vfs::close(fd);

    shell_println!("ELF size: {} bytes", data.len());
    match load_and_run_elf(&data, name) {
        Ok(task_id) => {
            shell_println!("{} started (task id={})", name, task_id);
            Ok(())
        }
        Err(e) => {
            shell_println!("load_and_run_elf failed: {}", e);
            Err(ShellError::ExecutionFailed)
        }
    }
}

/// Run the userspace GUI memory audit binary from initfs.
pub fn cmd_test_gui_mem(_args: &[String]) -> Result<(), ShellError> {
    launch_gui_audit("test_gui_mem")
}

/// Run the userspace GUI authority audit binary from initfs.
pub fn cmd_test_gui_authority(_args: &[String]) -> Result<(), ShellError> {
    launch_gui_audit("test_gui_authority")
}

/// Run the userspace GUI display audit binary from initfs.
pub fn cmd_test_gui_display(_args: &[String]) -> Result<(), ShellError> {
    launch_gui_audit("test_gui_display")
}
