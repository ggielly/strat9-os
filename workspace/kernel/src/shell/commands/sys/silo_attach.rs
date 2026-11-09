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

/// Attach to a silo's debug output stream.
///
/// Usage: `silo attach <id|label|name>`
///
/// Displays output from `sys_debug_log` calls made by tasks in the silo.
/// Press Ctrl+C or 'q' to detach.
pub(super) fn cmd_silo_attach(args: &[String]) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: silo attach <id|label|name>");
        return Err(ShellError::InvalidArguments);
    }
    let selector = normalize_current_silo_selector(args[1].as_str());

    let sid = match silo::silo_detail_snapshot(selector.as_str()) {
        Ok(detail) => {
            shell_println!(
                "Attached to silo {} ({}). Press Ctrl+C or 'q' to detach.",
                detail.base.id,
                detail.base.name
            );
            detail.base.id
        }
        Err(e) => {
            shell_println!("silo attach: {:?}", e);
            return Err(ShellError::ExecutionFailed);
        }
    };

    loop {
        if let Some(ch) = crate::arch::keyboard::read_char() {
            if ch == b'q' || ch == 0x03 || ch == 0x1B {
                break;
            }
        }

        match silo::silo_output_drain(&alloc::format!("{}", sid)) {
            Ok(data) if !data.is_empty() => {
                if let Ok(s) = core::str::from_utf8(&data) {
                    crate::shell_print!("{}", s);
                }
            }
            _ => {}
        }

        crate::process::yield_task();
    }

    shell_println!("
Detached from silo {}", sid);
    Ok(())
}
