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

/// Execute a command repeatedly at a given interval.
///
/// Usage: `watch <seconds> <command...>`
///
/// Runs the specified command every N seconds until Ctrl+C.
pub fn cmd_watch(args: &[String]) -> Result<(), ShellError> {
    if args.len() < 2 {
        shell_println!("Usage: watch <seconds> <command...>");
        return Err(ShellError::InvalidArguments);
    }
    let interval_secs: u64 = args[0].parse().map_err(|_| {
        shell_println!("watch: invalid interval '{}'", args[0]);
        ShellError::InvalidArguments
    })?;
    if interval_secs == 0 {
        shell_println!("watch: interval must be >= 1 second");
        return Err(ShellError::InvalidArguments);
    }
    let cmd_line = args[1..].join(" ");
    let hz = crate::arch::timer::TIMER_HZ;
    let interval_ticks = interval_secs * hz;

    shell_println!("Every {}s: {}", interval_secs, cmd_line);
    shell_println!("Press Ctrl+C to stop.
");

    loop {
        if crate::shell::is_interrupted() {
            break;
        }
        if let Some(ch) = crate::arch::keyboard::read_char() {
            if ch == 0x03 || ch == b'q' {
                break;
            }
        }

        crate::shell::run_line(&cmd_line);

        let start = crate::process::scheduler::ticks();
        while crate::process::scheduler::ticks() - start < interval_ticks {
            if crate::shell::is_interrupted() {
                return Ok(());
            }
            if let Some(ch) = crate::arch::keyboard::read_char() {
                if ch == 0x03 || ch == b'q' {
                    return Ok(());
                }
            }
            crate::process::yield_task();
        }
    }
    Ok(())
}
