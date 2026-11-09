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

/// Dynamically adjust silo resource limits.
///
/// Usage: `silo limit <id|label|name> <key> <value>`
///
/// Keys: `mem_max`, `mem_min`, `max_tasks`, `cpu_shares`.
pub(super) fn cmd_silo_limit(args: &[String]) -> Result<(), ShellError> {
    if args.len() < 4 {
        shell_println!("Usage: silo limit <id|label|name> <key> <value>");
        shell_println!("  Keys: mem_max, mem_min, max_tasks, cpu_shares");
        return Err(ShellError::InvalidArguments);
    }
    let selector = normalize_current_silo_selector(args[1].as_str());
    let key = args[2].as_str();
    let value: u64 = args[3].parse().map_err(|_| {
        shell_println!("silo limit: invalid value '{}'", args[3]);
        ShellError::InvalidArguments
    })?;

    match silo::kernel_limit_silo(selector.as_str(), key, value) {
        Ok(sid) => {
            shell_println!("silo limit: {}={} for sid={}", key, value, sid);
            Ok(())
        }
        Err(e) => {
            shell_println!("silo limit failed: {:?}", e);
            Err(ShellError::ExecutionFailed)
        }
    }
}
