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

//! Pure `/proc/meminfo` formatter, kept free of kernel state so it can be
//! host-tested (L2) verbatim.

use alloc::string::String;
use core::fmt::Write;

/// Formats `/proc/meminfo`.
///
/// `total` and `free` are byte counts; values are reported in kB by
/// truncation, like Linux. `MemUsed` is `total - free` with saturating
/// subtraction so a transient `free > total` snapshot cannot underflow.
pub fn format_meminfo(total: u64, free: u64) -> String {
    let used = total.saturating_sub(free);
    let mut output = String::new();
    let _ = writeln!(output, "MemTotal:       {:>10} kB", total / 1024);
    let _ = writeln!(output, "MemFree:        {:>10} kB", free / 1024);
    let _ = writeln!(output, "MemAvailable:   {:>10} kB", free / 1024);
    let _ = writeln!(output, "MemUsed:        {:>10} kB", used / 1024);
    let _ = writeln!(output, "Buffers:               0 kB");
    let _ = writeln!(output, "Cached:                0 kB");
    let _ = writeln!(output, "SwapTotal:             0 kB");
    let _ = writeln!(output, "SwapFree:              0 kB");
    output
}
