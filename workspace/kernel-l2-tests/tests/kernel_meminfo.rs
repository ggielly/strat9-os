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

//! L2 : `/proc/meminfo` formatter (real kernel code, host).
//!
//! The kernel module is pure (no allocator state), so it is included
//! verbatim and exercised on the host.

extern crate alloc;

#[path = "../../kernel/src/vfs/meminfo.rs"]
mod meminfo;

use meminfo::format_meminfo;

const KIB: u64 = 1024;

/// Parses the numeric field of the first line starting with `key`.
fn kb(output: &str, key: &str) -> u64 {
    let line = output
        .lines()
        .find(|l| l.starts_with(key))
        .unwrap_or_else(|| panic!("missing {key} in:\n{output}"));
    line.split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("malformed line: {line}"))
}

#[test]
fn reports_real_totals_and_used() {
    let out = format_meminfo(8 * 1024 * KIB * KIB, 2 * 1024 * KIB * KIB);

    assert_eq!(kb(&out, "MemTotal"), 8 * 1024 * 1024);
    assert_eq!(kb(&out, "MemFree"), 2 * 1024 * 1024);
    assert_eq!(kb(&out, "MemAvailable"), 2 * 1024 * 1024);
    assert_eq!(kb(&out, "MemUsed"), 6 * 1024 * 1024);
}

#[test]
fn kb_truncates_like_linux() {
    // total 5119 B -> 4 kB, free 1023 B -> 0 kB, used 4096 B -> 4 kB.
    let out = format_meminfo(5119, 1023);

    assert_eq!(kb(&out, "MemTotal"), 4);
    assert_eq!(kb(&out, "MemFree"), 0);
    assert_eq!(kb(&out, "MemUsed"), 4);
}

#[test]
fn free_above_total_does_not_underflow() {
    let out = format_meminfo(KIB, 2 * KIB);

    assert_eq!(kb(&out, "MemTotal"), 1);
    assert_eq!(kb(&out, "MemFree"), 2);
    assert_eq!(kb(&out, "MemUsed"), 0);
}

#[test]
fn zero_snapshot_stays_consistent() {
    let out = format_meminfo(0, 0);

    assert_eq!(kb(&out, "MemTotal"), 0);
    assert_eq!(kb(&out, "MemFree"), 0);
    assert_eq!(kb(&out, "MemAvailable"), 0);
    assert_eq!(kb(&out, "MemUsed"), 0);
}

#[test]
fn keeps_linux_line_order_and_zero_padding() {
    let out = format_meminfo(4 * KIB * KIB, KIB * KIB);
    let keys: alloc::vec::Vec<&str> = out.lines().map(|l| l.split(':').next().unwrap()).collect();

    assert_eq!(
        keys,
        [
            "MemTotal",
            "MemFree",
            "MemAvailable",
            "MemUsed",
            "Buffers",
            "Cached",
            "SwapTotal",
            "SwapFree",
        ]
    );
    assert_eq!(out.lines().nth(0).unwrap(), "MemTotal:             4096 kB");
    assert!(out.contains("Buffers:               0 kB"));
    assert!(out.contains("Cached:                0 kB"));
    assert!(out.contains("SwapTotal:             0 kB"));
    assert!(out.contains("SwapFree:              0 kB"));
}
