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

//! Shared helpers for the `test_gui_*` audit binaries.
//!
//! Two kinds of result are reported:
//!
//! * `CHECK` - a property the GUI design depends on and that must hold. A
//!   failing check makes the binary exit non-zero.
//! * `GAP`   - a property the GUI design would like to rely on but that may
//!   not exist yet. `GAP-PRESENT` means the limitation exists today (it is
//!   an audit finding, not a test failure). `GAP-ABSENT` means the property
//!   holds. `INCONCLUSIVE` means the experiment could not decide.
//!
//! The audit document (`doc/GUI_AUDIT_2026-11.md`) is updated from these
//! lines; do not change their format without updating it.

#![allow(dead_code)]

use strat9_syscall::{call, data::TimeSpec, error::Error};

pub const PAGE_SIZE: usize = 4096;
pub const WNOHANG: usize = 1;

pub struct Ctx {
    pub name: &'static str,
    pub pass: u64,
    pub fail: u64,
    pub gap_present: u64,
    pub gap_absent: u64,
    pub inconclusive: u64,
}

impl Ctx {
    pub const fn new(name: &'static str) -> Self {
        Ctx {
            name,
            pass: 0,
            fail: 0,
            gap_present: 0,
            gap_absent: 0,
            inconclusive: 0,
        }
    }
}

pub fn log(msg: &str) {
    let _ = call::write(1, msg.as_bytes());
}

pub fn log_u64(mut value: u64) {
    let mut buf = [0u8; 21];
    if value == 0 {
        log("0");
        return;
    }
    let mut i = buf.len();
    while value > 0 {
        i -= 1;
        buf[i] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    // SAFETY: the buffer only holds ASCII digits written above.
    log(unsafe { core::str::from_utf8_unchecked(&buf[i..]) });
}

pub fn log_hex(value: u64) {
    let mut buf = [0u8; 16];
    for i in 0..16 {
        let nib = ((value >> ((15 - i) * 4)) & 0xF) as u8;
        buf[i] = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
    }
    log("0x");
    // SAFETY: the buffer only holds ASCII hex digits written above.
    log(unsafe { core::str::from_utf8_unchecked(&buf) });
}

fn line(ctx: &Ctx, tag: &str, label: &str, detail: &str) {
    log("[");
    log(ctx.name);
    log("] ");
    log(tag);
    log(" ");
    log(label);
    if !detail.is_empty() {
        log(" :: ");
        log(detail);
    }
    log("\n");
}

pub fn section(ctx: &Ctx, title: &str) {
    log("\n=== [");
    log(ctx.name);
    log("] ");
    log(title);
    log(" ===\n");
}

/// A property that must hold.
pub fn check(ctx: &mut Ctx, label: &str, cond: bool, detail: &str) {
    if cond {
        ctx.pass += 1;
        line(ctx, "CHECK-OK  ", label, detail);
    } else {
        ctx.fail += 1;
        line(ctx, "CHECK-FAIL", label, detail);
    }
}

/// A property the design wants; `present == true` means the limitation exists.
pub fn gap(ctx: &mut Ctx, label: &str, present: bool, detail: &str) {
    if present {
        ctx.gap_present += 1;
        line(ctx, "GAP-PRESENT", label, detail);
    } else {
        ctx.gap_absent += 1;
        line(ctx, "GAP-ABSENT ", label, detail);
    }
}

pub fn inconclusive(ctx: &mut Ctx, label: &str, why: &str) {
    ctx.inconclusive += 1;
    line(ctx, "INCONCLUSIVE", label, why);
}

pub fn err_name(e: Error) -> &'static str {
    e.name()
}

pub fn sleep_ms(ms: u64) {
    let req = TimeSpec {
        tv_sec: (ms / 1000) as i64,
        tv_nsec: ((ms % 1000) * 1_000_000) as i64,
    };
    let mut rem = TimeSpec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let _ = call::nanosleep(&req, &mut rem);
}

/// Outcome of a reaped child.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Code(i32),
    Signal(i32),
}

pub fn decode_status(status: i32) -> Exit {
    if status & 0x7f == 0 {
        Exit::Code((status >> 8) & 0xff)
    } else {
        Exit::Signal(status & 0x7f)
    }
}

pub fn reap(pid: usize) -> Option<Exit> {
    let mut status = 0i32;
    match call::waitpid_blocking(pid as isize, &mut status) {
        Ok(_) => Some(decode_status(status)),
        Err(_) => None,
    }
}

/// Non-blocking reap. `None` = still running (or error).
pub fn try_reap(pid: usize) -> Option<Exit> {
    let mut status = 0i32;
    match call::waitpid(pid as isize, Some(&mut status), WNOHANG) {
        Ok(0) => None,
        Ok(_) => Some(decode_status(status)),
        Err(_) => None,
    }
}

pub fn write_all(fd: usize, mut buf: &[u8]) -> bool {
    while !buf.is_empty() {
        match call::write(fd, buf) {
            Ok(0) => return false,
            Ok(n) => buf = &buf[n..],
            Err(Error::Interrupted) | Err(Error::Again) => {
                let _ = call::sched_yield();
            }
            Err(_) => return false,
        }
    }
    true
}

pub fn read_exact(fd: usize, mut buf: &mut [u8]) -> bool {
    while !buf.is_empty() {
        match call::read(fd, buf) {
            Ok(0) => return false, // EOF: writer gone
            Ok(n) => {
                let (_, tail) = buf.split_at_mut(n);
                buf = tail;
            }
            Err(Error::Interrupted) | Err(Error::Again) => {
                let _ = call::sched_yield();
            }
            Err(_) => return false,
        }
    }
    true
}

pub fn send_u8(fd: usize, v: u8) -> bool {
    write_all(fd, &[v])
}

pub fn recv_u8(fd: usize) -> Option<u8> {
    let mut b = [0u8; 1];
    if read_exact(fd, &mut b) {
        Some(b[0])
    } else {
        None
    }
}

pub fn send_u64(fd: usize, v: u64) -> bool {
    write_all(fd, &v.to_ne_bytes())
}

pub fn recv_u64(fd: usize) -> Option<u64> {
    let mut b = [0u8; 8];
    if read_exact(fd, &mut b) {
        Some(u64::from_ne_bytes(b))
    } else {
        None
    }
}

/// Final report; returns the process exit code.
pub fn summary(ctx: &Ctx) -> usize {
    log("\n[");
    log(ctx.name);
    log("] SUMMARY check_ok=");
    log_u64(ctx.pass);
    log(" check_fail=");
    log_u64(ctx.fail);
    log(" gap_present=");
    log_u64(ctx.gap_present);
    log(" gap_absent=");
    log_u64(ctx.gap_absent);
    log(" inconclusive=");
    log_u64(ctx.inconclusive);
    log("\n");
    if ctx.fail == 0 {
        0
    } else {
        1
    }
}
