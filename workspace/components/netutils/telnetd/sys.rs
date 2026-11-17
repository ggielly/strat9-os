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

//! Thin userspace helpers over the Strat9 VFS syscalls used by telnetd.

use alloc::{string::String, vec::Vec};
use strat9_syscall::{
    call,
    data::{FileStat, TimeSpec},
    dirent::DirentIter,
    error::Error,
    flag::OpenFlags,
    number,
};

pub const EAGAIN: usize = 11;
pub const ECONNRESET: usize = 104;

pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFLNK: u32 = 0o120000;

pub const DT_DIR: u8 = 4;
pub const DT_LNK: u8 = 10;

pub type Res<T> = Result<T, Error>;

pub fn log(msg: &str) {
    let _ = call::debug_log(msg.as_bytes());
}

pub fn sleep_ms(ms: u64) {
    let req = TimeSpec {
        tv_sec: (ms / 1000) as i64,
        tv_nsec: ((ms % 1000) * 1_000_000) as i64,
    };
    // SAFETY: `req` is a valid TimeSpec for the duration of the call; the
    // remaining-time pointer is optional (null).
    let _ = unsafe {
        strat9_syscall::syscall2(number::SYS_NANOSLEEP, &req as *const TimeSpec as usize, 0)
    };
}

/// Write the whole buffer, retrying on `EAGAIN` (socket send window full).
pub fn write_all(fd: usize, data: &[u8]) -> bool {
    let mut off = 0usize;
    let mut retries = 0u32;
    while off < data.len() {
        match call::write(fd, &data[off..]) {
            Ok(0) => return false,
            Ok(n) => {
                off += n;
                retries = 0;
            }
            Err(e) => {
                if e.to_errno() == EAGAIN {
                    retries += 1;
                    if retries > 500 {
                        return false;
                    }
                    sleep_ms(10);
                    continue;
                }
                return false;
            }
        }
    }
    true
}

// ── Path helpers ────────────────────────────────────────────────────────────

/// Collapse `.`, `..` and duplicate `/` in an absolute path.
pub fn normalize(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for c in path.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                let _ = parts.pop();
            }
            other => parts.push(other),
        }
    }
    let mut out = String::from("/");
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            out.push('/');
        }
        out.push_str(p);
    }
    out
}

/// Resolve `path` against `cwd` into a normalized absolute path.
pub fn resolve(cwd: &str, path: &str) -> String {
    if path.is_empty() {
        return normalize(cwd);
    }
    if path.starts_with('/') {
        return normalize(path);
    }
    let mut joined = String::from(cwd);
    if !joined.ends_with('/') {
        joined.push('/');
    }
    joined.push_str(path);
    normalize(&joined)
}

/// Last component of a path (`/` for the root).
pub fn basename(path: &str) -> &str {
    let t = path.trim_end_matches('/');
    match t.rfind('/') {
        Some(i) if i + 1 < t.len() => &t[i + 1..],
        _ if t.is_empty() => "/",
        _ => t,
    }
}

pub fn join(dir: &str, name: &str) -> String {
    let mut s = String::from(dir);
    if !s.ends_with('/') {
        s.push('/');
    }
    s.push_str(name);
    s
}

// ── VFS wrappers ────────────────────────────────────────────────────────────

pub fn open(path: &str, flags: OpenFlags) -> Res<usize> {
    call::openat(0, path, flags.bits() as usize, 0)
}

pub fn stat(path: &str) -> Res<FileStat> {
    let mut st = FileStat::zeroed();
    call::stat(path, &mut st)?;
    Ok(st)
}

pub fn is_dir(path: &str) -> bool {
    match stat(path) {
        Ok(st) => st.st_mode & S_IFMT == S_IFDIR,
        Err(_) => match open(path, OpenFlags::READ | OpenFlags::DIRECTORY) {
            Ok(fd) => {
                let _ = call::close(fd);
                true
            }
            Err(_) => false,
        },
    }
}

pub fn mkdir(path: &str, mode: usize) -> Res<()> {
    // SAFETY: pointer/length describe a live `&str` for the whole call.
    unsafe { strat9_syscall::syscall3(number::SYS_MKDIR, path.as_ptr() as usize, path.len(), mode) }
        .map(|_| ())
}

pub fn unlink(path: &str) -> Res<()> {
    // SAFETY: pointer/length describe a live `&str` for the whole call.
    unsafe { strat9_syscall::syscall2(number::SYS_UNLINK, path.as_ptr() as usize, path.len()) }
        .map(|_| ())
}

pub fn rmdir(path: &str) -> Res<()> {
    // SAFETY: pointer/length describe a live `&str` for the whole call.
    unsafe { strat9_syscall::syscall2(number::SYS_RMDIR, path.as_ptr() as usize, path.len()) }
        .map(|_| ())
}

pub fn chmod(path: &str, mode: usize) -> Res<()> {
    // SAFETY: pointer/length describe a live `&str` for the whole call.
    unsafe { strat9_syscall::syscall3(number::SYS_CHMOD, path.as_ptr() as usize, path.len(), mode) }
        .map(|_| ())
}

pub fn link(old: &str, new: &str) -> Res<()> {
    // SAFETY: both pointer/length pairs describe live `&str`s for the call.
    unsafe {
        strat9_syscall::syscall4(
            number::SYS_LINK,
            old.as_ptr() as usize,
            old.len(),
            new.as_ptr() as usize,
            new.len(),
        )
    }
    .map(|_| ())
}

pub fn rename(old: &str, new: &str) -> Res<()> {
    // SAFETY: both pointer/length pairs describe live `&str`s for the call.
    unsafe {
        strat9_syscall::syscall4(
            number::SYS_RENAME,
            old.as_ptr() as usize,
            old.len(),
            new.as_ptr() as usize,
            new.len(),
        )
    }
    .map(|_| ())
}

/// One decoded directory entry.
pub struct DirEntry {
    pub name: String,
    pub file_type: u8,
}

/// List a directory (entries `.`/`..` removed, sorted by name).
pub fn read_dir(path: &str) -> Res<Vec<DirEntry>> {
    let fd = open(path, OpenFlags::READ | OpenFlags::DIRECTORY)?;
    let mut buf = alloc::vec![0u8; 32 * 1024];
    let res = call::getdents(fd, &mut buf);
    let _ = call::close(fd);
    let n = res?;
    let mut entries: Vec<DirEntry> = DirentIter::new(&buf, n)
        .filter_map(|d| {
            let name = core::str::from_utf8(d.name()).ok()?;
            if name == "." || name == ".." {
                return None;
            }
            Some(DirEntry {
                name: String::from(name),
                file_type: d.type_,
            })
        })
        .collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

/// Read up to `cap` bytes of a file.
pub fn read_file(path: &str, cap: usize) -> Res<Vec<u8>> {
    let fd = open(path, OpenFlags::READ)?;
    let mut data = Vec::new();
    let mut chunk = [0u8; 1024];
    let mut empty_retries = 0u32;
    loop {
        if data.len() >= cap {
            break;
        }
        match call::read(fd, &mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                empty_retries = 0;
                let take = n.min(cap - data.len());
                data.extend_from_slice(&chunk[..take]);
            }
            Err(e) if e.to_errno() == EAGAIN && empty_retries < 100 => {
                empty_retries += 1;
                sleep_ms(10);
            }
            Err(e) => {
                let _ = call::close(fd);
                return Err(e);
            }
        }
    }
    let _ = call::close(fd);
    Ok(data)
}

/// Read a small text file, returning the byte count (0 on any error).
pub fn read_text_file(path: &str, out: &mut [u8]) -> usize {
    let fd = match open(path, OpenFlags::READ) {
        Ok(fd) => fd,
        Err(_) => return 0,
    };
    let n = call::read(fd, out).unwrap_or(0);
    let _ = call::close(fd);
    n
}

// ── Date formatting (UTC) ───────────────────────────────────────────────────

/// Convert days since 1970-01-01 to (year, month 1-12, day 1-31).
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `YYYY-MM-DD HH:MM` for a unix timestamp.
pub fn format_time(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    alloc::format!("{:04}-{:02}-{:02} {:02}:{:02}", y, m, d, rem / 3600, (rem % 3600) / 60)
}

/// `drwxr-xr-x` style mode string.
pub fn format_mode(mode: u32) -> String {
    let t = match mode & S_IFMT {
        0o040000 => 'd',
        0o120000 => 'l',
        0o060000 => 'b',
        0o020000 => 'c',
        0o010000 => 'p',
        0o140000 => 's',
        _ => '-',
    };
    let mut s = String::with_capacity(10);
    s.push(t);
    for (shift, specials) in [(6u32, 0o4000u32), (3, 0o2000), (0, 0o1000)] {
        let bits = (mode >> shift) & 7;
        s.push(if bits & 4 != 0 { 'r' } else { '-' });
        s.push(if bits & 2 != 0 { 'w' } else { '-' });
        let x = bits & 1 != 0;
        let sp = mode & specials != 0;
        s.push(match (x, sp, shift) {
            (true, true, 0) => 't',
            (false, true, 0) => 'T',
            (true, true, _) => 's',
            (false, true, _) => 'S',
            (true, false, _) => 'x',
            _ => '-',
        });
    }
    s
}

/// Short English description of an error.
pub fn err_text(e: Error) -> String {
    alloc::format!("{} (errno {})", e, e.to_errno())
}
