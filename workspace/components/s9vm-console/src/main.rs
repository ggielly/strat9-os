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

//! s9vm-console: userspace front-end of the s9vm virtualization subsystem.
//!
//! The component is a pure reader of the `/dev/vmm` diagnostic scheme and a
//! relay for the guest console:
//!
//! 1. read `/dev/vmm/info` and `/dev/vmm/worlds` (engine summary and world
//!    list);
//! 2. print the snapshot of the first world found: `/dev/vmm/<id>/info`,
//!    `/dev/vmm/<id>/stats` and `/dev/vmm/<id>/exits`; a missing snapshot file
//!    is reported as `not available` instead of being fatal, because those
//!    files are produced by the kernel side and may lag behind this component;
//! 3. attach to `/dev/vmm/<id>/console` and relay bytes in both directions:
//!    guest output to stdout (file descriptor 1, backed by `/dev/console`),
//!    keyboard input to the console file. The console descriptor is opened
//!    with `O_NONBLOCK`: `EAGAIN` means "nothing to do right now", so the loop
//!    yields and retries instead of blocking.
//!
//! Input comes from `/dev/input/kbd` when available (the kernel console is
//! write-only) and falls back to stdin otherwise.
//!
//! # Exit codes
//!
//! | Code | Meaning                                                      |
//! |------|--------------------------------------------------------------|
//! | 0    | clean shutdown: stdin reached end of file                     |
//! | 1    | `/dev/vmm/info` or `/dev/vmm/worlds` unavailable              |
//! | 2    | no world listed by `/dev/vmm/worlds`                          |
//! | 3    | console attachment failed, or the world disappeared           |
//! | 4    | fatal console I/O error                                       |

#![no_std]
#![no_main]

use core::{
    fmt::{self, Write as _},
    panic::PanicInfo,
};
use strat9_syscall::{
    call,
    data::TimeSpec,
    error::Error,
    flag,
};

/// Snapshot of the engine state (kernel-generated text).
const PATH_INFO: &str = "/dev/vmm/info";
/// One line per existing world.
const PATH_WORLDS: &str = "/dev/vmm/worlds";
/// Keyboard input scheme; the kernel console itself is write-only.
const PATH_INPUT: &str = "/dev/input/kbd";

/// File descriptor of the component stdout (bound to `/dev/console`).
const STDOUT_FD: usize = 1;
/// File descriptor of the component stdin.
const STDIN_FD: usize = 0;

/// Clean shutdown (stdin end of file).
const EXIT_OK: usize = 0;
/// `/dev/vmm` scheme or its base files are unavailable.
const EXIT_VMM_UNAVAILABLE: usize = 1;
/// No world is listed by the scheme.
const EXIT_NO_WORLD: usize = 2;
/// Console file cannot be opened, or the world vanished while attached.
const EXIT_CONSOLE_UNAVAILABLE: usize = 3;
/// Non-recoverable console I/O error.
const EXIT_IO_ERROR: usize = 4;

/// Maximum size of a scheme snapshot read into memory (stack buffer).
const SNAPSHOT_MAX: usize = 4096;
/// Size of one console-output chunk.
const IO_CHUNK: usize = 512;
/// Size of one keyboard-input chunk.
const INPUT_CHUNK: usize = 64;
/// Idle sleep between two polling rounds, in milliseconds.
const IDLE_SLEEP_MS: u64 = 5;
/// Bound on consecutive retryable errors before a read/write gives up.
const MAX_RETRIES: u32 = 4096;

// ---------------------------------------------------------------------------
// Small formatting helpers (no allocation)
// ---------------------------------------------------------------------------

/// Writes raw bytes to `fd`, retrying on `EAGAIN`/`EINTR`.
///
/// The retry budget is bounded so a stalled peer cannot wedge the component.
fn write_all(fd: usize, mut data: &[u8]) -> Result<(), Error> {
    let mut retries = 0u32;
    while !data.is_empty() {
        match call::write(fd, data) {
            Ok(0) => return Err(Error::IoError),
            Ok(written) => {
                data = &data[written..];
                retries = 0;
            }
            Err(error) if error.is_retryable() => {
                retries += 1;
                if retries > MAX_RETRIES {
                    return Err(error);
                }
                let _ = call::sched_yield();
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Fixed-size UTF-8 text buffer used to build dynamic paths and labels.
struct TextBuf {
    buf: [u8; 128],
    len: usize,
}

impl TextBuf {
    /// Creates an empty buffer.
    fn new() -> Self {
        Self {
            buf: [0u8; 128],
            len: 0,
        }
    }

    /// Returns the valid content as a string slice.
    fn as_str(&self) -> &str {
        // SAFETY: only complete `str` slices are appended through `write_str`
        // of `core::fmt::Write`, so the bytes are valid UTF-8.
        unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }
}

impl fmt::Write for TextBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        if self.len + bytes.len() > self.buf.len() {
            return Err(fmt::Error);
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

/// Stdout writer: every formatted fragment is forwarded to file descriptor 1.
struct Stdout;

impl fmt::Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_all(STDOUT_FD, s.as_bytes()).map_err(|_| fmt::Error)
    }
}

/// Returns a stdout writer.
fn out() -> Stdout {
    Stdout
}

/// Sleeps for `milliseconds` without requiring an allocator.
fn sleep_ms(milliseconds: u64) {
    let request = TimeSpec {
        tv_sec: (milliseconds / 1000) as i64,
        tv_nsec: ((milliseconds % 1000) * 1_000_000) as i64,
    };
    let mut remaining = TimeSpec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if call::nanosleep(&request, &mut remaining).is_err() {
        let _ = call::sched_yield();
    }
}

// ---------------------------------------------------------------------------
// Scheme access
// ---------------------------------------------------------------------------

/// Reads a whole scheme snapshot into `buf`.
///
/// Returns the number of bytes read. `EAGAIN`/`EINTR` are retried a bounded
/// number of times because scheme files are snapshots, not blocking streams.
fn read_snapshot(path: &str, buf: &mut [u8]) -> Result<usize, Error> {
    let fd = call::open(path, flag::O_RDONLY)?;
    let mut total = 0usize;
    let mut retries = 0u32;
    let result = loop {
        if total == buf.len() {
            break Ok(total);
        }
        match call::read(fd, &mut buf[total..]) {
            Ok(0) => break Ok(total),
            Ok(count) => {
                total += count;
                retries = 0;
            }
            Err(error) if error.is_retryable() => {
                retries += 1;
                if retries > MAX_RETRIES {
                    break Err(Error::TimedOut);
                }
                let _ = call::sched_yield();
            }
            Err(error) => break Err(error),
        }
    };
    let _ = call::close(fd);
    result
}

/// Prints a scheme snapshot under a readable title.
///
/// A missing file is not an error: the kernel side may expose it later, so the
/// component reports `not available` and keeps going.
///
/// Returns `true` when the snapshot existed and was printed.
fn dump_snapshot(title: &str, path: &str) -> bool {
    let mut output = out();
    let mut buf = [0u8; SNAPSHOT_MAX];
    match read_snapshot(path, &mut buf) {
        Ok(count) => {
            let text = core::str::from_utf8(&buf[..count]).unwrap_or("<non-utf8>");
            let _ = writeln!(output, "--- {title}: {path} ---");
            let _ = output.write_str(text);
            if count == 0 || !text.ends_with('\n') {
                let _ = output.write_str("\n");
            }
            true
        }
        Err(Error::NotFound) => {
            let _ = writeln!(output, "--- {title}: {path} -> not available ---");
            false
        }
        Err(error) => {
            let _ = writeln!(
                output,
                "--- {title}: {path} -> unavailable ({}) ---",
                error.name()
            );
            false
        }
    }
}

/// Extracts the first world identifier from the `/dev/vmm/worlds` text.
///
/// The scheme formats one `world <id> name=...` line per world. Only the
/// identifier is needed: the console attaches to the first world listed.
fn first_world_id(worlds: &str) -> Option<u64> {
    for line in worlds.lines() {
        let line = line.trim();
        let rest = match line.strip_prefix("world ") {
            Some(rest) => rest,
            None => continue,
        };
        let digits = rest
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .unwrap_or("");
        if digits.is_empty() {
            continue;
        }
        if let Ok(id) = digits.parse::<u64>() {
            return Some(id);
        }
    }
    None
}

/// Builds `/dev/vmm/<id>/console` into `buffer`.
fn console_path(id: u64, buffer: &mut TextBuf) -> bool {
    write!(buffer, "/dev/vmm/{id}/console").is_ok()
}

/// Opens the keyboard input scheme, or stdin when it is unavailable.
fn open_input() -> usize {
    match call::open(PATH_INPUT, flag::O_RDONLY | flag::O_NONBLOCK) {
        Ok(fd) => fd,
        Err(_) => STDIN_FD,
    }
}

// ---------------------------------------------------------------------------
// Main logic
// ---------------------------------------------------------------------------

/// Prints the static banner with the exit-code contract.
fn print_banner() {
    let mut output = out();
    let _ = writeln!(
        output,
        "============================================================"
    );
    let _ = writeln!(output, "[s9vm-console] strat9-os: s9vm world console");
    let _ = writeln!(
        output,
        "[s9vm-console] exit codes: 0=stdin EOF, 1=/dev/vmm unavailable, \
         2=no world, 3=console unavailable, 4=console I/O error"
    );
    let _ = writeln!(
        output,
        "============================================================"
    );
}

/// Runs the component and returns its documented exit code.
fn run() -> usize {
    print_banner();

    let mut output = out();
    let mut info_buf = [0u8; SNAPSHOT_MAX];
    let mut worlds_buf = [0u8; SNAPSHOT_MAX];

    // 1. Engine summary. A missing scheme is fatal: nothing else can work.
    let info = match read_snapshot(PATH_INFO, &mut info_buf) {
        Ok(count) => Some(count),
        Err(Error::NotFound) => None,
        Err(error) => {
            let _ = writeln!(
                output,
                "[s9vm-console] /dev/vmm unavailable ({})",
                error.name()
            );
            return EXIT_VMM_UNAVAILABLE;
        }
    };
    let info_count = match info {
        Some(count) => count,
        None => {
            let _ = writeln!(
                output,
                "[s9vm-console] /dev/vmm unavailable: {PATH_INFO} not found"
            );
            return EXIT_VMM_UNAVAILABLE;
        }
    };
    let _ = writeln!(output, "--- engine: {PATH_INFO} ---");
    let _ = output.write_str(core::str::from_utf8(&info_buf[..info_count]).unwrap_or("<non-utf8>"));
    let _ = output.write_str("\n");

    // 2. World list. Missing list means a kernel without the worlds file.
    let worlds_count = match read_snapshot(PATH_WORLDS, &mut worlds_buf) {
        Ok(count) => count,
        Err(Error::NotFound) => {
            let _ = writeln!(
                output,
                "[s9vm-console] {PATH_WORLDS} not available: cannot list worlds"
            );
            return EXIT_VMM_UNAVAILABLE;
        }
        Err(error) => {
            let _ = writeln!(
                output,
                "[s9vm-console] cannot read {PATH_WORLDS} ({})",
                error.name()
            );
            return EXIT_VMM_UNAVAILABLE;
        }
    };
    let worlds = core::str::from_utf8(&worlds_buf[..worlds_count]).unwrap_or("<non-utf8>");
    let _ = writeln!(output, "--- worlds: {PATH_WORLDS} ---");
    let _ = output.write_str(worlds);
    if worlds_count == 0 || !worlds.ends_with('\n') {
        let _ = output.write_str("\n");
    }

    let world_id = match first_world_id(worlds) {
        Some(id) => id,
        None => {
            let _ = writeln!(output, "[s9vm-console] no world available");
            return EXIT_NO_WORLD;
        }
    };
    let _ = writeln!(output, "[s9vm-console] selected world {world_id}");

    // 3. Diagnostic snapshots. Files may not exist yet: keep going.
    let mut path = TextBuf::new();
    if write!(&mut path, "/dev/vmm/{world_id}/info").is_err() {
        return EXIT_VMM_UNAVAILABLE;
    }
    let info_path = path.as_str();
    dump_snapshot("world", info_path);

    let mut path = TextBuf::new();
    if write!(&mut path, "/dev/vmm/{world_id}/stats").is_err() {
        return EXIT_VMM_UNAVAILABLE;
    }
    let stats_path = path.as_str();
    dump_snapshot("stats", stats_path);

    let mut path = TextBuf::new();
    if write!(&mut path, "/dev/vmm/{world_id}/exits").is_err() {
        return EXIT_VMM_UNAVAILABLE;
    }
    let exits_path = path.as_str();
    dump_snapshot("exits", exits_path);

    // 4. Console relay.
    let mut console = TextBuf::new();
    if !console_path(world_id, &mut console) {
        let _ = writeln!(output, "[s9vm-console] console path too long");
        return EXIT_CONSOLE_UNAVAILABLE;
    }
    let console_path = console.as_str();
    let console_fd = match call::open(console_path, flag::O_RDWR | flag::O_NONBLOCK) {
        Ok(fd) => fd,
        Err(Error::NotFound) => {
            let _ = writeln!(
                output,
                "[s9vm-console] {console_path} not available: cannot attach to world {world_id}"
            );
            return EXIT_CONSOLE_UNAVAILABLE;
        }
        Err(error) => {
            let _ = writeln!(
                output,
                "[s9vm-console] cannot open {console_path} ({})",
                error.name()
            );
            return EXIT_CONSOLE_UNAVAILABLE;
        }
    };
    let input_fd = open_input();
    let _ = writeln!(
        output,
        "[s9vm-console] attached to world {world_id} ({console_path}); input fd {input_fd}"
    );
    let _ = writeln!(output, "[s9vm-console] press Ctrl-D on stdin to detach");

    let mut console_buf = [0u8; IO_CHUNK];
    let mut input_buf = [0u8; INPUT_CHUNK];
    loop {
        let mut activity = false;

        // Guest console output -> component stdout.
        match call::read(console_fd, &mut console_buf) {
            Ok(0) => {}
            Ok(count) => {
                activity = true;
                if let Err(error) = write_all(STDOUT_FD, &console_buf[..count]) {
                    let _ = writeln!(
                        output,
                        "[s9vm-console] stdout write failed ({})",
                        error.name()
                    );
                    return EXIT_IO_ERROR;
                }
            }
            Err(error) if error.is_retryable() => {}
            Err(Error::NotFound) => {
                let _ = writeln!(output, "[s9vm-console] world {world_id} disappeared");
                return EXIT_CONSOLE_UNAVAILABLE;
            }
            Err(error) => {
                let _ = writeln!(
                    output,
                    "[s9vm-console] console read failed ({})",
                    error.name()
                );
                return EXIT_IO_ERROR;
            }
        }

        // Keyboard input -> guest console. EAGAIN means "no key yet".
        match call::read(input_fd, &mut input_buf) {
            Ok(0) => {
                if input_fd == STDIN_FD {
                    let _ = writeln!(output, "[s9vm-console] stdin closed; detaching");
                    return EXIT_OK;
                }
            }
            Ok(count) => {
                activity = true;
                if let Err(error) = write_all(console_fd, &input_buf[..count]) {
                    if error == Error::Again {
                        // Guest input queue is full: drop this chunk, keep the
                        // console attached.
                        continue;
                    }
                    if error == Error::NotFound {
                        let _ = writeln!(output, "[s9vm-console] world {world_id} disappeared");
                        return EXIT_CONSOLE_UNAVAILABLE;
                    }
                    let _ = writeln!(
                        output,
                        "[s9vm-console] console write failed ({})",
                        error.name()
                    );
                    return EXIT_IO_ERROR;
                }
            }
            Err(error) if error.is_retryable() => {}
            Err(Error::NotATty) => {}
            Err(_) => {}
        }

        if activity {
            let _ = call::sched_yield();
        } else {
            sleep_ms(IDLE_SLEEP_MS);
        }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    call::handle_panic("s9vm-console", info);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    call::exit(run());
}
