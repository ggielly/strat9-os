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

//! SMP stress client (audit P1): churn surfaces in a loop and watch
//! `/proc/meminfo` `MemAvailable`.
//!
//! One process runs `CYCLES` create/alloc/commit/destroy cycles; run two
//! instances concurrently under `-smp 2`. A leak in the region
//! export/grant/map/unmap path shows up as `MemAvailable` declining
//! monotonically across cycles; a stable (noisy) series means the churn is
//! refunded. Not part of the default image: include it the same way the
//! test binaries are (`STRAT9_INCLUDE_TESTS`-style manifest entry).

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use vasistas_client::Client;
use strat9_syscall::{call, data::TimeSpec};

/// Cycles per run: enough churn that a per-cycle leak is visible in MiB.
const CYCLES: u32 = 200;
/// Report every this many cycles.
const REPORT_EVERY: u32 = 40;
const WIDTH: u32 = 320;
const HEIGHT: u32 = 200;
const CONNECT_TIMEOUT_NS: u64 = 100_000_000;

#[no_mangle]
/// Userspace entry point.
pub extern "C" fn _start() -> ! {
    let mut serial = 0u64;
    let mut commit_id = 0u64;
    let failures = run(&mut serial, &mut commit_id);
    log_u64(failures as u64);
    log(b" failed cycles\n");
    call::exit(if failures == 0 { 0 } else { 1 })
}

fn run(serial: &mut u64, commit_id: &mut u64) -> u32 {
    let mut client = match Client::connect(b"/srv/vasistas", CONNECT_TIMEOUT_NS) {
        Some(client) => client,
        None => {
            log(b"[vasistas-stress] connect failed\n");
            return CYCLES;
        }
    };
    log_pid(client.pid());

    let mut failures = 0u32;
    for cycle in 1..=CYCLES {
        *serial += 1;
        if churn(&mut client, serial, commit_id).is_none() {
            failures += 1;
        }
        if cycle % REPORT_EVERY == 0 {
            report(cycle);
        }
    }
    client.close();
    report(CYCLES);
    failures
}

/// One full surface life: create, allocate, commit, destroy.
fn churn(client: &mut Client, serial: &mut u64, commit_id: &mut u64) -> Option<()> {
    let surface = client.create_surface(WIDTH, HEIGHT, b"stress")?;
    let stride = WIDTH * 4;
    let mut view = client.alloc_buffer(surface, WIDTH, HEIGHT, stride)?;
    paint(&mut view);
    *commit_id += 1;
    let result = client.commit(surface, view.id, &[], true, *serial, *commit_id)?;
    let _ = result;
    if !client.destroy_buffer(view.id) {
        return None;
    }
    if !client.destroy_surface(surface) {
        return None;
    }
    Some(())
}

/// Fill the buffer with a cheap deterministic pattern; content is irrelevant.
fn paint(buffer: &mut vasistas_client::Buffer) {
    let (width, height, stride) = (buffer.width, buffer.height, buffer.stride as usize);
    let pixels = buffer.pixels_mut();
    for y in 0..height as usize {
        for x in 0..width as usize {
            let offset = y * stride + x * 4;
            let color = (x as u32) ^ (y as u32).rotate_left(8);
            pixels[offset..offset + 4].copy_from_slice(&color.to_le_bytes());
        }
    }
}

/// Parse `MemAvailable:` (kB) out of `/proc/meminfo`.
fn mem_available_kb() -> Option<u64> {
    const BUF: usize = 2048;
    let mut buffer = [0u8; BUF];
    let fd = call::open("/proc/meminfo", 0).ok()?;
    let mut total = 0usize;
    loop {
        let n = match call::read(fd, &mut buffer[total..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        total += n;
        if total == BUF {
            break;
        }
    }
    let _ = call::close(fd);
    let text = &buffer[..total];
    let key = b"MemAvailable:";
    let mut index = 0usize;
    while index + key.len() <= text.len() {
        if &text[index..index + key.len()] == key {
            let mut value = 0u64;
            let mut cursor = index + key.len();
            while cursor < text.len() && text[cursor] == b' ' {
                cursor += 1;
            }
            while cursor < text.len() && text[cursor].is_ascii_digit() {
                value = value
                    .wrapping_mul(10)
                    .wrapping_add((text[cursor] - b'0') as u64);
                cursor += 1;
            }
            return Some(value);
        }
        index += 1;
    }
    None
}

fn report(cycle: u32) {
    log(b"[vasistas-stress] cycle ");
    log_u64(cycle as u64);
    match mem_available_kb() {
        Some(kb) => {
            log(b" mem_available_kb ");
            log_u64(kb);
        }
        None => log(b" mem_available_kb unavailable"),
    }
    log(b"\n");
    let request = TimeSpec {
        tv_sec: 0,
        tv_nsec: 2_000_000,
    };
    let mut remaining = TimeSpec::zero();
    let _ = call::nanosleep(&request, &mut remaining);
}

fn log(text: &[u8]) {
    let _ = call::write(2, text);
}

fn log_u64(mut value: u64) {
    let mut digits = [0u8; 20];
    let mut count = 0usize;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let mut out = [0u8; 20];
    for index in 0..count {
        out[index] = digits[count - 1 - index];
    }
    let _ = call::write(2, &out[..count]);
}

fn log_pid(pid: u32) {
    log(b"[vasistas-stress] pid ");
    log_u64(pid as u64);
    log(b"\n");
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    call::handle_panic("vasistas-stress", info)
}
