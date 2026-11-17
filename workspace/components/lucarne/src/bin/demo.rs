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

//! Minimal Jalon 4 display client: gradient surface + bouncing square.
//!
//! Connects to `/srv/vasistas`, creates one 320x200 XRGB8888 surface, presents
//! a full frame, then animates a 16x16 white square for 120 frames using
//! damage-rect commits. Handles `CONFIGURE` by allocating a new buffer and
//! `CLOSE_REQUEST` by closing the session.
//!
//! Protocol v1 has no resize *request*: `CONFIGURE` is a server-to-client
//! event, and only a backend-driven configure (not reachable here) would emit
//! it. Resizing is client-initiated by creating a new surface, so the demo
//! resize block below does exactly that; the `Event::Configure` arm stays
//! correct for a future server that emits it.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use lucarne::{Client, Event};
use vasistas_protocol::Rect;
use strat9_syscall::{call, data::TimeSpec};

const WIDTH: u32 = 320;
const HEIGHT: u32 = 200;
/// Square side, in pixels.
const SQUARE: u32 = 16;
/// Animated frames after the first full commit.
const FRAMES: u32 = 120;
/// Connect timeout per attempt.
const CONNECT_TIMEOUT_NS: u64 = 100_000_000;

struct View {
    buffer: lucarne::Buffer,
    width: u32,
    height: u32,
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log(b"[lucarne-demo] waiting for /srv/vasistas\n");
    let mut client = loop {
        match Client::connect(b"/srv/vasistas", CONNECT_TIMEOUT_NS) {
            Some(client) => break client,
            None => sleep_ms(50),
        }
    };
    log(b"[lucarne-demo] connected\n");
    log_pid(client.pid());

    let surface = match create_surface(&mut client, WIDTH, HEIGHT) {
        Some(surface) => surface,
        None => fatal(b"[lucarne-demo] create_surface failed\n"),
    };

    let mut view = match alloc_view(&mut client, surface, WIDTH, HEIGHT) {
        Some(view) => view,
        None => fatal(b"[lucarne-demo] alloc_buffer failed\n"),
    };
    let mut other = match alloc_view(&mut client, surface, WIDTH, HEIGHT) {
        Some(view) => view,
        None => fatal(b"[lucarne-demo] second alloc_buffer failed\n"),
    };
    fill_gradient(&mut view.buffer);
    draw_square_at(&mut view.buffer, 8, 8);
    fill_gradient(&mut other.buffer);
    draw_square_at(&mut other.buffer, 8, 8);

    let mut serial = 0u64;
    let mut commit_id = 1u64;
    match client.commit(surface, view.buffer.id, &[], true, 0, commit_id) {
        Some(result) => {
            if let Some(frame) = result.frame {
                serial = frame.serial;
                if !frame.present_submitted() {
                    log(b"[lucarne-demo] first frame not submitted\n");
                }
            }
        }
        None => fatal(b"[lucarne-demo] first commit failed\n"),
    }
    log(b"[lucarne-demo] first frame presented\n");

    let mut x = 8i32;
    let mut y = 8i32;
    let mut dx = 2i32;
    let mut dy = 1i32;

    for _ in 0..FRAMES {
        loop {
            match client.recv(0) {
                Some(event) => {
                    if !handle_event(
                        &mut client,
                        surface,
                        &mut view,
                        &mut serial,
                        &mut commit_id,
                        event,
                    ) {
                        finish(client);
                    }
                }
                None => break,
            }
        }

        clamp_square(&mut x, &mut y, other.width, other.height);
        x += dx;
        y += dy;
        bounce(&mut x, &mut y, &mut dx, &mut dy, other.width, other.height);

        // Each submitted buffer is a complete image: redraw the whole slot
        // and commit FULL_DAMAGE, then swap. The server releases the older
        // current buffer, which becomes the next draw target.
        fill_gradient(&mut other.buffer);
        draw_square_at(&mut other.buffer, x, y);

        commit_id += 1;
        match client.commit(surface, other.buffer.id, &[], true, serial, commit_id) {
            Some(result) => {
                if let Some(frame) = result.frame {
                    serial = frame.serial;
                }
                if result.released.is_some() {
                    core::mem::swap(&mut view, &mut other);
                }
            }
            None => log(b"[lucarne-demo] commit failed\n"),
        }
        sleep_ms(16);
    }

    log(b"[lucarne-demo] animation done\n");
    // Resize: create a new surface with a different geometry, present one
    // full frame, then destroy the old surface. This exercises surface
    // creation/destruction, quota refund and the second surface slot.
    if let Some(resized) = create_surface(&mut client, 400, 240) {
        if let Some(mut buffer) = alloc_view(&mut client, resized, 400, 240) {
            fill_gradient(&mut buffer.buffer);
            draw_square_at(&mut buffer.buffer, 24, 24);
            commit_id += 1;
            if let Some(result) = client.commit(resized, buffer.buffer.id, &[], true, serial, commit_id) {
                if let Some(frame) = result.frame {
                    serial = frame.serial;
                }
            }
            log(b"[lucarne-demo] resized frame presented\n");
            // The resized buffer is the surface's current image: destroying it
            // first is BAD_STATE. Destroy the old surface (retires its two
            // buffers) and the resized surface (retires its current buffer).
            let _ = client.destroy_surface(surface);
            let _ = client.destroy_surface(resized);
            log(b"[lucarne-demo] resized surface closed\n");
        }
    }
    finish(client)
}

fn finish(client: Client) -> ! {
    client.close();
    call::exit(0)
}

fn fatal(message: &[u8]) -> ! {
    log(message);
    call::exit(1)
}

fn create_surface(client: &mut Client, width: u32, height: u32) -> Option<u64> {
    for _ in 0..100 {
        if let Some(surface) = client.create_surface(width, height, b"lucarne-demo") {
            return Some(surface);
        }
        sleep_ms(10);
    }
    None
}

fn alloc_view(client: &mut Client, surface: u64, width: u32, height: u32) -> Option<View> {
    for _ in 0..100 {
        if let Some(buffer) = client.alloc_buffer(surface, width, height, width * 4) {
            return Some(View {
                buffer,
                width,
                height,
            });
        }
        sleep_ms(10);
    }
    None
}

/// React to one spontaneous event. Returns `false` when the demo must exit.
fn handle_event(
    client: &mut Client,
    surface: u64,
    view: &mut View,
    serial: &mut u64,
    commit_id: &mut u64,
    event: Event,
) -> bool {
    match event {
        Event::Configure { serial: configure_serial, width, height, .. } => {
            log(b"[lucarne-demo] configure\n");
            let old_id = view.buffer.id;
            let Some(mut buffer) = client.alloc_buffer(surface, width, height, width * 4) else {
                log(b"[lucarne-demo] resize alloc failed\n");
                return false;
            };
            fill_gradient(&mut buffer);
            draw_square_at(&mut buffer, 8, 8);
            *commit_id += 1;
            // A commit after CONFIGURE must acknowledge that configure serial.
            if let Some(result) =
                client.commit(surface, buffer.id, &[], true, configure_serial, *commit_id)
            {
                if let Some(frame) = result.frame {
                    *serial = frame.serial;
                }
            }
            // The full commit of the new buffer released the old one.
            let _ = client.destroy_buffer(old_id);
            view.buffer = buffer;
            view.width = width;
            view.height = height;
            true
        }
        Event::CloseRequest { .. } => {
            log(b"[lucarne-demo] close requested\n");
            false
        }
        Event::Error { .. } => {
            log(b"[lucarne-demo] server error event\n");
            true
        }
        _ => true,
    }
}

fn clamp_square(x: &mut i32, y: &mut i32, width: u32, height: u32) {
    let max_x = (width as i32 - SQUARE as i32).max(0);
    let max_y = (height as i32 - SQUARE as i32).max(0);
    *x = (*x).clamp(0, max_x);
    *y = (*y).clamp(0, max_y);
}

fn bounce(x: &mut i32, y: &mut i32, dx: &mut i32, dy: &mut i32, width: u32, height: u32) {
    let max_x = (width as i32 - SQUARE as i32).max(0);
    let max_y = (height as i32 - SQUARE as i32).max(0);
    if *x < 0 {
        *x = 0;
        *dx = -(*dx);
    } else if *x > max_x {
        *x = max_x;
        *dx = -(*dx);
    }
    if *y < 0 {
        *y = 0;
        *dy = -(*dy);
    } else if *y > max_y {
        *y = max_y;
        *dy = -(*dy);
    }
}

fn fill_gradient(buffer: &mut lucarne::Buffer) {
    let width = buffer.width as usize;
    let height = buffer.height as usize;
    let stride = buffer.stride as usize;
    let pixels = buffer.pixels_mut();
    for y in 0..height {
        for x in 0..width {
            let color = gradient_color(x as u32, y as u32, width as u32, height as u32);
            let offset = y * stride + x * 4;
            pixels[offset..offset + 4].copy_from_slice(&color.to_le_bytes());
        }
    }
}

fn fill_gradient_rect(buffer: &mut lucarne::Buffer, x: i32, y: i32, w: u32, h: u32) {
    let width = buffer.width as i32;
    let height = buffer.height as i32;
    let stride = buffer.stride as usize;
    let x0 = x.max(0);
    let y0 = y.max(0);
    let x1 = (x + w as i32).min(width);
    let y1 = (y + h as i32).min(height);
    let pixels = buffer.pixels_mut();
    for yy in y0..y1 {
        for xx in x0..x1 {
            let color = gradient_color(xx as u32, yy as u32, width as u32, height as u32);
            let offset = yy as usize * stride + xx as usize * 4;
            pixels[offset..offset + 4].copy_from_slice(&color.to_le_bytes());
        }
    }
}

fn draw_square_at(buffer: &mut lucarne::Buffer, x: i32, y: i32) {
    let width = buffer.width as i32;
    let height = buffer.height as i32;
    let stride = buffer.stride as usize;
    let x0 = x.max(0);
    let y0 = y.max(0);
    let x1 = (x + SQUARE as i32).min(width);
    let y1 = (y + SQUARE as i32).min(height);
    let pixels = buffer.pixels_mut();
    for yy in y0..y1 {
        for xx in x0..x1 {
            let offset = yy as usize * stride + xx as usize * 4;
            pixels[offset..offset + 4].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
        }
    }
}

fn gradient_color(x: u32, y: u32, width: u32, height: u32) -> u32 {
    let red = x * 255 / width.max(1);
    let green = y * 255 / height.max(1);
    0x40_0000 | (red << 16) | (green << 8)
}

fn sleep_ms(ms: u64) {
    let req = TimeSpec {
        tv_sec: (ms / 1000) as i64,
        tv_nsec: ((ms % 1000) * 1_000_000) as i64,
    };
    let mut rem = TimeSpec::zero();
    let _ = call::nanosleep(&req, &mut rem);
}

fn log_pid(pid: u32) {
    let prefix = b"[lucarne-demo] pid=";
    let mut line = [0u8; 40];
    let mut len = prefix.len();
    line[..len].copy_from_slice(prefix);
    let mut digits = [0u8; 10];
    let mut count = 0usize;
    let mut value = pid;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    while count > 0 {
        count -= 1;
        line[len] = digits[count];
        len += 1;
    }
    line[len] = b'\n';
    len += 1;
    let _ = call::write(2, &line[..len]);
}

fn log(text: &[u8]) {
    let _ = call::write(2, text);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    call::handle_panic("lucarne-demo", info)
}
