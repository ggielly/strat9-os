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

//! Bounded, allocation-free SMP queue between logging and framebuffer rendering.
//! Formatting/rendering never retains a reference to a released queue slot.

#[path = "vga/log_queue.rs"]
mod log_queue;
use core::sync::atomic::{AtomicBool, Ordering};
use log_queue::{Line, LogQueue};

static CONSOLE_TASK_ACTIVE: AtomicBool = AtomicBool::new(false);

pub fn console_task_active() -> bool {
    CONSOLE_TASK_ACTIVE.load(Ordering::Acquire)
}

pub const VGABUF_CAPACITY: usize = log_queue::CAPACITY;
pub const VGABUF_LINE_LEN: usize = log_queue::LINE_LEN;
static QUEUE: LogQueue = LogQueue::new();
const FLUSH_BATCH: usize = 30;

pub fn vgabuf_write(line: &[u8]) {
    QUEUE.push(line);
}
pub fn vgabuf_total_written() -> usize {
    QUEUE.written()
}
pub fn vgabuf_total_dropped() -> usize {
    QUEUE.dropped()
}

fn write_line(writer: &mut impl core::fmt::Write, line: &Line) {
    if let Ok(s) = core::str::from_utf8(line.as_bytes()) {
        let _ = writer.write_str(s);
        if !s.ends_with('\n') {
            let _ = writer.write_str("\n");
        }
    } else {
        let _ = writer.write_str("<non-utf8>\n");
    }
}

/// Render a bounded batch. Retrying pending presents also displays the last
/// keyboard echo/log fragment when no subsequent message arrives.
pub fn vgabuf_flush_to_framebuffer() {
    if !crate::arch::x86_64::vga::is_available() || !crate::display_state::kernel_fb_allowed() {
        vgabuf_drain_discard();
        return;
    }
    let Some(mut writer) = crate::arch::x86_64::vga::VGA_WRITER.try_lock() else {
        return;
    };
    let mut flushed = 0;
    for _ in 0..FLUSH_BATCH {
        let Some(line) = QUEUE.pop() else {
            break;
        };
        write_line(&mut *writer, &line);
        flushed += 1;
    }
    if flushed > 0 {
        writer.flush_display();
    } else {
        writer.present_if_due(false);
    }
}

fn vgabuf_drain_discard() {
    for _ in 0..VGABUF_CAPACITY {
        if QUEUE.pop().is_none() {
            break;
        }
    }
}

pub fn vgabuf_flush_all() {
    if !crate::arch::x86_64::vga::is_available() || !crate::display_state::kernel_fb_allowed() {
        vgabuf_drain_discard();
        return;
    }
    let Some(mut writer) = crate::arch::x86_64::vga::VGA_WRITER.try_lock() else {
        vgabuf_flush_all_direct();
        return;
    };
    for _ in 0..VGABUF_CAPACITY {
        let Some(line) = QUEUE.pop() else {
            break;
        };
        write_line(&mut *writer, &line);
    }
    writer.present_if_due(true);
}

fn vgabuf_flush_all_direct() {
    if !crate::display_state::kernel_fb_allowed() {
        vgabuf_drain_discard();
        return;
    }
    // Own the bytes until drawing completes; released slots may immediately be
    // reused on another CPU. Limit scratch storage to about 4 KiB in panic context.
    const MAX_LINES: usize = 16;
    let mut owned = [Line::EMPTY; MAX_LINES];
    let mut count = 0;
    for slot in &mut owned {
        let Some(line) = QUEUE.pop() else {
            break;
        };
        *slot = line;
        count += 1;
    }
    let mut lines = [""; MAX_LINES];
    for i in 0..count {
        lines[i] = core::str::from_utf8(owned[i].as_bytes()).unwrap_or("<non-utf8>");
    }
    let mut lines = [""; MAX_LINES];
    for i in 0..count {
        lines[i] = core::str::from_utf8(owned[i].as_bytes()).unwrap_or("<non-utf8>");
    }
}

/// One render opportunity per timer tick, independent of commands/status I/O.
///
/// The console task owns the writer for this whole tick: it drains the mouse
/// input ring first, then a bounded batch of log lines, then presents once.
pub extern "C" fn console_task_main() -> ! {
    CONSOLE_TASK_ACTIVE.store(true, Ordering::Release);
    let mut input_state = crate::shell::vga_input::InputState::new();
    let mut last_tick = u64::MAX;
    loop {
        let tick = crate::process::scheduler::ticks();
        if tick != last_tick {
            last_tick = tick;
            console_render_tick(&mut input_state);
        }
        // Rendering is tick-paced; sleep so this worker does not spin between
        // frames and compete with interactive tasks.
        crate::process::sleep_current_task_ticks(1);
    }
}

/// Single writer acquisition per tick: apply deferred mouse input, drain a
/// bounded log batch, then present once. If the lock is busy, retry next tick.
fn console_render_tick(input_state: &mut crate::shell::vga_input::InputState) {
    if !crate::arch::x86_64::vga::is_available() || !crate::display_state::kernel_fb_allowed() {
        vgabuf_drain_discard();
        crate::shell::vga_input::discard();
        return;
    }
    let Some(mut writer) = crate::arch::x86_64::vga::VGA_WRITER.try_lock() else {
        return;
    };

    let mut applied = crate::shell::vga_input::take_pending();
    // Apply every tick (not only when the flag was set) so a deferred visual
    // still drains when the pointer stops moving while the button is held.
    applied |= crate::shell::vga_input::apply_input(&mut *writer, input_state);
    if !crate::debug_cfg::is_quiet() {
        for _ in 0..FLUSH_BATCH {
            let Some(line) = QUEUE.pop() else {
                break;
            };
            write_line(&mut *writer, &line);
            applied = true;
        }
    }

    // Eased wheel scroll: advance at most one line per tick, then present.
    applied |= writer.tick_scroll_anim();

    if applied {
        writer.flush_display();
    } else {
        writer.present_if_due(false);
    }
}
