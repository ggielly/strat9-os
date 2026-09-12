//! Bounded, allocation-free SMP queue between logging and framebuffer rendering.
//! Formatting/rendering never retains a reference to a released queue slot.

#[path = "vga/log_queue.rs"]
mod log_queue;
use log_queue::{Line, LogQueue};

pub const VGABUF_CAPACITY: usize = log_queue::CAPACITY;
pub const VGABUF_LINE_LEN: usize = log_queue::LINE_LEN;
static QUEUE: LogQueue = LogQueue::new();
const FLUSH_BATCH: usize = 30;

pub fn vgabuf_write(line: &[u8]) { QUEUE.push(line); }
pub fn vgabuf_total_written() -> usize { QUEUE.written() }
pub fn vgabuf_total_dropped() -> usize { QUEUE.dropped() }

fn write_line(writer: &mut impl core::fmt::Write, line: &Line) {
    if let Ok(s) = core::str::from_utf8(line.as_bytes()) {
        let _ = writer.write_str(s);
        if !s.ends_with('\n') { let _ = writer.write_str("\n"); }
    } else {
        let _ = writer.write_str("<non-utf8>\n");
    }
}

/// Render a bounded batch. Retrying pending presents also displays the last
/// keyboard echo/log fragment when no subsequent message arrives.
pub fn vgabuf_flush_to_framebuffer() {
    if !crate::arch::x86_64::vga::is_available() {
        vgabuf_drain_discard();
        return;
    }
    let Some(mut writer) = crate::arch::x86_64::vga::VGA_WRITER.try_lock() else { return; };
    let mut flushed = 0;
    for _ in 0..FLUSH_BATCH {
        let Some(line) = QUEUE.pop() else { break; };
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
        if QUEUE.pop().is_none() { break; }
    }
}

pub fn vgabuf_flush_all() {
    if !crate::arch::x86_64::vga::is_available() {
        vgabuf_drain_discard();
        return;
    }
    let Some(mut writer) = crate::arch::x86_64::vga::VGA_WRITER.try_lock() else {
        vgabuf_flush_all_direct();
        return;
    };
    for _ in 0..VGABUF_CAPACITY {
        let Some(line) = QUEUE.pop() else { break; };
        write_line(&mut *writer, &line);
    }
    writer.present_if_due(true);
}

fn vgabuf_flush_all_direct() {
    // Own the bytes until drawing completes; released slots may immediately be
    // reused on another CPU. Limit scratch storage to about 4 KiB in panic context.
    const MAX_LINES: usize = 16;
    let mut owned = [Line::EMPTY; MAX_LINES];
    let mut count = 0;
    for slot in &mut owned {
        let Some(line) = QUEUE.pop() else { break; };
        *slot = line;
        count += 1;
    }
    let mut lines = [""; MAX_LINES];
    for i in 0..count {
        lines[i] = core::str::from_utf8(owned[i].as_bytes()).unwrap_or("<non-utf8>");
    }
    if count > 0 { crate::arch::x86_64::vga::panic_draw_direct(&lines[..count]); }
}