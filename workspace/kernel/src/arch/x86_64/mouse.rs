//! PS/2 Mouse driver (IRQ12)
//!
//! Supports standard 3-byte PS/2 mouse and IntelliMouse (4-byte, scroll wheel).
//! Initialization follows the standard PS/2 controller protocol via I/O ports
//! 0x60 (data) and 0x64 (command/status).

use super::io::{inb, outb};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};
use spin::Mutex;

// ── PS/2 controller ports ─────────────────────────────────────────────────────
const PS2_DATA: u16 = 0x60;
const PS2_CMD: u16 = 0x64;

// PS/2 controller commands
const CMD_READ_CFG: u8 = 0x20;
const CMD_WRITE_CFG: u8 = 0x60;
const CMD_ENABLE_AUX: u8 = 0xA8;
const CMD_SEND_TO_MOUSE: u8 = 0xD4;

// Mouse commands
const MOUSE_RESET: u8 = 0xFF;
const MOUSE_SET_DEFAULTS: u8 = 0xF6;
const MOUSE_ENABLE_STREAM: u8 = 0xF4;
const MOUSE_GET_ID: u8 = 0xF2;
const MOUSE_SET_SAMPLE_RATE: u8 = 0xF3;
const MOUSE_ACK: u8 = 0xFA;

// PS/2 status bits
const STATUS_OUTPUT_FULL: u8 = 0x01; // data available on port 0x60
const STATUS_INPUT_FULL: u8 = 0x02; // controller busy, don't write

// ── Event ring buffer ─────────────────────────────────────────────────────────
const EVENT_BUF_SIZE: usize = 64;

struct EventBuffer {
    buf: [MouseEvent; EVENT_BUF_SIZE],
    head: usize,
    tail: usize,
}

static EVENT_BUF: Mutex<EventBuffer> = Mutex::new(EventBuffer {
    buf: [MouseEvent {
        dx: 0,
        dy: 0,
        dz: 0,
        left: false,
        right: false,
        middle: false,
    }; EVENT_BUF_SIZE],
    head: 0,
    tail: 0,
});

// ── Absolute cursor position (accumulated) ───────────────────────────────────
static MOUSE_ABS_X: AtomicI32 = AtomicI32::new(0);
static MOUSE_ABS_Y: AtomicI32 = AtomicI32::new(0);

// ── Packet state machine ──────────────────────────────────────────────────────
/// Current byte index within the current packet (0, 1, 2, [3])
static MOUSE_CYCLE: AtomicU8 = AtomicU8::new(0);
/// Whether IntelliMouse (4-byte) mode is active
static INTELLIMOUSE: AtomicBool = AtomicBool::new(false);
/// Mouse is initialized and streaming
pub static MOUSE_READY: AtomicBool = AtomicBool::new(false);

static PACKET_BUF: Mutex<[u8; 4]> = Mutex::new([0u8; 4]);

/// A decoded mouse event.
#[derive(Clone, Copy)]
pub struct MouseEvent {
    /// Horizontal delta (positive = right)
    pub dx: i16,
    /// Vertical delta (positive = down, matching screen coordinates)
    pub dy: i16,
    /// Scroll wheel delta (negative = scroll down / forward)
    pub dz: i8,
    pub left: bool,
    pub right: bool,
    pub middle: bool,
}

// ── PS/2 helpers ──────────────────────────────────────────────────────────────

/// Spin until the PS/2 input buffer is empty (safe to write).
#[inline]
fn wait_write() {
    for _ in 0..100_000u32 {
        if unsafe { inb(PS2_CMD) } & STATUS_INPUT_FULL == 0 {
            return;
        }
        core::hint::spin_loop();
    }
}

/// Spin until the PS/2 output buffer has data (safe to read).
#[inline]
fn wait_read() {
    for _ in 0..100_000u32 {
        if unsafe { inb(PS2_CMD) } & STATUS_OUTPUT_FULL != 0 {
            return;
        }
        core::hint::spin_loop();
    }
}

/// Read a byte from the PS/2 data port (waits for data).
fn ps2_read() -> u8 {
    wait_read();
    unsafe { inb(PS2_DATA) }
}

/// Write a byte to the PS/2 command port.
fn ps2_write_cmd(cmd: u8) {
    wait_write();
    unsafe { outb(PS2_CMD, cmd) };
}

/// Write a byte to the PS/2 data port.
fn ps2_write_data(data: u8) {
    wait_write();
    unsafe { outb(PS2_DATA, data) };
}

/// Send a byte directly to the mouse (via the 0xD4 mux).
fn mouse_write(data: u8) {
    ps2_write_cmd(CMD_SEND_TO_MOUSE);
    ps2_write_data(data);
}

/// Send a command to the mouse and wait for ACK. Returns true on success.
fn mouse_cmd(cmd: u8) -> bool {
    mouse_write(cmd);
    let ack = ps2_read();
    ack == MOUSE_ACK
}

/// Send a command + argument to the mouse and wait for ACK.
fn mouse_cmd_arg(cmd: u8, arg: u8) -> bool {
    mouse_write(cmd);
    let ack = ps2_read();
    if ack != MOUSE_ACK {
        return false;
    }
    mouse_write(arg);
    let ack2 = ps2_read();
    ack2 == MOUSE_ACK
}

/// Drain any pending bytes in the PS/2 output buffer.
fn flush_output() {
    for _ in 0..16 {
        if unsafe { inb(PS2_CMD) } & STATUS_OUTPUT_FULL == 0 {
            break;
        }
        unsafe { inb(PS2_DATA) };
    }
}

// ── Initialization ────────────────────────────────────────────────────────────

/// Initialize the PS/2 mouse.
///
/// Must be called after the IDT and I/O APIC are set up (IRQ12 routed).
/// Returns `true` on success.
pub fn init() -> bool {
    flush_output();

    // Enable the PS/2 auxiliary (mouse) channel
    ps2_write_cmd(CMD_ENABLE_AUX);

    // Enable IRQ12 in the PS/2 controller configuration byte
    ps2_write_cmd(CMD_READ_CFG);
    let mut cfg = ps2_read();
    cfg |= 0x02; // enable IRQ12 (mouse interrupt)
    cfg &= !0x20; // clear "mouse clock disable" bit
    ps2_write_cmd(CMD_WRITE_CFG);
    ps2_write_data(cfg);

    // Reset the mouse
    mouse_cmd(MOUSE_RESET);
    // Drain the reset response (0xAA 0x00)
    flush_output();

    // Set defaults
    if !mouse_cmd(MOUSE_SET_DEFAULTS) {
        crate::serial_println!("[mouse] set_defaults failed");
        return false;
    }

    // Attempt IntelliMouse activation (magic sequence: rates 200, 100, 80)
    let intellimouse = try_enable_intellimouse();
    INTELLIMOUSE.store(intellimouse, Ordering::Relaxed);
    if intellimouse {
        crate::serial_println!("[mouse] IntelliMouse (scroll wheel) detected");
    } else {
        crate::serial_println!("[mouse] Standard PS/2 mouse (3-byte packets)");
    }

    // Enable mouse data streaming
    if !mouse_cmd(MOUSE_ENABLE_STREAM) {
        crate::serial_println!("[mouse] enable_stream failed");
        return false;
    }

    MOUSE_READY.store(true, Ordering::Relaxed);
    crate::serial_println!("[mouse] PS/2 mouse initialized OK");
    true
}

/// Try activating IntelliMouse scroll wheel mode.
/// Returns true if the mouse identifies as IntelliMouse (ID = 0x03).
fn try_enable_intellimouse() -> bool {
    // Magic rate sequence to unlock IntelliMouse mode
    mouse_cmd_arg(MOUSE_SET_SAMPLE_RATE, 200);
    mouse_cmd_arg(MOUSE_SET_SAMPLE_RATE, 100);
    mouse_cmd_arg(MOUSE_SET_SAMPLE_RATE, 80);

    // Query device ID
    mouse_write(MOUSE_GET_ID);
    let ack = ps2_read();
    if ack != MOUSE_ACK {
        return false;
    }
    let id = ps2_read();
    id == 0x03
}

// ── IRQ12 handler ─────────────────────────────────────────────────────────────

/// Called from the IDT IRQ12 handler (interrupt context, interrupts disabled).
///
/// Reads one byte from the PS/2 data port and advances the packet state machine.
pub fn handle_irq() {
    let byte = unsafe { inb(PS2_DATA) };
    let cycle = MOUSE_CYCLE.load(Ordering::Relaxed);
    let packet_len: u8 = if INTELLIMOUSE.load(Ordering::Relaxed) {
        4
    } else {
        3
    };

    // Byte 0 sanity check: bit 3 must always be set; resync if not
    if cycle == 0 && (byte & 0x08) == 0 {
        // Out of sync – just drop and wait for a valid first byte
        return;
    }

    // Store byte in packet buffer
    {
        if let Some(mut buf) = PACKET_BUF.try_lock() {
            buf[cycle as usize] = byte;
        } else {
            return; // IRQ re-entrancy guard: drop
        }
    }

    let next_cycle = cycle + 1;
    if next_cycle >= packet_len {
        // Full packet received – decode it
        MOUSE_CYCLE.store(0, Ordering::Relaxed);
        decode_packet();
    } else {
        MOUSE_CYCLE.store(next_cycle, Ordering::Relaxed);
    }
}

/// Decode the current packet buffer and push a `MouseEvent`.
fn decode_packet() {
    let buf = {
        match PACKET_BUF.try_lock() {
            Some(b) => *b,
            None => return,
        }
    };

    let flags = buf[0];
    let raw_dx = buf[1] as i16;
    let raw_dy = buf[2] as i16;

    // Sign-extend dx / dy using bits 4 and 5 of flags (overflow bits 6/7 ignored)
    let dx: i16 = if flags & 0x10 != 0 {
        raw_dx - 256
    } else {
        raw_dx
    };
    // Y axis: PS/2 uses positive = up; we flip to positive = down (screen coords)
    let dy_ps2: i16 = if flags & 0x20 != 0 {
        raw_dy - 256
    } else {
        raw_dy
    };
    let dy = -dy_ps2;

    let dz: i8 = if INTELLIMOUSE.load(Ordering::Relaxed) {
        // Lower 4 bits of byte 3, sign-extend
        let raw = (buf[3] & 0x0F) as i8;
        if raw & 0x08 != 0 {
            raw | -16i8
        } else {
            raw
        }
    } else {
        0
    };

    let left = flags & 0x01 != 0;
    let right = flags & 0x02 != 0;
    let middle = flags & 0x04 != 0;

    // Clamp and accumulate absolute position (approx screen bounds)
    let scr_w = crate::arch::x86_64::vga::width() as i32;
    let scr_h = crate::arch::x86_64::vga::height() as i32;
    let max_x = if scr_w > 0 { scr_w - 1 } else { 1279 };
    let max_y = if scr_h > 0 { scr_h - 1 } else { 799 };

    let prev_x = MOUSE_ABS_X.load(Ordering::Relaxed);
    let prev_y = MOUSE_ABS_Y.load(Ordering::Relaxed);
    let new_x = (prev_x + dx as i32).clamp(0, max_x);
    let new_y = (prev_y + dy as i32).clamp(0, max_y);
    MOUSE_ABS_X.store(new_x, Ordering::Relaxed);
    MOUSE_ABS_Y.store(new_y, Ordering::Relaxed);

    let event = MouseEvent {
        dx,
        dy,
        dz,
        left,
        right,
        middle,
    };

    // Push to event ring buffer (non-blocking, drop on overflow)
    if let Some(mut q) = EVENT_BUF.try_lock() {
        let tail = q.tail;
        let next_tail = (tail + 1) % EVENT_BUF_SIZE;
        if next_tail != q.head {
            q.buf[tail] = event;
            q.tail = next_tail;
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Dequeue the oldest mouse event (non-blocking).
///
/// Must be called from task context only (not interrupt context).
pub fn read_event() -> Option<MouseEvent> {
    // Disable interrupts before taking the lock to prevent IRQ12 deadlock.
    let saved = super::save_flags_and_cli();
    let result = {
        let mut q = EVENT_BUF.lock();
        if q.head == q.tail {
            None
        } else {
            let ev = q.buf[q.head];
            q.head = (q.head + 1) % EVENT_BUF_SIZE;
            Some(ev)
        }
    };
    super::restore_flags(saved);
    result
}

/// Returns `true` if at least one mouse event is pending.
pub fn has_event() -> bool {
    let saved = super::save_flags_and_cli();
    let result = {
        let q = EVENT_BUF.lock();
        q.head != q.tail
    };
    super::restore_flags(saved);
    result
}

/// Returns the current accumulated mouse position (pixel coordinates).
pub fn mouse_pos() -> (i32, i32) {
    (
        MOUSE_ABS_X.load(Ordering::Relaxed),
        MOUSE_ABS_Y.load(Ordering::Relaxed),
    )
}
