//! PS/2 Keyboard driver
//!
//! Handles IRQ1 keyboard interrupts, reads scancodes from port 0x60,
//! and converts them to characters for the VGA console.
//!
//! Modifier state and scancode processing are shared via keyboard_layout.rs.
//! This module owns the ring buffer, PS/2 port init, and lost-key diagnostics.

use super::io::{inb, outb};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

/// Keyboard input buffer size
const KEYBOARD_BUFFER_SIZE: usize = 256;

// ========== Interrupt-safe ring buffer ======================================================================
//
// All state collapsed into a single Mutex. In non-ISR paths (pop/has_data),
// interrupts are disabled BEFORE taking the lock. The ISR already runs with
// IF=0, so it never needs to disable interrupts.

struct KeyboardBufferInner {
    buf: [u8; KEYBOARD_BUFFER_SIZE],
    head: usize,
    tail: usize,
}

struct KeyboardBuffer {
    inner: Mutex<KeyboardBufferInner>,
}

static KEYBOARD_BUFFER: KeyboardBuffer = KeyboardBuffer::new();

/// Number of characters dropped due to buffer overflow.
/// Incremented atomically in IRQ context, safe to read from any context.
static LOST_KEY_COUNT: AtomicUsize = AtomicUsize::new(0);

impl KeyboardBuffer {
    const fn new() -> Self {
        Self {
            inner: Mutex::new(KeyboardBufferInner {
                buf: [0u8; KEYBOARD_BUFFER_SIZE],
                head: 0,
                tail: 0,
            }),
        }
    }

    /// Called exclusively from IRQ context (IF=0 already).
    pub fn push(&self, ch: u8) {
        let mut g = self.inner.lock();
        let tail = g.tail;
        g.buf[tail] = ch;
        g.tail = (tail + 1) % KEYBOARD_BUFFER_SIZE;
        // Buffer full: drop oldest character and count it.
        if g.head == g.tail {
            g.head = (g.head + 1) % KEYBOARD_BUFFER_SIZE;
            LOST_KEY_COUNT.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Called from task context. Interrupts disabled before lock acquisition.
    pub fn pop(&self) -> Option<u8> {
        let saved = super::save_flags_and_cli();
        let result = {
            let mut g = self.inner.lock();
            if g.head == g.tail {
                None
            } else {
                let ch = g.buf[g.head];
                g.head = (g.head + 1) % KEYBOARD_BUFFER_SIZE;
                Some(ch)
            }
        };
        super::restore_flags(saved);
        result
    }

    /// Called from task context. Same interrupt-disable discipline as pop.
    pub fn has_data(&self) -> bool {
        let saved = super::save_flags_and_cli();
        let result = {
            let g = self.inner.lock();
            g.head != g.tail
        };
        super::restore_flags(saved);
        result
    }
}

/// Add a character to the keyboard buffer (called from IRQ context).
///
/// Ctrl+C (0x03) also sets the global SHELL_INTERRUPTED flag.
pub fn add_to_buffer(ch: u8) {
    if ch == 0x03 {
        crate::shell::SHELL_INTERRUPTED.store(true, Ordering::Relaxed);
    }
    KEYBOARD_BUFFER.push(ch);
}

/// Get a character from the keyboard buffer (non-blocking, task context only).
pub fn read_char() -> Option<u8> {
    KEYBOARD_BUFFER.pop()
}

/// Check if keyboard buffer has data (task context only).
pub fn has_input() -> bool {
    KEYBOARD_BUFFER.has_data()
}

/// Return the total number of characters lost due to buffer overflow since boot.
pub fn lost_key_count() -> usize {
    LOST_KEY_COUNT.load(Ordering::Relaxed)
}

/// Reset the lost-key counter to zero.
pub fn reset_lost_key_count() {
    LOST_KEY_COUNT.store(0, Ordering::Relaxed);
}

/// Inject a PS/2 scancode from USB HID or other non-PS/2 source.
///
/// Must be called from task context. Converts scancode to character via
/// the current layout and pushes to the buffer if applicable.
pub fn inject_hid_scancode(scancode: u8, pressed: bool) {
    let raw = if pressed { scancode } else { scancode | 0x80 };
    if let Some(ch) = super::keyboard_layout::handle_scancode_raw(raw) {
        let saved = super::save_flags_and_cli();
        KEYBOARD_BUFFER.push(ch);
        super::restore_flags(saved);
    }
}

// Re-export special key constants for consumers (e.g. shell/commands/top)
pub use super::keyboard_layout::{KEY_DOWN, KEY_END, KEY_HOME, KEY_LEFT, KEY_RIGHT, KEY_UP};

/// PS/2 keyboard data port
pub(crate) const KEYBOARD_DATA_PORT: u16 = 0x60;
const PS2_CMD_PORT: u16 = 0x64;

const CMD_READ_CFG: u8 = 0x20;
const CMD_WRITE_CFG: u8 = 0x60;
const CMD_ENABLE_KBD: u8 = 0xAE;

const STATUS_OUTPUT_FULL: u8 = 0x01;
const STATUS_INPUT_FULL: u8 = 0x02;

#[inline]
fn wait_write() {
    for _ in 0..100_000u32 {
        if unsafe { inb(PS2_CMD_PORT) } & STATUS_INPUT_FULL == 0 {
            return;
        }
        core::hint::spin_loop();
    }
}

#[inline]
fn wait_read() {
    for _ in 0..100_000u32 {
        if unsafe { inb(PS2_CMD_PORT) } & STATUS_OUTPUT_FULL != 0 {
            return;
        }
        core::hint::spin_loop();
    }
}

fn ps2_read() -> u8 {
    wait_read();
    unsafe { inb(KEYBOARD_DATA_PORT) }
}

fn ps2_write_cmd(cmd: u8) {
    wait_write();
    unsafe { outb(PS2_CMD_PORT, cmd) };
}

fn ps2_write_data(data: u8) {
    wait_write();
    unsafe { outb(KEYBOARD_DATA_PORT, data) };
}

fn flush_output() {
    for _ in 0..16 {
        if unsafe { inb(PS2_CMD_PORT) } & STATUS_OUTPUT_FULL == 0 {
            break;
        }
        unsafe { inb(KEYBOARD_DATA_PORT) };
    }
}

/// Initialize the PS/2 keyboard controller
///
/// After APIC/IOAPIC reconfiguration, explicitly enable the keyboard port,
/// IRQ1, and the keyboard clock.
pub fn init() {
    flush_output();

    ps2_write_cmd(CMD_ENABLE_KBD);

    ps2_write_cmd(CMD_READ_CFG);
    let mut cfg = ps2_read();
    cfg |= 0x01;
    cfg &= !0x10;
    ps2_write_cmd(CMD_WRITE_CFG);
    ps2_write_data(cfg);

    flush_output();
}
