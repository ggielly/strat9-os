//! PS/2 Keyboard driver (inspired by MaestroOS `keyboard.rs`)
//!
//! Handles IRQ1 keyboard interrupts, reads scancodes from port 0x60,
//! and converts them to characters for the VGA console.

use super::io::{inb, outb};
use spin::Mutex;

/// Keyboard input buffer size
const KEYBOARD_BUFFER_SIZE: usize = 256;

// ─── Interrupt-safe ring buffer ───────────────────────────────────────────────
//
// The previous design used three separate `Mutex` fields (buffer, head, tail).
// `push()` : called from the keyboard ISR : acquired them in order
// tail → buffer → head.  `pop()` : called from task context : acquired them in
// order head → tail → buffer.
//
// This created a classic spinlock + interrupt deadlock:
//   1. Task context calls `pop()` → acquires `head` lock.
//   2. Keyboard IRQ fires before `pop()` releases `head`.
//   3. ISR calls `push()` → acquires `tail`, then `buffer`, then tries `head`
//      → spins forever because `head` is still held by the preempted task.
//
// Fix: collapse all state into a SINGLE `Mutex` and, in the non-ISR path
// (`pop` / `has_data`), disable interrupts BEFORE taking the lock.
// The ISR already runs with IF=0, so it never needs to disable interrupts.

struct KeyboardBufferInner {
    buf: [u8; KEYBOARD_BUFFER_SIZE],
    head: usize,
    tail: usize,
}

struct KeyboardBuffer {
    inner: Mutex<KeyboardBufferInner>,
}

static KEYBOARD_BUFFER: KeyboardBuffer = KeyboardBuffer::new();

impl KeyboardBuffer {
    /// Creates a new instance.
    const fn new() -> Self {
        Self {
            inner: Mutex::new(KeyboardBufferInner {
                buf: [0u8; KEYBOARD_BUFFER_SIZE],
                head: 0,
                tail: 0,
            }),
        }
    }

    /// Called exclusively from IRQ context (IF=0 already).  No need to
    /// save/restore flags here.
    pub fn push(&self, ch: u8) {
        let mut g = self.inner.lock();
        let tail = g.tail;
        g.buf[tail] = ch;
        g.tail = (tail + 1) % KEYBOARD_BUFFER_SIZE;
        // Buffer full : drop oldest character silently.
        if g.head == g.tail {
            g.head = (g.head + 1) % KEYBOARD_BUFFER_SIZE;
        }
    }

    /// Called from task context.  We must disable interrupts before taking
    /// the lock so that the keyboard ISR cannot fire while we hold it.
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

    /// Called from task context : same interrupt-disable discipline as `pop`.
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
/// Ctrl+C (0x03) is also pushed to the buffer but additionally sets the
/// global [`crate::shell::SHELL_INTERRUPTED`] flag so that long-running
/// commands can detect cancellation.
///
/// Must NOT call serial_force_println! or any lock that could contend with
/// the interrupted task (e.g. FORCE_LOCK). Redox/Maestro/Asterinas keep
/// IRQ handlers minimal; printing here can deadlock if the preempted task
/// was holding FORCE_LOCK.
pub fn add_to_buffer(ch: u8) {
    if ch == 0x03 {
        crate::shell::SHELL_INTERRUPTED.store(true, core::sync::atomic::Ordering::Relaxed);
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

/// Inject a PS/2 scancode from USB HID or other non-PS/2 source.
///
/// Must be called from task context. Converts scancode to character via
/// the current layout and pushes to the buffer if applicable.
/// Used by hid::poll_all() when USB HID reports arrive.
///
/// - `scancode`: PS/2 Set 1 scancode (0x00-0x7F for press, or 0x80|code for release)
/// - `pressed`: true = key press, false = key release
pub fn inject_hid_scancode(scancode: u8, pressed: bool) {
    let raw = if pressed { scancode } else { scancode | 0x80 };
    if let Some(ch) = super::keyboard_layout::handle_scancode_raw(raw) {
        let saved = super::save_flags_and_cli();
        KEYBOARD_BUFFER.push(ch);
        super::restore_flags(saved);
    }
}

/// PS/2 keyboard data port
const KEYBOARD_DATA_PORT: u16 = 0x60;
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

/// Initialize the PS/2 keyboard controler
///
/// The firmware typically leaves IRQ1 enabled, but this is not guaranteed.
/// After APIC/IOAPIC reconfiguration and mouse initialization, we explicitly
/// enable the keyboard port, IRQ1, and the keyboard clock.
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

/// Keyboard state
pub struct KeyboardState {
    /// Left shift pressed
    pub left_shift: bool,
    /// Right shift pressed
    pub right_shift: bool,
    /// Caps lock active
    pub caps_lock: bool,
    /// Control pressed
    pub ctrl: bool,
    /// Alt pressed
    pub alt: bool,
}

impl KeyboardState {
    /// Creates a new instance.
    pub const fn new() -> Self {
        Self {
            left_shift: false,
            right_shift: false,
            caps_lock: false,
            ctrl: false,
            alt: false,
        }
    }

    /// Returns whether shift is active (shift XOR caps_lock for letters)
    pub fn shift_active(&self) -> bool {
        self.left_shift || self.right_shift
    }
}

/// Global keyboard state
pub static KEYBOARD: Mutex<KeyboardState> = Mutex::new(KeyboardState::new());

/// French AZERTY scancode set 1 -> ASCII mapping (lowercase)
static SCANCODE_TO_ASCII: [u8; 128] = {
    let mut table = [0u8; 128];
    // Row 1: Esc, 1-0, -, =, Backspace
    table[0x01] = 0x1B; // Esc
    table[0x02] = b'&'; // 1
    table[0x03] = b'e'; // 2 (é -> e)
    table[0x04] = b'"'; // 3
    table[0x05] = b'\''; // 4
    table[0x06] = b'('; // 5
    table[0x07] = b'-'; // 6
    table[0x08] = b'e'; // 7 (è -> e)
    table[0x09] = b'_'; // 8
    table[0x0A] = b'c'; // 9 (ç -> c)
    table[0x0B] = b'a'; // 0 (à -> a)
    table[0x0C] = b')'; // -
    table[0x0D] = b'='; // =
    table[0x0E] = 0x08; // Backspace
                        // Row 2: Tab, A-Z, [, ], Enter
    table[0x0F] = b'\t';
    table[0x10] = b'a'; // Q
    table[0x11] = b'z'; // W
    table[0x12] = b'e'; // E
    table[0x13] = b'r'; // R
    table[0x14] = b't'; // T
    table[0x15] = b'y'; // Y
    table[0x16] = b'u'; // U
    table[0x17] = b'i'; // I
    table[0x18] = b'o'; // O
    table[0x19] = b'p'; // P
    table[0x1A] = b'^'; // [
    table[0x1B] = b'$'; // ]
    table[0x1C] = b'\n'; // Enter
                         // Row 3: Ctrl, Q-S, M, ;, :, `
    table[0x1E] = b'q'; // A
    table[0x1F] = b's'; // S
    table[0x20] = b'd'; // D
    table[0x21] = b'f'; // F
    table[0x22] = b'g'; // G
    table[0x23] = b'h'; // H
    table[0x24] = b'j'; // J
    table[0x25] = b'k'; // K
    table[0x26] = b'l'; // L
    table[0x27] = b'm'; // ;
    table[0x28] = b'u'; // ' (ù -> u)
    table[0x29] = b'*'; // `
                        // Row 4: LShift, <, W-X, C-V, B-N, ,-. /?
    table[0x2A] = 0x00; // LShift (handled separately)
    table[0x2B] = b'<'; // \
    table[0x2C] = b'w'; // Z
    table[0x2D] = b'x'; // X
    table[0x2E] = b'c'; // C
    table[0x2F] = b'v'; // V
    table[0x30] = b'b'; // B
    table[0x31] = b'n'; // N
    table[0x32] = b','; // M
    table[0x33] = b';'; // ,
    table[0x34] = b'.'; // .
    table[0x35] = b'/'; // /
                        // Space
    table[0x39] = b' ';
    table
};

/// Shifted scancode -> ASCII mapping for French AZERTY
static SCANCODE_TO_ASCII_SHIFT: [u8; 128] = {
    let mut table = [0u8; 128];
    table[0x01] = 0x1B; // Esc
    table[0x02] = b'1'; // &
    table[0x03] = b'2'; // é
    table[0x04] = b'3'; // "
    table[0x05] = b'4'; // '
    table[0x06] = b'5'; // (
    table[0x07] = b'6'; // -
    table[0x08] = b'7'; // è
    table[0x09] = b'8'; // _
    table[0x0A] = b'9'; // ç
    table[0x0B] = b'0'; // à
    table[0x0C] = b')'; // ° -> )
    table[0x0D] = b'+'; // =
    table[0x0E] = 0x08; // Backspace
    table[0x0F] = b'\t'; // Tab
    table[0x10] = b'A'; // Q
    table[0x11] = b'Z'; // W
    table[0x12] = b'E'; // E
    table[0x13] = b'R'; // R
    table[0x14] = b'T'; // T
    table[0x15] = b'Y'; // Y
    table[0x16] = b'U'; // U
    table[0x17] = b'I'; // I
    table[0x18] = b'O'; // O
    table[0x19] = b'P'; // P
    table[0x1A] = b'^'; // ¨ -> ^
    table[0x1B] = b'*'; // $
    table[0x1C] = b'\n'; // Enter
    table[0x1E] = b'Q'; // A
    table[0x1F] = b'S'; // S
    table[0x20] = b'D'; // D
    table[0x21] = b'F'; // F
    table[0x22] = b'G'; // G
    table[0x23] = b'H'; // H
    table[0x24] = b'J'; // J
    table[0x25] = b'K'; // K
    table[0x26] = b'L'; // L
    table[0x27] = b'M'; // ;
    table[0x28] = b'%'; // '
    table[0x29] = b'm'; // µ -> m
    table[0x2B] = b'>'; // <
    table[0x2C] = b'W'; // Z
    table[0x2D] = b'X'; // X
    table[0x2E] = b'C'; // C
    table[0x2F] = b'V'; // V
    table[0x30] = b'B'; // B
    table[0x31] = b'N'; // N
    table[0x32] = b'?'; // ,
    table[0x33] = b'.'; // ;
    table[0x34] = b','; // .
    table[0x35] = b'/'; // § -> /
    table[0x39] = b' '; // Space
    table
};

// Special key constants (non-ASCII, outside 0-127)
pub const KEY_UP: u8 = 0x80;
pub const KEY_DOWN: u8 = 0x81;
pub const KEY_LEFT: u8 = 0x82;
pub const KEY_RIGHT: u8 = 0x83;
pub const KEY_HOME: u8 = 0x84;
pub const KEY_END: u8 = 0x85;

/// Handle a keyboard IRQ (called from interrupt handler)
///
/// Returns the ASCII character if a printable key was pressed,
/// or None for modifier keys / key releases.
pub fn handle_scancode() -> Option<u8> {
    let scancode = unsafe { inb(KEYBOARD_DATA_PORT) };
    handle_scancode_raw(scancode)
}

/// Same as `handle_scancode` but takes a pre-read scancode byte.
pub fn handle_scancode_raw(scancode: u8) -> Option<u8> {
    let mut kbd = KEYBOARD.lock();

    // Key release (bit 7 set)
    if scancode & 0x80 != 0 {
        let released = scancode & 0x7F;
        match released {
            0x2A => kbd.left_shift = false,
            0x36 => kbd.right_shift = false,
            0x1D => kbd.ctrl = false,
            0x38 => kbd.alt = false,
            _ => {}
        }
        return None;
    }

    // Key press
    match scancode {
        0x2A => {
            kbd.left_shift = true;
            return None;
        }
        0x36 => {
            kbd.right_shift = true;
            return None;
        }
        0x1D => {
            kbd.ctrl = true;
            return None;
        }
        0x38 => {
            kbd.alt = true;
            return None;
        }
        0x3A => {
            kbd.caps_lock = !kbd.caps_lock;
            return None;
        }
        // Arrow keys and special keys (Set 1 scancodes)
        0x48 => return Some(KEY_UP),
        0x50 => return Some(KEY_DOWN),
        0x4B => return Some(KEY_LEFT),
        0x4D => return Some(KEY_RIGHT),
        0x47 => return Some(KEY_HOME),
        0x4F => return Some(KEY_END),
        _ => {}
    }

    // Convert scancode to ASCII
    if scancode < 128 {
        let shift = kbd.shift_active();
        let ch = if shift {
            SCANCODE_TO_ASCII_SHIFT[scancode as usize]
        } else {
            SCANCODE_TO_ASCII[scancode as usize]
        };

        // Handle caps lock for letters
        if kbd.caps_lock && ch.is_ascii_alphabetic() {
            let ch = if shift {
                ch.to_ascii_lowercase()
            } else {
                ch.to_ascii_uppercase()
            };
            if ch != 0 {
                return Some(ch);
            }
        }

        if ch != 0 {
            return Some(ch);
        }
    }

    None
}
