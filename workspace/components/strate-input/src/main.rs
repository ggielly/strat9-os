//! Input Server for strat9-os
//!
//! Reads raw PS/2 scancodes from /dev/input/kbd and mouse events from
//! /dev/input/mouse. Translates scancodes to ASCII using keyboard layout
//! tables (AZERTY/QWERTY). Distributes processed events to clients.
//!
//! Architecture:
//!   Hardware → PS/2 IRQ → kernel ring buffer → /dev/input/kbd → THIS SERVER
//!   → layout translation → processed chars → clients (console, shell, apps)
//!
//! This moves keyboard layout logic out of the kernel, following the Haiku
//! Input Server / Fuchsia Input Reader pattern.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use strat9_syscall::call;

// ============================================================================
// Keyboard layout tables (moved from kernel keyboard_layout.rs)
// ============================================================================

/// French AZERTY scancode set 1 -> ASCII (lowercase)
static AZERTY_NORMAL: [u8; 128] = {
    let mut t = [0u8; 128];
    t[0x01] = 0x1B; // ESC
    t[0x02] = b'&';
    t[0x03] = b'e';
    t[0x04] = b'"';
    t[0x05] = b'\'';
    t[0x06] = b'(';
    t[0x07] = b'-';
    t[0x08] = b'e';
    t[0x09] = b'_';
    t[0x0A] = b'c';
    t[0x0B] = b'a';
    t[0x0C] = b')';
    t[0x0D] = b'+';
    t[0x0E] = 0x08; // Backspace
    t[0x0F] = b'\t';
    t[0x10] = b'a';
    t[0x11] = b'z';
    t[0x12] = b'e';
    t[0x13] = b'r';
    t[0x14] = b't';
    t[0x15] = b'y';
    t[0x16] = b'u';
    t[0x17] = b'i';
    t[0x18] = b'o';
    t[0x19] = b'p';
    t[0x1A] = b'^';
    t[0x1B] = b'$';
    t[0x1C] = b'\n'; // Enter
    t[0x1E] = b'q';
    t[0x1F] = b's';
    t[0x20] = b'd';
    t[0x21] = b'f';
    t[0x22] = b'g';
    t[0x23] = b'h';
    t[0x24] = b'j';
    t[0x25] = b'k';
    t[0x26] = b'l';
    t[0x27] = b'm';
    t[0x28] = b'u';
    t[0x29] = b'*';
    t[0x2B] = b'<';
    t[0x2C] = b'w';
    t[0x2D] = b'x';
    t[0x2E] = b'c';
    t[0x2F] = b'v';
    t[0x30] = b'b';
    t[0x31] = b'n';
    t[0x32] = b',';
    t[0x33] = b';';
    t[0x34] = b'.';
    t[0x35] = b'/';
    t[0x39] = b' '; // Space
    t[0x47] = b'7';
    t[0x48] = b'8';
    t[0x49] = b'9';
    t[0x4A] = b'-';
    t[0x4B] = b'4';
    t[0x4C] = b'5';
    t[0x4D] = b'6';
    t[0x4E] = b'+';
    t[0x4F] = b'1';
    t[0x50] = b'2';
    t[0x51] = b'3';
    t[0x52] = b'0';
    t[0x53] = b'.';
    t
};

/// French AZERTY shifted scancode -> ASCII
static AZERTY_SHIFT: [u8; 128] = {
    let mut t = [0u8; 128];
    t[0x01] = 0x1B;
    t[0x02] = b'1';
    t[0x03] = b'2';
    t[0x04] = b'3';
    t[0x05] = b'4';
    t[0x06] = b'5';
    t[0x07] = b'6';
    t[0x08] = b'7';
    t[0x09] = b'8';
    t[0x0A] = b'9';
    t[0x0B] = b'0';
    t[0x0C] = b'\xe7'; // c cedilla
    t[0x0D] = b'=';
    t[0x0E] = 0x08;
    t[0x0F] = b'\t';
    t[0x10] = b'A';
    t[0x11] = b'Z';
    t[0x12] = b'E';
    t[0x13] = b'R';
    t[0x14] = b'T';
    t[0x15] = b'Y';
    t[0x16] = b'U';
    t[0x17] = b'I';
    t[0x18] = b'O';
    t[0x19] = b'P';
    t[0x1A] = b'\xe8'; // e grave
    t[0x1B] = b'\xa3'; // pound sign
    t[0x1C] = b'\n';
    t[0x1E] = b'Q';
    t[0x1F] = b'S';
    t[0x20] = b'D';
    t[0x21] = b'F';
    t[0x22] = b'G';
    t[0x23] = b'H';
    t[0x24] = b'J';
    t[0x25] = b'K';
    t[0x26] = b'L';
    t[0x27] = b'M';
    t[0x28] = b'%';
    t[0x29] = b'\xb5'; // mu
    t[0x2B] = b'>';
    t[0x2C] = b'W';
    t[0x2D] = b'X';
    t[0x2E] = b'C';
    t[0x2F] = b'V';
    t[0x30] = b'B';
    t[0x31] = b'N';
    t[0x32] = b'?';
    t[0x33] = b'.';
    t[0x34] = b'/';
    t[0x35] = b'\xd7'; // multiply
    t[0x39] = b' ';
    t
};

/// US QWERTY scancode set 1 -> ASCII (lowercase)
static QWERTY_NORMAL: [u8; 128] = {
    let mut t = [0u8; 128];
    t[0x01] = 0x1B;
    t[0x02] = b'`';
    t[0x03] = b'1';
    t[0x04] = b'2';
    t[0x05] = b'3';
    t[0x06] = b'4';
    t[0x07] = b'5';
    t[0x08] = b'6';
    t[0x09] = b'7';
    t[0x0A] = b'8';
    t[0x0B] = b'9';
    t[0x0C] = b'0';
    t[0x0D] = b'-';
    t[0x0E] = 0x08;
    t[0x0F] = b'\t';
    t[0x10] = b'q';
    t[0x11] = b'w';
    t[0x12] = b'e';
    t[0x13] = b'r';
    t[0x14] = b't';
    t[0x15] = b'y';
    t[0x16] = b'u';
    t[0x17] = b'i';
    t[0x18] = b'o';
    t[0x19] = b'p';
    t[0x1A] = b'[';
    t[0x1B] = b']';
    t[0x1C] = b'\n';
    t[0x1E] = b'a';
    t[0x1F] = b's';
    t[0x20] = b'd';
    t[0x21] = b'f';
    t[0x22] = b'g';
    t[0x23] = b'h';
    t[0x24] = b'j';
    t[0x25] = b'k';
    t[0x26] = b'l';
    t[0x27] = b';';
    t[0x28] = b'\'';
    t[0x29] = b'\\';
    t[0x2B] = b'\\';
    t[0x2C] = b'z';
    t[0x2D] = b'x';
    t[0x2E] = b'c';
    t[0x2F] = b'v';
    t[0x30] = b'b';
    t[0x31] = b'n';
    t[0x32] = b',';
    t[0x33] = b'.';
    t[0x34] = b'/';
    t[0x39] = b' ';
    t
};

/// US QWERTY shifted scancode -> ASCII
static QWERTY_SHIFT: [u8; 128] = {
    let mut t = [0u8; 128];
    t[0x01] = 0x1B;
    t[0x02] = b'~';
    t[0x03] = b'!';
    t[0x04] = b'@';
    t[0x05] = b'#';
    t[0x06] = b'$';
    t[0x07] = b'%';
    t[0x08] = b'^';
    t[0x09] = b'&';
    t[0x0A] = b'*';
    t[0x0B] = b'(';
    t[0x0C] = b')';
    t[0x0D] = b'_';
    t[0x0E] = 0x08;
    t[0x0F] = b'\t';
    t[0x10] = b'Q';
    t[0x11] = b'W';
    t[0x12] = b'E';
    t[0x13] = b'R';
    t[0x14] = b'T';
    t[0x15] = b'Y';
    t[0x16] = b'U';
    t[0x17] = b'I';
    t[0x18] = b'O';
    t[0x19] = b'P';
    t[0x1A] = b'{';
    t[0x1B] = b'}';
    t[0x1C] = b'\n';
    t[0x1E] = b'A';
    t[0x1F] = b'S';
    t[0x20] = b'D';
    t[0x21] = b'F';
    t[0x22] = b'G';
    t[0x23] = b'H';
    t[0x24] = b'J';
    t[0x25] = b'K';
    t[0x26] = b'L';
    t[0x27] = b':';
    t[0x28] = b'"';
    t[0x29] = b'|';
    t[0x2B] = b'|';
    t[0x2C] = b'Z';
    t[0x2D] = b'X';
    t[0x2E] = b'C';
    t[0x2F] = b'V';
    t[0x30] = b'B';
    t[0x31] = b'N';
    t[0x32] = b'<';
    t[0x33] = b'>';
    t[0x34] = b'?';
    t[0x39] = b' ';
    t
};

// ============================================================================
// Keyboard state (modifier tracking)
// ============================================================================

struct KeyboardState {
    left_shift: bool,
    right_shift: bool,
    caps_lock: bool,
    left_ctrl: bool,
    left_alt: bool,
    extended: bool,
}

impl KeyboardState {
    fn new() -> Self {
        KeyboardState {
            left_shift: false,
            right_shift: false,
            caps_lock: false,
            left_ctrl: false,
            left_alt: false,
            extended: false,
        }
    }

    fn shift_active(&self) -> bool {
        self.left_shift || self.right_shift
    }
}

/// Process a raw PS/2 set-1 scancode and return the ASCII character.
/// Returns None for non-printable keys (modifiers, function keys).
fn process_scancode(scancode: u8, state: &mut KeyboardState) -> Option<u8> {
    let pressed = scancode & 0x80 == 0;
    let code = scancode & 0x7F;

    // Handle extended scancode prefix (0xE0)
    if code == 0xE0 {
        state.extended = true;
        return None;
    }

    // Extended scancodes (arrows, home, etc.)
    if state.extended {
        state.extended = false;
        return None; // Extended keys not yet handled
    }

    // Track modifier state
    match code {
        0x2A => {
            state.left_shift = pressed;
            return None;
        }
        0x36 => {
            state.right_shift = pressed;
            return None;
        }
        0x3A => {
            if pressed {
                state.caps_lock = !state.caps_lock;
            }
            return None;
        }
        0x1D => {
            state.left_ctrl = pressed;
            return None;
        }
        0x38 => {
            state.left_alt = pressed;
            return None;
        }
        _ => {}
    }

    if !pressed {
        return None; // Key release
    }

    // Ctrl+C = interrupt
    if state.left_ctrl && code == 0x2E {
        return Some(0x03);
    }

    // Translate scancode to ASCII using AZERTY layout (default)
    let shift = state.shift_active() ^ state.caps_lock;
    let table = if shift { &AZERTY_SHIFT } else { &AZERTY_NORMAL };
    let ch = table[code as usize];

    if ch == 0 {
        None
    } else {
        Some(ch)
    }
}

// ============================================================================
// Main loop
// ============================================================================

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Open keyboard device
    let kbd_fd = match call::open(b"/dev/input/kbd\0", 0 /* O_RDONLY */) {
        Ok(fd) => fd,
        Err(e) => {
            serial_println!("[input-server] failed to open /dev/input/kbd: {:?}", e);
            loop {
                core::hint::spin_loop();
            }
        }
    };

    // Open mouse device
    let mouse_fd = match call::open(b"/dev/input/mouse\0", 0) {
        Ok(fd) => fd,
        Err(e) => {
            serial_println!("[input-server] failed to open /dev/input/mouse: {:?}", e);
            loop {
                core::hint::spin_loop();
            }
        }
    };

    serial_println!(
        "[input-server] started (kbd_fd={}, mouse_fd={})",
        kbd_fd,
        mouse_fd
    );

    let mut state = KeyboardState::new();
    let mut kbd_buf = [0u8; 64];
    let mut mouse_buf = [0u8; 56]; // 8 events × 7 bytes

    loop {
        // Read keyboard scancodes
        if let Ok(n) = call::read(kbd_fd, &mut kbd_buf) {
            for &sc in &kbd_buf[..n] {
                if let Some(ch) = process_scancode(sc, &mut state) {
                    // Write translated character to stdout
                    let _ = call::write(1, &[ch]);
                }
            }
        }

        // Read mouse events (just consume for now : display server will use them)
        let _ = call::read(mouse_fd, &mut mouse_buf);

        // Yield to other processes
        let _ = call::yield_cpu();
    }
}

fn serial_println(s: &str) {
    let _ = call::write(2, s.as_bytes());
    let _ = call::write(2, b"\n");
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
