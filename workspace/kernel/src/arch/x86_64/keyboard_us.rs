//! US QWERTY PS/2 Keyboard driver
//!
//! Handles IRQ1 keyboard interrupts, reads scancodes from port 0x60,
//! and converts them to characters for the VGA console.

use super::io::inb;
use spin::Mutex;

/// PS/2 keyboard data port
const KEYBOARD_DATA_PORT: u16 = 0x60;

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

/// US QWERTY scancode set 1 -> ASCII mapping (lowercase)
static SCANCODE_TO_ASCII: [u8; 128] = {
    let mut table = [0u8; 128];
    // Row 1: Esc, 1-0, -, =, Backspace
    table[0x01] = 0x1B; // Esc
    table[0x02] = b'1';
    table[0x03] = b'2';
    table[0x04] = b'3';
    table[0x05] = b'4';
    table[0x06] = b'5';
    table[0x07] = b'6';
    table[0x08] = b'7';
    table[0x09] = b'8';
    table[0x0A] = b'9';
    table[0x0B] = b'0';
    table[0x0C] = b'-';
    table[0x0D] = b'=';
    table[0x0E] = 0x08; // Backspace
                        // Row 2: Tab, Q-P, [, ], Enter
    table[0x0F] = b'\t';
    table[0x10] = b'q';
    table[0x11] = b'w';
    table[0x12] = b'e';
    table[0x13] = b'r';
    table[0x14] = b't';
    table[0x15] = b'y';
    table[0x16] = b'u';
    table[0x17] = b'i';
    table[0x18] = b'o';
    table[0x19] = b'p';
    table[0x1A] = b'[';
    table[0x1B] = b']';
    table[0x1C] = b'\n'; // Enter
                         // Row 3: Ctrl, A-L, ;, ', `
    table[0x1E] = b'a';
    table[0x1F] = b's';
    table[0x20] = b'd';
    table[0x21] = b'f';
    table[0x22] = b'g';
    table[0x23] = b'h';
    table[0x24] = b'j';
    table[0x25] = b'k';
    table[0x26] = b'l';
    table[0x27] = b';';
    table[0x28] = b'\'';
    table[0x29] = b'`';
    // Row 4: LShift, \, Z-M, comma, dot, /
    table[0x2B] = b'\\';
    table[0x2C] = b'z';
    table[0x2D] = b'x';
    table[0x2E] = b'c';
    table[0x2F] = b'v';
    table[0x30] = b'b';
    table[0x31] = b'n';
    table[0x32] = b'm';
    table[0x33] = b',';
    table[0x34] = b'.';
    table[0x35] = b'/';
    // Space
    table[0x39] = b' ';
    table
};

/// Shifted scancode -> ASCII mapping
static SCANCODE_TO_ASCII_SHIFT: [u8; 128] = {
    let mut table = [0u8; 128];
    table[0x01] = 0x1B;
    table[0x02] = b'!';
    table[0x03] = b'@';
    table[0x04] = b'#';
    table[0x05] = b'$';
    table[0x06] = b'%';
    table[0x07] = b'^';
    table[0x08] = b'&';
    table[0x09] = b'*';
    table[0x0A] = b'(';
    table[0x0B] = b')';
    table[0x0C] = b'_';
    table[0x0D] = b'+';
    table[0x0E] = 0x08;
    table[0x0F] = b'\t';
    table[0x10] = b'Q';
    table[0x11] = b'W';
    table[0x12] = b'E';
    table[0x13] = b'R';
    table[0x14] = b'T';
    table[0x15] = b'Y';
    table[0x16] = b'U';
    table[0x17] = b'I';
    table[0x18] = b'O';
    table[0x19] = b'P';
    table[0x1A] = b'{';
    table[0x1B] = b'}';
    table[0x1C] = b'\n';
    table[0x1E] = b'A';
    table[0x1F] = b'S';
    table[0x20] = b'D';
    table[0x21] = b'F';
    table[0x22] = b'G';
    table[0x23] = b'H';
    table[0x24] = b'J';
    table[0x25] = b'K';
    table[0x26] = b'L';
    table[0x27] = b':';
    table[0x28] = b'"';
    table[0x29] = b'~';
    table[0x2B] = b'|';
    table[0x2C] = b'Z';
    table[0x2D] = b'X';
    table[0x2E] = b'C';
    table[0x2F] = b'V';
    table[0x30] = b'B';
    table[0x31] = b'N';
    table[0x32] = b'M';
    table[0x33] = b'<';
    table[0x34] = b'>';
    table[0x35] = b'?';
    table[0x39] = b' ';
    table
};

/// Handle a keyboard IRQ (called from interrupt handler)
///
/// Returns the ASCII character if a printable key was pressed,
/// or None for modifier keys / key releases.
pub fn handle_scancode() -> Option<u8> {
    let scancode = unsafe { inb(KEYBOARD_DATA_PORT) };
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
