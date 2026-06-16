//! Keyboard Layout Configuration
//!
//! Owns the shared keyboard modifier state and scancode processing logic.
//! Layout-specific modules (keyboard.rs, keyboard_us.rs) only provide
//! scancode-to-ASCII lookup tables.

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

/// French AZERTY scancode set 1 -> ASCII mapping (lowercase)
pub static AZERTY_NORMAL: [u8; 128] = {
    let mut t = [0u8; 128];
    t[0x01] = 0x1B;
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
    t[0x0E] = 0x08;
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
    t[0x1C] = b'\n';
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
    t[0x2A] = 0x00;
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
    t[0x36] = 0x00;
    t[0x37] = b'*';
    t[0x38] = 0x00;
    t[0x39] = b' ';
    t[0x3A] = 0x00;
    t[0x56] = b'<';
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

/// French AZERTY shifted scancode -> ASCII mapping
pub static AZERTY_SHIFT: [u8; 128] = {
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
    t[0x0C] = b')';
    t[0x0D] = b'+';
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
    t[0x1A] = b'l';
    t[0x1B] = b'*';
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
    t[0x29] = b'u';
    t[0x2B] = b'>';
    t[0x2C] = b'W';
    t[0x2D] = b'X';
    t[0x2E] = b'C';
    t[0x2F] = b'V';
    t[0x30] = b'B';
    t[0x31] = b'N';
    t[0x32] = b'?';
    t[0x33] = b'.';
    t[0x34] = b':';
    t[0x35] = b'/';
    t[0x36] = 0x00;
    t[0x37] = b'*';
    t[0x38] = 0x00;
    t[0x39] = b' ';
    t[0x3A] = 0x00;
    t[0x56] = b'>';
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

/// US QWERTY scancode set 1 -> ASCII mapping (lowercase)
pub static QWERTY_NORMAL: [u8; 128] = {
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
    t[0x0C] = b'-';
    t[0x0D] = b'=';
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
    t[0x29] = b'`';
    t[0x2A] = 0x00;
    t[0x2B] = b'\\';
    t[0x2C] = b'z';
    t[0x2D] = b'x';
    t[0x2E] = b'c';
    t[0x2F] = b'v';
    t[0x30] = b'b';
    t[0x31] = b'n';
    t[0x32] = b'm';
    t[0x33] = b',';
    t[0x34] = b'.';
    t[0x35] = b'/';
    t[0x36] = 0x00;
    t[0x37] = b'*';
    t[0x38] = 0x00;
    t[0x39] = b' ';
    t[0x3A] = 0x00;
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

/// US QWERTY shifted scancode -> ASCII mapping
pub static QWERTY_SHIFT: [u8; 128] = {
    let mut t = [0u8; 128];
    t[0x01] = 0x1B;
    t[0x02] = b'!';
    t[0x03] = b'@';
    t[0x04] = b'#';
    t[0x05] = b'$';
    t[0x06] = b'%';
    t[0x07] = b'^';
    t[0x08] = b'&';
    t[0x09] = b'*';
    t[0x0A] = b'(';
    t[0x0B] = b')';
    t[0x0C] = b'_';
    t[0x0D] = b'+';
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
    t[0x29] = b'~';
    t[0x2B] = b'|';
    t[0x2C] = b'Z';
    t[0x2D] = b'X';
    t[0x2E] = b'C';
    t[0x2F] = b'V';
    t[0x30] = b'B';
    t[0x31] = b'N';
    t[0x32] = b'M';
    t[0x33] = b'<';
    t[0x34] = b'>';
    t[0x35] = b'?';
    t[0x36] = 0x00;
    t[0x37] = b'*';
    t[0x38] = 0x00;
    t[0x39] = b' ';
    t[0x3A] = 0x00;
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

// Flag to determine which keyboard layout to use
// true = French AZERTY, false = US QWERTY
static USE_FRENCH_LAYOUT: AtomicBool = AtomicBool::new(true);

/// Set the keyboard layout to French AZERTY
pub fn set_french_layout() {
    USE_FRENCH_LAYOUT.store(true, Ordering::Relaxed);
}

/// Set the keyboard layout to US QWERTY
pub fn set_us_layout() {
    USE_FRENCH_LAYOUT.store(false, Ordering::Relaxed);
}

/// Get the current keyboard layout setting
pub fn is_french_layout() -> bool {
    USE_FRENCH_LAYOUT.load(Ordering::Relaxed)
}

/// Keyboard modifier state — shared across all layouts.
pub struct KeyboardState {
    pub left_shift: bool,
    pub right_shift: bool,
    pub caps_lock: bool,
    pub ctrl: bool,
    pub alt: bool,
    pub extended_scancode: bool,
}

impl KeyboardState {
    pub const fn new() -> Self {
        Self {
            left_shift: false,
            right_shift: false,
            caps_lock: false,
            ctrl: false,
            alt: false,
            extended_scancode: false,
        }
    }

    pub fn shift_active(&self) -> bool {
        self.left_shift || self.right_shift
    }
}

/// Global keyboard modifier state — single instance shared by all layouts.
pub static KEYBOARD: Mutex<KeyboardState> = Mutex::new(KeyboardState::new());

/// Special key constants (non-ASCII, outside 0-127)
pub const KEY_UP: u8 = 0x80;
pub const KEY_DOWN: u8 = 0x81;
pub const KEY_LEFT: u8 = 0x82;
pub const KEY_RIGHT: u8 = 0x83;
pub const KEY_HOME: u8 = 0x84;
pub const KEY_END: u8 = 0x85;

/// Process a single scancode byte with the given lookup tables.
///
/// Handles modifier tracking, extended scancode prefix (0xE0), caps lock
/// inversion, and extended key dispatch (arrows, Home, End, Delete).
/// Called from both PS/2 IRQ and task context (inject_hid_scancode).
pub fn process_scancode(
    scancode: u8,
    normal: &[u8; 128],
    shift: &[u8; 128],
) -> Option<u8> {
    let mut kbd = KEYBOARD.lock();

    // Extended scancode prefix (0xE0)
    if scancode == 0xE0 {
        kbd.extended_scancode = true;
        return None;
    }

    let is_extended = kbd.extended_scancode;
    kbd.extended_scancode = false;

    // Key release (bit 7 set)
    if scancode & 0x80 != 0 {
        match scancode & 0x7F {
            0x2A => kbd.left_shift = false,
            0x36 => kbd.right_shift = false,
            0x1D => kbd.ctrl = false,
            0x38 => kbd.alt = false,
            _ => {}
        }
        return None;
    }

    // Modifier key presses
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

    // Extended keys (arrow keys, Home, End, Delete sent as 0xE0 + scancode)
    if is_extended {
        return match scancode {
            0x48 => Some(KEY_UP),
            0x50 => Some(KEY_DOWN),
            0x4B => Some(KEY_LEFT),
            0x4D => Some(KEY_RIGHT),
            0x47 => Some(KEY_HOME),
            0x4F => Some(KEY_END),
            0x53 => Some(b'\x7F'),
            _ => None,
        };
    }

    // Regular key: lookup in tables, apply caps lock
    if scancode < 128 {
        let shift_active = kbd.shift_active();
        let ch = if shift_active {
            shift[scancode as usize]
        } else {
            normal[scancode as usize]
        };

        if kbd.caps_lock && ch.is_ascii_alphabetic() {
            let ch = if shift_active {
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

/// Read port 0x60 and process the scancode with the current layout tables.
pub fn handle_scancode() -> Option<u8> {
    let scancode = unsafe { super::io::inb(super::keyboard::KEYBOARD_DATA_PORT) };
    handle_scancode_raw(scancode)
}

/// Process a pre-read scancode byte with the current layout tables.
pub fn handle_scancode_raw(scancode: u8) -> Option<u8> {
    if is_french_layout() {
        process_scancode(scancode, &AZERTY_NORMAL, &AZERTY_SHIFT)
    } else {
        process_scancode(scancode, &QWERTY_NORMAL, &QWERTY_SHIFT)
    }
}
