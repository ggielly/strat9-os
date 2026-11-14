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

//! Kernel keyboard layout front-end.
//!
//! All decoding (tables, modifiers, AltGr, dead keys, UTF-8 output) lives in
//! the shared `strat9-keymap` crate; this module only owns the global decoder
//! instance and the layout switch.

use spin::Mutex;
pub use strat9_keymap::{
    KeyBytes, Layout, KEY_DOWN, KEY_END, KEY_HOME, KEY_LEFT, KEY_RIGHT, KEY_UP,
};
use strat9_keymap::Decoder;

/// Global decoder, shared by the PS/2 IRQ and the USB HID injection path.
static DECODER: Mutex<Decoder> = Mutex::new(Decoder::new(Layout::Azerty));

/// Set the keyboard layout to French AZERTY.
pub fn set_french_layout() {
    DECODER.lock().set_layout(Layout::Azerty);
}

/// Set the keyboard layout to US QWERTY.
pub fn set_us_layout() {
    DECODER.lock().set_layout(Layout::Qwerty);
}

/// Whether the French AZERTY layout is active.
pub fn is_french_layout() -> bool {
    DECODER.lock().layout() == Layout::Azerty
}

/// Read port 0x60 and decode the scancode.
pub fn handle_scancode() -> KeyBytes {
    let scancode = unsafe { super::io::inb(super::keyboard::KEYBOARD_DATA_PORT) };
    handle_scancode_raw(scancode)
}

/// Decode a pre-read scancode byte with the current layout.
pub fn handle_scancode_raw(scancode: u8) -> KeyBytes {
    DECODER.lock().feed(scancode)
}
