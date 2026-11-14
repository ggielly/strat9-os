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

//! USB HID keyboard usage -> PS/2 scancode set 1.
//!
//! Lets the USB keyboard driver feed the same [`crate::Decoder`] as the PS/2
//! path, so both produce identical text for a given layout.

/// One set-1 key: `(extended, code)`. `extended` means an `0xE0` prefix.
pub type Set1Key = (bool, u8);

/// HID modifier-byte bits -> set-1 key (LCtrl, LShift, LAlt, LGUI, RCtrl, RShift, RAlt, RGUI).
pub const HID_MODIFIERS: [(u8, Option<Set1Key>); 8] = [
    (0x01, Some((false, 0x1D))),
    (0x02, Some((false, 0x2A))),
    (0x04, Some((false, 0x38))),
    (0x08, None),
    (0x10, Some((true, 0x1D))),
    (0x20, Some((false, 0x36))),
    (0x40, Some((true, 0x38))), // AltGr
    (0x80, None),
];

/// Convert a HID keyboard usage (page 0x07) to a set-1 key.
pub fn usage_to_set1(usage: u8) -> Option<Set1Key> {
    const LETTERS: [u8; 26] = [
        0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18,
        0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C,
    ];
    const KEYPAD_DIGITS: [u8; 9] = [0x4F, 0x50, 0x51, 0x4B, 0x4C, 0x4D, 0x47, 0x48, 0x49];
    Some(match usage {
        0x04..=0x1D => (false, LETTERS[(usage - 0x04) as usize]),
        0x1E..=0x27 => (false, 0x02 + (usage - 0x1E)), // 1..9, 0
        0x28 => (false, 0x1C),
        0x29 => (false, 0x01),
        0x2A => (false, 0x0E),
        0x2B => (false, 0x0F),
        0x2C => (false, 0x39),
        0x2D => (false, 0x0C),
        0x2E => (false, 0x0D),
        0x2F => (false, 0x1A),
        0x30 => (false, 0x1B),
        0x31 | 0x32 => (false, 0x2B),
        0x33 => (false, 0x27),
        0x34 => (false, 0x28),
        0x35 => (false, 0x29),
        0x36 => (false, 0x33),
        0x37 => (false, 0x34),
        0x38 => (false, 0x35),
        0x39 => (false, 0x3A),
        0x3A..=0x43 => (false, 0x3B + (usage - 0x3A)), // F1..F10
        0x44 => (false, 0x57),
        0x45 => (false, 0x58),
        0x49 => (true, 0x52),
        0x4A => (true, 0x47),
        0x4B => (true, 0x49),
        0x4C => (true, 0x53),
        0x4D => (true, 0x4F),
        0x4E => (true, 0x51),
        0x4F => (true, 0x4D),
        0x50 => (true, 0x4B),
        0x51 => (true, 0x50),
        0x52 => (true, 0x48),
        0x54 => (true, 0x35),
        0x55 => (false, 0x37),
        0x56 => (false, 0x4A),
        0x57 => (false, 0x4E),
        0x58 => (true, 0x1C),
        0x59..=0x61 => (false, KEYPAD_DIGITS[(usage - 0x59) as usize]),
        0x62 => (false, 0x52),
        0x63 => (false, 0x53),
        0x64 => (false, 0x56), // ISO key between left Shift and W (`<`)
        _ => return None,
    })
}
