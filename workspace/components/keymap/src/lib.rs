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

//! Shared keyboard decoding for strat9-os.
//!
//! One implementation used by the kernel console, the `strate-input` server
//! and the userspace console: PS/2 scancode set 1 in, UTF-8 bytes out.
//!
//! * ASCII keys and the special keys `KEY_*` (0xF8..=0xFD, invalid in UTF-8)
//!   yield one byte.
//! * Accented characters yield their UTF-8 encoding.
//! * French layout: accents, `AltGr` symbols and the `^` / `¨` dead keys.
//! * `Ctrl` + letter yields the matching control code (Ctrl+C = 0x03).

#![cfg_attr(not(test), no_std)]

pub mod hid;
mod tables;

use tables::{AZERTY_NORMAL, AZERTY_SHIFT, QWERTY_NORMAL, QWERTY_SHIFT};

// Special keys are in-band single bytes. They use 0xF8..=0xFD, which never
// occurs in valid UTF-8, so they cannot be confused with the continuation or
// lead bytes of accented characters (e.g. `À` = C3 80).
pub const KEY_UP: u8 = 0xF8;
pub const KEY_DOWN: u8 = 0xF9;
pub const KEY_LEFT: u8 = 0xFA;
pub const KEY_RIGHT: u8 = 0xFB;
pub const KEY_HOME: u8 = 0xFC;
pub const KEY_END: u8 = 0xFD;

/// Keyboard layout.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Layout {
    /// French AZERTY (PC 105 keys).
    Azerty,
    /// US QWERTY.
    Qwerty,
}

/// Bytes produced by one scancode (UTF-8, at most 8 bytes).
#[derive(Clone, Copy, Debug)]
pub struct KeyBytes {
    buf: [u8; 8],
    len: u8,
}

impl KeyBytes {
    pub const fn none() -> Self {
        Self {
            buf: [0; 8],
            len: 0,
        }
    }

    fn push_str(&mut self, s: &str) {
        for &b in s.as_bytes() {
            if (self.len as usize) < self.buf.len() {
                self.buf[self.len as usize] = b;
                self.len += 1;
            }
        }
    }

    fn from_str(s: &str) -> Self {
        let mut k = Self::none();
        k.push_str(s);
        k
    }

    fn from_byte(b: u8) -> Self {
        let mut k = Self::none();
        k.buf[0] = b;
        k.len = 1;
        k
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Non-ASCII / AltGr keys of the French PC layout.
fn french_special(sc: u8, shift: bool, altgr: bool, caps: bool) -> Option<&'static str> {
    if altgr {
        return match sc {
            0x03 => Some("~"),
            0x04 => Some("#"),
            0x05 => Some("{"),
            0x06 => Some("["),
            0x07 => Some("|"),
            0x08 => Some("`"),
            0x09 => Some("\\"),
            0x0A => Some("^"),
            0x0B => Some("@"),
            0x0C => Some("]"),
            0x0D => Some("}"),
            0x12 => Some("€"),
            _ => None,
        };
    }
    if shift {
        return match sc {
            0x0C => Some("°"),
            0x1B => Some("£"),
            0x2B => Some("µ"),
            0x35 => Some("§"),
            _ => None,
        };
    }
    match sc {
        0x03 => Some(if caps { "É" } else { "é" }),
        0x08 => Some(if caps { "È" } else { "è" }),
        0x0A => Some(if caps { "Ç" } else { "ç" }),
        0x0B => Some(if caps { "À" } else { "à" }),
        0x28 => Some(if caps { "Ù" } else { "ù" }),
        0x29 => Some("²"),
        _ => None,
    }
}

/// Compose a dead key (`b'^'` circumflex, `b'"'` diaeresis) with a base letter.
fn compose_dead(dead: u8, base: u8) -> Option<&'static str> {
    Some(match (dead, base) {
        (b'^', b'a') => "â",
        (b'^', b'e') => "ê",
        (b'^', b'i') => "î",
        (b'^', b'o') => "ô",
        (b'^', b'u') => "û",
        (b'^', b'A') => "Â",
        (b'^', b'E') => "Ê",
        (b'^', b'I') => "Î",
        (b'^', b'O') => "Ô",
        (b'^', b'U') => "Û",
        (b'"', b'a') => "ä",
        (b'"', b'e') => "ë",
        (b'"', b'i') => "ï",
        (b'"', b'o') => "ö",
        (b'"', b'u') => "ü",
        (b'"', b'y') => "ÿ",
        (b'"', b'A') => "Ä",
        (b'"', b'E') => "Ë",
        (b'"', b'I') => "Ï",
        (b'"', b'O') => "Ö",
        (b'"', b'U') => "Ü",
        _ => return None,
    })
}

fn dead_char(dead: u8) -> &'static str {
    if dead == b'^' {
        "^"
    } else {
        "¨"
    }
}

/// Stateful scancode decoder (modifiers, 0xE0 prefix, dead key).
///
/// State persists across calls, so a scancode burst can be split anywhere.
pub struct Decoder {
    layout: Layout,
    left_shift: bool,
    right_shift: bool,
    caps_lock: bool,
    ctrl: bool,
    alt: bool,
    altgr: bool,
    extended: bool,
    /// Pending dead key: `b'^'` (circumflex), `b'"'` (diaeresis) or 0.
    dead: u8,
}

impl Decoder {
    pub const fn new(layout: Layout) -> Self {
        Self {
            layout,
            left_shift: false,
            right_shift: false,
            caps_lock: false,
            ctrl: false,
            alt: false,
            altgr: false,
            extended: false,
            dead: 0,
        }
    }

    pub fn layout(&self) -> Layout {
        self.layout
    }

    pub fn set_layout(&mut self, layout: Layout) {
        self.layout = layout;
        self.dead = 0;
    }

    pub fn shift_active(&self) -> bool {
        self.left_shift || self.right_shift
    }

    pub fn ctrl_active(&self) -> bool {
        self.ctrl
    }

    pub fn alt_active(&self) -> bool {
        self.alt
    }

    /// Feed one raw set-1 scancode byte and return the bytes it produces.
    pub fn feed(&mut self, scancode: u8) -> KeyBytes {
        if scancode == 0xE0 {
            self.extended = true;
            return KeyBytes::none();
        }
        let extended = self.extended;
        self.extended = false;

        let pressed = scancode & 0x80 == 0;
        let code = scancode & 0x7F;

        // Modifiers (press and release).
        match code {
            0x2A if !extended => {
                self.left_shift = pressed;
                return KeyBytes::none();
            }
            0x36 if !extended => {
                self.right_shift = pressed;
                return KeyBytes::none();
            }
            0x1D => {
                self.ctrl = pressed;
                return KeyBytes::none();
            }
            0x38 if extended => {
                self.altgr = pressed;
                return KeyBytes::none();
            }
            0x38 => {
                self.alt = pressed;
                return KeyBytes::none();
            }
            0x3A if !extended => {
                if pressed {
                    self.caps_lock = !self.caps_lock;
                }
                return KeyBytes::none();
            }
            _ => {}
        }
        if !pressed {
            return KeyBytes::none();
        }

        if extended {
            return match code {
                0x48 => KeyBytes::from_byte(KEY_UP),
                0x50 => KeyBytes::from_byte(KEY_DOWN),
                0x4B => KeyBytes::from_byte(KEY_LEFT),
                0x4D => KeyBytes::from_byte(KEY_RIGHT),
                0x47 => KeyBytes::from_byte(KEY_HOME),
                0x4F => KeyBytes::from_byte(KEY_END),
                0x53 => KeyBytes::from_byte(0x7F),
                0x1C => KeyBytes::from_byte(b'\n'), // keypad Enter
                0x35 => KeyBytes::from_byte(b'/'),  // keypad /
                _ => KeyBytes::none(),
            };
        }

        self.translate(code)
    }

    fn translate(&mut self, code: u8) -> KeyBytes {
        let shift = self.shift_active();
        let french = self.layout == Layout::Azerty;

        if french {
            // Dead keys: ^ (plain) and ¨ (shifted) on scancode 0x1A.
            if code == 0x1A && !self.altgr {
                let accent = if shift { b'"' } else { b'^' };
                if self.dead == accent {
                    self.dead = 0;
                    return KeyBytes::from_str(dead_char(accent));
                }
                let mut out = KeyBytes::none();
                if self.dead != 0 {
                    out.push_str(dead_char(self.dead));
                }
                self.dead = accent;
                return out;
            }

            if let Some(s) = french_special(code, shift, self.altgr, self.caps_lock && !shift) {
                let mut out = KeyBytes::none();
                if self.dead != 0 {
                    out.push_str(dead_char(self.dead));
                    self.dead = 0;
                }
                out.push_str(s);
                return out;
            }
        }

        let (normal, shifted) = if french {
            (&AZERTY_NORMAL, &AZERTY_SHIFT)
        } else {
            (&QWERTY_NORMAL, &QWERTY_SHIFT)
        };
        let mut ch = if shift {
            shifted[code as usize]
        } else {
            normal[code as usize]
        };
        if ch == 0 {
            return KeyBytes::none();
        }
        if self.caps_lock && ch.is_ascii_alphabetic() {
            ch = if shift {
                ch.to_ascii_lowercase()
            } else {
                ch.to_ascii_uppercase()
            };
        }
        if self.ctrl && ch.is_ascii_alphabetic() {
            self.dead = 0;
            return KeyBytes::from_byte(ch & 0x1F);
        }

        if self.dead != 0 {
            let dead = self.dead;
            self.dead = 0;
            if let Some(s) = compose_dead(dead, ch) {
                return KeyBytes::from_str(s);
            }
            let mut out = KeyBytes::from_str(dead_char(dead));
            if ch != b' ' {
                out.push_str(core::str::from_utf8(&[ch]).unwrap_or(""));
            }
            return out;
        }
        KeyBytes::from_byte(ch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Press then release each key; return everything typed as a string.
    fn type_keys(d: &mut Decoder, codes: &[u8]) -> String {
        let mut bytes = Vec::new();
        for &c in codes {
            bytes.extend_from_slice(d.feed(c).as_bytes());
            bytes.extend_from_slice(d.feed(c | 0x80).as_bytes());
        }
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn azerty_reported_bugs() {
        let mut d = Decoder::new(Layout::Azerty);
        assert_eq!(type_keys(&mut d, &[0x0D, 0x34, 0x35]), "=:!");
        d.feed(0x2A);
        assert_eq!(type_keys(&mut d, &[0x0C, 0x0D, 0x34, 0x35]), "°+/§");
        d.feed(0xAA);
    }

    #[test]
    fn azerty_accents_and_caps() {
        let mut d = Decoder::new(Layout::Azerty);
        assert_eq!(
            type_keys(&mut d, &[0x03, 0x08, 0x0A, 0x0B, 0x28, 0x29]),
            "éèçàù²"
        );
        d.feed(0x3A);
        d.feed(0xBA);
        assert_eq!(type_keys(&mut d, &[0x03]), "É");
    }

    #[test]
    fn altgr() {
        let mut d = Decoder::new(Layout::Azerty);
        d.feed(0xE0);
        d.feed(0x38);
        assert_eq!(type_keys(&mut d, &[0x0B, 0x05, 0x06, 0x07, 0x12]), "@{[|€");
        d.feed(0xE0);
        d.feed(0xB8);
        assert_eq!(type_keys(&mut d, &[0x0B]), "à");
    }

    #[test]
    fn dead_keys() {
        let mut d = Decoder::new(Layout::Azerty);
        assert_eq!(type_keys(&mut d, &[0x1A, 0x12]), "ê");
        assert_eq!(type_keys(&mut d, &[0x1A, 0x1A]), "^");
        assert_eq!(type_keys(&mut d, &[0x1A, 0x39]), "^ ".trim_end_matches(' '));
        assert_eq!(type_keys(&mut d, &[0x1A, 0x31]), "^n");
        d.feed(0x2A);
        assert_eq!(type_keys(&mut d, &[0x1A]), "");
        d.feed(0xAA);
        assert_eq!(type_keys(&mut d, &[0x18]), "ö");
    }

    #[test]
    fn ctrl_c_and_arrows() {
        let mut d = Decoder::new(Layout::Azerty);
        d.feed(0x1D);
        assert_eq!(d.feed(0x2E).as_bytes(), &[0x03]);
        d.feed(0x9D);
        d.feed(0xE0);
        assert_eq!(d.feed(0x4B).as_bytes(), &[KEY_LEFT]);
    }

    #[test]
    fn hid_letters_match_set1() {
        let mut d = Decoder::new(Layout::Azerty);
        let (_, a) = hid::usage_to_set1(0x14).unwrap(); // HID Q
        assert_eq!(type_keys(&mut d, &[a]), "a"); // AZERTY: Q-position key is `a`
        let (ext, left) = hid::usage_to_set1(0x50).unwrap();
        assert!(ext);
        d.feed(0xE0);
        assert_eq!(d.feed(left).as_bytes(), &[KEY_LEFT]);
    }

    #[test]
    fn qwerty_basics() {
        let mut d = Decoder::new(Layout::Qwerty);
        assert_eq!(type_keys(&mut d, &[0x1E, 0x0D]), "a=");
    }

    #[test]
    fn special_keys_are_not_valid_utf8_bytes() {
        for k in [KEY_UP, KEY_DOWN, KEY_LEFT, KEY_RIGHT, KEY_HOME, KEY_END] {
            assert!(k >= 0xF8);
        }
        let mut d = Decoder::new(Layout::Azerty);
        d.feed(0x2A);
        // Shift+ç etc. never yields a special-key byte; À = C3 80 must survive.
        d.feed(0xAA);
        d.feed(0x3A);
        assert_eq!(type_keys(&mut d, &[0x0B]), "À");
    }
}
