//! Keyboard input handler for the console.
//! Reads from /dev/input/kbd, handles line editing in canonical mode.

use strat9_syscall::call;

pub struct InputHandler {
    kbd_fd: usize,
    shift: bool,
    ctrl: bool,
    alt: bool,
    caps_lock: bool,
}

impl InputHandler {
    pub fn open() -> Option<Self> {
        let kbd_fd = call::openat(0, "/dev/input/kbd", 0x1, 0).ok()?;
        Some(InputHandler {
            kbd_fd,
            shift: false,
            ctrl: false,
            alt: false,
            caps_lock: false,
        })
    }

    pub fn read_byte(&mut self) -> Option<u8> {
        let mut buf = [0u8; 1];
        match call::read(self.kbd_fd, &mut buf) {
            Ok(1) => {
                let scancode = buf[0];
                self.process_scancode(scancode)
            }
            _ => None,
        }
    }

    fn process_scancode(&mut self, scancode: u8) -> Option<u8> {
        let pressed = (scancode & 0x80) == 0;
        let code = scancode & 0x7F;

        // 0xE0 prefix marks an extended scancode. The next byte carries
        // the actual code. Extended scancodes (e.g. right Ctrl = 0xE0 0x1D)
        // are handled by treating 0xE0 as a prefix that we skip — the real
        // code follows on the next read.
        if scancode == 0xE0 {
            return None; // Prefix byte, next call has the real code.
        }

        match code {
            0x2A | 0x36 => {
                self.shift = pressed;
                None
            }
            0x1D => {
                self.ctrl = pressed;
                None
            }
            0x38 => {
                self.alt = pressed;
                None
            }
            0x3A => {
                if pressed {
                    self.caps_lock = !self.caps_lock
                };
                None
            }
            _ => {
                if pressed {
                    Some(self.translate_key(code))
                } else {
                    None
                }
            }
        }
    }

    fn translate_key(&self, scancode: u8) -> u8 {
        let base = match scancode {
            0x02 => b'1',
            0x03 => b'2',
            0x04 => b'3',
            0x05 => b'4',
            0x06 => b'5',
            0x07 => b'6',
            0x08 => b'7',
            0x09 => b'8',
            0x0A => b'9',
            0x0B => b'0',
            0x0C => b'-',
            0x0D => b'=',
            0x1A => b'[',
            0x1B => b']',
            0x27 => b';',
            0x28 => b'\'',
            0x29 => b'`',
            0x2B => b'\\',
            0x33 => b',',
            0x34 => b'.',
            0x35 => b'/',
            0x10 => b'q',
            0x11 => b'w',
            0x12 => b'e',
            0x13 => b'r',
            0x14 => b't',
            0x15 => b'y',
            0x16 => b'u',
            0x17 => b'i',
            0x18 => b'o',
            0x19 => b'p',
            0x1E => b'a',
            0x1F => b's',
            0x20 => b'd',
            0x21 => b'f',
            0x22 => b'g',
            0x23 => b'h',
            0x24 => b'j',
            0x25 => b'k',
            0x26 => b'l',
            0x2C => b'z',
            0x2D => b'x',
            0x2E => b'c',
            0x2F => b'v',
            0x30 => b'b',
            0x31 => b'n',
            0x32 => b'm',
            0x39 => b' ',
            0x0E => 0x08,
            0x1C => b'\n',
            0x0F => b'\t',
            0x01 => 0x1B,
            _ => 0,
        };

        if self.ctrl && base >= b'a' && base <= b'z' {
            return base - b'a' + 1;
        }

        if base >= b'a' && base <= b'z' {
            let shifted = base - b'a' + b'A';
            if self.shift ^ self.caps_lock {
                shifted
            } else {
                base
            }
        } else if self.shift {
            match base {
                b'1' => b'!',
                b'2' => b'@',
                b'3' => b'#',
                b'4' => b'$',
                b'5' => b'%',
                b'6' => b'^',
                b'7' => b'&',
                b'8' => b'*',
                b'9' => b'(',
                b'0' => b')',
                b'-' => b'_',
                b'=' => b'+',
                b'[' => b'{',
                b']' => b'}',
                b';' => b':',
                b'\'' => b'"',
                b'`' => b'~',
                b'\\' => b'|',
                b',' => b'<',
                b'.' => b'>',
                b'/' => b'?',
                _ => base,
            }
        } else {
            base
        }
    }
}
