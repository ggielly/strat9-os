use core::{fmt, ptr};

#[derive(Clone, Copy)]
#[repr(C)]
pub struct VgaTextBlock {
    pub char: u8,
    pub color: u8,
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum VgaTextColor {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Purple = 5,
    Brown = 6,
    Gray = 7,
    DarkGray = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    LightPurple = 13,
    Yellow = 14,
    White = 15,
}

pub struct Vga {
    pub base: usize,
    pub width: usize,
    pub height: usize,
    pub x: usize,
    pub y: usize,
    pub bg: VgaTextColor,
    pub fg: VgaTextColor,
}

impl Vga {
    pub const fn new(base: usize, width: usize, height: usize) -> Self {
        Self {
            base,
            width,
            height,
            x: 0,
            y: 0,
            bg: VgaTextColor::Black,
            fg: VgaTextColor::Gray,
        }
    }

    #[inline(always)]
    fn color_byte(&self) -> u8 {
        ((self.bg as u8) << 4) | (self.fg as u8)
    }

    #[inline(always)]
    fn is_disabled(&self) -> bool {
        self.width == 0 || self.height == 0
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.width * self.height
    }

    #[inline(always)]
    fn ptr(&self) -> *mut VgaTextBlock {
        self.base as *mut VgaTextBlock
    }

    #[inline(always)]
    unsafe fn write_block(&self, index: usize, value: VgaTextBlock) {
        unsafe { ptr::write_volatile(self.ptr().add(index), value) };
    }

    #[inline(always)]
    unsafe fn read_block(&self, index: usize) -> VgaTextBlock {
        unsafe { ptr::read_volatile(self.ptr().add(index)) }
    }

    fn scroll_up_one(&mut self, blank: VgaTextBlock) {
        let width = self.width;
        let len = self.len();
        let visible_len = len.saturating_sub(width);

        for i in 0..visible_len {
            let src = unsafe { self.read_block(i + width) };
            unsafe { self.write_block(i, src) };
        }

        for i in visible_len..len {
            unsafe { self.write_block(i, blank) };
        }
    }

    pub fn clear(&mut self) {
        if self.is_disabled() {
            self.x = 0;
            self.y = 0;
            return;
        }

        self.x = 0;
        self.y = 0;
        let blank = VgaTextBlock {
            char: b' ',
            color: self.color_byte(),
        };
        for i in 0..self.len() {
            unsafe { self.write_block(i, blank) };
        }
    }
}

impl fmt::Write for Vga {
    fn write_str(&mut self, s: &str) -> Result<(), fmt::Error> {
        if self.is_disabled() {
            return Ok(());
        }

        let color = self.color_byte();
        let blank = VgaTextBlock { char: b' ', color };

        for b in s.bytes() {
            if self.x >= self.width {
                self.x = 0;
                self.y += 1;
            }
            while self.y >= self.height {
                self.scroll_up_one(blank);
                self.y -= 1;
            }
            match b {
                b'\x08' => {
                    if self.x > 0 {
                        self.x -= 1;
                    }
                }
                b'\r' => {
                    self.x = 0;
                }
                b'\n' => {
                    self.x = 0;
                    self.y += 1;
                }
                _ => {
                    let i = self.y * self.width + self.x;
                    let char = if b.is_ascii() { b } else { b'?' };
                    unsafe { self.write_block(i, VgaTextBlock { char, color }) };
                    self.x += 1;
                }
            }
        }

        Ok(())
    }
}
