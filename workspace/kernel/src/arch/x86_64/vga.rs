//! VGA text mode driver (inspired by MaestroOS `vga.rs`)
//!
//! Provides 80x25 text output with color support.
//! The VGA text buffer is at physical address 0xB8000.
//!
//! NOTE: VGA text mode is NOT available under Limine boot (PIE kernel,
//! 0xB8000 not mapped). When unavailable, all output falls back to serial.

use super::io::{inb, outb};
use core::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};
use spin::Mutex;

/// VGA text mode character type (char byte + attribute byte)
pub type VgaChar = u16;

/// VGA text buffer physical address
pub const BUFFER_PHYS: usize = 0xB8000;

/// Screen width in characters
pub const WIDTH: usize = 80;
/// Screen height in characters
pub const HEIGHT: usize = 25;

/// Whether VGA text mode is available (set during init)
static VGA_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Check if VGA text mode is available
#[inline]
pub fn is_available() -> bool {
    VGA_AVAILABLE.load(Ordering::Relaxed)
}

/// VGA colors
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum Color {
    Black = 0x0,
    Blue = 0x1,
    Green = 0x2,
    Cyan = 0x3,
    Red = 0x4,
    Magenta = 0x5,
    Brown = 0x6,
    LightGrey = 0x7,
    DarkGrey = 0x8,
    LightBlue = 0x9,
    LightGreen = 0xA,
    LightCyan = 0xB,
    LightRed = 0xC,
    LightMagenta = 0xD,
    Yellow = 0xE,
    White = 0xF,
}

/// Create a color attribute byte from foreground and background colors
#[inline]
pub const fn color_entry(fg: Color, bg: Color) -> u8 {
    (bg as u8) << 4 | (fg as u8)
}

/// Default color: light grey on black
pub const DEFAULT_COLOR: u8 = color_entry(Color::LightGrey, Color::Black);

/// VGA text mode writer
pub struct VgaWriter {
    col: usize,
    row: usize,
    color: u8,
}

impl VgaWriter {
    /// Create a new VGA writer
    pub const fn new() -> Self {
        Self {
            col: 0,
            row: 0,
            color: DEFAULT_COLOR,
        }
    }

    /// Get a mutable pointer to the VGA buffer (HHDM-aware)
    #[inline]
    fn buffer(&self) -> *mut VgaChar {
        crate::memory::phys_to_virt(BUFFER_PHYS as u64) as *mut VgaChar
    }

    /// Set the color attribute
    pub fn set_color(&mut self, fg: Color, bg: Color) {
        self.color = color_entry(fg, bg);
    }

    /// Clear the screen
    pub fn clear(&mut self) {
        let blank = (self.color as u16) << 8 | b' ' as u16;
        for i in 0..(WIDTH * HEIGHT) {
            unsafe {
                self.buffer().add(i).write_volatile(blank);
            }
        }
        self.col = 0;
        self.row = 0;
        self.update_cursor();
    }

    /// Write a single character
    pub fn write_char(&mut self, c: u8) {
        match c {
            b'\n' => {
                self.col = 0;
                self.row += 1;
            }
            b'\r' => {
                self.col = 0;
            }
            b'\t' => {
                self.col = (self.col + 8) & !7;
            }
            0x08 => {
                // Backspace
                if self.col > 0 {
                    self.col -= 1;
                    let pos = self.row * WIDTH + self.col;
                    let blank = (self.color as u16) << 8 | b' ' as u16;
                    unsafe {
                        self.buffer().add(pos).write_volatile(blank);
                    }
                }
            }
            c => {
                let pos = self.row * WIDTH + self.col;
                let entry = (self.color as u16) << 8 | c as u16;
                unsafe {
                    self.buffer().add(pos).write_volatile(entry);
                }
                self.col += 1;
            }
        }

        // Line wrap
        if self.col >= WIDTH {
            self.col = 0;
            self.row += 1;
        }

        // Scroll if needed
        if self.row >= HEIGHT {
            self.scroll();
        }

        self.update_cursor();
    }

    /// Write a string
    pub fn write_str(&mut self, s: &str) {
        for byte in s.bytes() {
            self.write_char(byte);
        }
    }

    /// Scroll the screen up by one line
    fn scroll(&mut self) {
        let blank = (self.color as u16) << 8 | b' ' as u16;

        // Move lines up
        for row in 1..HEIGHT {
            for col in 0..WIDTH {
                let src = row * WIDTH + col;
                let dst = (row - 1) * WIDTH + col;
                unsafe {
                    let ch = self.buffer().add(src).read_volatile();
                    self.buffer().add(dst).write_volatile(ch);
                }
            }
        }

        // Clear last line
        for col in 0..WIDTH {
            let pos = (HEIGHT - 1) * WIDTH + col;
            unsafe {
                self.buffer().add(pos).write_volatile(blank);
            }
        }

        self.row = HEIGHT - 1;
    }

    /// Update hardware cursor position
    fn update_cursor(&self) {
        let pos = (self.row * WIDTH + self.col) as u16;
        unsafe {
            outb(0x3D4, 0x0F);
            outb(0x3D5, (pos & 0xFF) as u8);
            outb(0x3D4, 0x0E);
            outb(0x3D5, ((pos >> 8) & 0xFF) as u8);
        }
    }

    /// Enable the hardware cursor
    pub fn enable_cursor(&self) {
        unsafe {
            outb(0x3D4, 0x0A);
            outb(0x3D5, (inb(0x3D5) & 0xC0) | 0);
            outb(0x3D4, 0x0B);
            outb(0x3D5, (inb(0x3D5) & 0xE0) | 15);
        }
    }
}

impl fmt::Write for VgaWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_str(s);
        Ok(())
    }
}

/// Global VGA writer instance
pub static VGA_WRITER: Mutex<VgaWriter> = Mutex::new(VgaWriter::new());

/// Initialize VGA text mode
///
/// Under Limine boot, the VGA text buffer at 0xB8000 is not mapped
/// (PIE kernel = no identity mapping, HHDM may not cover MMIO).
/// In that case, VGA is marked unavailable and all output goes to serial.
pub fn init() {
    // VGA text mode buffer at 0xB8000 is not accessible under Limine boot.
    // The kernel is compiled as PIE (x86_64-unknown-none), so Limine does
    // not identity-map the first 4 GiB, and the HHDM only covers RAM
    // regions from the memory map, not legacy VGA MMIO.
    let hhdm_offset = crate::memory::phys_to_virt(0);
    if hhdm_offset != 0 {
        // Limine boot: VGA text mode unavailable
        log::info!(
            "VGA text mode: unavailable (Limine boot, HHDM=0x{:x})",
            hhdm_offset
        );
        log::info!("All console output routed to serial port");
        VGA_AVAILABLE.store(false, Ordering::Relaxed);
        return;
    }

    // BIOS boot path: identity-mapped, VGA text mode works
    VGA_AVAILABLE.store(true, Ordering::Relaxed);
    let mut writer = VGA_WRITER.lock();
    writer.clear();
    writer.enable_cursor();
    writer.set_color(Color::LightCyan, Color::Black);
    writer.write_str("Strat9-OS v0.1.0\n");
    writer.set_color(Color::LightGrey, Color::Black);
}

/// Print to VGA (falls back to serial if VGA unavailable)
#[macro_export]
macro_rules! vga_print {
    ($($arg:tt)*) => {
        $crate::arch::x86_64::vga::_print(format_args!($($arg)*));
    };
}

/// Print to VGA with newline (falls back to serial if VGA unavailable)
#[macro_export]
macro_rules! vga_println {
    () => ($crate::vga_print!("\n"));
    ($($arg:tt)*) => ($crate::vga_print!("{}\n", format_args!($($arg)*)));
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    if is_available() {
        VGA_WRITER.lock().write_fmt(args).unwrap();
    } else {
        // Fall back to serial
        crate::arch::x86_64::serial::_print(args);
    }
}
