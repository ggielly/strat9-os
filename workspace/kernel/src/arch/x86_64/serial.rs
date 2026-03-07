use core::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};
use spin::Mutex;
use uart_16550::SerialPort;

/// Global serial port instance
static SERIAL1: Mutex<SerialPort> = Mutex::new(unsafe { SerialPort::new(0x3F8) });

/// Flag indicating if the kernel is in a panic state.
/// When true, serial output bypasses all locks to ensure messages are displayed.
static PANIC_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_VIOLET: &str = "\x1b[35m";
const TOKEN_BUF_CAP: usize = 64;

/// Signal that the kernel has entered an emergency panic state.
pub fn enter_emergency_mode() {
    PANIC_IN_PROGRESS.store(true, Ordering::SeqCst);
}

/// Returns whether token char.
#[inline]
fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Returns whether hex word.
#[inline]
fn is_hex_word(s: &str) -> bool {
    if s.len() <= 2 {
        return false;
    }
    let bytes = s.as_bytes();
    if bytes[0] != b'0' || (bytes[1] != b'x' && bytes[1] != b'X') {
        return false;
    }
    bytes[2..].iter().all(|b| b.is_ascii_hexdigit())
}

struct AnsiStylingWriter<'a, W: fmt::Write> {
    inner: &'a mut W,
    in_escape: bool,
    token_buf: [u8; TOKEN_BUF_CAP],
    token_len: usize,
    token_passthrough: bool,
}

impl<'a, W: fmt::Write> AnsiStylingWriter<'a, W> {
    /// Creates a new instance.
    fn new(inner: &'a mut W) -> Self {
        Self {
            inner,
            in_escape: false,
            token_buf: [0u8; TOKEN_BUF_CAP],
            token_len: 0,
            token_passthrough: false,
        }
    }

    /// Performs the flush token operation.
    fn flush_token(&mut self) -> fmt::Result {
        if self.token_len == 0 {
            return Ok(());
        }
        let token = unsafe { core::str::from_utf8_unchecked(&self.token_buf[..self.token_len]) };
        if token == "PASS" {
            self.inner.write_str(ANSI_GREEN)?;
            self.inner.write_str(token)?;
            self.inner.write_str(ANSI_RESET)?;
        } else if token == "FAIL" {
            self.inner.write_str(ANSI_RED)?;
            self.inner.write_str(token)?;
            self.inner.write_str(ANSI_RESET)?;
        } else if is_hex_word(token) {
            self.inner.write_str(ANSI_VIOLET)?;
            self.inner.write_str(token)?;
            self.inner.write_str(ANSI_RESET)?;
        } else {
            self.inner.write_str(token)?;
        }
        self.token_len = 0;
        Ok(())
    }

    /// Writes byte raw.
    fn write_byte_raw(&mut self, b: u8) -> fmt::Result {
        self.inner.write_char(b as char)
    }

    /// Performs the finish operation.
    fn finish(&mut self) -> fmt::Result {
        self.flush_token()
    }
}

impl<W: fmt::Write> fmt::Write for AnsiStylingWriter<'_, W> {
    /// Writes str.
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if self.in_escape {
                self.write_byte_raw(b)?;
                if (b as char).is_ascii_alphabetic() {
                    self.in_escape = false;
                }
                continue;
            }

            if b == 0x1b {
                self.flush_token()?;
                self.token_passthrough = false;
                self.in_escape = true;
                self.write_byte_raw(b)?;
                continue;
            }

            if is_token_char(b) {
                if self.token_passthrough {
                    self.write_byte_raw(b)?;
                    continue;
                }
                if self.token_len < TOKEN_BUF_CAP {
                    self.token_buf[self.token_len] = b;
                    self.token_len += 1;
                } else {
                    self.flush_token()?;
                    self.token_passthrough = true;
                    self.write_byte_raw(b)?;
                }
            } else {
                self.flush_token()?;
                self.token_passthrough = false;
                self.write_byte_raw(b)?;
            }
        }
        Ok(())
    }
}

/// Initialize the serial port
pub fn init() {
    SERIAL1.lock().init();
}

/// Print to serial port
#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;

    // Check if we are in emergency panic mode.
    if PANIC_IN_PROGRESS.load(Ordering::Relaxed) {
        // SAFETY: In emergency mode, we bypass the mutex to ensure output.
        // We re-initialize a local SerialPort instance pointing to the same IO port.
        let mut port = unsafe { SerialPort::new(0x3F8) };
        // We don't use AnsiStylingWriter here to minimize risk of further panics/complex logic.
        let _ = port.write_fmt(args);
        return;
    }

    // Normal mode: Use try_lock to avoid deadlock in interrupt handlers.
    if let Some(mut port) = SERIAL1.try_lock() {
        let mut writer = AnsiStylingWriter::new(&mut *port);
        let _ = writer.write_fmt(args);
        let _ = writer.finish();
    }
}

/// Print to serial port
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::arch::x86_64::serial::_print(format_args!($($arg)*))
    };
}

/// Print to serial port with newline
#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => ($crate::serial_print!("{}\n", format_args!($($arg)*)));
}
