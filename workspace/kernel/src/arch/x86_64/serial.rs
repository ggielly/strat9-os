use core::{
    fmt,
    sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
};
use spin::Mutex;
use uart_16550::SerialPort;

/// Global serial port instance
static SERIAL1: Mutex<SerialPort> = Mutex::new(unsafe { SerialPort::new(0x3F8) });

/// Fixed-size buffer for kernel cmdline (up to 2KB).
/// SAFETY: Written once during early boot (single-threaded, IRQs disabled),
/// then read-only. Safe for concurrent reads after initialization.
static CMDLINE_BUF: [u8; 2048] = [0; 2048];
static CMDLINE_LEN: AtomicUsize = AtomicUsize::new(0);
static CMDLINE_READY: AtomicBool = AtomicBool::new(false);

/// Flag indicating if the kernel is in a panic state.
/// When true, serial output bypasses all locks to ensure messages are displayed.
static PANIC_IN_PROGRESS: AtomicBool = AtomicBool::new(false);
static BOOT_LOG_PREFIX_ENABLED: AtomicBool = AtomicBool::new(false);
static SERIAL_AT_LINE_START: AtomicBool = AtomicBool::new(true);

/// Raw spinlock for `_print_force` to prevent multi-core character interleaving.
/// Uses a ticket-style test-and-set: 0 = free, 1 = locked.
///
/// **Interrupt safety**: `force_lock_acquire` saves and disables IRQs before
/// spinning, and `force_lock_release` restores them. This prevents a nested
/// timer IRQ on the same CPU from trying to acquire `FORCE_LOCK` while it is
/// already held by an outer `serial_force_println!` call, which would deadlock.
static FORCE_LOCK: AtomicU8 = AtomicU8::new(0);

#[inline(always)]
fn force_lock_acquire() -> u64 {
    // Disable IRQs before spinning to prevent a timer IRQ on this CPU from
    // re-entering _print_force while FORCE_LOCK is held (nested IRQ deadlock).
    let saved = crate::arch::x86_64::save_flags_and_cli();
    while FORCE_LOCK
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    saved
}

#[inline(always)]
fn force_lock_release(saved_flags: u64) {
    FORCE_LOCK.store(0, Ordering::Release);
    // Restore RFLAGS (re-enables IRQs if they were enabled before the acquire).
    crate::arch::x86_64::restore_flags(saved_flags);
}

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_VIOLET: &str = "\x1b[35m";
const TOKEN_BUF_CAP: usize = 64;

/// Signal that the kernel has entered an emergency panic state.
pub fn enter_emergency_mode() {
    PANIC_IN_PROGRESS.store(true, Ordering::SeqCst);
}

/// Enable or disable Linux-style boot timestamps at the beginning of each line.
pub fn set_boot_log_prefix_enabled(enabled: bool) {
    BOOT_LOG_PREFIX_ENABLED.store(enabled, Ordering::SeqCst);
    SERIAL_AT_LINE_START.store(true, Ordering::SeqCst);
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

struct BootPrefixWriter<'a, W: fmt::Write> {
    inner: &'a mut W,
    line_start: bool,
    prefix_enabled: bool,
}

impl<'a, W: fmt::Write> BootPrefixWriter<'a, W> {
    fn new(inner: &'a mut W) -> Self {
        Self {
            inner,
            line_start: SERIAL_AT_LINE_START.load(Ordering::Relaxed),
            prefix_enabled: BOOT_LOG_PREFIX_ENABLED.load(Ordering::Relaxed),
        }
    }

    fn write_prefix(&mut self) -> fmt::Result {
        if !self.prefix_enabled {
            return Ok(());
        }
        let elapsed_us = crate::arch::x86_64::boot_timestamp::elapsed_us();
        let secs = elapsed_us / 1_000_000;
        let micros = elapsed_us % 1_000_000;
        write!(self.inner, "[{:>5}.{:06}] ", secs, micros)
    }

    fn finish(&mut self) {
        SERIAL_AT_LINE_START.store(self.line_start, Ordering::Relaxed);
    }
}

impl<W: fmt::Write> fmt::Write for BootPrefixWriter<'_, W> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for ch in s.chars() {
            if self.line_start && ch != '\n' {
                self.write_prefix()?;
                self.line_start = false;
            }
            self.inner.write_char(ch)?;
            if ch == '\n' {
                self.line_start = true;
            }
        }
        Ok(())
    }
}

/// Initialize the serial port
pub fn init() {
    SERIAL1.lock().init();
}

/// Parse kernel cmdline from Limine boot arguments.
///
/// `ptr` is a pointer to a null-terminated C string provided by the bootloader.
/// `len` is the length of the cmdline string (including the null terminator).
///
/// This function:
/// - Stores the cmdline globally for `/proc/cmdline` access.
/// - Detects `console=ttyS0,baud` parameters and logs the configuration.
pub unsafe fn parse_cmdline(ptr: u64, len: u64) {
    if ptr == 0 || len == 0 {
        return;
    }

    // Convert C string to Rust &str and copy into static buffer.
    let cstr = core::ffi::CStr::from_ptr(ptr as *const core::ffi::c_char);
    let cmdline = cstr.to_str().unwrap_or("");

    let copy_len = cmdline.len().min(2047);
    // SAFETY: Single-threaded early boot, IRQs disabled. No concurrent access.
    let buf_ptr = CMDLINE_BUF.as_ptr() as *mut u8;
    core::ptr::copy_nonoverlapping(cmdline.as_ptr(), buf_ptr, copy_len);
    CMDLINE_LEN.store(copy_len, Ordering::Release);
    CMDLINE_READY.store(true, Ordering::Release);

    // Parse console parameters.
    let cmdline_str =
        core::str::from_utf8_unchecked(core::slice::from_raw_parts(buf_ptr, copy_len));

    let mut has_serial_console = false;
    let mut baud: Option<u32> = None;

    let mut pos = 0;
    while pos < cmdline_str.len() {
        while pos < cmdline_str.len() && cmdline_str.as_bytes()[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos >= cmdline_str.len() {
            break;
        }
        let start = pos;
        while pos < cmdline_str.len() && !cmdline_str.as_bytes()[pos].is_ascii_whitespace() {
            pos += 1;
        }
        let token = &cmdline_str[start..pos];

        if let Some(value) = token.strip_prefix("console=") {
            if value.starts_with("ttyS0") {
                has_serial_console = true;
                if let Some((_, baud_str)) = value.split_once(',') {
                    if let Ok(b) = baud_str.parse::<u32>() {
                        baud = Some(b);
                    }
                }
            }
        }
    }

    if has_serial_console {
        if let Some(b) = baud {
            crate::serial_force_println!("[cmdline] console=ttyS0,{}", b);
        } else {
            crate::serial_force_println!("[cmdline] console=ttyS0 (115200 baud)");
        }
    } else {
        crate::serial_force_println!("[cmdline] no serial console detected");
    }
}

/// Returns the stored kernel cmdline for `/proc/cmdline`.
pub fn get_cmdline() -> &'static str {
    if !CMDLINE_READY.load(Ordering::Acquire) {
        return "";
    }
    let len = CMDLINE_LEN.load(Ordering::Acquire);
    // SAFETY: CMDLINE_READY guarantees CMDLINE_BUF has been written.
    unsafe { core::str::from_utf8_unchecked(&CMDLINE_BUF[..len]) }
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
        let mut prefix_writer = BootPrefixWriter::new(&mut *port);
        let mut writer = AnsiStylingWriter::new(&mut prefix_writer);
        let _ = writer.write_fmt(args);
        let _ = writer.finish();
        prefix_writer.finish();
    }
}

/// Print to serial port bypassing the shared mutex.
///
/// Uses a dedicated raw spinlock (with IRQs disabled) so that multiple CPUs
/// cannot interleave their output at the character level, and so that a timer
/// IRQ firing on the same CPU while this function is in progress cannot cause
/// a deadlock by trying to re-acquire `FORCE_LOCK`.
#[doc(hidden)]
pub fn _print_force(args: fmt::Arguments) {
    use core::fmt::Write;

    // Check if we are in emergency panic mode.
    if PANIC_IN_PROGRESS.load(Ordering::Relaxed) {
        // SAFETY: In emergency mode, we bypass the lock to ensure output.
        let mut port = unsafe { SerialPort::new(0x3F8) };
        let _ = port.write_fmt(args);
        return;
    }

    // Acquire the raw force-lock (saves + clears IF, then spins until free).
    let saved_flags = force_lock_acquire();
    // SAFETY: We hold `FORCE_LOCK` with IRQs disabled, giving exclusive UART access.
    let mut port = unsafe { SerialPort::new(0x3F8) };
    let mut prefix_writer = BootPrefixWriter::new(&mut port);
    let _ = prefix_writer.write_fmt(args);
    prefix_writer.finish();
    // Release lock and restore RFLAGS (re-enables IRQs if they were on before).
    force_lock_release(saved_flags);
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

/// Print to serial port with newline, bypassing the shared mutex.
#[macro_export]
macro_rules! serial_force_println {
    () => ($crate::arch::x86_64::serial::_print_force(format_args!("\n")));
    ($($arg:tt)*) => ($crate::arch::x86_64::serial::_print_force(format_args!("{}\n", format_args!($($arg)*))));
}
