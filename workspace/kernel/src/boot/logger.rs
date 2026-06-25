use log::{Level, LevelFilter, Metadata, Record};

/// Simple serial port logger
struct SerialLogger;

static LOGGER: SerialLogger = SerialLogger;

impl log::Log for SerialLogger {
    /// Performs the enabled operation.
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Trace
    }

    /// Performs the log operation.
    ///
    /// Architecture (FreeBSD vt(4) / Linux nbcon pattern):
    ///   1. Always write to serial (fast, always works).
    ///   2. Enqueue a plain-text copy into the lock-free `vgabuf` ring buffer.
    ///      No lock is acquired here : safe from any context (IRQ, panic).
    ///   3. The `status_line_task` drains `vgabuf` to the framebuffer
    ///      asynchronously via `vgabuf_flush_to_framebuffer()`.
    ///
    /// This decouples the hot logging path from framebuffer rendering,
    /// making deadlocks structurally impossible.
    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let (level_str, msg_color) = match record.level() {
                Level::Error => ("\x1b[31mERROR\x1b[0m", "\x1b[31m"),
                Level::Warn => ("\x1b[33mWARN\x1b[0m", "\x1b[33m"),
                Level::Info => ("\x1b[32mINFO\x1b[0m", "\x1b[37m"),
                Level::Debug => ("\x1b[90mDEBUG\x1b[0m", "\x1b[90m"),
                Level::Trace => ("\x1b[90mTRACE\x1b[0m", "\x1b[90m"),
            };

            // 1. Serial : always works, no locks needed.
            crate::arch::x86_64::serial::_print(format_args!(
                "[{}] {}{}\x1b[0m\n",
                level_str,
                msg_color,
                record.args()
            ));

            // 1b. Live VGA debug (early boot): write directly to framebuffer
            //     via vga_debug_write.  This bypasses VGA_WRITER and works
            //     before the scheduler / status_line_task are running.
            //     Controlled by debug_cfg::VGA_DEBUG_LIVE toggle.
            if crate::debug_cfg::is_vga_debug_live() && crate::arch::x86_64::vga::is_available() {
                let mut line_buf = [0u8; 256];
                let mut lpos = 0usize;
                use core::fmt::Write;
                struct LineWriter<'a> {
                    buf: &'a mut [u8],
                    pos: &'a mut usize,
                }
                impl Write for LineWriter<'_> {
                    fn write_str(&mut self, s: &str) -> core::fmt::Result {
                        let bytes = s.as_bytes();
                        let remaining = self.buf.len().saturating_sub(*self.pos);
                        let n = bytes.len().min(remaining);
                        self.buf[*self.pos..*self.pos + n].copy_from_slice(&bytes[..n]);
                        *self.pos += n;
                        Ok(())
                    }
                }
                let _ = write!(
                    LineWriter {
                        buf: &mut line_buf,
                        pos: &mut lpos
                    },
                    "[{}] {}",
                    record.level(),
                    record.args(),
                );
                if lpos > 0 {
                    if let Ok(s) = core::str::from_utf8(&line_buf[..lpos]) {
                        crate::arch::x86_64::vga::vga_debug_writeln(s);
                    }
                }
            }

            // 2. VGA ring buffer : lock-free enqueue.
            //    Controlled by debug_cfg::VGA_DEBUG_BUFFER toggle.
            if crate::debug_cfg::is_vga_debug_buffer() && crate::arch::x86_64::vga::is_available() {
                let mut vbuf = [0u8; crate::arch::x86_64::vgabuf::VGABUF_LINE_LEN];
                let mut vpos = 0usize;
                use core::fmt::Write;
                struct VgaBufWriter<'a> {
                    buf: &'a mut [u8],
                    pos: &'a mut usize,
                }
                impl Write for VgaBufWriter<'_> {
                    fn write_str(&mut self, s: &str) -> core::fmt::Result {
                        let bytes = s.as_bytes();
                        let remaining = self.buf.len().saturating_sub(*self.pos);
                        let n = bytes.len().min(remaining);
                        self.buf[*self.pos..*self.pos + n].copy_from_slice(&bytes[..n]);
                        *self.pos += n;
                        Ok(())
                    }
                }
                let _ = write!(
                    VgaBufWriter {
                        buf: &mut vbuf,
                        pos: &mut vpos
                    },
                    "[{}] {}\n",
                    record.level(),
                    record.args(),
                );
                if vpos > 0 {
                    crate::arch::x86_64::vgabuf::vgabuf_write(&vbuf[..vpos]);
                }
            }
        }
    }

    /// Performs the flush operation.
    fn flush(&self) {}
}

/// Initialize the logger
pub fn init() {
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(LevelFilter::Trace))
        .expect("Failed to set logger");
}
