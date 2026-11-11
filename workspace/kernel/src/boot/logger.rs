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

use core::sync::atomic::{AtomicBool, Ordering};
use log::{Level, LevelFilter, Metadata, Record};

/// Gate for format_args-heavy logging paths.
///
/// During early boot, `format_args!` involving nested `fmt::Arguments`
/// (e.g. `record.args()` inside another `format_args!`) can resolve to
/// identity-mapped function pointers and #UD.  This flag is set to `true`
/// after `init_cpu_extensions()` enables CR4.OSXSAVE + XCR0, at which
/// point all formatting is safe.
static EXTENSIONS_READY: AtomicBool = AtomicBool::new(false);

/// Simple serial port logger
struct SerialLogger;

static LOGGER: SerialLogger = SerialLogger;

impl log::Log for SerialLogger {
    /// Performs the enabled operation.
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    /// Performs the log operation.
    ///
    /// Architecture (FreeBSD vt(4) / Linux nbcon pattern):
    ///   1. Queue serial output at runtime (synchronous during early boot).
    ///   2. Enqueue a plain-text copy into the lock-free `vgabuf` ring buffer.
    ///      No lock is acquired here : safe from any context (IRQ, panic).
    ///   3. The `console-render` task drains `vgabuf` to the framebuffer
    ///      asynchronously via `vgabuf_flush_to_framebuffer()`.
    ///
    /// This decouples the hot logging path from framebuffer rendering,
    /// making deadlocks structurally impossible.
    fn log(&self, record: &Record) {
        // Gate: skip format_args-heavy paths until SSE/XSAVE are initialized.
        if !EXTENSIONS_READY.load(Ordering::Acquire) {
            return;
        }
        if self.enabled(record.metadata()) {
            // In quiet mode, skip all log output entirely.
            if crate::debug_cfg::is_quiet() {
                return;
            }

            let (level_str, msg_color) = match record.level() {
                Level::Error => ("\x1b[31mERROR\x1b[0m", "\x1b[31m"),
                Level::Warn => ("\x1b[33mWARN\x1b[0m", "\x1b[33m"),
                Level::Info => ("\x1b[32mINFO\x1b[0m", "\x1b[37m"),
                Level::Debug => ("\x1b[90mDEBUG\x1b[0m", "\x1b[90m"),
                Level::Trace => ("\x1b[90mTRACE\x1b[0m", "\x1b[90m"),
            };

            // 1. Serial: bounded, nonblocking enqueue once its worker is running.
            crate::arch::serial::_print(format_args!(
                "[{}] {}{}\x1b[0m\n",
                level_str,
                msg_color,
                record.args()
            ));

            // 1b. Console sink: exactly one of live or buffered, never both.
            //     Live draws directly through the writer (early boot, before
            //     the scheduler / console-render task run); the buffered path
            //     feeds the lock-free vgabuf drained by console-render.
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
                "[{}] {}\n",
                record.level(),
                record.args(),
            );

            let mut live_drawn = false;
            if lpos > 0 && crate::debug_cfg::is_vga_debug_live() {
                if let Ok(line) = core::str::from_utf8(&line_buf[..lpos]) {
                    live_drawn = crate::arch::vga::try_with_writer(|w| {
                        w.write_bytes(line);
                        w.present_if_due(!crate::arch::vgabuf::console_task_active());
                    })
                    .is_some();
                }
            }

            // 2. VGA ring buffer : only when the live draw did not happen.
            //    Controlled by debug_cfg::VGA_DEBUG_BUFFER toggle.
            if !live_drawn
                && lpos > 0
                && crate::debug_cfg::is_vga_debug_buffer()
                && crate::arch::vga::is_available()
            {
                crate::arch::vgabuf::vgabuf_write(&line_buf[..lpos]);
            }
        }
    }

    /// Performs the flush operation.
    fn flush(&self) {}
}

/// Initialize the logger
pub fn init() {
    crate::e9_mark!(b'{');
    log::set_logger(&LOGGER)
        .map(|()| {
            crate::e9_mark!(b'|');
            // Release builds keep Info+ only: driver/scheduler Trace output is
            // thousands of lines per second and starves the console (and the
            // tasks waiting on the serial lock). Debug builds keep everything.
            let level = if cfg!(debug_assertions) {
                LevelFilter::Trace
            } else {
                LevelFilter::Info
            };
            log::set_max_level(level);
            crate::e9_mark!(b'}');
        })
        .expect("Failed to set logger");
    crate::e9_mark!(b'~');
}

/// Mark SSE/XSAVE extensions as ready.
///
/// Called once from `kernel_main` after `init_cpu_extensions()` has set
/// CR4.OSXSAVE and XCR0.  Until this is called, all `log::info!` / etc.
/// fire the `e9_println!("LOG enter")` marker but skip the format_args-heavy
/// formatting paths that can #UD on early boot.
pub fn set_extensions_ready() {
    crate::e9_mark!(b'Z');
    EXTENSIONS_READY.store(true, Ordering::Release);
    crate::e9_mark!(b'z');
}
