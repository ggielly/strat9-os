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

//! Buffered, telnet-safe output with ANSI/256-color styling and `>` redirection.

use crate::sys;
use alloc::vec::Vec;
use core::fmt;
use strat9_syscall::call;

/// How many colors the remote terminal can display.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ColorMode {
    /// Plain text (dumb terminal or user opted out).
    None,
    /// Classic 8/16 ANSI colors.
    Ansi,
    /// xterm 256-color palette.
    Xterm256,
}

/// Semantic styles; mapped to escape sequences according to [`ColorMode`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Style {
    Reset,
    Dir,
    File,
    Link,
    Device,
    Error,
    Ok,
    Warn,
    Dim,
    Prompt,
    Path,
    Accent,
    Head,
}

pub struct Out {
    pub fd: usize,
    buf: Vec<u8>,
    /// Set once a network write failed: commands should stop producing output.
    pub failed: bool,
    pub color: ColorMode,
    /// When set, output goes (raw) to this file fd instead of the socket.
    redirect: Option<usize>,
    /// Raw bytes received from the client while a command was running.
    pub pending: Vec<u8>,
    /// `Ctrl-C` seen while a command was running.
    pub interrupted: bool,
    pub peer_closed: bool,
    poll_tick: u32,
}

impl Out {
    pub fn new(fd: usize) -> Self {
        Self {
            fd,
            buf: Vec::with_capacity(2048),
            failed: false,
            color: ColorMode::Ansi,
            redirect: None,
            pending: Vec::new(),
            interrupted: false,
            peer_closed: false,
            poll_tick: 0,
        }
    }

    pub fn set_redirect(&mut self, fd: Option<usize>) {
        self.flush();
        self.redirect = fd;
    }

    pub fn redirected(&self) -> bool {
        self.redirect.is_some()
    }

    /// True if output should stop (client gone, write failed or Ctrl-C).
    pub fn stop(&mut self) -> bool {
        if self.failed || self.peer_closed {
            return true;
        }
        self.poll_input();
        self.interrupted
    }

    /// Cheaply look for `Ctrl-C` (and stash anything else as type-ahead).
    fn poll_input(&mut self) {
        self.poll_tick = self.poll_tick.wrapping_add(1);
        if self.poll_tick % 8 != 0 {
            return;
        }
        let mut tmp = [0u8; 64];
        match call::read(self.fd, &mut tmp) {
            Ok(0) => self.peer_closed = true,
            Ok(n) => {
                for &b in &tmp[..n] {
                    if b == 0x03 {
                        self.interrupted = true;
                    } else if self.pending.len() < 1024 {
                        self.pending.push(b);
                    }
                }
            }
            Err(_) => {}
        }
    }

    pub fn flush(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let ok = match self.redirect {
            Some(fd) => sys::write_all(fd, &self.buf),
            None => sys::write_all(self.fd, &self.buf),
        };
        if !ok {
            self.failed = true;
        }
        self.buf.clear();
    }

    fn push(&mut self, b: u8) {
        self.buf.push(b);
        if self.buf.len() >= 1536 {
            self.flush();
        }
    }

    /// Terminal text: `\n` becomes CRLF, 0xFF is IAC-escaped.
    pub fn text(&mut self, s: &str) {
        if self.failed {
            return;
        }
        for &b in s.as_bytes() {
            self.byte(b);
        }
    }

    fn byte(&mut self, b: u8) {
        if self.redirect.is_some() {
            self.push(b);
            return;
        }
        match b {
            b'\n' => {
                self.push(b'\r');
                self.push(b'\n');
            }
            255 => {
                self.push(255);
                self.push(255);
            }
            _ => self.push(b),
        }
    }

    /// Raw protocol bytes (telnet commands, escape sequences): no translation.
    pub fn raw(&mut self, bytes: &[u8]) {
        if self.failed {
            return;
        }
        for &b in bytes {
            self.push(b);
        }
    }

    /// File content: control characters (including ESC) are neutralised so a
    /// binary file cannot corrupt the terminal. Redirected output is raw.
    pub fn data(&mut self, bytes: &[u8]) {
        if self.failed {
            return;
        }
        if self.redirect.is_some() {
            for &b in bytes {
                self.push(b);
            }
            return;
        }
        for &b in bytes {
            match b {
                b'\n' | b'\t' | 0x20..=0x7e | 0x80..=0xfe => self.byte(b),
                b'\r' => {}
                _ => self.byte(b'.'),
            }
        }
    }

    pub fn style(&mut self, s: Style) {
        if self.redirect.is_some() || self.color == ColorMode::None {
            return;
        }
        let c256 = self.color == ColorMode::Xterm256;
        let seq: &str = match (s, c256) {
            (Style::Reset, _) => "\x1b[0m",
            (Style::Dir, false) => "\x1b[1;34m",
            (Style::Dir, true) => "\x1b[1;38;5;75m",
            (Style::File, _) => "\x1b[0m",
            (Style::Link, false) => "\x1b[36m",
            (Style::Link, true) => "\x1b[38;5;44m",
            (Style::Device, false) => "\x1b[33m",
            (Style::Device, true) => "\x1b[38;5;215m",
            (Style::Error, false) => "\x1b[1;31m",
            (Style::Error, true) => "\x1b[1;38;5;203m",
            (Style::Ok, false) => "\x1b[32m",
            (Style::Ok, true) => "\x1b[38;5;114m",
            (Style::Warn, false) => "\x1b[33m",
            (Style::Warn, true) => "\x1b[38;5;221m",
            (Style::Dim, false) => "\x1b[2m",
            (Style::Dim, true) => "\x1b[38;5;245m",
            (Style::Prompt, false) => "\x1b[1;32m",
            (Style::Prompt, true) => "\x1b[1;38;5;114m",
            (Style::Path, false) => "\x1b[1;34m",
            (Style::Path, true) => "\x1b[1;38;5;111m",
            (Style::Accent, false) => "\x1b[1;35m",
            (Style::Accent, true) => "\x1b[1;38;5;177m",
            (Style::Head, false) => "\x1b[1;33m",
            (Style::Head, true) => "\x1b[1;38;5;221m",
        };
        self.raw(seq.as_bytes());
    }

    /// Print `s` in style `st`, then reset.
    pub fn styled(&mut self, st: Style, s: &str) {
        self.style(st);
        self.text(s);
        self.style(Style::Reset);
    }

    /// `cmd: detail` error line in red.
    pub fn error(&mut self, cmd: &str, detail: fmt::Arguments<'_>) {
        // Errors always go to the terminal, even under `> file`.
        self.flush();
        let saved = self.redirect.take();
        self.style(Style::Error);
        let _ = fmt::write(self, format_args!("{}: ", cmd));
        let _ = fmt::write(self, detail);
        self.style(Style::Reset);
        self.text("\n");
        self.flush();
        self.redirect = saved;
    }
}

impl fmt::Write for Out {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.text(s);
        Ok(())
    }
}
