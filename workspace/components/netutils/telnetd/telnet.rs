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

//! Telnet protocol (RFC 854/855, ECHO, SGA, NAWS, TTYPE) and a small
//! readline-style line editor (cursor keys, history, Tab completion).

use crate::{
    out::{ColorMode, Out, Style},
    shell, sys,
};
use alloc::{string::String, vec::Vec};

const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;

const OPT_ECHO: u8 = 1;
const OPT_SGA: u8 = 3;
const OPT_TTYPE: u8 = 24;
const OPT_NAWS: u8 = 31;

const TTYPE_IS: u8 = 0;
const TTYPE_SEND: u8 = 1;

/// Options offered to every new client.
const NEGOTIATION: [u8; 15] = [
    IAC, WILL, OPT_ECHO, // we echo
    IAC, WILL, OPT_SGA, // character-at-a-time
    IAC, DO, OPT_SGA, //
    IAC, DO, OPT_NAWS, // window size
    IAC, DO, OPT_TTYPE, // terminal type -> color support
];

/// Detect a freshly accepted connection and send the negotiation if so.
///
/// strate-net only accepts a write once a session exists (`EAGAIN` before),
/// which lets us greet clients that wait for the server to speak first.
pub fn probe_connect(fd: usize) -> bool {
    match strat9_syscall::call::write(fd, &NEGOTIATION) {
        Ok(0) => false,
        Ok(n) => n >= NEGOTIATION.len() || sys::write_all(fd, &NEGOTIATION[n..]),
        Err(_) => false,
    }
}

const HISTORY_MAX: usize = 64;
const LINE_MAX: usize = 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Parser {
    Normal,
    Iac,
    Neg(u8),
    Sb,
    SbIac,
    AfterCr,
    Esc,
    Csi,
    Ss3,
}

/// What the remote terminal told us about itself.
pub struct Term {
    pub name: String,
    pub cols: u16,
    pub rows: u16,
    /// Color mode detected from TERM (before any manual override).
    pub detected: ColorMode,
}

pub struct Session {
    pub connected: bool,
    parser: Parser,
    sb: Vec<u8>,
    csi: Vec<u8>,
    line: Vec<u8>,
    pos: usize,
    history: Vec<Vec<u8>>,
    hist_idx: usize,
    saved_line: Vec<u8>,
    pub term: Term,
    pub cwd: String,
    /// True when the user forced a color mode with the `color` command.
    pub color_forced: bool,
}

/// Decide the color mode from a TERM string.
fn color_from_term(name: &str) -> ColorMode {
    let n = name.to_ascii_lowercase();
    if n.is_empty() {
        return ColorMode::Ansi;
    }
    if n.contains("dumb") || n == "unknown" || n.contains("vt52") || n.contains("network") {
        return ColorMode::None;
    }
    if n.contains("256") || n.contains("truecolor") || n.contains("direct") || n.contains("kitty")
        || n.contains("alacritty") || n.contains("wezterm") || n.contains("foot")
        || n.contains("tmux") || n.contains("screen-256")
    {
        return ColorMode::Xterm256;
    }
    ColorMode::Ansi
}

impl Session {
    pub fn new() -> Self {
        Self {
            connected: false,
            parser: Parser::Normal,
            sb: Vec::new(),
            csi: Vec::new(),
            line: Vec::new(),
            pos: 0,
            history: Vec::new(),
            hist_idx: 0,
            saved_line: Vec::new(),
            term: Term {
                name: String::new(),
                cols: 80,
                rows: 24,
                detected: ColorMode::Ansi,
            },
            cwd: String::from("/"),
            color_forced: false,
        }
    }

    /// Reset everything tied to one connection (including history and cwd).
    pub fn reset(&mut self) {
        self.connected = false;
        self.parser = Parser::Normal;
        self.sb.clear();
        self.csi.clear();
        self.line.clear();
        self.pos = 0;
        self.history.clear();
        self.hist_idx = 0;
        self.saved_line.clear();
        self.term = Term {
            name: String::new(),
            cols: 80,
            rows: 24,
            detected: ColorMode::Ansi,
        };
        self.cwd = String::from("/");
        self.color_forced = false;
    }

    pub fn history(&self) -> impl Iterator<Item = &[u8]> {
        self.history.iter().map(|h| h.as_slice())
    }

    // ── Greeting ───────────────────────────────────────────────────────────

    /// Option negotiation (used when the client spoke before the probe won).
    pub fn send_negotiation(&self, out: &mut Out) {
        out.raw(&NEGOTIATION);
        out.flush();
    }

    pub fn send_banner(&mut self, out: &mut Out) {
        out.style(Style::Accent);
        out.text("\nStrat9-OS telnet shell");
        out.style(Style::Reset);
        out.style(Style::Dim);
        out.text("  (dev/test console)\n");
        out.style(Style::Reset);
        out.text("Type ");
        out.styled(Style::Ok, "help");
        out.text(" for commands. Tab completes, \u{2191}/\u{2193} browse history, Ctrl-C cancels.\n\n");
        self.draw_prompt(out);
        out.flush();
    }

    // ── Prompt / line rendering ────────────────────────────────────────────

    fn draw_prompt(&self, out: &mut Out) {
        out.style(Style::Prompt);
        out.text("strat9");
        out.style(Style::Reset);
        out.text(":");
        out.styled(Style::Path, &self.cwd);
        out.styled(Style::Prompt, "# ");
    }

    /// Redraw prompt + line and put the cursor back at `pos`.
    fn redraw(&self, out: &mut Out) {
        out.raw(b"\r");
        self.draw_prompt(out);
        out.raw(&self.line);
        out.raw(b"\x1b[K");
        let after = chars_in(&self.line[self.pos..]);
        if after > 0 {
            let seq = alloc::format!("\x1b[{}D", after);
            out.raw(seq.as_bytes());
        }
        out.flush();
    }

    fn new_prompt(&mut self, out: &mut Out) {
        self.line.clear();
        self.pos = 0;
        self.draw_prompt(out);
        out.flush();
    }

    // ── Input ──────────────────────────────────────────────────────────────

    /// Feed bytes received from the client. Returns `false` to disconnect.
    pub fn feed(&mut self, out: &mut Out, bytes: &[u8]) -> bool {
        for &b in bytes {
            if !self.feed_byte(out, b) {
                return false;
            }
        }
        self.apply_color(out);
        out.flush();
        true
    }

    fn feed_byte(&mut self, out: &mut Out, b: u8) -> bool {
        match self.parser {
            Parser::Iac => {
                self.parser = match b {
                    WILL | WONT | DO | DONT => Parser::Neg(b),
                    SB => {
                        self.sb.clear();
                        Parser::Sb
                    }
                    IAC => {
                        self.insert(out, IAC);
                        Parser::Normal
                    }
                    _ => Parser::Normal, // NOP, GA, AYT, ... ignored
                };
                return true;
            }
            Parser::Neg(cmd) => {
                self.parser = Parser::Normal;
                self.negotiate(out, cmd, b);
                return true;
            }
            Parser::Sb => {
                if b == IAC {
                    self.parser = Parser::SbIac;
                } else if self.sb.len() < 128 {
                    self.sb.push(b);
                }
                return true;
            }
            Parser::SbIac => {
                if b == SE {
                    self.parser = Parser::Normal;
                    self.subnegotiation();
                } else {
                    if b == IAC && self.sb.len() < 128 {
                        self.sb.push(IAC);
                    }
                    self.parser = Parser::Sb;
                }
                return true;
            }
            Parser::AfterCr => {
                self.parser = Parser::Normal;
                if b == b'\n' || b == 0 {
                    return true; // CR LF / CR NUL: line already submitted
                }
            }
            Parser::Esc => {
                self.parser = match b {
                    b'[' => {
                        self.csi.clear();
                        Parser::Csi
                    }
                    b'O' => Parser::Ss3,
                    _ => Parser::Normal,
                };
                return true;
            }
            Parser::Csi => {
                if (0x40..=0x7e).contains(&b) {
                    self.parser = Parser::Normal;
                    self.csi_key(out, b);
                } else if self.csi.len() < 16 {
                    self.csi.push(b);
                }
                return true;
            }
            Parser::Ss3 => {
                self.parser = Parser::Normal;
                self.csi.clear();
                self.csi_key(out, b);
                return true;
            }
            Parser::Normal => {}
        }

        match b {
            IAC => self.parser = Parser::Iac,
            0x1b => self.parser = Parser::Esc,
            b'\r' => {
                self.parser = Parser::AfterCr;
                return self.submit(out);
            }
            b'\n' => return self.submit(out),
            0x08 | 0x7f => self.backspace(out),
            0x03 => {
                // Ctrl-C: abandon the current line.
                out.styled(Style::Dim, "^C");
                out.text("\n");
                self.new_prompt(out);
            }
            0x04 => {
                // Ctrl-D: EOF on an empty line logs out, otherwise delete.
                if self.line.is_empty() {
                    out.text("logout\n");
                    return false;
                }
                self.delete(out);
            }
            0x01 => {
                self.pos = 0;
                self.redraw(out);
            }
            0x05 => {
                self.pos = self.line.len();
                self.redraw(out);
            }
            0x0b => {
                self.line.truncate(self.pos);
                self.redraw(out);
            }
            0x15 => {
                self.line.drain(..self.pos);
                self.pos = 0;
                self.redraw(out);
            }
            0x17 => self.kill_word(out),
            0x0c => {
                out.raw(b"\x1b[2J\x1b[H");
                self.redraw(out);
            }
            b'\t' => self.tab(out),
            0x20..=0x7e | 0x80..=0xfe => self.insert(out, b),
            _ => {}
        }
        true
    }

    fn negotiate(&mut self, out: &mut Out, cmd: u8, opt: u8) {
        match (cmd, opt) {
            // Replies to our own requests: nothing more to say.
            (DO, OPT_ECHO) | (DO, OPT_SGA) | (WILL, OPT_SGA) | (WILL, OPT_NAWS) => {}
            (DONT, _) | (WONT, _) => {}
            (WILL, OPT_TTYPE) => {
                out.raw(&[IAC, SB, OPT_TTYPE, TTYPE_SEND, IAC, SE]);
                out.flush();
            }
            // Refuse everything else politely.
            (DO, o) => {
                out.raw(&[IAC, WONT, o]);
                out.flush();
            }
            (WILL, o) => {
                out.raw(&[IAC, DONT, o]);
                out.flush();
            }
            _ => {}
        }
    }

    fn subnegotiation(&mut self) {
        match self.sb.first().copied() {
            Some(OPT_NAWS) if self.sb.len() >= 5 => {
                let cols = u16::from_be_bytes([self.sb[1], self.sb[2]]);
                let rows = u16::from_be_bytes([self.sb[3], self.sb[4]]);
                if cols > 0 {
                    self.term.cols = cols;
                }
                if rows > 0 {
                    self.term.rows = rows;
                }
            }
            Some(OPT_TTYPE) if self.sb.len() >= 2 && self.sb[1] == TTYPE_IS => {
                let name = String::from_utf8_lossy(&self.sb[2..]).into_owned();
                self.term.detected = color_from_term(&name);
                self.term.name = name;
            }
            _ => {}
        }
    }

    /// Color mode currently in effect for command output and the prompt.
    pub fn apply_color(&self, out: &mut Out) {
        if !self.color_forced {
            out.color = self.term.detected;
        }
    }

    // ── Line editing ───────────────────────────────────────────────────────

    fn insert(&mut self, out: &mut Out, b: u8) {
        if self.line.len() >= LINE_MAX {
            return;
        }
        self.line.insert(self.pos, b);
        self.pos += 1;
        if self.pos == self.line.len() {
            out.raw(&[b]);
            // Escape a literal 0xFF for the wire.
            if b == IAC {
                out.raw(&[IAC]);
            }
        } else {
            self.redraw(out);
        }
    }

    fn backspace(&mut self, out: &mut Out) {
        if self.pos == 0 {
            return;
        }
        let mut start = self.pos - 1;
        while start > 0 && (self.line[start] & 0xc0) == 0x80 {
            start -= 1;
        }
        self.line.drain(start..self.pos);
        let at_end = start == self.line.len();
        self.pos = start;
        if at_end {
            out.raw(b"\x08 \x08");
        } else {
            self.redraw(out);
        }
    }

    fn delete(&mut self, out: &mut Out) {
        if self.pos >= self.line.len() {
            return;
        }
        let mut end = self.pos + 1;
        while end < self.line.len() && (self.line[end] & 0xc0) == 0x80 {
            end += 1;
        }
        self.line.drain(self.pos..end);
        self.redraw(out);
    }

    fn kill_word(&mut self, out: &mut Out) {
        let mut i = self.pos;
        while i > 0 && self.line[i - 1] == b' ' {
            i -= 1;
        }
        while i > 0 && self.line[i - 1] != b' ' {
            i -= 1;
        }
        self.line.drain(i..self.pos);
        self.pos = i;
        self.redraw(out);
    }

    fn move_left(&mut self, out: &mut Out) {
        if self.pos == 0 {
            return;
        }
        self.pos -= 1;
        while self.pos > 0 && (self.line[self.pos] & 0xc0) == 0x80 {
            self.pos -= 1;
        }
        out.raw(b"\x1b[D");
    }

    fn move_right(&mut self, out: &mut Out) {
        if self.pos >= self.line.len() {
            return;
        }
        self.pos += 1;
        while self.pos < self.line.len() && (self.line[self.pos] & 0xc0) == 0x80 {
            self.pos += 1;
        }
        out.raw(b"\x1b[C");
    }

    fn set_line(&mut self, out: &mut Out, new: Vec<u8>) {
        self.line = new;
        self.pos = self.line.len();
        self.redraw(out);
    }

    fn csi_key(&mut self, out: &mut Out, fin: u8) {
        let param = self.csi.iter().take_while(|c| c.is_ascii_digit()).fold(0u32, |a, &c| {
            a.saturating_mul(10).saturating_add((c - b'0') as u32)
        });
        match fin {
            b'A' => {
                if self.history.is_empty() || self.hist_idx == 0 {
                    return;
                }
                if self.hist_idx == self.history.len() {
                    self.saved_line = self.line.clone();
                }
                self.hist_idx -= 1;
                let h = self.history[self.hist_idx].clone();
                self.set_line(out, h);
            }
            b'B' => {
                if self.hist_idx >= self.history.len() {
                    return;
                }
                self.hist_idx += 1;
                let l = if self.hist_idx == self.history.len() {
                    core::mem::take(&mut self.saved_line)
                } else {
                    self.history[self.hist_idx].clone()
                };
                self.set_line(out, l);
            }
            b'C' => self.move_right(out),
            b'D' => self.move_left(out),
            b'H' => {
                self.pos = 0;
                self.redraw(out);
            }
            b'F' => {
                self.pos = self.line.len();
                self.redraw(out);
            }
            b'~' => match param {
                1 | 7 => {
                    self.pos = 0;
                    self.redraw(out);
                }
                4 | 8 => {
                    self.pos = self.line.len();
                    self.redraw(out);
                }
                3 => self.delete(out),
                _ => {}
            },
            _ => {}
        }
    }

    // ── Tab completion ─────────────────────────────────────────────────────

    fn tab(&mut self, out: &mut Out) {
        let (start, cands) = shell::complete(&self.cwd, &self.line[..self.pos]);
        if cands.is_empty() {
            out.raw(b"\x07");
            return;
        }
        let typed = &self.line[start..self.pos];
        let typed_len = typed.len();
        // Longest common prefix of all candidates.
        let first = cands[0].name.as_bytes();
        let mut common = first.len();
        for c in &cands[1..] {
            let b = c.name.as_bytes();
            let mut i = 0;
            while i < common && i < b.len() && first[i] == b[i] {
                i += 1;
            }
            common = i;
        }
        // Keep UTF-8 boundaries intact.
        while common > 0 && common < first.len() && (first[common] & 0xc0) == 0x80 {
            common -= 1;
        }
        if cands.len() == 1 {
            let c = &cands[0];
            let mut text: Vec<u8> = c.name.as_bytes().to_vec();
            if !c.is_dir {
                text.push(b' ');
            }
            self.replace_tail(out, start, text);
        } else if common > typed_len {
            let text = first[..common].to_vec();
            self.replace_tail(out, start, text);
        } else {
            out.text("\n");
            for c in &cands {
                out.style(if c.is_dir { Style::Dir } else { Style::File });
                out.text(&c.label);
                out.style(Style::Reset);
                out.text("  ");
            }
            out.text("\n");
            self.redraw(out);
        }
    }

    fn replace_tail(&mut self, out: &mut Out, start: usize, text: Vec<u8>) {
        self.line.splice(start..self.pos, text.iter().copied());
        self.pos = start + text.len();
        self.redraw(out);
    }

    // ── Command execution ──────────────────────────────────────────────────

    fn submit(&mut self, out: &mut Out) -> bool {
        out.text("\n");
        let line_bytes = core::mem::take(&mut self.line);
        self.pos = 0;
        let line = String::from_utf8_lossy(&line_bytes).into_owned();
        let trimmed = line.trim();

        if !trimmed.is_empty() {
            if self.history.last().map(|h| h.as_slice()) != Some(trimmed.as_bytes()) {
                if self.history.len() >= HISTORY_MAX {
                    self.history.remove(0);
                }
                self.history.push(trimmed.as_bytes().to_vec());
            }
        }
        self.hist_idx = self.history.len();
        self.saved_line.clear();

        let keep_going = if trimmed.is_empty() {
            true
        } else {
            out.interrupted = false;
            let r = shell::run_line(self, out, trimmed);
            self.apply_color(out);
            r
        };
        out.set_redirect(None);
        if !keep_going {
            out.styled(Style::Dim, "Bye.\n");
            out.flush();
            return false;
        }
        if out.peer_closed {
            return false;
        }
        self.draw_prompt(out);
        out.flush();

        // Replay anything typed while the command was running.
        if !out.pending.is_empty() {
            let pending = core::mem::take(&mut out.pending);
            return self.feed(out, &pending);
        }
        true
    }
}

/// Number of Unicode scalar values (non-continuation bytes) in `b`.
fn chars_in(b: &[u8]) -> usize {
    b.iter().filter(|&&c| (c & 0xc0) != 0x80).count()
}
