//! Terminal core: state machine, ANSI dispatch, line editing.

use crate::{
    ansi::{AnsiAction, AnsiParser, EraseMode, SgrParam},
    scrollback::{Cell, CircularBuffer},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalMode {
    Raw,
    Canonical,
}

const MAX_COLS: usize = 256;
const MAX_ROWS: usize = 64;

pub struct TerminalCore {
    pub cols: usize,
    pub rows: usize,
    pub cursor_row: usize,
    pub cursor_col: usize,
    pub scroll_top: usize,
    pub scroll_bottom: usize,
    /// Current editing line buffer.
    pub line_cells: [Cell; MAX_COLS],
    pub line_len: usize,
    /// Visible screen buffer: all rows rendered on screen.
    pub screen: [[Cell; MAX_COLS]; MAX_ROWS],
    pub fg: u32,
    pub bg: u32,
    pub bold: bool,
    pub inverse: bool,
    pub default_fg: u32,
    pub default_bg: u32,
    pub scrollback: CircularBuffer,
    ansi: AnsiParser,
    esc_buf: [u8; 32],
    esc_len: usize,
    in_esc: bool,
    pub mode: TerminalMode,
    pub line_buf: [u8; 256],
    pub line_pos: usize,
}

impl TerminalCore {
    pub fn new(cols: usize, rows: usize, default_fg: u32, default_bg: u32) -> Self {
        let blank = Cell::blank(default_fg, default_bg);
        TerminalCore {
            cols,
            rows,
            cursor_row: 0,
            cursor_col: 0,
            scroll_top: 0,
            scroll_bottom: rows,
            line_cells: [blank; MAX_COLS],
            line_len: 0,
            screen: [[blank; MAX_COLS]; MAX_ROWS],
            fg: default_fg,
            bg: default_bg,
            bold: false,
            inverse: false,
            default_fg,
            default_bg,
            scrollback: CircularBuffer::new(cols, default_fg, default_bg),
            ansi: AnsiParser::new(),
            esc_buf: [0u8; 32],
            esc_len: 0,
            in_esc: false,
            mode: TerminalMode::Canonical,
            line_buf: [0u8; 256],
            line_pos: 0,
        }
    }

    pub fn process_byte(&mut self, byte: u8) -> bool {
        if byte == 0x1B {
            self.in_esc = true;
            self.esc_len = 0;
            return false;
        }
        if self.in_esc {
            self.esc_buf[self.esc_len] = byte;
            self.esc_len += 1;
            if let Some(action) = self.ansi.feed(byte) {
                self.in_esc = false;
                self.esc_len = 0;
                return self.handle_action(action);
            }
            return false;
        }
        self.handle_char(byte)
    }

    fn handle_char(&mut self, byte: u8) -> bool {
        match byte {
            b'\n' => {
                self.flush_line();
                self.cursor_row += 1;
                if self.cursor_row >= self.scroll_bottom {
                    self.scroll_up();
                    self.cursor_row = self.scroll_bottom - 1;
                }
                true
            }
            b'\r' => {
                self.cursor_col = 0;
                true
            }
            b'\t' => {
                self.cursor_col = (self.cursor_col + 8) & !7;
                if self.cursor_col >= self.cols {
                    self.cursor_col = 0;
                    self.cursor_row += 1;
                    if self.cursor_row >= self.scroll_bottom {
                        self.scroll_up();
                        self.cursor_row = self.scroll_bottom - 1;
                    }
                }
                true
            }
            0x08 | 0x7F => {
                if self.cursor_col > 0 {
                    self.cursor_col -= 1;
                    self.set_cell(self.cursor_col, self.cursor_row, b' ');
                }
                true
            }
            0x07 | 0x00 => false,
            ch @ 0x20..=0x7E => {
                self.set_cell(self.cursor_col, self.cursor_row, ch);
                self.cursor_col += 1;
                if self.cursor_col >= self.cols {
                    self.cursor_col = 0;
                    self.cursor_row += 1;
                    if self.cursor_row >= self.scroll_bottom {
                        self.scroll_up();
                        self.cursor_row = self.scroll_bottom - 1;
                    }
                }
                true
            }
            _ => false,
        }
    }

    fn handle_action(&mut self, action: AnsiAction) -> bool {
        match action {
            AnsiAction::CursorUp(n) => {
                self.cursor_row = self.cursor_row.saturating_sub(n as usize);
            }
            AnsiAction::CursorDown(n) => {
                self.cursor_row = (self.cursor_row + n as usize).min(self.scroll_bottom - 1);
            }
            AnsiAction::CursorForward(n) => {
                self.cursor_col = (self.cursor_col + n as usize).min(self.cols - 1);
            }
            AnsiAction::CursorBack(n) => {
                self.cursor_col = self.cursor_col.saturating_sub(n as usize);
            }
            AnsiAction::CursorPosition(row, col) => {
                self.cursor_row = (row as usize - 1).min(self.rows - 1);
                self.cursor_col = (col as usize - 1).min(self.cols - 1);
            }
            AnsiAction::CursorHorizontalAbsolute(col) => {
                self.cursor_col = (col as usize - 1).min(self.cols - 1);
            }
            AnsiAction::EraseDisplay(mode) => {
                self.erase_display(mode);
            }
            AnsiAction::EraseLine(mode) => {
                self.erase_line(mode);
            }
            AnsiAction::ScrollUp(n) => {
                for _ in 0..n {
                    self.scroll_up();
                }
            }
            AnsiAction::ScrollDown(n) => {
                for _ in 0..n {
                    self.scroll_down();
                }
            }
            AnsiAction::SetScrollRegion(top, bottom) => {
                self.scroll_top = (top as usize - 1).min(self.rows - 1);
                self.scroll_bottom = (bottom as usize).min(self.rows);
                if self.scroll_top >= self.scroll_bottom {
                    self.scroll_top = 0;
                    self.scroll_bottom = self.rows;
                }
                self.cursor_row = self.scroll_top;
                self.cursor_col = 0;
            }
            AnsiAction::Sgr(param) => {
                self.apply_sgr(param);
            }
            _ => {}
        }
        true
    }

    fn apply_sgr(&mut self, param: SgrParam) {
        match param {
            SgrParam::Reset => {
                self.fg = self.default_fg;
                self.bg = self.default_bg;
                self.bold = false;
                self.inverse = false;
            }
            SgrParam::Bold(b) => self.bold = b,
            SgrParam::Inverse(b) => self.inverse = b,
            SgrParam::FgColor(c) => {
                self.fg = ansi_color_to_rgb(c, true, self.bold);
            }
            SgrParam::BgColor(c) => {
                self.bg = ansi_color_to_rgb(c, false, false);
            }
            SgrParam::FgRgb(r, g, b) => {
                self.fg = ((r as u32) << 16) | ((g as u32) << 8) | b as u32;
            }
            SgrParam::BgRgb(r, g, b) => {
                self.bg = ((r as u32) << 16) | ((g as u32) << 8) | b as u32;
            }
            SgrParam::DefaultColor => {
                self.fg = self.default_fg;
                self.bg = self.default_bg;
            }
            _ => {}
        }
    }

    fn set_cell(&mut self, col: usize, row: usize, ch: u8) {
        if col < self.cols && row < self.rows {
            let (fg, bg) = if self.inverse {
                (self.bg, self.fg)
            } else {
                (self.fg, self.bg)
            };
            let bold_color = if self.bold && fg == self.default_fg {
                brighten(fg)
            } else {
                fg
            };
            let cell = Cell {
                ch,
                fg: bold_color,
                bg,
            };
            self.line_cells[col] = cell;
            self.screen[row][col] = cell;
            self.line_len = self.line_len.max(col + 1);
        }
    }

    fn flush_line(&mut self) {
        // Copy the completed line into the screen buffer.
        for col in 0..self.line_len.min(MAX_COLS).min(self.cols) {
            if self.cursor_row < self.rows {
                // If cursor_row is at the bottom, scroll first.
                if self.cursor_row >= self.screen.len() {
                    self.scroll_screen_up();
                }
                self.screen[self.cursor_row.min(self.rows - 1)][col] = self.line_cells[col];
            }
        }
        // Clear the current editing line for the next input line.
        self.scrollback
            .push_line(&self.line_cells[..self.line_len], self.line_len);
        let blank = Cell::blank(self.default_fg, self.default_bg);
        self.line_cells = [blank; MAX_COLS];
        self.line_len = 0;
    }

    fn scroll_screen_up(&mut self) {
        // Shift all screen rows up by one, losing the top row.
        for r in 1..self.rows.min(MAX_ROWS) {
            self.screen[r - 1] = self.screen[r];
        }
        // Clear the last row.
        let blank = Cell::blank(self.default_fg, self.default_bg);
        if self.rows > 0 {
            self.screen[self.rows - 1] = [blank; MAX_COLS];
        }
    }

    fn scroll_up(&mut self) {
        self.flush_line();
        self.scrollback.push_line(&[], 0);
    }

    fn scroll_down(&mut self) {}

    fn erase_display(&mut self, mode: EraseMode) {
        match mode {
            EraseMode::Below => {
                for c in self.cursor_col..self.cols {
                    self.set_cell(c, self.cursor_row, b' ');
                }
            }
            EraseMode::All => {
                for c in 0..self.cols {
                    self.set_cell(c, self.cursor_row, b' ');
                }
            }
            _ => {}
        }
    }

    fn erase_line(&mut self, mode: EraseMode) {
        match mode {
            EraseMode::Below => {
                for c in self.cursor_col..self.cols {
                    self.set_cell(c, self.cursor_row, b' ');
                }
            }
            EraseMode::Above => {
                for c in 0..self.cursor_col {
                    self.set_cell(c, self.cursor_row, b' ');
                }
            }
            EraseMode::All => {
                for c in 0..self.cols {
                    self.set_cell(c, self.cursor_row, b' ');
                }
            }
            _ => {}
        }
    }
}

fn ansi_color_to_rgb(c: u8, _is_fg: bool, bright: bool) -> u32 {
    let base = match c {
        0 => (0, 0, 0),
        1 => (170, 0, 0),
        2 => (0, 170, 0),
        3 => (170, 85, 0),
        4 => (0, 0, 170),
        5 => (170, 0, 170),
        6 => (0, 170, 170),
        7 => (170, 170, 170),
        _ => (170, 170, 170),
    };
    if bright {
        // Bright variant: 255 instead of 170 for all channels.
        let brightened = (base.0 + 85, base.1 + 85, base.2 + 85);
        ((brightened.0 as u32).min(255) << 16)
            | ((brightened.1 as u32).min(255) << 8)
            | brightened.2 as u32
    } else {
        ((base.0 as u32) << 16) | ((base.1 as u32) << 8) | base.2 as u32
    }
}

fn brighten(color: u32) -> u32 {
    let r = ((color >> 16) & 0xFF).min(255) as u32;
    let g = ((color >> 8) & 0xFF).min(255) as u32;
    let b = (color & 0xFF).min(255) as u32;
    ((r + 85).min(255) << 16) | ((g + 85).min(255) << 8) | (b + 85).min(255)
}
