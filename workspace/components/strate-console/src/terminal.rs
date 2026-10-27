//! Terminal core: state machine, ANSI dispatch, line editing.

use crate::{
    ansi::{AnsiAction, AnsiParser, EraseMode, SgrParam},
    scrollback::{Cell, CircularBuffer},
};

const MAX_COLS: usize = 256;
const MAX_ROWS: usize = 64;

pub struct TerminalCore {
    pub cols: usize,
    pub rows: usize,
    pub cursor_row: usize,
    pub cursor_col: usize,
    pub scroll_top: usize,
    pub scroll_bottom: usize,
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
    /// Reused action scratch, so a chunk never allocates per byte.
    actions: alloc::vec::Vec<AnsiAction>,
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
            screen: [[blank; MAX_COLS]; MAX_ROWS],
            fg: default_fg,
            bg: default_bg,
            bold: false,
            inverse: false,
            default_fg,
            default_bg,
            scrollback: CircularBuffer::new(cols, default_fg, default_bg),
            ansi: AnsiParser::new(),
            actions: alloc::vec::Vec::new(),
        }
    }

    /// Process a chunk of terminal input (UTF-8 bytes, escape sequences and
    /// C0 controls). Returns true if anything changed on screen.
    ///
    /// `vte` keeps partial UTF-8/escape state across calls, so chunks may be
    /// split anywhere. The action scratch is reused: no per-byte allocation.
    pub fn process_bytes(&mut self, bytes: &[u8]) -> bool {
        self.ansi.feed_into(bytes, &mut self.actions);
        let mut changed = false;
        for i in 0..self.actions.len() {
            let action = self.actions[i];
            changed |= self.handle_action(action);
        }
        changed
    }

    fn handle_char(&mut self, ch: char) -> bool {
        match ch {
            '\n' => {
                self.cursor_col = 0;
                self.advance_row();
                true
            }
            '\r' => {
                self.cursor_col = 0;
                true
            }
            '\t' => {
                self.cursor_col = (self.cursor_col + 8) & !7;
                if self.cursor_col >= self.cols {
                    self.cursor_col = 0;
                    self.advance_row();
                }
                true
            }
            '\u{8}' | '\u{7f}' => {
                if self.cursor_col > 0 {
                    self.cursor_col -= 1;
                    self.set_cell(self.cursor_col, self.cursor_row, ' ');
                }
                true
            }
            '\u{7}' | '\0' => false,
            c if c.is_control() => false,
            c => {
                self.set_cell(self.cursor_col, self.cursor_row, c);
                self.cursor_col += 1;
                if self.cursor_col >= self.cols {
                    self.cursor_col = 0;
                    self.advance_row();
                }
                true
            }
        }
    }

    /// Move to the next line, scrolling the configured region if needed.
    fn advance_row(&mut self) {
        self.cursor_row += 1;
        if self.cursor_row >= self.scroll_bottom {
            self.scroll_up(1);
            self.cursor_row = self.scroll_bottom.saturating_sub(1);
        }
    }

    fn handle_action(&mut self, action: AnsiAction) -> bool {
        match action {
            AnsiAction::CursorUp(n) => {
                self.cursor_row = self.cursor_row.saturating_sub((n as usize).max(1));
            }
            AnsiAction::CursorDown(n) => {
                self.cursor_row = (self.cursor_row + (n as usize).max(1))
                    .min(self.scroll_bottom.saturating_sub(1));
            }
            AnsiAction::CursorForward(n) => {
                self.cursor_col =
                    (self.cursor_col + (n as usize).max(1)).min(self.cols.saturating_sub(1));
            }
            AnsiAction::CursorBack(n) => {
                self.cursor_col = self.cursor_col.saturating_sub((n as usize).max(1));
            }
            AnsiAction::CursorPosition(row, col) => {
                self.cursor_row = (row as usize)
                    .saturating_sub(1)
                    .min(self.rows.saturating_sub(1));
                self.cursor_col = (col as usize)
                    .saturating_sub(1)
                    .min(self.cols.saturating_sub(1));
            }
            AnsiAction::CursorHorizontalAbsolute(col) => {
                self.cursor_col = (col as usize)
                    .saturating_sub(1)
                    .min(self.cols.saturating_sub(1));
            }
            AnsiAction::Print(c) => {
                self.handle_char(c);
            }
            AnsiAction::Execute(b) => {
                self.handle_char(b as char);
            }
            AnsiAction::EraseDisplay(mode) => {
                self.erase_display(mode);
            }
            AnsiAction::EraseLine(mode) => {
                self.erase_line(mode);
            }
            AnsiAction::ScrollUp(n) => {
                self.scroll_up((n as usize).max(1));
            }
            AnsiAction::ScrollDown(n) => {
                self.scroll_down((n as usize).max(1));
            }
            AnsiAction::SetScrollRegion(top, bottom) => {
                self.scroll_top = (top as usize)
                    .saturating_sub(1)
                    .min(self.rows.saturating_sub(1));
                // An omitted bottom parameter (0) means "last row".
                self.scroll_bottom = if bottom == 0 {
                    self.rows
                } else {
                    (bottom as usize).min(self.rows)
                };
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
            SgrParam::DefaultFg => {
                self.fg = self.default_fg;
            }
            SgrParam::DefaultBg => {
                self.bg = self.default_bg;
            }
            _ => {}
        }
    }

    fn set_cell(&mut self, col: usize, row: usize, ch: char) {
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
            self.screen[row][col] = Cell {
                ch: ch as u32,
                fg: bold_color,
                bg,
            };
        }
    }

    /// Scroll the active region up by `n` lines.
    ///
    /// Rows leaving the screen (a region starting at row 0) are appended to
    /// the scrollback. Only the region is shifted; rows above `scroll_top`
    /// and below `scroll_bottom` stay untouched.
    fn scroll_up(&mut self, n: usize) {
        let top = self.scroll_top.min(self.rows.saturating_sub(1));
        let bottom = self.scroll_bottom.min(self.rows);
        if top >= bottom || n == 0 {
            return;
        }
        let blank = Cell::blank(self.default_fg, self.default_bg);
        let width = self.cols.min(MAX_COLS);
        for _ in 0..n.min(bottom - top) {
            if top == 0 {
                let line = self.screen[0];
                self.scrollback.push_line(&line[..width], width);
            }
            self.screen.copy_within((top + 1)..bottom, top);
            self.screen[bottom - 1] = [blank; MAX_COLS];
        }
    }

    /// Insert `n` blank lines at the top of the active region.
    fn scroll_down(&mut self, n: usize) {
        let top = self.scroll_top.min(self.rows.saturating_sub(1));
        let bottom = self.scroll_bottom.min(self.rows);
        if top >= bottom || n == 0 {
            return;
        }
        let blank = Cell::blank(self.default_fg, self.default_bg);
        for _ in 0..n.min(bottom - top) {
            self.screen.copy_within(top..(bottom - 1), top + 1);
            self.screen[top] = [blank; MAX_COLS];
        }
    }

    fn erase_display(&mut self, mode: EraseMode) {
        let row = self.cursor_row.min(self.rows.saturating_sub(1));
        match mode {
            EraseMode::Below => {
                for c in self.cursor_col..self.cols {
                    self.set_cell(c, row, ' ');
                }
                for r in (row + 1)..self.rows {
                    for c in 0..self.cols {
                        self.set_cell(c, r, ' ');
                    }
                }
            }
            EraseMode::Above => {
                for r in 0..row {
                    for c in 0..self.cols {
                        self.set_cell(c, r, ' ');
                    }
                }
                for c in 0..=self.cursor_col.min(self.cols.saturating_sub(1)) {
                    self.set_cell(c, row, ' ');
                }
            }
            EraseMode::All => {
                for r in 0..self.rows {
                    for c in 0..self.cols {
                        self.set_cell(c, r, ' ');
                    }
                }
            }
        }
    }

    fn erase_line(&mut self, mode: EraseMode) {
        let row = self.cursor_row.min(self.rows.saturating_sub(1));
        match mode {
            EraseMode::Below => {
                for c in self.cursor_col..self.cols {
                    self.set_cell(c, row, ' ');
                }
            }
            EraseMode::Above => {
                for c in 0..=self.cursor_col.min(self.cols.saturating_sub(1)) {
                    self.set_cell(c, row, ' ');
                }
            }
            EraseMode::All => {
                for c in 0..self.cols {
                    self.set_cell(c, row, ' ');
                }
            }
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
