//! Scrollback buffer for the framebuffer terminal.
//!
//! Implements a ring-buffer of character cells for scrollback, plus
//! a "current" partial row that accumulates characters before a newline
//! finalises it into the ring.

use alloc::vec::Vec;

/// Maximum number of scrollback lines retained.
pub(crate) const MAX_SCROLLBACK: usize = 500;

/// A single character cell stored in the scrollback buffer.
#[derive(Clone, Copy)]
pub(crate) struct SbCell {
    pub ch: char,
    pub fg: u32, // packed pixel colour
    pub bg: u32, // packed pixel colour
}

/// Ring-buffer scrollback store.
///
/// `rows` holds the completed rows (capped at `MAX_SCROLLBACK + visible_rows`).
/// `cur_row` accumulates the line currently being typed.
/// `row_head` is the ring-buffer insertion index.
pub(crate) struct ScrollbackBuffer {
    /// Completed rows (ring buffer).
    pub rows: Vec<Vec<SbCell>>,
    /// Current (partial) row being accumulated.
    pub cur_row: Vec<SbCell>,
    /// Ring-buffer head index.
    pub row_head: usize,
}

impl ScrollbackBuffer {
    /// Create an empty scrollback.
    pub const fn new() -> Self {
        Self {
            rows: Vec::new(),
            cur_row: Vec::new(),
            row_head: 0,
        }
    }

    /// Maximum number of rows the buffer can hold before trimming.
    #[inline]
    pub fn capacity(&self, visible_rows: usize) -> usize {
        MAX_SCROLLBACK + visible_rows + 1
    }

    /// Access a completed row by logical (oldest→newest) index.
    pub fn row_at(&self, logical_idx: usize) -> Option<&Vec<SbCell>> {
        if logical_idx >= self.rows.len() {
            return None;
        }
        let phys = (self.row_head + logical_idx) % self.rows.len();
        self.rows.get(phys)
    }

    /// Push a completed row into the ring, growing or wrapping as needed.
    pub fn push_row(&mut self, row: Vec<SbCell>, visible_rows: usize) {
        let cap = self.capacity(visible_rows);
        if cap == 0 {
            return;
        }
        if self.rows.len() < cap {
            self.rows.push(row);
            return;
        }
        if self.rows.is_empty() {
            self.rows.push(row);
            self.row_head = 0;
            return;
        }
        self.rows[self.row_head] = row;
        self.row_head = (self.row_head + 1) % self.rows.len();
    }

    /// Trim the buffer so it does not exceed `MAX_SCROLLBACK + visible_rows`.
    #[inline]
    pub fn trim(&mut self, visible_rows: usize) {
        let cap = self.capacity(visible_rows);
        if self.rows.len() <= cap {
            return;
        }
        let remove_count = self.rows.len() - cap;
        self.rows.drain(..remove_count);
        self.row_head = 0;
    }

    /// Mirror a single character into the current (partial) row,
    /// finalising it into the ring when a newline or overflow occurs.
    ///
    /// `cols` = current terminal width in columns.
    /// `fg` / `bg` = packed foreground / background colours for the cell.
    pub fn mirror_char(
        &mut self,
        c: char,
        cols: usize,
        fg: u32,
        bg: u32,
        visible_rows: usize,
    ) {
        match c {
            '\n' => {
                let row = core::mem::take(&mut self.cur_row);
                self.push_row(row, visible_rows);
                self.trim(visible_rows);
            }
            '\r' => {
                self.cur_row.clear();
            }
            '\t' => {
                let stop = (self.cur_row.len() + 4) & !3;
                let end = stop.min(cols);
                while self.cur_row.len() < end {
                    self.cur_row.push(SbCell { ch: ' ', fg, bg });
                }
                if self.cur_row.len() >= cols {
                    let row = core::mem::take(&mut self.cur_row);
                    self.push_row(row, visible_rows);
                    self.trim(visible_rows);
                }
            }
            '\u{8}' => {
                self.cur_row.pop();
            }
            '\0' => {}
            ch => {
                self.cur_row.push(SbCell { ch, fg, bg });
                if self.cur_row.len() >= cols {
                    let row = core::mem::take(&mut self.cur_row);
                    self.push_row(row, visible_rows);
                    self.trim(visible_rows);
                }
            }
        }
    }
}
