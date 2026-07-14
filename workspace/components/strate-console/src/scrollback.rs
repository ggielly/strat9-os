//! Circular scrollback buffer for terminal output.
//! Fixed-size, no heap reallocation. Inspired by MaestroOS.

/// A single line in the scrollback buffer.
#[derive(Clone, Copy)]
pub struct ScrollLine {
    pub cells: [Cell; MAX_COLS],
    pub len: usize,
}

#[derive(Clone, Copy)]
pub struct Cell {
    pub ch: u8,
    pub fg: u32,
    pub bg: u32,
}

impl Cell {
    pub const fn blank(fg: u32, bg: u32) -> Self {
        Cell { ch: b' ', fg, bg }
    }
}

const MAX_COLS: usize = 256;
const SCROLLBACK_LINES: usize = 1000;

pub struct CircularBuffer {
    lines: [ScrollLine; SCROLLBACK_LINES],
    head: usize,
    count: usize,
    pub cols: usize,
    pub default_fg: u32,
    pub default_bg: u32,
}

impl CircularBuffer {
    pub fn new(cols: usize, fg: u32, bg: u32) -> Self {
        let blank = Cell::blank(fg, bg);
        let line = ScrollLine {
            cells: [blank; MAX_COLS],
            len: 0,
        };
        CircularBuffer {
            lines: [line; SCROLLBACK_LINES],
            head: 0,
            count: 0,
            cols,
            default_fg: fg,
            default_bg: bg,
        }
    }

    /// Push a completed line into the ring buffer.
    pub fn push_line(&mut self, cells: &[Cell], len: usize) {
        let idx = (self.head + self.count) % SCROLLBACK_LINES;
        if self.count < SCROLLBACK_LINES {
            self.count += 1;
        } else {
            self.head = (self.head + 1) % SCROLLBACK_LINES;
        }
        let line = &mut self.lines[idx];
        let copy_len = len.min(MAX_COLS);
        line.cells[..copy_len].copy_from_slice(&cells[..copy_len]);
        line.len = copy_len;
    }

    /// Get line at virtual index (0 = oldest, count-1 = newest).
    pub fn get(&self, index: usize) -> Option<&ScrollLine> {
        if index >= self.count {
            return None;
        }
        let real = (self.head + index) % SCROLLBACK_LINES;
        Some(&self.lines[real])
    }

    pub fn line_count(&self) -> usize {
        self.count
    }
}