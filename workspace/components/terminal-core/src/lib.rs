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

//! Terminal engine extracted from strate-console: text grid, cursor, line
//! editing, scrollback and ANSI dispatch on top of the `vte` parser, plus
//! the shared 8x16 bitmap font. Pure `no_std` + `alloc` with no syscall or
//! renderer dependency, so any console backend can drive a screen through
//! [`TerminalCore`] and the unit tests below run on the host.

#![no_std]

extern crate alloc;

// Host tests only: makes `std` nameable inside `#[cfg(test)]` code.
#[cfg(test)]
extern crate std;

mod ansi;
mod scrollback;
mod terminal;

pub mod font_data;

pub use scrollback::Cell;
pub use terminal::TerminalCore;

#[cfg(test)]
mod tests {
    use super::TerminalCore;

    /// Default colors, matching the strate-console binary.
    const FG: u32 = 0xE2E8F0;
    const BG: u32 = 0x12161E;

    /// TerminalCore embeds a 1000-line scrollback ring (~3 MiB), so building
    /// it needs more stack than the 2 MiB default test-thread stack. Run each
    /// test body on a dedicated big-stack thread and forward its panics.
    fn with_term(cols: usize, rows: usize, f: impl FnOnce(&mut TerminalCore) + Send + 'static) {
        let handle = std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(move || {
                let mut term = TerminalCore::new(cols, rows, FG, BG);
                f(&mut term);
            })
            .expect("spawn test thread");
        if let Err(payload) = handle.join() {
            std::panic::resume_unwind(payload);
        }
    }

    #[test]
    fn init_in_place_matches_new_without_a_big_stack_frame() {
        // Heap-allocate the slot: the point of the in-place constructor is
        // that callers never reserve the ~3 MiB ring on their stack.
        let mut slot = std::boxed::Box::<TerminalCore>::new_uninit();
        // SAFETY: `new_uninit` allocated writable, aligned storage for one
        // `TerminalCore`; `init_in_place` initialises every field.
        let term = unsafe {
            TerminalCore::init_in_place(slot.as_mut_ptr(), 80, 25, FG, BG);
            slot.assume_init()
        };
        assert_eq!(term.cols, 80);
        assert_eq!(term.rows, 25);
        assert_eq!(term.scroll_bottom, 25);
        assert_eq!(term.screen[0][0].ch, b' ' as u32);
        assert_eq!(term.screen[0][0].fg, FG);
        assert_eq!(term.scrollback.len(), 0);
    }

    #[test]
    fn typed_text_appears_at_cursor_and_advances_it() {
        with_term(80, 24, |term| {
            // An empty chunk produces no action and reports no change.
            assert!(!term.process_bytes(b""));
            assert!(term.process_bytes(b"AB"));
            assert_eq!(term.screen[0][0].ch, b'A' as u32);
            assert_eq!(term.screen[0][1].ch, b'B' as u32);
            // Cells carry the default colors until an SGR changes them.
            assert_eq!(term.screen[0][0].fg, FG);
            assert_eq!(term.screen[0][0].bg, BG);
            // Untouched cells stay blank.
            assert_eq!(term.screen[0][2].ch, b' ' as u32);
            assert_eq!(term.cursor_row, 0);
            assert_eq!(term.cursor_col, 2);
        });
    }

    #[test]
    fn newline_scrolls_at_bottom_and_pushes_top_line_into_scrollback() {
        with_term(10, 4, |term| {
            term.process_bytes(b"AAAA\nBBBB\nCCCC\nDDDD");
            assert_eq!(term.cursor_row, 3);
            assert_eq!(term.cursor_col, 4);
            assert!(term.process_bytes(b"\n"));
            // Cursor stays clamped on the last row; every row shifted up.
            assert_eq!(term.cursor_row, 3);
            assert_eq!(term.cursor_col, 0);
            assert_eq!(term.screen[0][0].ch, b'B' as u32);
            assert_eq!(term.screen[1][0].ch, b'C' as u32);
            assert_eq!(term.screen[2][0].ch, b'D' as u32);
            assert_eq!(term.screen[3][0].ch, b' ' as u32);
            // The "AAAA" line left the screen through the scrollback ring.
            assert_eq!(term.scrollback.len(), 1);
            let line = term.scrollback.line_from_end(0);
            assert_eq!(line.len, 10);
            assert_eq!(line.cells[0].ch, b'A' as u32);
            assert_eq!(line.cells[3].ch, b'A' as u32);
            assert_eq!(line.cells[4].ch, b' ' as u32);
        });
    }

    #[test]
    fn sgr_color_changes_fg_and_reset_restores_defaults() {
        with_term(80, 24, |term| {
            assert!(term.process_bytes(b"\x1b[31mX"));
            // SGR 31 is ANSI red: (170, 0, 0) with bold off.
            assert_eq!(term.fg, 0xAA0000);
            assert_eq!(term.screen[0][0].ch, b'X' as u32);
            assert_eq!(term.screen[0][0].fg, 0xAA0000);
            assert_eq!(term.screen[0][0].bg, BG);
            assert!(term.process_bytes(b"\x1b[0mY"));
            assert_eq!(term.fg, FG);
            assert_eq!(term.bg, BG);
            assert!(!term.bold);
            assert!(!term.inverse);
            // Text after the reset uses the default colors again.
            assert_eq!(term.screen[0][1].ch, b'Y' as u32);
            assert_eq!(term.screen[0][1].fg, FG);
        });
    }

    #[test]
    fn carriage_return_moves_cursor_to_column_zero() {
        with_term(80, 24, |term| {
            term.process_bytes(b"ABCD\r");
            assert_eq!(term.cursor_col, 0);
            assert_eq!(term.cursor_row, 0);
            // The next glyph lands at column 0, overwriting 'A'.
            term.process_bytes(b"X");
            assert_eq!(term.screen[0][0].ch, b'X' as u32);
            assert_eq!(term.screen[0][1].ch, b'B' as u32);
            assert_eq!(term.cursor_col, 1);
        });
    }

    #[test]
    fn split_utf8_sequence_decodes_into_one_cell() {
        with_term(80, 24, |term| {
            let bytes = "é".as_bytes(); // U+00E9 = 0xC3 0xA9
            assert_eq!(bytes.len(), 2);
            assert_eq!(bytes[0], 0xC3);
            // The leading byte alone is buffered by the parser: no action.
            assert!(!term.process_bytes(&bytes[..1]));
            assert_eq!(term.cursor_col, 0);
            // The continuation byte completes the scalar into a single cell.
            assert!(term.process_bytes(&bytes[1..]));
            assert_eq!(term.screen[0][0].ch, 0xE9);
            assert_eq!(term.cursor_col, 1);
            assert_eq!(term.screen[0][1].ch, b' ' as u32);
        });
    }

    #[test]
    fn backspace_erases_cell_and_moves_cursor_back() {
        with_term(80, 24, |term| {
            term.process_bytes(b"AB");
            assert_eq!(term.cursor_col, 2);
            assert!(term.process_bytes(b"\x08"));
            assert_eq!(term.cursor_col, 1);
            // 'B' is erased, 'A' survives.
            assert_eq!(term.screen[0][1].ch, b' ' as u32);
            assert_eq!(term.screen[0][0].ch, b'A' as u32);
            // Typing lands on the erased cell.
            term.process_bytes(b"C");
            assert_eq!(term.screen[0][1].ch, b'C' as u32);
            assert_eq!(term.cursor_col, 2);
            // Backspace at column 0 stays put (no reverse line wrap).
            term.process_bytes(b"\r\x08");
            assert_eq!(term.cursor_col, 0);
            assert_eq!(term.cursor_row, 0);
            assert_eq!(term.screen[0][0].ch, b'A' as u32);
        });
    }
}
