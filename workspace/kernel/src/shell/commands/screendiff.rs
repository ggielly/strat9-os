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

//! Line diff for the interactive DOS console.
//!
//! `vm dos console` reprints only what changed on the guest screen. A naive
//! line-by-line comparison is wrong as soon as the guest scrolls: the DOS
//! prompt sits on the last row, so pressing Enter scrolls the whole screen up
//! by one line, every line index shifts and the diff would report the entire
//! screen as changed — the console then reprints everything and appears to
//! scroll backwards.
//!
//! This module recognises the scroll first: if the new screen is the previous
//! one shifted up by `k` lines, only the `k` new bottom lines are returned.
//! Other changes fall back to a positional diff. It is pure (`alloc` only) so
//! the host tests can drive it without a guest.

use alloc::{string::{String, ToString}, vec::Vec};

/// Lines of `text` with trailing blanks removed.
///
/// The guest VGA text is padded to the screen width; the padding is noise for
/// comparison and must not count as a change.
fn screen_lines(text: &str) -> Vec<&str> {
    text.lines().map(|line| line.trim_end()).collect()
}

/// Lines that have to be printed after `previous` to show `current`.
///
/// Returns the new bottom lines when the guest scrolled, otherwise the lines
/// that changed in place (plus any line appended past the previous screen).
/// Empty lines are never returned: printing them only adds visual noise, and
/// the caller's terminal scrolls by itself.
pub fn changed_lines(previous: &str, current: &str) -> Vec<String> {
    let previous = screen_lines(previous);
    let current = screen_lines(current);
    if previous.is_empty() {
        return current
            .iter()
            .filter(|line| !line.is_empty())
            .map(|line| (*line).to_string())
            .collect();
    }
    // Scroll detection. When the guest scrolls up by `k` lines, the old screen
    // from row `k` becomes the new screen from row 0, and the last `k` rows are
    // new. `k == previous.len()` would mean "nothing survived", which is not a
    // scroll but a full repaint, so it is left to the positional diff.
    let max_shift = previous.len().min(current.len());
    for shift in (1..max_shift).rev() {
        let kept = previous.len() - shift;
        if kept <= current.len() && previous[shift..] == current[..kept] {
            // A scroll was recognised: the survivors are already on the
            // operator's terminal, so nothing is reprinted even when the new
            // bottom lines are blank.
            return current[kept..]
                .iter()
                .filter(|line| !line.is_empty())
                .map(|line| (*line).to_string())
                .collect();
        }
    }
    // Positional diff: the screen changed in place (a field updated, a line
    // erased and rewritten) without moving.
    let mut changed = Vec::new();
    for (index, line) in current.iter().enumerate() {
        let old = previous.get(index).copied().unwrap_or("");
        if old != *line && !line.is_empty() {
            changed.push((*line).to_string());
        }
    }
    changed
}
