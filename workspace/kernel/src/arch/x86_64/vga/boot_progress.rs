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

//! Pastel boot-progress bar drawn along the bottom of the framebuffer.
//!
//! Each boot milestone calls [`render`] with its ordinal; the bar fills
//! proportionally and shows the current stage label. If the boot freezes, the
//! bar simply stops growing at the last completed stage — a zero-cost visual
//! "where did it hang" on hardware with no serial port (the target X13 case).
//!
//! All drawing goes through the guarded VGA primitives, so every call made
//! before the framebuffer console is up — or under `console.mode=serial` — is a
//! silent no-op. No allocation, no locks of our own: safe at any boot stage.

use super::api;
use crate::framebuffer::RgbColor;

/// Total number of boot milestones. Must match the highest ordinal passed by
/// the call sites in `kernel_main` / `init_apic_subsystem`.
pub const TOTAL: usize = 11;

// Light / pastel palette (the user asked for clair/pastel).
/// Empty part of the track: soft lavender grey.
const TRACK: RgbColor = RgbColor::new(0xDD, 0xDD, 0xEC);
/// Completed part: pastel mint green.
const FILL: RgbColor = RgbColor::new(0xA8, 0xE6, 0xCF);
/// Thin border around the track: muted grey.
const BORDER: RgbColor = RgbColor::new(0xB5, 0xB5, 0xC8);
/// Label text: muted slate on a near-white strip.
const LABEL_FG: RgbColor = RgbColor::new(0x4A, 0x4A, 0x5E);
const LABEL_BG: RgbColor = RgbColor::new(0xF2, 0xF0, 0xF7);

/// Draws the bar at `step`/[`TOTAL`] with a short stage label.
///
/// Redraws the whole widget each call, so console scrolling between milestones
/// never leaves it half-erased: at any milestone the bar is clean, and on a
/// freeze the last rendered state persists.
pub fn render(step: usize, label: &str) {
    if !api::is_available() {
        return;
    }
    let screen_w = api::width();
    let screen_h = api::height();
    if screen_w == 0 || screen_h == 0 {
        return;
    }
    let step = step.min(TOTAL);

    // Geometry: a wide bar sitting a little above the bottom edge.
    let margin = (screen_w / 20).max(8);
    let bar_w = screen_w.saturating_sub(margin * 2);
    if bar_w == 0 {
        return;
    }
    let bar_h = (screen_h / 50).max(10);
    let bar_x = margin;
    let bar_y = screen_h.saturating_sub(bar_h + screen_h / 16);

    // Label strip above the bar, cleared first so a shorter label cannot leave
    // tail characters from a previous, longer one.
    let (_, glyph_h) = api::glyph_size();
    let glyph_h = if glyph_h == 0 { 16 } else { glyph_h };
    let label_y = bar_y.saturating_sub(glyph_h + 4);
    api::fill_rect(bar_x, label_y, bar_w, glyph_h, LABEL_BG);

    // Build "[step/TOTAL] label" without allocation.
    let mut buf = [0u8; 64];
    let mut len = fmt_prefix(&mut buf, step, TOTAL);
    for &byte in label.as_bytes() {
        if len >= buf.len() {
            break;
        }
        buf[len] = byte;
        len += 1;
    }
    if let Ok(text) = core::str::from_utf8(&buf[..len]) {
        api::draw_text_at(bar_x, label_y, text, LABEL_FG, LABEL_BG);
    }

    // Track, filled portion, border.
    api::fill_rect(bar_x, bar_y, bar_w, bar_h, TRACK);
    let fill_w = bar_w.saturating_mul(step) / TOTAL;
    if fill_w > 0 {
        api::fill_rect(bar_x, bar_y, fill_w, bar_h, FILL);
    }
    api::draw_rect(bar_x, bar_y, bar_w, bar_h, BORDER);
}

/// Writes `"[step/total] "` into `buf`, returning the number of bytes written.
fn fmt_prefix(buf: &mut [u8; 64], step: usize, total: usize) -> usize {
    let mut len = 0;
    push(buf, &mut len, b'[');
    len = push_usize(buf, len, step);
    push(buf, &mut len, b'/');
    len = push_usize(buf, len, total);
    push(buf, &mut len, b']');
    push(buf, &mut len, b' ');
    len
}

fn push(buf: &mut [u8; 64], len: &mut usize, byte: u8) {
    if *len < buf.len() {
        buf[*len] = byte;
        *len += 1;
    }
}

fn push_usize(buf: &mut [u8; 64], mut len: usize, mut value: usize) -> usize {
    let mut digits = [0u8; 20];
    let mut count = 0;
    if value == 0 {
        digits[count] = b'0';
        count += 1;
    } else {
        while value > 0 {
            digits[count] = b'0' + (value % 10) as u8;
            value /= 10;
            count += 1;
        }
    }
    while count > 0 {
        count -= 1;
        push(buf, &mut len, digits[count]);
    }
    len
}
