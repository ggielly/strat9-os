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
//! bar simply stops growing at the last completed stage : a zero-cost visual
//! "where did it hang" on hardware with no serial port (the target X13 case).
//!
//! All drawing goes through the guarded VGA primitives, so every call made
//! before the framebuffer console is up : or under `console.mode=serial` : is a
//! silent no-op. No allocation, no locks of our own: safe at any boot stage.

use super::api;
use crate::framebuffer::RgbColor;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Total number of boot milestones. Must match the highest ordinal passed by
/// the call sites in `kernel_main` / `init_apic_subsystem`.
pub const TOTAL: usize = 11;

// Light / pastel palette (the user asked for clair/pastel).
/// Empty part of the track: soft lavender grey.
pub(crate) const TRACK: RgbColor = RgbColor::new(0xDD, 0xDD, 0xEC);
/// Completed part: pastel mint green.
pub(crate) const FILL: RgbColor = RgbColor::new(0xA8, 0xE6, 0xCF);
/// Thin border around the track: muted grey.
pub(crate) const BORDER: RgbColor = RgbColor::new(0xB5, 0xB5, 0xC8);
/// Label text: muted slate on a near-white strip.
pub(crate) const LABEL_FG: RgbColor = RgbColor::new(0x4A, 0x4A, 0x5E);
pub(crate) const LABEL_BG: RgbColor = RgbColor::new(0xF2, 0xF0, 0xF7);

/// Reserved pixel height of the HUD band: label strip + gap + bar + padding.
pub fn band_height(_h: usize, gh: usize) -> usize {
    gh + 4 + gh.max(10) + 6
}

/// Shared HUD geometry: the writer reserves exactly this band and the bar
/// draws into it, so the console text and the bar can never overlap.
pub struct Layout {
    pub band_y: usize,
    pub band_h: usize,
    pub label_y: usize,
    pub bar_x: usize,
    pub bar_y: usize,
    pub bar_w: usize,
    pub bar_h: usize,
}

/// Computes the HUD band layout for a `w`×`h` framebuffer.
pub fn layout(w: usize, h: usize, gh: usize, status_h: usize) -> Layout {
    let band_h = band_height(h, gh);
    let band_y = h.saturating_sub(status_h + band_h);
    let margin = (w / 20).max(8);
    let bar_h = gh.max(10);
    Layout {
        band_y,
        band_h,
        label_y: band_y + 2,
        bar_x: margin,
        bar_y: band_y + 2 + gh + 2,
        bar_w: w.saturating_sub(2 * margin),
        bar_h,
    }
}

// Last rendered milestone, replayed after a full-screen clear.
static HAS_LAST: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static LAST_STEP: AtomicUsize = AtomicUsize::new(0);
static LAST_LABEL: spin::Mutex<([u8; 64], usize)> = spin::Mutex::new(([0u8; 64], 0));

/// Remember the last drawn milestone so `clear_with()` can repaint it.
pub(crate) fn remember(step: usize, label: &str) {
    let bytes = label.as_bytes();
    let mut n = bytes.len().min(64);
    while n > 0 && !label.is_char_boundary(n) {
        n -= 1;
    }
    if let Some(mut guard) = LAST_LABEL.try_lock() {
        guard.0[..n].copy_from_slice(&bytes[..n]);
        guard.1 = n;
    }
    LAST_STEP.store(step, Ordering::Relaxed);
    HAS_LAST.store(true, Ordering::Relaxed);
}

/// Copy the last drawn milestone into `buf` and return it.
pub(crate) fn last_render<'a>(buf: &'a mut [u8; 96]) -> Option<(usize, &'a str)> {
    if !HAS_LAST.load(Ordering::Relaxed) {
        return None;
    }
    let n = {
        let guard = LAST_LABEL.try_lock()?;
        let (bytes, len) = &*guard;
        let n = (*len).min(buf.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        n
    };
    let text = core::str::from_utf8(&buf[..n]).ok()?;
    Some((LAST_STEP.load(Ordering::Relaxed), text))
}

/// Draws the bar at `step`/[`TOTAL`] with a short stage label.
///
/// All drawing happens in a single writer lock (`draw_boot_progress`), so the
/// bar is repainted atomically and never interleaves with console text.
pub fn render(step: usize, label: &str) {
    if !api::is_available() {
        return;
    }
    let step = step.min(TOTAL);
    let _ = api::with_writer(|w| w.draw_boot_progress(step, label));
}

/// Writes `"[step/total] "` into `buf`, returning the number of bytes written.
pub(crate) fn fmt_prefix(buf: &mut [u8], step: usize, total: usize) -> usize {
    let mut len = 0;
    push(buf, &mut len, b'[');
    len = push_usize(buf, len, step);
    push(buf, &mut len, b'/');
    len = push_usize(buf, len, total);
    push(buf, &mut len, b']');
    push(buf, &mut len, b' ');
    len
}

fn push(buf: &mut [u8], len: &mut usize, byte: u8) {
    if *len < buf.len() {
        buf[*len] = byte;
        *len += 1;
    }
}

fn push_usize(buf: &mut [u8], mut len: usize, mut value: usize) -> usize {
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
