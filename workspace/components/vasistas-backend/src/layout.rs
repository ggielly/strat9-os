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

//! Damage-rectangle placement: surface-local to screen-space translation.
//!
//! The core hands the backend surface-local damage rects plus the surface's
//! screen origin. [`clip_to_screen`] translates one rect and clips it to the
//! screen, so a surface larger than its tile (or than the screen) only paints
//! the visible part.

use vasistas_protocol::Rect;

/// Translate `rect` from surface space to screen space and clip it to the screen.
///
/// Returns the screen-space rectangle, or `None` when the result is empty
/// (fully off-screen or an empty input rect). All arithmetic is done in `i64`,
/// so coordinates near `u32::MAX` cannot overflow; the returned `x`/`y` are
/// clamped into `i32` by saturating casts.
pub fn clip_to_screen(
    rect: Rect,
    origin_x: u32,
    origin_y: u32,
    screen_w: u32,
    screen_h: u32,
) -> Option<Rect> {
    if rect.w == 0 || rect.h == 0 {
        return None;
    }
    let x0 = origin_x as i64 + rect.x as i64;
    let y0 = origin_y as i64 + rect.y as i64;
    let x1 = x0 + rect.w as i64;
    let y1 = y0 + rect.h as i64;
    let left = x0.max(0);
    let top = y0.max(0);
    let right = x1.min(screen_w as i64);
    let bottom = y1.min(screen_h as i64);
    if right <= left || bottom <= top {
        return None;
    }
    Some(Rect {
        x: left as i32,
        y: top as i32,
        w: (right - left) as u32,
        h: (bottom - top) as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(x: i32, y: i32, w: u32, h: u32) -> Rect {
        Rect { x, y, w, h }
    }

    const SCREEN_W: u32 = 1600;
    const SCREEN_H: u32 = 600;

    #[test]
    fn rect_inside_the_screen_is_only_translated() {
        assert_eq!(
            clip_to_screen(rect(0, 0, 400, 300), 400, 300, SCREEN_W, SCREEN_H),
            Some(rect(400, 300, 400, 300))
        );
        assert_eq!(
            clip_to_screen(rect(10, 20, 30, 40), 1200, 0, SCREEN_W, SCREEN_H),
            Some(rect(1210, 20, 30, 40))
        );
    }

    #[test]
    fn rect_on_a_screen_edge_is_clipped() {
        // Right edge: surface origin 1200, the surface is 800 wide, the screen
        // ends at 1600.
        assert_eq!(
            clip_to_screen(rect(0, 0, 800, 300), 1200, 0, SCREEN_W, SCREEN_H),
            Some(rect(1200, 0, 400, 300))
        );
        // Bottom edge: origin y 300, the surface is 600 high, the screen ends
        // at 600.
        assert_eq!(
            clip_to_screen(rect(0, 0, 100, 600), 0, 300, SCREEN_W, SCREEN_H),
            Some(rect(0, 300, 100, 300))
        );
        // Both edges at once.
        assert_eq!(
            clip_to_screen(rect(390, 290, 100, 100), 1200, 300, SCREEN_W, SCREEN_H),
            Some(rect(1590, 590, 10, 10))
        );
    }

    #[test]
    fn rect_fully_off_screen_is_dropped() {
        assert_eq!(
            clip_to_screen(rect(0, 0, 10, 10), 1600, 0, SCREEN_W, SCREEN_H),
            None
        );
        assert_eq!(
            clip_to_screen(rect(0, 0, 10, 10), 0, 600, SCREEN_W, SCREEN_H),
            None
        );
        assert_eq!(
            clip_to_screen(rect(0, 0, 10, 10), u32::MAX, u32::MAX, SCREEN_W, SCREEN_H),
            None
        );
        // Empty input rect.
        assert_eq!(clip_to_screen(rect(0, 0, 0, 10), 0, 0, SCREEN_W, SCREEN_H), None);
        assert_eq!(clip_to_screen(rect(0, 0, 10, 0), 0, 0, SCREEN_W, SCREEN_H), None);
        // Zero-sized screen.
        assert_eq!(clip_to_screen(rect(0, 0, 10, 10), 0, 0, 0, 0), None);
    }

    #[test]
    fn negative_surface_rect_yields_only_the_visible_part() {
        assert_eq!(
            clip_to_screen(rect(-10, -10, 20, 20), 0, 0, SCREEN_W, SCREEN_H),
            Some(rect(0, 0, 10, 10))
        );
    }

    #[test]
    fn extreme_coordinates_do_not_panic() {
        for (rect, origin) in [
            (rect(i32::MAX, i32::MAX, u32::MAX, u32::MAX), (0, 0)),
            (rect(i32::MIN, i32::MIN, u32::MAX, u32::MAX), (u32::MAX, u32::MAX)),
            (rect(0, 0, u32::MAX, u32::MAX), (u32::MAX, u32::MAX)),
            (rect(i32::MAX, 0, 1, 1), (u32::MAX, 0)),
        ] {
            let _ = clip_to_screen(rect, origin.0, origin.1, SCREEN_W, SCREEN_H);
        }
    }
}
