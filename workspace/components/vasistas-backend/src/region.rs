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

//! Occlusion regions: fixed-capacity sets of disjoint damage rectangles.
//!
//! The compositor needs to answer one question per frame: *what part of this
//! window is still visible after the higher layers painted?* Photon answers it
//! with a `PhRegion_t` per window and only copies the visible rectangles.
//! [`Region`] is the same idea with a fixed array of pairwise-disjoint
//! rectangles:
//!
//! ```text
//! let mut visited = Region::from_rect(damage);
//! for layer in top_to_bottom {
//!     let visible = visited.intersect_rect(layer_rect);
//!     copy each visible piece of layer;
//!     visited.subtract(layer_rect);
//! }
//! ```
//!
//! It is exact while it fits in `N`. When a subtraction would overflow, the
//! region degrades to its bounding box, which is a **superset** of the true
//! result: a caller may copy a few pixels twice, but can never skip a pixel
//! that should be painted. Overflow costs overdraw, never a visual hole.
//!
//! No allocation, no `unsafe`: the value lives on the display server's small
//! user stack.

use vasistas_protocol::Rect;

/// Default number of rectangles held by a [`Region`] before it degrades.
pub const DEFAULT_REGION_CAPACITY: usize = 32;

#[inline]
pub(crate) fn is_empty(rect: Rect) -> bool {
    rect.w == 0 || rect.h == 0
}

#[inline]
fn right(rect: Rect) -> i64 {
    rect.x as i64 + rect.w as i64
}

#[inline]
fn bottom(rect: Rect) -> i64 {
    rect.y as i64 + rect.h as i64
}

/// Overlap of two rectangles, empty when they do not touch.
pub(crate) fn intersect(a: Rect, b: Rect) -> Rect {
    if is_empty(a) || is_empty(b) {
        return Rect {
            x: 0,
            y: 0,
            w: 0,
            h: 0,
        };
    }
    let x0 = (a.x as i64).max(b.x as i64);
    let y0 = (a.y as i64).max(b.y as i64);
    let x1 = right(a).min(right(b));
    let y1 = bottom(a).min(bottom(b));
    if x1 <= x0 || y1 <= y0 {
        return Rect {
            x: 0,
            y: 0,
            w: 0,
            h: 0,
        };
    }
    Rect {
        x: x0 as i32,
        y: y0 as i32,
        w: (x1 - x0) as u32,
        h: (y1 - y0) as u32,
    }
}

/// Smallest rectangle containing both; an empty operand is ignored.
pub(crate) fn union(a: Rect, b: Rect) -> Rect {
    if is_empty(a) {
        return b;
    }
    if is_empty(b) {
        return a;
    }
    let x0 = (a.x as i64).min(b.x as i64);
    let y0 = (a.y as i64).min(b.y as i64);
    let x1 = right(a).max(right(b));
    let y1 = bottom(a).max(bottom(b));
    Rect {
        x: x0 as i32,
        y: y0 as i32,
        w: (x1 - x0) as u32,
        h: (y1 - y0) as u32,
    }
}

/// True when the two rectangles overlap.
#[inline]
pub fn intersects(a: Rect, b: Rect) -> bool {
    !is_empty(intersect(a, b))
}

/// True when the two rectangles share a full edge without overlapping.
pub(crate) fn is_adjacent(a: Rect, b: Rect) -> bool {
    if is_empty(a) || is_empty(b) {
        return false;
    }
    let same_rows = a.y == b.y && a.h == b.h;
    let same_cols = a.x == b.x && a.w == b.w;
    (same_rows && (right(a) == b.x as i64 || right(b) == a.x as i64))
        || (same_cols && (bottom(a) == b.y as i64 || bottom(b) == a.y as i64))
}

/// A bounded set of disjoint rectangles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region<const N: usize = DEFAULT_REGION_CAPACITY> {
    rects: [Rect; N],
    len: usize,
    degraded: bool,
}

impl<const N: usize> Default for Region<N> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<const N: usize> Region<N> {
    /// The empty region.
    #[inline]
    pub const fn empty() -> Self {
        Self {
            rects: [Rect {
                x: 0,
                y: 0,
                w: 0,
                h: 0,
            }; N],
            len: 0,
            degraded: false,
        }
    }

    /// A region holding exactly `rect`.
    pub fn from_rect(rect: Rect) -> Self {
        let mut region = Self::empty();
        if !is_empty(rect) && N > 0 {
            region.rects[0] = rect;
            region.len = 1;
        }
        region
    }

    /// The whole `width` x `height` output rectangle.
    pub fn full(width: u32, height: u32) -> Self {
        Self::from_rect(Rect {
            x: 0,
            y: 0,
            w: width,
            h: height,
        })
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        N
    }

    /// True when an exact subtraction overflowed and the region became a
    /// bounding-box superset.
    #[inline]
    pub fn is_degraded(&self) -> bool {
        self.degraded
    }

    pub fn iter(&self) -> RegionIter<'_, N> {
        RegionIter {
            region: self,
            idx: 0,
        }
    }

    pub fn area(&self) -> u64 {
        self.iter().map(|r| r.w as u64 * r.h as u64).sum()
    }

    pub fn bounds(&self) -> Rect {
        let mut bounds = Rect {
            x: 0,
            y: 0,
            w: 0,
            h: 0,
        };
        for rect in self.iter() {
            bounds = union(bounds, rect);
        }
        bounds
    }

    /// The part of this region inside `clip`.
    ///
    /// Never degrades: each stored rectangle yields at most one rectangle.
    pub fn intersect_rect(&self, clip: Rect) -> Self {
        let mut region = Self::empty();
        if is_empty(clip) {
            return region;
        }
        for idx in 0..self.len {
            let hit = intersect(self.rects[idx], clip);
            if is_empty(hit) {
                continue;
            }
            if region.len == N {
                region = Self::from_rect(union(region.bounds(), clip));
                region.degraded = true;
                return region;
            }
            region.rects[region.len] = hit;
            region.len += 1;
        }
        region
    }

    /// Clip every rectangle to `clip`.
    pub fn clip_to(&mut self, clip: Rect) {
        if is_empty(clip) {
            self.len = 0;
            return;
        }
        let mut out = 0usize;
        for idx in 0..self.len {
            let hit = intersect(self.rects[idx], clip);
            if !is_empty(hit) {
                self.rects[out] = hit;
                out += 1;
            }
        }
        self.len = out;
    }

    /// Remove `cut` from every stored rectangle.
    pub fn subtract(&mut self, cut: Rect) {
        if self.len == 0 || is_empty(cut) {
            return;
        }
        let previous = if N > 0 {
            self.bounds()
        } else {
            Self::empty().bounds()
        };
        let mut out = [Rect {
            x: 0,
            y: 0,
            w: 0,
            h: 0,
        }; N];
        let mut count = 0usize;
        let mut overflow = false;

        for idx in 0..self.len {
            let src = self.rects[idx];
            if is_empty(intersect(src, cut)) {
                if count < N {
                    out[count] = src;
                    count += 1;
                } else {
                    overflow = true;
                    break;
                }
                continue;
            }
            let mut parts = [src; 4];
            let pieces = subtract_rect(src, cut, &mut parts);
            for &piece in &parts[..pieces] {
                if is_empty(piece) {
                    continue;
                }
                if count < N {
                    out[count] = piece;
                    count += 1;
                } else {
                    overflow = true;
                    break;
                }
            }
            if overflow {
                break;
            }
        }

        if overflow {
            // Superset fallback: keep what the region covered before the cut.
            self.len = if N > 0 && !is_empty(previous) {
                self.rects[0] = previous;
                1
            } else {
                0
            };
            self.degraded = true;
            return;
        }

        self.rects = out;
        self.len = count;
    }
}

impl<const N: usize> IntoIterator for Region<N> {
    type Item = Rect;
    type IntoIter = RegionIntoIter<N>;

    fn into_iter(self) -> Self::IntoIter {
        RegionIntoIter {
            region: self,
            idx: 0,
        }
    }
}

impl<'a, const N: usize> IntoIterator for &'a Region<N> {
    type Item = Rect;
    type IntoIter = RegionIter<'a, N>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct RegionIter<'a, const N: usize> {
    region: &'a Region<N>,
    idx: usize,
}

impl<const N: usize> Iterator for RegionIter<'_, N> {
    type Item = Rect;

    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.region.len {
            let rect = self.region.rects[self.idx];
            self.idx += 1;
            if !is_empty(rect) {
                return Some(rect);
            }
        }
        None
    }
}

pub struct RegionIntoIter<const N: usize> {
    region: Region<N>,
    idx: usize,
}

impl<const N: usize> Iterator for RegionIntoIter<N> {
    type Item = Rect;

    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.region.len {
            let rect = self.region.rects[self.idx];
            self.idx += 1;
            if !is_empty(rect) {
                return Some(rect);
            }
        }
        None
    }
}

/// Split `src` into the disjoint pieces not covered by `cut`.
fn subtract_rect(src: Rect, cut: Rect, out: &mut [Rect; 4]) -> usize {
    let overlap = intersect(src, cut);
    if is_empty(overlap) {
        out[0] = src;
        return 1;
    }

    let mut count = 0usize;
    let src_right = right(src);
    let src_bottom = bottom(src);
    let cut_right = right(cut);
    let cut_bottom = bottom(cut);

    // Full-width band above the cut.
    if cut.y as i64 > src.y as i64 {
        out[count] = Rect {
            x: src.x,
            y: src.y,
            w: src.w,
            h: (cut.y as i64 - src.y as i64) as u32,
        };
        count += 1;
    }
    // Full-width band below the cut.
    if cut_bottom < src_bottom {
        out[count] = Rect {
            x: src.x,
            y: cut_bottom as i32,
            w: src.w,
            h: (src_bottom - cut_bottom) as u32,
        };
        count += 1;
    }
    // Left and right strips in the rows the cut actually touches.
    if cut.x as i64 > src.x as i64 {
        out[count] = Rect {
            x: src.x,
            y: overlap.y,
            w: (cut.x as i64 - src.x as i64) as u32,
            h: overlap.h,
        };
        count += 1;
    }
    if cut_right < src_right {
        out[count] = Rect {
            x: cut_right as i32,
            y: overlap.y,
            w: (src_right - cut_right) as u32,
            h: overlap.h,
        };
        count += 1;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn rect(x: i32, y: i32, w: u32, h: u32) -> Rect {
        Rect { x, y, w, h }
    }

    #[test]
    fn empty_and_full() {
        let empty = Region::<8>::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.area(), 0);
        let full = Region::<8>::full(10, 6);
        assert_eq!(full.len(), 1);
        assert_eq!(full.area(), 60);
        assert_eq!(full.bounds(), rect(0, 0, 10, 6));
    }

    #[test]
    fn subtract_center_leaves_four_pieces() {
        let mut region = Region::<8>::from_rect(rect(0, 0, 10, 10));
        region.subtract(rect(3, 3, 4, 4));
        assert_eq!(region.len(), 4);
        assert_eq!(region.area(), 84);
    }

    #[test]
    fn subtract_covering_empties() {
        let mut region = Region::<8>::from_rect(rect(2, 2, 4, 4));
        region.subtract(rect(0, 0, 10, 10));
        assert!(region.is_empty());
    }

    #[test]
    fn intersect_clips() {
        let region = Region::<8>::from_rect(rect(0, 0, 10, 10));
        let clipped = region.intersect_rect(rect(4, 4, 10, 10));
        assert_eq!(clipped.bounds(), rect(4, 4, 6, 6));
        assert_eq!(clipped.area(), 36);
    }

    #[test]
    fn overflow_degrades_to_a_superset() {
        let mut region = Region::<2>::empty();
        region.rects[0] = rect(0, 0, 10, 10);
        region.rects[1] = rect(20, 0, 10, 10);
        region.len = 2;
        let before = region.bounds();
        region.subtract(rect(3, 3, 4, 4));
        assert!(region.is_degraded());
        assert!(region.bounds().x <= before.x && region.bounds().w >= before.w);
    }

    /// The compositor's promise: top-down `visited` paints the topmost layer
    /// exactly once per pixel.
    #[test]
    fn occlusion_picks_the_topmost_layer_per_pixel() {
        struct Lcg(u64);
        impl Lcg {
            fn next(&mut self) -> u32 {
                self.0 = self
                    .0
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (self.0 >> 33) as u32
            }
            fn range(&mut self, max: u32) -> u32 {
                if max == 0 {
                    0
                } else {
                    self.next() % max
                }
            }
        }

        let mut rng = Lcg(0x5EED_0CC1_2027);
        let screen_w = 24u32;
        let screen_h = 18u32;

        for _ in 0..500 {
            let mut layers: Vec<Rect> = Vec::new();
            for _ in 0..1 + rng.range(6) {
                let x = rng.range(screen_w);
                let y = rng.range(screen_h);
                let w = 1 + rng.range(screen_w - x);
                let h = 1 + rng.range(screen_h - y);
                layers.push(rect(x as i32, y as i32, w, h));
            }
            let dx = rng.range(screen_w);
            let dy = rng.range(screen_h);
            let dw = 1 + rng.range(screen_w - dx);
            let dh = 1 + rng.range(screen_h - dy);
            let damage = rect(dx as i32, dy as i32, dw, dh);

            let mut expected = std::vec![None; (screen_w * screen_h) as usize];
            for (index, layer) in layers.iter().enumerate() {
                for y in layer.y..(layer.y as u32 + layer.h) as i32 {
                    for x in layer.x..(layer.x as u32 + layer.w) as i32 {
                        if x >= damage.x
                            && y >= damage.y
                            && x < damage.x + damage.w as i32
                            && y < damage.y + damage.h as i32
                        {
                            expected[(y as u32 * screen_w + x as u32) as usize] = Some(index);
                        }
                    }
                }
            }

            let mut painted = std::vec![None; (screen_w * screen_h) as usize];
            let mut visited = Region::<64>::from_rect(damage);
            for (index, layer) in layers.iter().enumerate().rev() {
                if visited.is_empty() {
                    break;
                }
                let visible = visited.intersect_rect(*layer);
                for piece in visible.iter() {
                    for y in piece.y..(piece.y as u32 + piece.h) as i32 {
                        for x in piece.x..(piece.x as u32 + piece.w) as i32 {
                            let slot = &mut painted[(y as u32 * screen_w + x as u32) as usize];
                            assert!(slot.is_none(), "pixel painted twice");
                            *slot = Some(index);
                        }
                    }
                }
                visited.subtract(*layer);
            }
            assert_eq!(painted, expected);
        }
    }
}
