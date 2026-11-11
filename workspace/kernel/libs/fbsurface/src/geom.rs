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

//! Pure geometry: sizes, rectangles and bounded rectangle sets.
//!
//! This module has no pixel knowledge and no allocation. Everything is
//! `Copy`, which makes the types safe to pass across the framebuffer lock.
//!
//! The single clipping rule used by [`Canvas`](crate::Canvas) lives here:
//! [`Rect::intersect`]. There is deliberately no other definition of "inside
//! the screen" anywhere in the crate.

/// Width and height of a surface, in pixels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Dims {
    pub w: u32,
    pub h: u32,
}

impl Dims {
    pub const ZERO: Self = Self { w: 0, h: 0 };

    #[inline]
    pub const fn new(w: u32, h: u32) -> Self {
        Self { w, h }
    }

    #[inline]
    pub const fn area(self) -> u64 {
        self.w as u64 * self.h as u64
    }

    #[inline]
    pub const fn is_empty(self) -> bool {
        self.w == 0 || self.h == 0
    }
}

/// An axis-aligned rectangle, in pixels.
///
/// An empty rectangle (`w == 0` or `h == 0`) is never drawable and is what
/// clipping operations return when nothing remains.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

impl Rect {
    pub const EMPTY: Self = Self {
        x: 0,
        y: 0,
        w: 0,
        h: 0,
    };

    #[inline]
    pub const fn new(x: u32, y: u32, w: u32, h: u32) -> Self {
        Self { x, y, w, h }
    }

    #[inline]
    pub const fn is_empty(self) -> bool {
        self.w == 0 || self.h == 0
    }

    /// One past the last column. Saturates instead of wrapping, so a bogus
    /// `x + w` can never turn into a rectangle on the other side of zero.
    #[inline]
    pub const fn right(self) -> u32 {
        self.x.saturating_add(self.w)
    }

    /// One past the last row.
    #[inline]
    pub const fn bottom(self) -> u32 {
        self.y.saturating_add(self.h)
    }

    #[inline]
    pub const fn area(self) -> u64 {
        self.w as u64 * self.h as u64
    }

    #[inline]
    pub const fn contains_point(self, x: u32, y: u32) -> bool {
        !self.is_empty() && x >= self.x && x < self.right() && y >= self.y && y < self.bottom()
    }

    #[inline]
    pub const fn contains_rect(self, other: Rect) -> bool {
        !other.is_empty()
            && other.x >= self.x
            && other.y >= self.y
            && other.right() <= self.right()
            && other.bottom() <= self.bottom()
    }

    /// The overlap of two rectangles (empty when they do not overlap).
    #[inline]
    pub const fn intersect(self, other: Rect) -> Rect {
        if self.is_empty() || other.is_empty() {
            return Rect::EMPTY;
        }
        let x0 = max_u32(self.x, other.x);
        let y0 = max_u32(self.y, other.y);
        let x1 = min_u32(self.right(), other.right());
        let y1 = min_u32(self.bottom(), other.bottom());
        if x1 <= x0 || y1 <= y0 {
            Rect::EMPTY
        } else {
            Rect::new(x0, y0, x1 - x0, y1 - y0)
        }
    }

    /// The smallest rectangle containing both. An empty operand is ignored.
    #[inline]
    pub const fn union(self, other: Rect) -> Rect {
        if self.is_empty() {
            return other;
        }
        if other.is_empty() {
            return self;
        }
        let x0 = min_u32(self.x, other.x);
        let y0 = min_u32(self.y, other.y);
        let x1 = max_u32(self.right(), other.right());
        let y1 = max_u32(self.bottom(), other.bottom());
        Rect::new(x0, y0, x1 - x0, y1 - y0)
    }

    /// True when the two rectangles share a full edge (no overlap and no
    /// gap). Used by [`RectSet`] to coalesce glyph rows without covering
    /// clean pixels.
    #[inline]
    pub const fn is_adjacent(self, other: Rect) -> bool {
        if self.is_empty() || other.is_empty() {
            return false;
        }
        let same_rows = self.y == other.y && self.h == other.h;
        let same_cols = self.x == other.x && self.w == other.w;
        (same_rows && (self.right() == other.x || other.right() == self.x))
            || (same_cols && (self.bottom() == other.y || other.bottom() == self.y))
    }

    /// Translate by a signed offset, saturating at the origin.
    #[inline]
    pub const fn offset(self, dx: i32, dy: i32) -> Rect {
        let x = self.x as i64 + dx as i64;
        let y = self.y as i64 + dy as i64;
        Rect::new(
            if x < 0 { 0 } else { x as u32 },
            if y < 0 { 0 } else { y as u32 },
            self.w,
            self.h,
        )
    }
}

#[inline]
const fn min_u32(a: u32, b: u32) -> u32 {
    if a < b {
        a
    } else {
        b
    }
}

#[inline]
const fn max_u32(a: u32, b: u32) -> u32 {
    if a > b {
        a
    } else {
        b
    }
}

/// Default number of rectangles kept without merging.
pub const DEFAULT_SET_CAPACITY: usize = 16;

/// A fixed-capacity set of non-overlapping dirty rectangles.
///
/// Replacement for both `DirtyRectSet` and `Damage`. The rules are:
///
/// - overlapping or edge-adjacent rectangles are merged, transitively;
/// - when the set is full, the new rectangle is merged into the existing one
///   whose union grows the least, so a single far-away rect cannot drag the
///   presented area to the corner of the screen;
/// - insertion never allocates and never fails.
#[derive(Clone, Copy, Debug)]
pub struct RectSet<const N: usize = DEFAULT_SET_CAPACITY> {
    rects: [Rect; N],
    len: usize,
}

impl<const N: usize> Default for RectSet<N> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<const N: usize> RectSet<N> {
    #[inline]
    pub const fn empty() -> Self {
        Self {
            rects: [Rect::EMPTY; N],
            len: 0,
        }
    }

    /// Insert a rectangle. Empty rectangles are ignored.
    pub fn include(&mut self, rect: Rect) {
        if rect.is_empty() {
            return;
        }
        let mut next = rect;

        let mut idx = 0;
        while idx < self.len {
            let cur = self.rects[idx];
            if cur.is_empty() {
                idx += 1;
                continue;
            }
            if !cur.intersect(next).is_empty() || cur.is_adjacent(next) {
                next = cur.union(next);
                // Swap-remove, then restart: the merged rectangle may now
                // touch a rectangle that came before it.
                self.rects[idx] = self.rects[self.len - 1];
                self.rects[self.len - 1] = Rect::EMPTY;
                self.len -= 1;
                idx = 0;
                continue;
            }
            idx += 1;
        }

        if self.len < N {
            self.rects[self.len] = next;
            self.len += 1;
            return;
        }

        if N == 0 {
            return;
        }

        let mut best = 0;
        let mut best_cost = u64::MAX;
        for i in 0..self.len {
            let union = self.rects[i].union(next);
            let cost = union.area().saturating_sub(self.rects[i].area());
            if cost < best_cost {
                best_cost = cost;
                best = i;
            }
        }
        self.rects[best] = self.rects[best].union(next);
    }

    /// Insert every rectangle of another set.
    pub fn include_set(&mut self, other: &RectSet<N>) {
        for r in other.iter() {
            self.include(r);
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.len = 0;
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Number of slots still available before merging starts.
    #[inline]
    pub fn spare(&self) -> usize {
        N.saturating_sub(self.len)
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        N
    }

    pub fn iter(&self) -> RectSetIter<'_, N> {
        RectSetIter { set: self, idx: 0 }
    }

    /// Bounding box of every rectangle, or [`Rect::EMPTY`].
    pub fn bounds(&self) -> Rect {
        let mut bounds = Rect::EMPTY;
        for r in self.iter() {
            bounds = bounds.union(r);
        }
        bounds
    }

    /// Sum of the areas. Adjacent rects are merged, so this does not
    /// double-count the common case.
    pub fn total_area(&self) -> u64 {
        self.iter().map(Rect::area).sum()
    }
}

impl<const N: usize> IntoIterator for RectSet<N> {
    type Item = Rect;
    type IntoIter = RectSetOwnedIter<N>;

    fn into_iter(self) -> Self::IntoIter {
        RectSetOwnedIter { set: self, idx: 0 }
    }
}

impl<'a, const N: usize> IntoIterator for &'a RectSet<N> {
    type Item = Rect;
    type IntoIter = RectSetIter<'a, N>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct RectSetIter<'a, const N: usize> {
    set: &'a RectSet<N>,
    idx: usize,
}

impl<const N: usize> Iterator for RectSetIter<'_, N> {
    type Item = Rect;

    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.set.len {
            let r = self.set.rects[self.idx];
            self.idx += 1;
            if !r.is_empty() {
                return Some(r);
            }
        }
        None
    }
}

pub struct RectSetOwnedIter<const N: usize> {
    set: RectSet<N>,
    idx: usize,
}

impl<const N: usize> Iterator for RectSetOwnedIter<N> {
    type Item = Rect;

    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.set.len {
            let r = self.set.rects[self.idx];
            self.idx += 1;
            if !r.is_empty() {
                return Some(r);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intersect_clips_both_axes() {
        let screen = Rect::new(0, 0, 100, 50);
        assert_eq!(
            Rect::new(90, 40, 30, 30).intersect(screen),
            Rect::new(90, 40, 10, 10)
        );
        assert_eq!(Rect::new(100, 0, 10, 10).intersect(screen), Rect::EMPTY);
        assert_eq!(Rect::EMPTY.intersect(screen), Rect::EMPTY);
    }

    #[test]
    fn intersect_saturates_on_overflow() {
        let huge = Rect::new(u32::MAX - 1, 0, 100, 10);
        assert_eq!(huge.right(), u32::MAX);
        assert_eq!(huge.intersect(Rect::new(0, 0, 10, 10)), Rect::EMPTY);
    }

    #[test]
    fn union_ignores_empty() {
        let r = Rect::new(4, 4, 8, 8);
        assert_eq!(r.union(Rect::EMPTY), r);
        assert_eq!(Rect::EMPTY.union(r), r);
        assert_eq!(Rect::new(0, 0, 2, 2).union(r), Rect::new(0, 0, 12, 12));
    }

    #[test]
    fn adjacency_is_edge_only() {
        let a = Rect::new(0, 0, 10, 10);
        assert!(a.is_adjacent(Rect::new(10, 0, 5, 10)));
        assert!(a.is_adjacent(Rect::new(0, 10, 10, 5)));
        // Diagonal contact is not adjacency, and neither is a gap.
        assert!(!a.is_adjacent(Rect::new(10, 10, 5, 5)));
        assert!(!a.is_adjacent(Rect::new(11, 0, 5, 10)));
        // Overlap is handled by intersect(), not adjacency.
        assert!(!a.is_adjacent(Rect::new(5, 0, 10, 10)));
    }

    #[test]
    fn set_merges_adjacent_rows() {
        let mut set = RectSet::<4>::empty();
        set.include(Rect::new(0, 0, 8, 8));
        set.include(Rect::new(8, 0, 8, 8));
        assert_eq!(set.len(), 1);
        assert_eq!(set.iter().next(), Some(Rect::new(0, 0, 16, 8)));
    }

    #[test]
    fn set_merges_transitively() {
        let mut set = RectSet::<8>::empty();
        set.include(Rect::new(0, 0, 10, 10));
        set.include(Rect::new(30, 0, 10, 10));
        // Bridges the two existing rects.
        set.include(Rect::new(10, 0, 20, 10));
        assert_eq!(set.len(), 1);
        assert_eq!(set.iter().next(), Some(Rect::new(0, 0, 40, 10)));
    }

    #[test]
    fn set_keeps_disjoint_rects_apart() {
        let mut set = RectSet::<4>::empty();
        set.include(Rect::new(0, 0, 4, 4));
        set.include(Rect::new(20, 20, 4, 4));
        assert_eq!(set.len(), 2);
        assert_eq!(set.total_area(), 32);
        assert_eq!(set.bounds(), Rect::new(0, 0, 24, 24));
    }

    #[test]
    fn set_overflow_merges_cheapest() {
        let mut set = RectSet::<2>::empty();
        set.include(Rect::new(0, 0, 10, 10));
        set.include(Rect::new(100, 0, 10, 10));
        // Third rect sits next to the first one: it must merge there.
        set.include(Rect::new(10, 0, 10, 10));
        assert_eq!(set.len(), 2);
        let mut rects: [Rect; 2] = [Rect::EMPTY; 2];
        for (i, r) in set.iter().enumerate() {
            rects[i] = r;
        }
        assert!(rects.contains(&Rect::new(0, 0, 20, 10)));
        assert!(rects.contains(&Rect::new(100, 0, 10, 10)));
    }

    #[test]
    fn set_ignores_empty_and_clears() {
        let mut set = RectSet::<4>::empty();
        set.include(Rect::EMPTY);
        assert!(set.is_empty());
        set.include(Rect::new(1, 2, 3, 4));
        assert_eq!(set.len(), 1);
        set.clear();
        assert!(set.is_empty());
        assert_eq!(set.bounds(), Rect::EMPTY);
    }

    #[test]
    fn zero_capacity_set_never_panics() {
        let mut set = RectSet::<0>::empty();
        set.include(Rect::new(1, 2, 3, 4));
        assert!(set.is_empty());
    }
}
