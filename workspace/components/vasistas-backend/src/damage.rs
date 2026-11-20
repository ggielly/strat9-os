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

//! Coalescing damage sets.
//!
//! The compositor presents many small changes per frame (cursor, several
//! windows, a drag). Sending one `DMG2` per rectangle costs one kernel entry
//! and one virtio transfer each. [`DamageSet`] merges overlapping and
//! edge-adjacent rectangles as they are added, so the frame usually ends up
//! with a handful of rectangles and one `DMG2` write.
//!
//! The set never allocates and never fails: when it is full, the new rectangle
//! is merged into the entry whose union grows the least, so one far-away rect
//! cannot drag the presented area to the corner of the screen. The result can
//! cover clean pixels (overdraw) but never drops a dirty one.

use vasistas_protocol::Rect;

use crate::region::{intersect, is_adjacent, is_empty, union};

/// Default number of rectangles kept without forced merging.
pub const DEFAULT_DAMAGE_CAPACITY: usize = 32;

/// A fixed-capacity set of coalesced damage rectangles.
#[derive(Clone, Copy, Debug)]
pub struct DamageSet<const N: usize = DEFAULT_DAMAGE_CAPACITY> {
    rects: [Rect; N],
    len: usize,
}

impl<const N: usize> Default for DamageSet<N> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<const N: usize> DamageSet<N> {
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
        }
    }

    /// Insert a rectangle. Empty rectangles are ignored.
    pub fn include(&mut self, rect: Rect) {
        if is_empty(rect) {
            return;
        }
        let mut next = rect;

        let mut idx = 0;
        while idx < self.len {
            let current = self.rects[idx];
            if is_empty(current) {
                idx += 1;
                continue;
            }
            if !is_empty(intersect(current, next)) || is_adjacent(current, next) {
                next = union(current, next);
                // Swap-remove and restart: the merged rectangle may now touch
                // a rectangle that came before it.
                self.rects[idx] = self.rects[self.len - 1];
                self.rects[self.len - 1] = Rect {
                    x: 0,
                    y: 0,
                    w: 0,
                    h: 0,
                };
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
            let merged = union(self.rects[i], next);
            let cost = (merged.w as u64 * merged.h as u64)
                .saturating_sub(self.rects[i].w as u64 * self.rects[i].h as u64);
            if cost < best_cost {
                best_cost = cost;
                best = i;
            }
        }
        self.rects[best] = union(self.rects[best], next);
    }

    /// Insert every rectangle of another set.
    pub fn include_set<const M: usize>(&mut self, other: &DamageSet<M>) {
        for rect in other.iter() {
            self.include(rect);
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

    #[inline]
    pub fn capacity(&self) -> usize {
        N
    }

    pub fn iter(&self) -> DamageIter<'_, N> {
        DamageIter { set: self, idx: 0 }
    }

    /// Bounding box of every rectangle.
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

    /// Sum of the rectangle areas. Merged rectangles do not double-count.
    pub fn total_area(&self) -> u64 {
        self.iter().map(|r| r.w as u64 * r.h as u64).sum()
    }
}

impl<const N: usize> IntoIterator for DamageSet<N> {
    type Item = Rect;
    type IntoIter = DamageIntoIter<N>;

    fn into_iter(self) -> Self::IntoIter {
        DamageIntoIter { set: self, idx: 0 }
    }
}

impl<'a, const N: usize> IntoIterator for &'a DamageSet<N> {
    type Item = Rect;
    type IntoIter = DamageIter<'a, N>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct DamageIter<'a, const N: usize> {
    set: &'a DamageSet<N>,
    idx: usize,
}

impl<const N: usize> Iterator for DamageIter<'_, N> {
    type Item = Rect;

    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.set.len {
            let rect = self.set.rects[self.idx];
            self.idx += 1;
            if !is_empty(rect) {
                return Some(rect);
            }
        }
        None
    }
}

pub struct DamageIntoIter<const N: usize> {
    set: DamageSet<N>,
    idx: usize,
}

impl<const N: usize> Iterator for DamageIntoIter<N> {
    type Item = Rect;

    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.set.len {
            let rect = self.set.rects[self.idx];
            self.idx += 1;
            if !is_empty(rect) {
                return Some(rect);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(x: i32, y: i32, w: u32, h: u32) -> Rect {
        Rect { x, y, w, h }
    }

    #[test]
    fn empty_is_noop() {
        let mut set = DamageSet::<4>::empty();
        set.include(rect(0, 0, 0, 10));
        assert!(set.is_empty());
    }

    #[test]
    fn adjacent_rectangles_merge() {
        let mut set = DamageSet::<8>::empty();
        set.include(rect(10, 10, 20, 5));
        set.include(rect(10, 15, 20, 5));
        assert_eq!(set.len(), 1);
        assert_eq!(set.bounds(), rect(10, 10, 20, 10));
        assert_eq!(set.total_area(), 200);
    }

    #[test]
    fn distant_rectangles_stay_separate() {
        let mut set = DamageSet::<8>::empty();
        set.include(rect(0, 0, 4, 4));
        set.include(rect(100, 100, 4, 4));
        assert_eq!(set.len(), 2);
        assert_eq!(set.total_area(), 32);
    }

    #[test]
    fn full_set_merges_the_least_growth() {
        let mut set = DamageSet::<2>::empty();
        set.include(rect(0, 0, 10, 10));
        set.include(rect(100, 0, 10, 10));
        // The set is full; the new rect is near the first one.
        set.include(rect(12, 0, 2, 2));
        assert_eq!(set.len(), 2);
        // It grew the first entry (10x10 -> 14x10) rather than dragging the
        // far entry across the screen (which would cover ~98x10).
        assert_eq!(set.total_area(), 140 + 100);
    }

    #[test]
    fn include_set_copies_everything() {
        let mut a = DamageSet::<8>::empty();
        a.include(rect(0, 0, 2, 2));
        let mut b = DamageSet::<8>::empty();
        b.include(rect(10, 10, 2, 2));
        b.include_set(&a);
        assert_eq!(b.len(), 2);
    }
}
