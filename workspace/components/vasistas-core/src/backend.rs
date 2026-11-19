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

//! Presentation backend boundary (A.4: metadata and presentation only).
//!
//! The core never touches pixels. A backend turns a buffer descriptor into an
//! opaque region, frees it, and composites the current images of the z order
//! over the screen's dirty rectangles.

use vasistas_protocol::Rect;

/// Opaque handle to a backend-allocated pixel region.
///
/// The value is meaningful only to the backend that produced it; the core
/// stores and returns it untouched.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RegionHandle(u64);

impl RegionHandle {
    /// Construct a handle from a backend-owned value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The backend-owned value.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// One compositable surface image; the bottom-to-top order is given by the
/// slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layer {
    /// Region holding the surface's current image.
    pub region: RegionHandle,
    /// Screen-space origin x of the image.
    pub x: u32,
    /// Screen-space origin y of the image.
    pub y: u32,
}

/// Allocation and presentation operations the core delegates to.
///
/// Implementations may fail allocation; the error is surfaced as
/// [`CoreError::BackendError`](crate::CoreError::BackendError) and leaves the
/// core unchanged.
pub trait Backend {
    /// Backend failure value; it is copied out, never inspected.
    type Error: Copy;

    /// Allocate a pixel region able to hold `stride * height` bytes.
    fn allocate(
        &mut self,
        width: u32,
        height: u32,
        stride: u32,
        format: u32,
    ) -> Result<RegionHandle, Self::Error>;

    /// Release a region previously returned by [`Backend::allocate`].
    ///
    /// The core only calls this from [`DisplayCore::take_retired`] and from
    /// `Drop`, i.e. after the server had a chance to revoke and unmap the client
    /// mapping. The backend must not reuse or recycle a region while a client
    /// mapping or reference to it may still exist: freeing at
    /// [`DisplayCore::take_retired`] is the safe point, not at buffer
    /// destruction.
    ///
    /// [`DisplayCore::take_retired`]: crate::DisplayCore::take_retired
    fn free(&mut self, region: RegionHandle);

    /// Composite `bottom_to_top` over the screen-space dirty `rects`.
    ///
    /// `rects` are already clipped to the output; the backend copies, for each
    /// rect, every layer's intersection in slice order (the last layer paints
    /// on top). The slices are borrowed for the call only.
    fn composite(&mut self, bottom_to_top: &[Layer], rects: &[Rect]) -> Result<(), Self::Error>;

    /// Select the software cursor shape (A.3.1 `SET_CURSOR_SHAPE`).
    ///
    /// `shape` is already validated to `0..=2`; backends that do not paint a
    /// cursor may ignore it. The default keeps existing backends source- and
    /// behavior-compatible.
    fn set_cursor_shape(&mut self, _shape: u32) {}
}
