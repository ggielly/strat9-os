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
//! opaque region, frees it, and presents the current region of a surface with
//! the damage accumulated since the previous presentation.

use crate::types::SurfaceId;
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

    /// Present `region` on `surface` with `damage` since the last present.
    ///
    /// `damage` is a single full-surface rect for a full presentation, sized to
    /// the current buffer. The rects are **surface-local**; `x` and `y` are the
    /// surface's screen-space origin, so the backend translates each rect by
    /// them and clips to the screen before copying. The slice is borrowed for
    /// the call only: it must not be retained past the return.
    fn present(
        &mut self,
        surface: SurfaceId,
        region: RegionHandle,
        damage: &[Rect],
        x: u32,
        y: u32,
    ) -> Result<(), Self::Error>;

    /// Select the software cursor shape (A.3.1 `SET_CURSOR_SHAPE`).
    ///
    /// `shape` is already validated to `0..=2`; backends that do not paint a
    /// cursor may ignore it. The default keeps existing backends source- and
    /// behavior-compatible.
    fn set_cursor_shape(&mut self, _shape: u32) {}
}
