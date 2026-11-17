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

//! Heap-backed surfaces.
//!
//! [`OwnedSurface`] is the double-buffer half of the API: a 32 bpp surface
//! that owns its pixels (`Vec<u32>`, so the base is 4-byte aligned) and keeps
//! its own damage set across drawing calls.
//!
//! It is the replacement for `CanvasBuffer`'s `back_buffer` field, with the
//! lifetime problem removed: instead of storing a `Canvas` next to the
//! `Vec`, it builds a short-lived `Canvas` on demand and merges the damage
//! back into the owner. That keeps the borrow checker in charge and makes a
//! dangling surface pointer impossible.
//!
//! ```
//! use fbsurface::{Dims, Format, OwnedSurface, Rect};
//!
//! let mut back = OwnedSurface::new(Dims::new(8, 8), Format::XRGB8888).unwrap();
//! back.fill_rect(Rect::new(2, 2, 3, 3), Format::XRGB8888.white());
//! assert_eq!(back.dirty().len(), 1);
//! ```

use alloc::{vec, vec::Vec};

use crate::{
    canvas::{Canvas, Error},
    format::{Format, Packed},
    geom::{Dims, Rect, RectSet, DEFAULT_SET_CAPACITY},
    ops::{PixelOps, ScalarOps},
    view::{Source, View},
};

/// A heap-backed, 32 bpp surface with damage tracking.
///
/// The pitch is always `width * 4` (no padding), which is what a compositor
/// or a console back buffer wants. Use [`Canvas`](crate::Canvas) directly
/// when the backing store has a driver-provided pitch (scanout, client
/// buffer).
pub struct OwnedSurface<O: PixelOps = ScalarOps> {
    words: Vec<u32>,
    dims: Dims,
    format: Format,
    ops: O,
    dirty: RectSet<DEFAULT_SET_CAPACITY>,
    track_dirty: bool,
}

impl<O: PixelOps> core::fmt::Debug for OwnedSurface<O> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OwnedSurface")
            .field("dims", &self.dims)
            .field("format", &self.format)
            .field("dirty", &self.dirty)
            .field("track_dirty", &self.track_dirty)
            .finish_non_exhaustive()
    }
}

impl<O: PixelOps + Copy> OwnedSurface<O> {
    /// Allocate a zeroed surface.
    ///
    /// Only 32 bpp layouts are accepted: a heap surface is a drawing target,
    /// not a 24 bpp scanout, and `Vec<u32>` gives the alignment the pixel
    /// backends expect.
    pub fn with_ops(dims: Dims, format: Format, ops: O) -> Result<Self, Error> {
        if dims.is_empty() {
            return Err(Error::EmptySurface);
        }
        if format.bits_per_pixel() != 32 {
            return Err(Error::UnsupportedFormat {
                bits_per_pixel: format.bits_per_pixel(),
            });
        }
        if !format.is_valid() {
            return Err(Error::InvalidFormat);
        }
        let area = (dims.w as usize)
            .checked_mul(dims.h as usize)
            .ok_or(Error::Overflow)?;
        Ok(Self {
            words: vec![0u32; area],
            dims,
            format,
            ops,
            dirty: RectSet::empty(),
            track_dirty: true,
        })
    }

    /// Wrap an existing word buffer.
    ///
    /// The buffer must hold at least `dims.w * dims.h` pixels; extra words
    /// are ignored.
    pub fn from_words(words: Vec<u32>, dims: Dims, format: Format, ops: O) -> Result<Self, Error> {
        if dims.is_empty() {
            return Err(Error::EmptySurface);
        }
        if format.bits_per_pixel() != 32 {
            return Err(Error::UnsupportedFormat {
                bits_per_pixel: format.bits_per_pixel(),
            });
        }
        if !format.is_valid() {
            return Err(Error::InvalidFormat);
        }
        let area = (dims.w as usize)
            .checked_mul(dims.h as usize)
            .ok_or(Error::Overflow)?;
        if words.len() < area {
            return Err(Error::BufferTooSmall {
                len: words.len() * 4,
                required: area * 4,
            });
        }
        Ok(Self {
            words,
            dims,
            format,
            ops,
            dirty: RectSet::empty(),
            track_dirty: true,
        })
    }

    #[inline]
    pub fn dims(&self) -> Dims {
        self.dims
    }

    #[inline]
    pub fn format(&self) -> Format {
        self.format
    }

    /// Bytes per row (always `width * 4`).
    #[inline]
    pub fn pitch(&self) -> usize {
        self.dims.w as usize * 4
    }

    #[inline]
    pub fn bounds(&self) -> Rect {
        Rect::new(0, 0, self.dims.w, self.dims.h)
    }

    /// Raw pixels. Bypasses damage tracking; call [`Self::mark_dirty`] if
    /// the caller wrote through this slice.
    #[inline]
    pub fn words(&self) -> &[u32] {
        &self.words
    }

    /// Mutable raw pixels. See [`Self::words`].
    #[inline]
    pub fn words_mut(&mut self) -> &mut [u32] {
        &mut self.words
    }

    /// Record damage from an external write.
    #[inline]
    pub fn mark_dirty(&mut self, rect: Rect) {
        if self.track_dirty {
            self.dirty.include(rect);
        }
    }

    #[inline]
    pub fn dirty(&self) -> &RectSet<DEFAULT_SET_CAPACITY> {
        &self.dirty
    }

    #[inline]
    pub fn take_dirty(&mut self) -> RectSet<DEFAULT_SET_CAPACITY> {
        core::mem::take(&mut self.dirty)
    }

    #[inline]
    pub fn clear_dirty(&mut self) {
        self.dirty.clear();
    }

    #[inline]
    pub fn set_tracking(&mut self, on: bool) {
        self.track_dirty = on;
        if !on {
            self.dirty.clear();
        }
    }

    /// Build a canvas over the pixels.
    ///
    /// Private on purpose: a caller that drops the canvas loses its damage.
    /// [`Self::draw`] is the safe way to run a multi-operation frame.
    fn canvas(&mut self) -> Canvas<'_, O> {
        let len = self.words.len() * 4;
        // SAFETY: `Vec<u32>` guarantees a 4-byte aligned base, the length is
        // exact, and the canvas borrows the words for `'_`.
        let bytes =
            unsafe { core::slice::from_raw_parts_mut(self.words.as_mut_ptr() as *mut u8, len) };
        Canvas::with_ops(bytes, self.dims, self.pitch(), self.format, self.ops)
            .expect("an owned surface is always a valid canvas")
    }

    /// Immutable view over the pixels.
    pub fn view(&self) -> View<'_> {
        let len = self.words.len() * 4;
        // SAFETY: same reasoning as `canvas`, with a shared slice.
        let bytes = unsafe { core::slice::from_raw_parts(self.words.as_ptr() as *const u8, len) };
        View::new(bytes, self.dims, self.pitch(), self.format)
            .expect("an owned surface is always a valid view")
    }

    /// Run a drawing closure and merge its damage into this surface.
    ///
    /// Use this to draw a whole frame through one canvas without losing
    /// damage tracking. The per-operation helpers call it internally.
    pub fn draw<T>(&mut self, f: impl FnOnce(&mut Canvas<'_, O>) -> T) -> T {
        let tracking = self.track_dirty;
        // The temporary canvas borrows `self.words`; end that borrow before
        // merging its damage into `self.dirty`.
        let (out, damage) = {
            let mut canvas = self.canvas();
            canvas.set_tracking(tracking);
            let out = f(&mut canvas);
            (out, canvas.take_dirty())
        };
        if tracking {
            self.dirty.include_set(&damage);
        }
        out
    }

    pub fn fill_rect(&mut self, rect: Rect, color: Packed) -> Option<Rect> {
        self.draw(|canvas| canvas.fill_rect(rect, color))
    }

    pub fn fill(&mut self, color: Packed) -> Rect {
        let bounds = self.bounds();
        self.fill_rect(bounds, color).unwrap_or(Rect::EMPTY)
    }

    pub fn blit<S: Source + ?Sized>(
        &mut self,
        dst: Rect,
        src: &S,
        src_rect: Rect,
    ) -> Result<Option<Rect>, Error> {
        self.draw(|canvas| canvas.blit(dst, src, src_rect))
    }

    pub fn blend_rect<S: Source + ?Sized>(
        &mut self,
        dst: Rect,
        src: &S,
        src_rect: Rect,
        alpha: u8,
    ) -> Result<Option<Rect>, Error> {
        self.draw(|canvas| canvas.blend_rect(dst, src, src_rect, alpha))
    }

    pub fn convert_from<S: Source + ?Sized>(
        &mut self,
        dst: Rect,
        src: &S,
        src_rect: Rect,
    ) -> Result<Option<Rect>, Error> {
        self.draw(|canvas| canvas.convert_from(dst, src, src_rect))
    }

    pub fn read_pixel(&self, x: u32, y: u32) -> Option<Packed> {
        self.view().read_pixel(x, y)
    }

    pub fn write_pixel(&mut self, x: u32, y: u32, pixel: Packed) -> bool {
        self.draw(|canvas| canvas.write_pixel(x, y, pixel))
    }
}

impl OwnedSurface<ScalarOps> {
    /// Allocate a zeroed XRGB8888 surface with the scalar backend.
    pub fn new(dims: Dims, format: Format) -> Result<Self, Error> {
        Self::with_ops(dims, format, ScalarOps)
    }
}

// SAFETY: the `Vec` heap allocation is stable while the surface is alive,
// the pitch is `width * 4`, and the bytes were validated at construction.
unsafe impl<O: PixelOps> Source for OwnedSurface<O> {
    #[inline]
    fn dims(&self) -> Dims {
        self.dims
    }

    #[inline]
    fn format(&self) -> Format {
        self.format
    }

    #[inline]
    fn pitch(&self) -> usize {
        self.dims.w as usize * 4
    }

    #[inline]
    unsafe fn row_ptr(&self, y: u32) -> *const u8 {
        // SAFETY: `y < height` by the trait contract, and the buffer holds
        // `pitch * height` bytes.
        unsafe {
            self.words
                .as_ptr()
                .cast::<u8>()
                .add(y as usize * (self.dims.w as usize * 4))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::Rgb;

    #[test]
    fn damage_survives_across_drawing_calls() {
        let mut back = OwnedSurface::new(Dims::new(8, 8), Format::XRGB8888).unwrap();
        back.fill_rect(Rect::new(0, 0, 2, 2), Format::XRGB8888.white());
        back.fill_rect(Rect::new(4, 4, 2, 2), Format::XRGB8888.white());
        assert_eq!(back.dirty().len(), 2);
        assert_eq!(back.dirty().total_area(), 8);
    }

    #[test]
    fn drawing_goes_through_the_canvas() {
        let mut back = OwnedSurface::new(Dims::new(4, 4), Format::XRGB8888).unwrap();
        back.fill_rect(Rect::new(1, 1, 2, 2), Format::XRGB8888.rgb(1, 2, 3));
        assert_eq!(
            Format::XRGB8888.unpack(Packed::raw(back.words()[4 + 1])),
            Rgb::new(1, 2, 3)
        );
        assert_eq!(back.words()[0], 0);
    }

    #[test]
    fn two_owned_surfaces_copy_between_each_other() {
        let mut src = OwnedSurface::new(Dims::new(4, 4), Format::XRGB8888).unwrap();
        let mut dst = OwnedSurface::new(Dims::new(8, 8), Format::XRGB8888).unwrap();
        src.fill(Format::XRGB8888.white());
        let written = dst
            .blit(Rect::new(2, 2, 4, 4), &src, Rect::new(0, 0, 4, 4))
            .unwrap();
        assert_eq!(written, Some(Rect::new(2, 2, 4, 4)));
        assert_eq!(dst.words()[2 * 8 + 2], 0xFFFF_FFFF);
        assert_eq!(dst.words()[8 + 1], 0);
        assert_eq!(dst.dirty().bounds(), Rect::new(2, 2, 4, 4));
    }

    #[test]
    fn full_frame_blit_uses_the_contiguous_path() {
        let mut src = OwnedSurface::new(Dims::new(8, 8), Format::XRGB8888).unwrap();
        let mut dst = OwnedSurface::new(Dims::new(8, 8), Format::XRGB8888).unwrap();
        for y in 0..8 {
            for x in 0..8 {
                src.write_pixel(x, y, Format::XRGB8888.rgb(x as u8, y as u8, 0x5A));
            }
        }
        let written = dst
            .blit(Rect::new(0, 0, 8, 8), &src, Rect::new(0, 0, 8, 8))
            .unwrap();
        assert_eq!(written, Some(Rect::new(0, 0, 8, 8)));
        assert_eq!(dst.words(), src.words());
    }

    #[test]
    fn owned_surface_converts_to_24bpp_view() {
        // A 24 bpp sibling is only representable as a borrowed View; the
        // conversion path is still the same `Format::convert`.
        let mut src = [0u8; 8 * 8 * 3];
        src[0..3].copy_from_slice(&[0x30, 0x20, 0x10]);
        let view = View::new(&src, Dims::new(8, 8), 8 * 3, Format::RGB888).unwrap();
        let mut dst = OwnedSurface::new(Dims::new(8, 8), Format::XRGB8888).unwrap();
        dst.convert_from(Rect::new(0, 0, 1, 1), &view, Rect::new(0, 0, 1, 1))
            .unwrap();
        assert_eq!(
            Format::XRGB8888.unpack(Packed::raw(dst.words()[0])),
            Rgb::new(0x10, 0x20, 0x30)
        );
    }

    #[test]
    fn raw_words_must_be_marked_manually() {
        let mut back = OwnedSurface::new(Dims::new(2, 2), Format::XRGB8888).unwrap();
        back.words_mut()[0] = 0xFFFF_FFFF;
        assert!(back.dirty().is_empty());
        back.mark_dirty(Rect::new(0, 0, 1, 1));
        assert_eq!(back.dirty().len(), 1);
    }

    #[test]
    fn constructor_rejects_bad_input() {
        assert!(OwnedSurface::new(Dims::ZERO, Format::XRGB8888).is_err());
        assert!(OwnedSurface::new(Dims::new(2, 2), Format::RGB888).is_err());
        assert!(OwnedSurface::from_words(
            alloc::vec![0u32; 2],
            Dims::new(2, 2),
            Format::XRGB8888,
            ScalarOps
        )
        .is_err());
    }
}
