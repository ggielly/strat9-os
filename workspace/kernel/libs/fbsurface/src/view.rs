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

//! Read-only surfaces, and the sealed source trait used by bulk copies.
//!
//! [`View`] is the immutable counterpart of [`Canvas`](crate::Canvas): it
//! borrows a `&[u8]` (or points at shared memory) and can only be read.
//! This is what lets a caller blit directly from a client buffer, a mapped
//! frame or a wire payload without copying it into a mutable surface first.
//!
//! [`Source`] is deliberately an `unsafe trait`: it hands out a raw row
//! pointer to the crate's copy loops, so a bad implementation would turn a
//! safe `blit` into undefined behaviour. It is implemented only for
//! [`Canvas`](crate::Canvas) and [`View`], and cannot be implemented outside
//! this crate without an explicit `unsafe impl`.

use core::marker::PhantomData;

use crate::{
    canvas::{validate, validate_alignment, Canvas, Error},
    format::{Format, Packed},
    geom::{Dims, Rect},
};

/// A surface that a [`Canvas`](crate::Canvas) can copy from.
///
/// # Safety
///
/// Implementors must guarantee that, for every `y < dims().h`, [`Self::row_ptr`]
/// returns a pointer to at least `dims().w * format().bytes_per_pixel()`
/// readable bytes, and that the pointer stays valid for as long as `self` is
/// borrowed.
pub unsafe trait Source {
    fn dims(&self) -> Dims;
    fn format(&self) -> Format;

    /// Pointer to the first pixel of row `y`. `y` must be in bounds.
    fn row_ptr(&self, y: u32) -> *const u8;

    /// Read one pixel with no volatile semantics.
    ///
    /// Defaulted so both `Canvas` and `View` share the exact same decoding
    /// rules. `x` and `y` must be in bounds.
    #[inline]
    fn read_raw(&self, x: u32, y: u32) -> u32 {
        let ptr = self.row_ptr(y);
        let format = self.format();
        // SAFETY: the trait contract guarantees the row is readable and
        // `x` is in bounds; 32 bpp surfaces are 4-byte aligned by
        // construction, 24 bpp uses byte reads.
        unsafe {
            match format.bytes_per_pixel() {
                4 => (ptr.add(x as usize * 4) as *const u32).read_unaligned(),
                3 => {
                    let p = ptr.add(x as usize * 3);
                    p.read() as u32 | (p.add(1).read() as u32) << 8 | (p.add(2).read() as u32) << 16
                }
                _ => 0,
            }
        }
    }
}

// SAFETY: `Canvas::row_ptr` is the validated surface geometry from
// `canvas.rs`; the pointer stays valid for the borrow of the canvas.
unsafe impl<O: crate::ops::PixelOps> Source for Canvas<'_, O> {
    #[inline]
    fn dims(&self) -> Dims {
        Canvas::dims(self)
    }

    #[inline]
    fn format(&self) -> Format {
        Canvas::format(self)
    }

    #[inline]
    fn row_ptr(&self, y: u32) -> *const u8 {
        Canvas::row_ptr(self, y) as *const u8
    }
}

/// An immutable rectangle of pixels.
///
/// Created from a borrowed slice or from raw memory (MMIO, shared mapping).
/// It records no damage and cannot be drawn into.
pub struct View<'a> {
    base: *const u8,
    pitch: usize,
    dims: Dims,
    format: Format,
    _borrow: PhantomData<&'a [u8]>,
}

// The view is a shared borrow of immutable pixels, so it can cross CPUs as
// long as the backing bytes are `Sync`.
unsafe impl Send for View<'_> {}
unsafe impl Sync for View<'_> {}

impl core::fmt::Debug for View<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("View")
            .field("dims", &self.dims)
            .field("pitch", &self.pitch)
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}

impl<'a> View<'a> {
    /// Build a view over a borrowed buffer.
    ///
    /// `pitch` is a byte count, not a pixel count.
    pub fn new(buf: &'a [u8], dims: Dims, pitch: usize, format: Format) -> Result<Self, Error> {
        validate(dims, pitch, format)?;
        validate_alignment(buf.as_ptr() as usize, format)?;
        let required = pitch.checked_mul(dims.h as usize).ok_or(Error::Overflow)?;
        if buf.len() < required {
            return Err(Error::BufferTooSmall {
                len: buf.len(),
                required,
            });
        }
        // SAFETY: validated above; the borrow ties the view to `buf`.
        unsafe { Self::from_raw(buf.as_ptr(), dims, pitch, format) }
    }

    /// Build a view over raw memory.
    ///
    /// # Safety
    ///
    /// `base` must be readable for `pitch * height` bytes for the whole
    /// lifetime `'a`.
    pub unsafe fn from_raw(
        base: *const u8,
        dims: Dims,
        pitch: usize,
        format: Format,
    ) -> Result<Self, Error> {
        validate(dims, pitch, format)?;
        validate_alignment(base as usize, format)?;
        pitch.checked_mul(dims.h as usize).ok_or(Error::Overflow)?;
        Ok(Self {
            base,
            pitch,
            dims,
            format,
            _borrow: PhantomData,
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

    #[inline]
    pub fn pitch(&self) -> usize {
        self.pitch
    }

    #[inline]
    pub fn bytes_per_pixel(&self) -> usize {
        self.format.bytes_per_pixel()
    }

    #[inline]
    pub fn bounds(&self) -> Rect {
        Rect::new(0, 0, self.dims.w, self.dims.h)
    }

    #[inline]
    pub fn clip(&self, rect: Rect) -> Option<Rect> {
        let clipped = rect.intersect(self.bounds());
        if clipped.is_empty() {
            None
        } else {
            Some(clipped)
        }
    }

    /// Read one pixel. Volatile, because the backing memory may be MMIO or
    /// a shared mapping that a device updates.
    pub fn read_pixel(&self, x: u32, y: u32) -> Option<Packed> {
        if x >= self.dims.w || y >= self.dims.h {
            return None;
        }
        let ptr = unsafe { self.base.add(y as usize * self.pitch) };
        let value = match self.format.bytes_per_pixel() {
            4 => {
                // SAFETY: in bounds and aligned.
                unsafe { core::ptr::read_volatile(ptr.add(x as usize * 4) as *const u32) }
            }
            3 => {
                // SAFETY: in bounds.
                unsafe {
                    let p = ptr.add(x as usize * 3);
                    core::ptr::read_volatile(p) as u32
                        | (core::ptr::read_volatile(p.add(1)) as u32) << 8
                        | (core::ptr::read_volatile(p.add(2)) as u32) << 16
                }
            }
            _ => return None,
        };
        Some(Packed::raw(value))
    }
}

// SAFETY: the geometry was validated at construction, and the pointer is
// valid for `pitch * height` bytes for `'a`.
unsafe impl Source for View<'_> {
    #[inline]
    fn dims(&self) -> Dims {
        self.dims
    }

    #[inline]
    fn format(&self) -> Format {
        self.format
    }

    #[inline]
    fn row_ptr(&self, y: u32) -> *const u8 {
        // SAFETY: `y < height` by the trait contract, and the backing store
        // holds `pitch * height` bytes.
        unsafe { self.base.add(y as usize * self.pitch) }
    }
}

impl<'a, O: crate::ops::PixelOps> Canvas<'a, O> {
    /// Borrow this canvas as an immutable view.
    ///
    /// Useful to keep a source alive while the destination is drawn through
    /// a different alias, or to pass a canvas to code that only reads.
    pub fn view(&self) -> View<'_> {
        // SAFETY: the canvas geometry was validated at construction and the
        // view borrows it for `'_`.
        unsafe {
            View::from_raw(
                Canvas::row_ptr(self, 0) as *const u8,
                self.dims(),
                self.pitch(),
                self.format(),
            )
            .expect("a validated canvas is a valid view")
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use crate::geom::Rect;

    #[test]
    fn view_reads_the_underlying_bytes() {
        let words = [0x0011_2233u32, 0x0044_5566];
        // SAFETY: `u32` has no padding.
        let bytes =
            unsafe { core::slice::from_raw_parts(words.as_ptr() as *const u8, words.len() * 4) };
        let view = View::new(bytes, Dims::new(2, 1), 8, Format::XRGB8888).unwrap();
        assert_eq!(view.read_pixel(0, 0), Some(Packed::raw(0x0011_2233)));
        assert_eq!(view.read_pixel(1, 0), Some(Packed::raw(0x0044_5566)));
        assert_eq!(view.read_pixel(2, 0), None);
    }

    #[test]
    fn view_rejects_inconsistent_geometry() {
        let bytes = [0u8; 16];
        assert!(View::new(&bytes, Dims::new(4, 4), 16, Format::XRGB8888).is_err());
        assert!(View::new(&bytes[1..], Dims::new(1, 1), 4, Format::XRGB8888).is_err());
    }

    #[test]
    fn view_clip_matches_canvas_clip() {
        let bytes = [0u8; 64];
        let view = View::new(&bytes, Dims::new(4, 4), 16, Format::XRGB8888).unwrap();
        assert_eq!(
            view.clip(Rect::new(2, 2, 8, 8)),
            Some(Rect::new(2, 2, 2, 2))
        );
        assert_eq!(view.clip(Rect::new(9, 0, 1, 1)), None);
    }
}
