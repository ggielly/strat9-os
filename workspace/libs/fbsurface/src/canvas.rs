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

//! The surface type: a validated, contiguous rectangle of pixels.
//!
//! One type replaces `CanvasBuffer`, the drawing half of `HeapScreen`,
//! `SimpleDisplayAdapter`'s raw pointer and the framebuffer wrapper. The
//! invariants that used to be comments are enforced here:
//!
//! - the pitch covers the width and the backing store covers the pitch;
//! - the format is one the pixel backends can actually drive;
//! - a bulk blit only happens between identical formats; conversion is a
//!   separate, explicit call;
//! - clipping is [`Rect::intersect`] and nothing else;
//! - dirty rectangles come from [`RectSet`], not three overlapping models.
//!
//! # Storage
//!
//! A `Canvas` borrows its pixels or points at MMIO; it never allocates.
//! `Canvas::new` / [`Canvas::with_ops`] take a `&mut [u8]`, [`Canvas::direct`]
//! takes a validated `NonNull<u8>` for a physical framebuffer. Paged
//! (`HeapScreen`-style) storage is deliberately out of scope: it is the
//! thing R12 removes from the kernel.
//!
//! # Example
//!
//! ```
//! use fbsurface::{Canvas, Dims, Format, Rect};
//!
//! // Back the surface with `u32` so the 32 bpp alignment rule holds.
//! let mut words = [0u32; 16];
//! let bytes = unsafe {
//!     core::slice::from_raw_parts_mut(words.as_mut_ptr() as *mut u8, words.len() * 4)
//! };
//! let mut canvas = Canvas::new(bytes, Dims::new(4, 4), 16, Format::XRGB8888).unwrap();
//! canvas.fill_rect(Rect::new(1, 1, 2, 2), Format::XRGB8888.white());
//! assert_eq!(canvas.read_pixel(1, 1), Some(Format::XRGB8888.white()));
//! ```

use core::{marker::PhantomData, ptr::NonNull};

use crate::{
    format::{Format, Packed},
    geom::{Dims, Rect, RectSet, DEFAULT_SET_CAPACITY},
    ops::{blend_word, PixelOps, ScalarOps},
    view::Source,
};

/// Why a canvas could not be created or a copy refused to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Zero width or height.
    EmptySurface,
    /// A layout the drawing backends do not implement (anything but 24/32 bpp).
    UnsupportedFormat { bits_per_pixel: u8 },
    /// Masks, shifts and width do not form a usable layout.
    InvalidFormat,
    /// `pitch < width * bytes_per_pixel`.
    PitchTooSmall { pitch: usize, required: usize },
    /// The backing store is shorter than `pitch * height`.
    BufferTooSmall { len: usize, required: usize },
    /// 32 bpp requires a 4-byte aligned pitch and base pointer.
    Unaligned,
    /// A bulk copy was attempted between two different native layouts.
    FormatMismatch { dst: Format, src: Format },
    /// Arithmetic overflow while validating the geometry.
    Overflow,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Error::EmptySurface => f.write_str("empty surface"),
            Error::UnsupportedFormat { bits_per_pixel } => {
                write!(f, "unsupported format: {bits_per_pixel} bpp")
            }
            Error::InvalidFormat => f.write_str("invalid pixel format"),
            Error::PitchTooSmall { pitch, required } => {
                write!(f, "pitch {pitch} is smaller than one row ({required})")
            }
            Error::BufferTooSmall { len, required } => {
                write!(f, "buffer of {len} bytes is smaller than {required}")
            }
            Error::Unaligned => f.write_str("unaligned surface"),
            Error::FormatMismatch { dst, src } => {
                write!(f, "format mismatch: dst {dst:?}, src {src:?}")
            }
            Error::Overflow => f.write_str("geometry overflow"),
        }
    }
}

#[cfg(test)]
impl std::error::Error for Error {}

/// A contiguous pixel surface with a validated geometry and format.
///
/// The default ops backend is [`ScalarOps`], which keeps the type usable
/// from a host test. The kernel instantiates `Canvas<'_, KernelOps>` so the
/// SSE2 paths are inlined with no dispatch.
pub struct Canvas<'a, O: PixelOps = ScalarOps> {
    base: *mut u8,
    pitch: usize,
    dims: Dims,
    format: Format,
    wc: bool,
    track_dirty: bool,
    dirty: RectSet<DEFAULT_SET_CAPACITY>,
    ops: O,
    _borrow: PhantomData<&'a mut [u8]>,
}

// A canvas owns exclusive access to its pixels at run time (the `&mut`
// borrow or the `direct` contract). Sending it to another CPU is therefore
// safe as long as the ops value is; the pointer itself is not `Sync`,
// because concurrent reads and writes through the same `&Canvas` are not
// allowed.
unsafe impl<O: PixelOps + Send> Send for Canvas<'_, O> {}

impl<O: PixelOps> core::fmt::Debug for Canvas<'_, O> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Canvas")
            .field("dims", &self.dims)
            .field("pitch", &self.pitch)
            .field("format", &self.format)
            .field("wc", &self.wc)
            .field("dirty", &self.dirty)
            .finish_non_exhaustive()
    }
}

impl<'a> Canvas<'a, ScalarOps> {
    /// Build a scalar-backend canvas over a borrowed buffer.
    ///
    /// `pitch` is a byte count, not a pixel count.
    pub fn new(buf: &'a mut [u8], dims: Dims, pitch: usize, format: Format) -> Result<Self, Error> {
        Self::with_ops(buf, dims, pitch, format, ScalarOps)
    }
}

impl<'a, O: PixelOps> Canvas<'a, O> {
    /// Build a canvas over a borrowed buffer with an explicit ops backend.
    pub fn with_ops(
        buf: &'a mut [u8],
        dims: Dims,
        pitch: usize,
        format: Format,
        ops: O,
    ) -> Result<Self, Error> {
        validate(dims, pitch, format)?;
        let base = buf.as_mut_ptr();
        validate_alignment(base as usize, format)?;
        let required = required_len(pitch, dims)?;
        if buf.len() < required {
            return Err(Error::BufferTooSmall {
                len: buf.len(),
                required,
            });
        }
        // SAFETY: the pointer and length were just validated, and the
        // borrow ties the canvas to `buf`.
        Ok(unsafe { Self::from_raw(base, dims, pitch, format, false, ops) })
    }

    /// Build a canvas over physical framebuffer memory.
    ///
    /// `base` is the HHDM-mapped virtual address, already validated by the
    /// caller (page-aligned and mapped for `pitch * height` bytes).
    ///
    /// # Safety
    ///
    /// `base` must stay mapped and exclusively owned by this canvas for the
    /// whole lifetime of the value, and `pitch * height` must not wrap.
    pub unsafe fn direct(
        base: NonNull<u8>,
        dims: Dims,
        pitch: usize,
        format: Format,
        write_combining: bool,
        ops: O,
    ) -> Result<Self, Error> {
        validate(dims, pitch, format)?;
        validate_alignment(base.as_ptr() as usize, format)?;
        required_len(pitch, dims)?;
        // SAFETY: forwarded to the caller.
        Ok(unsafe { Self::from_raw(base.as_ptr(), dims, pitch, format, write_combining, ops) })
    }

    unsafe fn from_raw(
        base: *mut u8,
        dims: Dims,
        pitch: usize,
        format: Format,
        wc: bool,
        ops: O,
    ) -> Self {
        Self {
            base,
            pitch,
            dims,
            format,
            wc,
            track_dirty: true,
            dirty: RectSet::empty(),
            ops,
            _borrow: PhantomData,
        }
    }

    // -- accessors ---------------------------------------------------------

    #[inline]
    pub fn dims(&self) -> Dims {
        self.dims
    }

    #[inline]
    pub fn format(&self) -> Format {
        self.format
    }

    /// Bytes per row.
    #[inline]
    pub fn pitch(&self) -> usize {
        self.pitch
    }

    /// Bytes from the start of one row to the start of the same column in
    /// the next row.
    #[inline]
    pub fn bytes_per_pixel(&self) -> usize {
        self.format.bytes_per_pixel()
    }

    #[inline]
    pub fn is_write_combining(&self) -> bool {
        self.wc
    }

    /// Mark the surface as write-combining (MMIO framebuffer). Drawing then
    /// uses the non-temporal stores and fences once per call.
    #[inline]
    pub fn set_write_combining(&mut self, wc: bool) {
        self.wc = wc;
    }

    /// The whole surface, as a rectangle.
    #[inline]
    pub fn bounds(&self) -> Rect {
        Rect::new(0, 0, self.dims.w, self.dims.h)
    }

    #[inline]
    pub fn ops(&self) -> &O {
        &self.ops
    }

    #[inline]
    pub fn ops_mut(&mut self) -> &mut O {
        &mut self.ops
    }

    // -- clipping and damage ----------------------------------------------

    /// Clip a rectangle to this surface. `None` means nothing to draw.
    ///
    /// This is the only clipping rule in the crate.
    #[inline]
    pub fn clip(&self, rect: Rect) -> Option<Rect> {
        let clipped = rect.intersect(self.bounds());
        if clipped.is_empty() {
            None
        } else {
            Some(clipped)
        }
    }

    /// Enable or disable dirty-rectangle tracking. Enabled by default:
    /// the cost is one bounded insertion per drawing call.
    #[inline]
    pub fn set_tracking(&mut self, on: bool) {
        self.track_dirty = on;
        if !on {
            self.dirty.clear();
        }
    }

    #[inline]
    pub fn is_tracking(&self) -> bool {
        self.track_dirty
    }

    #[inline]
    pub fn dirty(&self) -> &RectSet<DEFAULT_SET_CAPACITY> {
        &self.dirty
    }

    /// Take the accumulated damage, leaving the set empty.
    #[inline]
    pub fn take_dirty(&mut self) -> RectSet<DEFAULT_SET_CAPACITY> {
        core::mem::take(&mut self.dirty)
    }

    #[inline]
    pub fn clear_dirty(&mut self) {
        self.dirty.clear();
    }

    #[inline]
    fn mark(&mut self, rect: Rect) {
        if self.track_dirty {
            self.dirty.include(rect);
        }
    }

    /// Fence the stores of a write-combining surface.
    ///
    /// Called once per public drawing call; callers that emit their own
    /// stores must call it before the pixels are read.
    #[inline]
    pub fn fence(&self) {
        if !self.wc {
            return;
        }
        #[cfg(target_arch = "x86_64")]
        // SAFETY: `sfence` has no operand and no memory side effect beyond
        // ordering, which is exactly what is wanted.
        unsafe {
            core::arch::asm!("sfence", options(nostack, preserves_flags));
        }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: `dsb st` is a barrier instruction with no operands.
        unsafe {
            core::arch::asm!("dsb st", options(nostack, preserves_flags));
        }
    }

    // -- raw pixel access --------------------------------------------------

    #[inline]
    pub(crate) fn row_ptr(&self, y: u32) -> *mut u8 {
        // SAFETY: `y < height` and `pitch * height` fits the backing store
        // by construction.
        unsafe { self.base.add(y as usize * self.pitch) }
    }

    /// Read a pixel. Coordinates must be inside the surface.
    ///
    /// Volatile on a write-combining (MMIO) surface: the value may have been
    /// changed by the device since the last cached load.
    #[inline]
    fn read_raw(&self, x: u32, y: u32) -> u32 {
        let ptr = self.row_ptr(y);
        match self.format.bytes_per_pixel() {
            4 => {
                // SAFETY: in bounds, 4-byte aligned surface.
                unsafe {
                    let p = ptr.add(x as usize * 4) as *const u32;
                    if self.wc {
                        core::ptr::read_volatile(p)
                    } else {
                        p.read_unaligned()
                    }
                }
            }
            3 => {
                // SAFETY: in bounds; 24 bpp has no alignment requirement.
                unsafe {
                    let p = ptr.add(x as usize * 3);
                    if self.wc {
                        core::ptr::read_volatile(p) as u32
                            | (core::ptr::read_volatile(p.add(1)) as u32) << 8
                            | (core::ptr::read_volatile(p.add(2)) as u32) << 16
                    } else {
                        p.read() as u32
                            | (p.add(1).read() as u32) << 8
                            | (p.add(2).read() as u32) << 16
                    }
                }
            }
            _ => 0,
        }
    }

    /// Write a pixel. Coordinates must be inside the surface. Volatile on a
    /// write-combining (MMIO) surface.
    #[inline]
    fn write_raw(&mut self, x: u32, y: u32, value: u32) {
        let ptr = self.row_ptr(y);
        match self.format.bytes_per_pixel() {
            4 => {
                // SAFETY: in bounds, 4-byte aligned surface.
                unsafe {
                    let p = ptr.add(x as usize * 4) as *mut u32;
                    if self.wc {
                        core::ptr::write_volatile(p, value)
                    } else {
                        p.write_unaligned(value)
                    }
                }
            }
            3 => {
                // SAFETY: in bounds; 24 bpp has no alignment requirement.
                unsafe {
                    let p = ptr.add(x as usize * 3);
                    if self.wc {
                        core::ptr::write_volatile(p, value as u8);
                        core::ptr::write_volatile(p.add(1), (value >> 8) as u8);
                        core::ptr::write_volatile(p.add(2), (value >> 16) as u8);
                    } else {
                        p.write(value as u8);
                        p.add(1).write((value >> 8) as u8);
                        p.add(2).write((value >> 16) as u8);
                    }
                }
            }
            _ => {}
        }
    }

    /// Read one pixel. Volatile, because the surface may be MMIO.
    pub fn read_pixel(&self, x: u32, y: u32) -> Option<Packed> {
        if x >= self.dims.w || y >= self.dims.h {
            return None;
        }
        let ptr = self.row_ptr(y);
        let value = match self.format.bytes_per_pixel() {
            4 => {
                // SAFETY: in bounds.
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

    /// Write one pixel. Volatile, because the surface may be MMIO.
    pub fn write_pixel(&mut self, x: u32, y: u32, pixel: Packed) -> bool {
        if x >= self.dims.w || y >= self.dims.h {
            return false;
        }
        let ptr = self.row_ptr(y);
        match self.format.bytes_per_pixel() {
            4 => {
                // SAFETY: in bounds.
                unsafe {
                    core::ptr::write_volatile(ptr.add(x as usize * 4) as *mut u32, pixel.value());
                }
            }
            3 => {
                // SAFETY: in bounds.
                unsafe {
                    let p = ptr.add(x as usize * 3);
                    let v = pixel.value();
                    core::ptr::write_volatile(p, v as u8);
                    core::ptr::write_volatile(p.add(1), (v >> 8) as u8);
                    core::ptr::write_volatile(p.add(2), (v >> 16) as u8);
                }
            }
            _ => return false,
        }
        self.fence();
        self.mark(Rect::new(x, y, 1, 1));
        true
    }

    // -- drawing -----------------------------------------------------------

    /// Fill `rect` (clipped) with a packed colour. Returns the rectangle
    /// actually written, or `None` when entirely outside.
    pub fn fill_rect(&mut self, rect: Rect, color: Packed) -> Option<Rect> {
        let clipped = self.clip(rect)?;
        let guard = self.ops.guard();
        let value = color.value();
        match self.format.bytes_per_pixel() {
            4 => {
                let y_end = clipped.bottom();
                for y in clipped.y..y_end {
                    let row = self.row_ptr(y);
                    // SAFETY: clipped.x + clipped.w <= width, and the row
                    // has at least `width` pixels.
                    unsafe {
                        let dst = row.add(clipped.x as usize * 4) as *mut u32;
                        if self.wc {
                            self.ops.fill_nt(dst, value, clipped.w as usize);
                        } else {
                            self.ops.fill(dst, value, clipped.w as usize);
                        }
                    }
                }
            }
            3 => {
                let y_end = clipped.bottom();
                for y in clipped.y..y_end {
                    for x in clipped.x..clipped.right() {
                        // Honors the write-combining flag per byte.
                        self.write_raw(x, y, value);
                    }
                }
            }
            _ => return None,
        }
        drop(guard);
        self.fence();
        self.mark(clipped);
        Some(clipped)
    }

    /// Fill the whole surface. Convenience over [`Self::fill_rect`].
    pub fn fill(&mut self, color: Packed) -> Rect {
        let bounds = self.bounds();
        self.fill_rect(bounds, color).unwrap_or(Rect::EMPTY)
    }

    /// Copy `src_rect` from `src` into `dst` on this surface.
    ///
    /// Both formats must be identical: a bulk copy must not silently
    /// reinterpret channels. Clipping is applied to the destination and to
    /// the source, and `src_rect`'s origin is shifted accordingly.
    ///
    /// Returns the destination rectangle written, or `None` when nothing was
    /// visible.
    pub fn blit<S: Source + ?Sized>(
        &mut self,
        dst: Rect,
        src: &S,
        src_rect: Rect,
    ) -> Result<Option<Rect>, Error> {
        if !self.format.compatible(src.format()) {
            return Err(Error::FormatMismatch {
                dst: self.format,
                src: src.format(),
            });
        }
        let Some((d, sx, sy)) = self.map_rect(dst, src.dims(), src_rect) else {
            return Ok(None);
        };
        let guard = self.ops.guard();
        match self.format.bytes_per_pixel() {
            4 => {
                // One contiguous copy when both rectangles span a full row
                // of their surface: this is the common full-frame present.
                if self.is_contiguous(d, sx, src) {
                    let dst_ptr = self.row_ptr(d.y) as *mut u32;
                    // SAFETY: `sy + d.h <= src.dims().h` by `map_rect`.
                    let src_ptr = unsafe { src.row_ptr(sy) } as *const u32;
                    let count = d.area() as usize;
                    // SAFETY: both buffers hold `count` pixels.
                    unsafe {
                        if self.wc {
                            self.ops.blit_nt(dst_ptr, src_ptr, count);
                        } else {
                            self.ops.blit(dst_ptr, src_ptr, count);
                        }
                    }
                } else {
                    for row in 0..d.h {
                        let dst_row = self.row_ptr(d.y + row);
                        // SAFETY: `sy + row < src.dims().h` by `map_rect`.
                        let src_row = unsafe { src.row_ptr(sy + row) };
                        // SAFETY: both rectangles were clipped to their
                        // surfaces; the rows hold at least `d.w` pixels.
                        unsafe {
                            let dst_ptr = dst_row.add(d.x as usize * 4) as *mut u32;
                            let src_ptr = src_row.add(sx as usize * 4) as *const u32;
                            if self.wc {
                                self.ops.blit_nt(dst_ptr, src_ptr, d.w as usize);
                            } else {
                                self.ops.blit(dst_ptr, src_ptr, d.w as usize);
                            }
                        }
                    }
                }
            }
            3 => {
                if self.wc {
                    // Per-byte volatile copies: a MMIO 24 bpp scanout must
                    // not be written through cached stores.
                    for row in 0..d.h {
                        let y = d.y + row;
                        for x in 0..d.w {
                            // SAFETY: clipped to both surfaces.
                            let packed = unsafe { src.read_raw(sx + x, sy + row) };
                            self.write_raw(d.x + x, y, packed);
                        }
                    }
                } else {
                    for row in 0..d.h {
                        let dst_row = self.row_ptr(d.y + row);
                        // SAFETY: `sy + row < src.dims().h` by `map_rect`.
                        let src_row = unsafe { src.row_ptr(sy + row) };
                        // SAFETY: in bounds; the byte ranges are disjoint
                        // because `src` and `self` cannot alias by borrow
                        // rules.
                        unsafe {
                            let dst_ptr = dst_row.add(d.x as usize * 3);
                            let src_ptr = src_row.add(sx as usize * 3);
                            core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, d.w as usize * 3);
                        }
                    }
                }
            }
            _ => return Ok(None),
        }
        drop(guard);
        self.fence();
        self.mark(d);
        Ok(Some(d))
    }

    /// Blend an optional constant alpha.
    ///
    /// With `alpha == 255` this is a plain copy; with `alpha == 0` the
    /// destination is unchanged, so the call returns `None` without touching
    /// the surface or recording damage. The blend is per byte of the native
    /// word, matching the kernel's `FramebufferOps::blend`.
    pub fn blend_rect<S: Source + ?Sized>(
        &mut self,
        dst: Rect,
        src: &S,
        src_rect: Rect,
        alpha: u8,
    ) -> Result<Option<Rect>, Error> {
        if !self.format.compatible(src.format()) {
            return Err(Error::FormatMismatch {
                dst: self.format,
                src: src.format(),
            });
        }
        if alpha == 0 {
            return Ok(None);
        }
        let Some((d, sx, sy)) = self.map_rect(dst, src.dims(), src_rect) else {
            return Ok(None);
        };
        let guard = self.ops.guard();
        match self.format.bytes_per_pixel() {
            4 => {
                if self.is_contiguous(d, sx, src) {
                    let dst_ptr = self.row_ptr(d.y) as *mut u32;
                    // SAFETY: `sy + d.h <= src.dims().h` by `map_rect`.
                    let src_ptr = unsafe { src.row_ptr(sy) } as *const u32;
                    let count = d.area() as usize;
                    // SAFETY: both buffers hold `count` pixels.
                    unsafe {
                        if alpha == 255 {
                            if self.wc {
                                self.ops.blit_nt(dst_ptr, src_ptr, count);
                            } else {
                                self.ops.blit(dst_ptr, src_ptr, count);
                            }
                        } else {
                            self.ops.blend(dst_ptr, src_ptr, alpha, count);
                        }
                    }
                } else {
                    for row in 0..d.h {
                        let dst_row = self.row_ptr(d.y + row);
                        // SAFETY: `sy + row < src.dims().h` by `map_rect`.
                        let src_row = unsafe { src.row_ptr(sy + row) };
                        // SAFETY: clipped to both surfaces.
                        unsafe {
                            let dst_ptr = dst_row.add(d.x as usize * 4) as *mut u32;
                            let src_ptr = src_row.add(sx as usize * 4) as *const u32;
                            if alpha == 255 {
                                if self.wc {
                                    self.ops.blit_nt(dst_ptr, src_ptr, d.w as usize);
                                } else {
                                    self.ops.blit(dst_ptr, src_ptr, d.w as usize);
                                }
                            } else {
                                self.ops.blend(dst_ptr, src_ptr, alpha, d.w as usize);
                            }
                        }
                    }
                }
            }
            3 => {
                let a = alpha as u32;
                let inv = 255 - a;
                for row in 0..d.h {
                    let y = d.y + row;
                    for x in 0..d.w {
                        // SAFETY: clipped to both surfaces.
                        let s = unsafe { src.read_raw(sx + x, sy + row) };
                        let dpx = self.read_raw(d.x + x, y);
                        self.write_raw(d.x + x, y, blend_word(dpx, s, a, inv));
                    }
                }
            }
            _ => return Ok(None),
        }
        drop(guard);
        self.fence();
        self.mark(d);
        Ok(Some(d))
    }

    /// Copy from a surface that may have a different format.
    ///
    /// This is the crate's only per-pixel conversion path: each source
    /// pixel is decoded with [`Format::unpack`] and re-encoded with
    /// [`Format::pack`]. Prefer [`Self::blit`] when the formats match.
    pub fn convert_from<S: Source + ?Sized>(
        &mut self,
        dst: Rect,
        src: &S,
        src_rect: Rect,
    ) -> Result<Option<Rect>, Error> {
        if self.format.compatible(src.format()) {
            return self.blit(dst, src, src_rect);
        }
        let Some((d, sx, sy)) = self.map_rect(dst, src.dims(), src_rect) else {
            return Ok(None);
        };
        let guard = self.ops.guard();
        let src_format = src.format();
        let dst_format = self.format;
        for row in 0..d.h {
            for x in 0..d.w {
                // SAFETY: clipped to both surfaces.
                let packed = unsafe { src.read_raw(sx + x, sy + row) };
                let converted = dst_format.convert(src_format, Packed::raw(packed));
                self.write_raw(d.x + x, d.y + row, converted.value());
            }
        }
        drop(guard);
        self.fence();
        self.mark(d);
        Ok(Some(d))
    }

    /// Copy the whole surface into `dst` at `origin`, with the same format
    /// rules as [`Self::blit`].
    pub fn copy_to<O2: PixelOps>(
        &self,
        dst: &mut Canvas<'_, O2>,
        origin: (u32, u32),
    ) -> Result<Option<Rect>, Error> {
        let bounds = self.bounds();
        dst.blit(
            Rect::new(origin.0, origin.1, bounds.w, bounds.h),
            self,
            bounds,
        )
    }

    /// True when `d` spans a full row of both surfaces and both pitches have
    /// no padding, so the whole block is contiguous in memory.
    fn is_contiguous<S: Source + ?Sized>(&self, d: Rect, sx: u32, src: &S) -> bool {
        let src_dims = src.dims();
        self.pitch == self.dims.w as usize * 4
            && src.pitch() == src_dims.w as usize * 4
            && d.x == 0
            && sx == 0
            && d.w == self.dims.w
            && d.w == src_dims.w
    }

    /// Map a requested copy onto the destination and source surfaces.
    ///
    /// Returns the clipped destination rectangle plus the source origin to
    /// start from. This is what keeps a partially off-screen blit correct:
    /// clipping the destination shifts the source window by the same
    /// amount, it never stretches or re-anchors the image.
    fn map_rect(&self, dst: Rect, src_dims: Dims, src_rect: Rect) -> Option<(Rect, u32, u32)> {
        if dst.is_empty() || src_rect.is_empty() {
            return None;
        }
        let requested = Rect::new(dst.x, dst.y, dst.w.min(src_rect.w), dst.h.min(src_rect.h));
        let clipped = requested.intersect(self.bounds());
        if clipped.is_empty() {
            return None;
        }
        let sx = src_rect.x.saturating_add(clipped.x - dst.x);
        let sy = src_rect.y.saturating_add(clipped.y - dst.y);
        if sx >= src_dims.w || sy >= src_dims.h {
            return None;
        }
        let w = clipped.w.min(src_dims.w - sx);
        let h = clipped.h.min(src_dims.h - sy);
        if w == 0 || h == 0 {
            return None;
        }
        Some((Rect::new(clipped.x, clipped.y, w, h), sx, sy))
    }
}

pub(crate) fn validate(dims: Dims, pitch: usize, format: Format) -> Result<(), Error> {
    if dims.is_empty() {
        return Err(Error::EmptySurface);
    }
    if !format.is_supported() {
        return Err(Error::UnsupportedFormat {
            bits_per_pixel: format.bits_per_pixel(),
        });
    }
    if !format.is_valid() {
        return Err(Error::InvalidFormat);
    }
    let row = (dims.w as usize)
        .checked_mul(format.bytes_per_pixel())
        .ok_or(Error::Overflow)?;
    if pitch < row {
        return Err(Error::PitchTooSmall {
            pitch,
            required: row,
        });
    }
    // The 32 bpp backends write `u32` words, so every row must start on a
    // 4-byte boundary. A base alignment check alone is not enough: an
    // odd pitch would leave row 1 unaligned.
    if format.bits_per_pixel() == 32 && !pitch.is_multiple_of(4) {
        return Err(Error::Unaligned);
    }
    required_len(pitch, dims)?;
    Ok(())
}

pub(crate) fn required_len(pitch: usize, dims: Dims) -> Result<usize, Error> {
    pitch.checked_mul(dims.h as usize).ok_or(Error::Overflow)
}

pub(crate) fn validate_alignment(base: usize, format: Format) -> Result<(), Error> {
    if format.bits_per_pixel() == 32 && !base.is_multiple_of(4) {
        return Err(Error::Unaligned);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::Rgb;

    /// A 32 bpp buffer backed by `u32`, which guarantees the alignment the
    /// canvas requires.
    struct Pixels {
        words: alloc::vec::Vec<u32>,
    }

    impl Pixels {
        fn new(w: u32, h: u32) -> Self {
            Self {
                words: alloc::vec![0u32; (w * h) as usize],
            }
        }

        fn bytes(&mut self) -> &mut [u8] {
            // SAFETY: `u32` has no padding and the length is exact.
            unsafe {
                core::slice::from_raw_parts_mut(
                    self.words.as_mut_ptr() as *mut u8,
                    self.words.len() * 4,
                )
            }
        }
    }

    extern crate alloc;

    const W: u32 = 8;
    const H: u32 = 8;

    fn with_canvas<T>(
        f: impl FnOnce(&mut Canvas<'_, ScalarOps>) -> T,
    ) -> (T, alloc::vec::Vec<u32>) {
        let mut pixels = Pixels::new(W, H);
        let result = {
            let mut canvas = Canvas::new(
                pixels.bytes(),
                Dims::new(W, H),
                (W * 4) as usize,
                Format::XRGB8888,
            )
            .unwrap();
            f(&mut canvas)
        };
        (result, pixels.words)
    }

    #[test]
    fn fill_is_clipped_to_the_surface() {
        let (written, words) =
            with_canvas(|c| c.fill_rect(Rect::new(6, 6, 10, 10), Format::XRGB8888.white()));
        assert_eq!(written, Some(Rect::new(6, 6, 2, 2)));
        assert_eq!(words[6 * W as usize + 6], 0xFFFF_FFFF);
        assert_eq!(words[7 * W as usize + 7], 0xFFFF_FFFF);
        assert_eq!(words[5 * W as usize + 5], 0);
    }

    #[test]
    fn fill_outside_draws_nothing() {
        let (written, words) =
            with_canvas(|c| c.fill_rect(Rect::new(8, 0, 4, 4), Format::XRGB8888.white()));
        assert_eq!(written, None);
        assert!(words.iter().all(|&p| p == 0));
    }

    #[test]
    fn dirty_rect_is_the_clipped_one() {
        let (dirty, _) = with_canvas(|c| {
            c.fill_rect(Rect::new(6, 6, 10, 10), Format::XRGB8888.white());
            let mut set = c.take_dirty();
            set.include(Rect::new(1, 1, 2, 2));
            (set.bounds(), set.len())
        });
        assert_eq!(dirty, (Rect::new(1, 1, 7, 7), 2));
    }

    #[test]
    fn blit_shifts_source_when_destination_is_clipped() {
        let mut src_px = Pixels::new(4, 4);
        let mut dst_px = Pixels::new(W, H);
        let src_rect = {
            let mut src =
                Canvas::new(src_px.bytes(), Dims::new(4, 4), 16, Format::XRGB8888).unwrap();
            for y in 0..4 {
                for x in 0..4 {
                    src.write_pixel(x, y, Format::XRGB8888.rgb(x as u8, y as u8, 0));
                }
            }
            // Destination starts at the origin: the first source column
            // must not be lost, only the off-screen ones.
            let mut dst = Canvas::new(
                dst_px.bytes(),
                Dims::new(W, H),
                (W * 4) as usize,
                Format::XRGB8888,
            )
            .unwrap();
            let written = dst
                .blit(Rect::new(0, 0, 4, 4), &src, Rect::new(1, 1, 4, 4))
                .unwrap();
            assert_eq!(written, Some(Rect::new(0, 0, 3, 3)));
            written
        };
        assert!(src_rect.is_some());
        assert_eq!(dst_px.words[0], Format::XRGB8888.rgb(1, 1, 0).value());
        assert_eq!(
            dst_px.words[2 * W as usize + 2],
            Format::XRGB8888.rgb(3, 3, 0).value()
        );
    }

    #[test]
    fn blit_keeps_pixels_outside_the_destination() {
        let mut src_px = Pixels::new(4, 4);
        let mut dst_px = Pixels::new(W, H);
        {
            let mut src =
                Canvas::new(src_px.bytes(), Dims::new(4, 4), 16, Format::XRGB8888).unwrap();
            src.fill(Format::XRGB8888.white());
            let mut dst = Canvas::new(
                dst_px.bytes(),
                Dims::new(W, H),
                (W * 4) as usize,
                Format::XRGB8888,
            )
            .unwrap();
            let written = dst
                .blit(Rect::new(6, 6, 4, 4), &src, Rect::new(0, 0, 4, 4))
                .unwrap();
            assert_eq!(written, Some(Rect::new(6, 6, 2, 2)));
        }
        assert_eq!(dst_px.words[6 * W as usize + 6], 0xFFFF_FFFF);
        assert_eq!(dst_px.words[5 * W as usize + 5], 0);
    }

    #[test]
    fn blit_refuses_a_format_mismatch() {
        let mut a_px = Pixels::new(2, 2);
        let mut b_px = Pixels::new(2, 2);
        let mut a = Canvas::new(a_px.bytes(), Dims::new(2, 2), 8, Format::XRGB8888).unwrap();
        let b = Canvas::new(b_px.bytes(), Dims::new(2, 2), 6, Format::RGB888).unwrap();
        let err = a
            .blit(Rect::new(0, 0, 2, 2), &b, Rect::new(0, 0, 2, 2))
            .unwrap_err();
        assert!(matches!(err, Error::FormatMismatch { .. }));
    }

    #[test]
    fn blend_half_white_over_black() {
        let mut src_px = Pixels::new(2, 2);
        let mut dst_px = Pixels::new(2, 2);
        {
            let mut src =
                Canvas::new(src_px.bytes(), Dims::new(2, 2), 8, Format::XRGB8888).unwrap();
            src.fill(Format::XRGB8888.white());
            let mut dst =
                Canvas::new(dst_px.bytes(), Dims::new(2, 2), 8, Format::XRGB8888).unwrap();
            dst.blend_rect(Rect::new(0, 0, 2, 2), &src, Rect::new(0, 0, 2, 2), 128)
                .unwrap();
        }
        let px = dst_px.words[0];
        let rgb = Format::XRGB8888.unpack(Packed::raw(px));
        assert!(rgb.r >= 127 && rgb.r <= 129, "r = {}", rgb.r);
    }

    #[test]
    fn rgb888_blit_clips_at_the_edge() {
        let mut src_buf = [0u8; 2 * 2 * 3];
        for (i, byte) in src_buf.iter_mut().enumerate() {
            *byte = i as u8 + 1;
        }
        let mut dst_buf = [0u8; 4 * 4 * 3];
        {
            let src = Canvas::new(&mut src_buf, Dims::new(2, 2), 6, Format::RGB888).unwrap();
            let mut dst = Canvas::new(&mut dst_buf, Dims::new(4, 4), 12, Format::RGB888).unwrap();
            let written = dst
                .blit(Rect::new(3, 3, 2, 2), &src, Rect::new(0, 0, 2, 2))
                .unwrap();
            assert_eq!(written, Some(Rect::new(3, 3, 1, 1)));
        }
        let dst_off = (3 * 4 + 3) * 3;
        assert_eq!(&dst_buf[dst_off..dst_off + 3], &src_buf[0..3]);
    }

    #[test]
    fn blend_alpha_zero_is_a_noop() {
        let mut src_px = Pixels::new(2, 2);
        let mut dst_px = Pixels::new(2, 2);
        {
            let mut src =
                Canvas::new(src_px.bytes(), Dims::new(2, 2), 8, Format::XRGB8888).unwrap();
            src.fill(Format::XRGB8888.white());
            let mut dst =
                Canvas::new(dst_px.bytes(), Dims::new(2, 2), 8, Format::XRGB8888).unwrap();
            assert_eq!(
                dst.blend_rect(Rect::new(0, 0, 2, 2), &src, Rect::new(0, 0, 2, 2), 0)
                    .unwrap(),
                None
            );
            assert!(dst.dirty().is_empty());
        }
        assert!(dst_px.words.iter().all(|&w| w == 0));
    }

    #[test]
    fn constructor_rejects_an_invalid_format() {
        let mut pixels = Pixels::new(2, 2);
        let bad = Format::from_masks(32, 0x00FF_0000, 8, 0, 0, 0, 0);
        assert_eq!(
            Canvas::new(pixels.bytes(), Dims::new(2, 2), 8, bad).unwrap_err(),
            Error::InvalidFormat
        );
    }

    #[test]
    fn convert_from_changes_layout() {
        let mut src_px = Pixels::new(2, 2);
        let mut dst_px = Pixels::new(2, 2);
        {
            let mut src =
                Canvas::new(src_px.bytes(), Dims::new(2, 2), 8, Format::BGRX8888).unwrap();
            src.fill(Format::BGRX8888.pack(Rgb::new(0x10, 0x20, 0x30)));
            let mut dst =
                Canvas::new(dst_px.bytes(), Dims::new(2, 2), 8, Format::XRGB8888).unwrap();
            dst.convert_from(Rect::new(0, 0, 2, 2), &src, Rect::new(0, 0, 2, 2))
                .unwrap();
        }
        assert_eq!(
            Format::XRGB8888.unpack(Packed::raw(dst_px.words[0])),
            Rgb::new(0x10, 0x20, 0x30)
        );
    }

    #[test]
    fn zero_sized_inputs_are_noops() {
        let (res, _) = with_canvas(|c| {
            assert_eq!(c.fill_rect(Rect::EMPTY, Format::XRGB8888.white()), None);
            assert_eq!(c.clip(Rect::new(100, 100, 0, 10)), None);
        });
        assert_eq!(res, ());
    }

    #[test]
    fn constructor_rejects_bad_geometry() {
        let mut buf = [0u8; 64];
        assert_eq!(
            Canvas::new(&mut buf, Dims::new(4, 4), 4, Format::XRGB8888).unwrap_err(),
            Error::PitchTooSmall {
                pitch: 4,
                required: 16
            }
        );
        assert_eq!(
            Canvas::new(&mut buf, Dims::new(8, 8), 32, Format::XRGB8888).unwrap_err(),
            Error::BufferTooSmall {
                len: 64,
                required: 256
            }
        );
        assert_eq!(
            Canvas::new(&mut buf, Dims::new(4, 4), 16, Format::RGB565).unwrap_err(),
            Error::UnsupportedFormat { bits_per_pixel: 16 }
        );
        assert_eq!(
            Canvas::new(&mut buf, Dims::ZERO, 16, Format::XRGB8888).unwrap_err(),
            Error::EmptySurface
        );
    }

    #[test]
    fn constructor_rejects_unaligned_32bpp() {
        let mut buf = [0u8; 64];
        let unaligned = &mut buf[1..];
        assert_eq!(
            Canvas::new(unaligned, Dims::new(2, 2), 8, Format::XRGB8888).unwrap_err(),
            Error::Unaligned
        );
    }

    #[test]
    fn constructor_rejects_an_unaligned_32bpp_pitch() {
        let mut pixels = Pixels::new(4, 4);
        // Base is 4-byte aligned, but a pitch of 10 puts row 1 at +10.
        assert_eq!(
            Canvas::new(pixels.bytes(), Dims::new(2, 2), 10, Format::XRGB8888).unwrap_err(),
            Error::Unaligned
        );
        // A multiple of 4 is accepted.
        assert!(Canvas::new(pixels.bytes(), Dims::new(2, 2), 12, Format::XRGB8888).is_ok());
    }

    #[test]
    fn blit_from_view_copies_without_touching_the_source() {
        use crate::view::View;

        let words = [
            Format::XRGB8888.rgb(1, 2, 3).value(),
            Format::XRGB8888.rgb(4, 5, 6).value(),
        ];
        // SAFETY: `u32` has no padding.
        let bytes =
            unsafe { core::slice::from_raw_parts(words.as_ptr() as *const u8, words.len() * 4) };
        let view = View::new(bytes, Dims::new(2, 1), 8, Format::XRGB8888).unwrap();
        let (written, dst) = with_canvas(|c| {
            c.blit(Rect::new(1, 1, 2, 1), &view, Rect::new(0, 0, 2, 1))
                .unwrap()
        });
        assert_eq!(written, Some(Rect::new(1, 1, 2, 1)));
        assert_eq!(dst[W as usize + 1], words[0]);
        assert_eq!(dst[W as usize + 2], words[1]);
        assert_eq!(dst[W as usize], 0);
    }

    #[test]
    fn tracking_can_be_disabled() {
        let (len, _) = with_canvas(|c| {
            c.set_tracking(false);
            c.fill(Format::XRGB8888.white());
            c.dirty().len()
        });
        assert_eq!(len, 0);
    }
}
