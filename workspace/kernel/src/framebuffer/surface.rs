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

//! Kernel adapter for the `fbsurface` crate.
//!
//! `fbsurface` owns the geometry, the format rules and the clipping. This
//! module supplies the two pieces that are kernel-specific:
//!
//! - [`KernelOps`], which forwards the 32-bit primitives to the existing
//!   SSE2/AVX2/scalar backend in [`FramebufferOps`] and returns an
//!   [`FpuGuard`] so every drawing call preserves the caller's SSE state;
//! - [`Presenter`], which owns the write-combining framebuffer surface and
//!   the refresh policy (`PRESENT_MIN_TICKS`), and copies damaged rectangles
//!   from a back surface.
//!
//! The intended split is: buffers and damage are `fbsurface` types, the
//! refresh policy is [`Presenter`], and the raw pixels stay behind
//! [`FramebufferOps`].
//!
//! # Example
//!
//! ```ignore
//! # use core::ptr::NonNull;
//! # use fbsurface::{Canvas, Dims, Format, Rect};
//! # use crate::framebuffer::{FramebufferOps, KernelOps};
//! # fn ops() -> FramebufferOps { unimplemented!() }
//! # unsafe fn demo(base: NonNull<u8>) {
//! let surface: Canvas<'_, KernelOps> = unsafe {
//!     Canvas::direct(
//!         base,
//!         Dims::new(1920, 1080),
//!         1920 * 4,
//!         Format::XRGB8888,
//!         /* write_combining = */ true,
//!         KernelOps::new(ops()),
//!     )
//! }
//! .unwrap();
//! # let _ = surface;
//! # }
//! ```

use core::ptr::NonNull;

use fbsurface::{Canvas, Dims, Format, OwnedSurface, PixelGuard, PixelOps, Rect, RectSet, Source};

use crate::framebuffer::{FpuGuard, FramebufferOps, MAX_DIRTY_RECTS, PRESENT_MIN_TICKS};

/// Pixel backend backed by the kernel's [`FramebufferOps`] function table.
///
/// The FPU guard is created inside the trait, so a caller cannot forget it:
/// every `fbsurface` drawing call passes through [`PixelOps::guard`] before
/// touching a pixel.
#[derive(Clone, Copy)]
pub struct KernelOps {
    inner: FramebufferOps,
}

impl KernelOps {
    #[inline]
    pub const fn new(inner: FramebufferOps) -> Self {
        Self { inner }
    }

    #[inline]
    pub const fn inner(&self) -> FramebufferOps {
        self.inner
    }
}

// Boundary conversions: the legacy `PixelFormat` is still what the GOP
// parser and `FramebufferInfo` carry. Keeping the conversion here means
// there is exactly one place where the two representations meet.
impl From<crate::hardware::video::framebuffer::PixelFormat> for Format {
    fn from(p: crate::hardware::video::framebuffer::PixelFormat) -> Self {
        Format::from_masks(
            p.bits_per_pixel,
            p.red_mask,
            p.red_shift,
            p.green_mask,
            p.green_shift,
            p.blue_mask,
            p.blue_shift,
        )
    }
}

impl From<Format> for crate::hardware::video::framebuffer::PixelFormat {
    fn from(f: Format) -> Self {
        Self {
            red_mask: f.red_mask(),
            red_shift: f.red_shift(),
            green_mask: f.green_mask(),
            green_shift: f.green_shift(),
            blue_mask: f.blue_mask(),
            blue_shift: f.blue_shift(),
            bits_per_pixel: f.bits_per_pixel(),
        }
    }
}

/// `FpuGuard` is a local type, so the marker trait from `fbsurface` can be
/// implemented here.
impl PixelGuard for FpuGuard {}

impl PixelOps for KernelOps {
    type Guard = FpuGuard;

    #[inline]
    fn guard(&self) -> FpuGuard {
        // SSE2 pixel paths clobber XMM registers; the guard restores the
        // interrupted/caller state on drop. AVX (YMM) is not preserved, so
        // no AVX path may be added until this switches to XSAVE.
        FpuGuard::save()
    }

    unsafe fn fill(&self, dst: *mut u32, color: u32, count: usize) {
        // SAFETY: forwarded from the `PixelOps` contract; the function
        // pointer is one of the validated backends selected at boot.
        unsafe { (self.inner.fill)(dst, color, count) }
    }

    unsafe fn blit(&self, dst: *mut u32, src: *const u32, count: usize) {
        // SAFETY: see `fill`.
        unsafe { (self.inner.blit)(dst, src, count) }
    }

    unsafe fn blend(&self, dst: *mut u32, src: *const u32, alpha: u8, count: usize) {
        // SAFETY: see `fill`.
        unsafe { (self.inner.blend)(dst, src, alpha, count) }
    }

    unsafe fn fill_nt(&self, dst: *mut u32, color: u32, count: usize) {
        // SAFETY: see `fill`; `Canvas` only selects this path when the
        // surface is flagged write-combining.
        unsafe { (self.inner.fill_nt)(dst, color, count) }
    }

    unsafe fn blit_nt(&self, dst: *mut u32, src: *const u32, count: usize) {
        // SAFETY: see `fill_nt`.
        unsafe { (self.inner.blit_nt)(dst, src, count) }
    }
}

/// A kernel surface: the crate's canvas with the kernel pixel backend.
pub type Surface<'a> = Canvas<'a, KernelOps>;

/// Create a kernel surface over an HHDM-mapped physical framebuffer.
///
/// # Safety
///
/// `base` must stay mapped and exclusively owned for `'a`.
pub unsafe fn surface_from_fb<'a>(
    base: NonNull<u8>,
    dims: Dims,
    pitch: usize,
    format: Format,
    write_combining: bool,
    ops: FramebufferOps,
) -> Result<Surface<'a>, fbsurface::Error> {
    // SAFETY: forwarded to the caller.
    unsafe {
        Canvas::direct(
            base,
            dims,
            pitch,
            format,
            write_combining,
            KernelOps::new(ops),
        )
    }
}

/// Frame presentation: owns the scanout surface and rate-limits the flush.
///
/// The presenter is the only place that knows about write-combining memory
/// and about `PRESENT_MIN_TICKS`. A `Canvas` does not rate-limit anything;
/// it only records damage.
///
/// The usual layout is one back surface (drawn by the console, the compositor
/// or a kernel demo) and one presenter over the physical framebuffer:
///
/// ```text
/// draw into back  ->  back.dirty()  ->  Presenter::present(now, &mut back)
///                                              |
///                                              +-> blit damaged rects to scanout
/// ```
pub struct Presenter<'a> {
    canvas: Surface<'a>,
    min_ticks: u64,
    last_present_tick: u64,
    /// False until the first successful present, so the first frame is not
    /// dropped by the rate limiter when the tick counter starts near zero.
    presented: bool,
}

impl<'a> Presenter<'a> {
    /// Wrap a scanout surface. The first release is always immediate.
    pub fn new(canvas: Surface<'a>) -> Self {
        Self {
            canvas,
            min_ticks: PRESENT_MIN_TICKS,
            last_present_tick: 0,
            presented: false,
        }
    }

    /// Build a presenter over a physical framebuffer.
    ///
    /// # Safety
    ///
    /// Same contract as [`surface_from_fb`], plus exclusive ownership of the
    /// scanout for `'a`.
    pub unsafe fn from_fb(
        base: NonNull<u8>,
        dims: Dims,
        pitch: usize,
        format: Format,
        ops: FramebufferOps,
    ) -> Result<Self, fbsurface::Error> {
        // SAFETY: forwarded to the caller.
        let canvas = unsafe { surface_from_fb(base, dims, pitch, format, true, ops)? };
        Ok(Self::new(canvas))
    }

    #[inline]
    pub fn canvas(&self) -> &Surface<'a> {
        &self.canvas
    }

    /// Mutable access to the scanout surface. Draw here only for content
    /// that must survive without a back buffer (cursor, early console).
    #[inline]
    pub fn canvas_mut(&mut self) -> &mut Surface<'a> {
        &mut self.canvas
    }

    #[inline]
    pub fn min_ticks(&self) -> u64 {
        self.min_ticks
    }

    /// Override the refresh floor. Zero disables rate limiting.
    #[inline]
    pub fn set_min_ticks(&mut self, ticks: u64) {
        self.min_ticks = ticks;
    }

    /// Force the next [`Self::present`] to flush even if the minimum tick
    /// interval has not elapsed (mode change, panic console takeover).
    #[inline]
    pub fn invalidate(&mut self) {
        self.presented = false;
    }

    /// Flush the damaged rectangles of `back` to the scanout.
    ///
    /// Returns the damage that was actually presented (empty when the rate
    /// limiter suppressed the frame, or when nothing was damaged). The
    /// caller keeps ownership of `back`; its damage set is cleared.
    ///
    /// Both surfaces must share the same format. On a mismatch the frame is
    /// skipped **without consuming the damage**, rather than panicking or
    /// silently swapping channels: presentation must never take the kernel
    /// down.
    pub fn present(&mut self, now_ticks: u64, back: &mut Surface<'_>) -> RectSet<MAX_DIRTY_RECTS> {
        if !self.due(now_ticks) || !self.format_matches(back) {
            return RectSet::empty();
        }

        let damage = back.take_dirty();
        // Writes made directly through `canvas_mut` are already on screen.
        // Adding them to the blit set would copy the back buffer over them
        // (a cursor drawn on the scanout would disappear), so forget them.
        self.canvas.clear_dirty();
        self.flush(now_ticks, &damage, back)
    }

    /// Same contract as [`Self::present`], for a heap back buffer.
    pub fn present_owned(
        &mut self,
        now_ticks: u64,
        back: &mut OwnedSurface<KernelOps>,
    ) -> RectSet<MAX_DIRTY_RECTS> {
        if !self.due(now_ticks) || !self.format_matches(&*back) {
            return RectSet::empty();
        }

        let damage = back.take_dirty();
        // See `present`: direct scanout writes must not be overwritten.
        self.canvas.clear_dirty();
        self.flush(now_ticks, &damage, &*back)
    }

    /// Present the whole surface, ignoring damage. Used on the first frame,
    /// after a resolution change, or when coming back from a blank screen.
    pub fn present_full(&mut self, now_ticks: u64, back: &mut Surface<'_>) {
        if !self.format_matches(&*back) {
            return;
        }
        self.full(&*back);
        back.clear_dirty();
        self.canvas.clear_dirty();
        self.last_present_tick = now_ticks;
        self.presented = true;
    }

    /// Same contract as [`Self::present_full`], for a heap back buffer.
    pub fn present_full_owned(&mut self, now_ticks: u64, back: &mut OwnedSurface<KernelOps>) {
        if !self.format_matches(&*back) {
            return;
        }
        self.full(&*back);
        back.clear_dirty();
        self.canvas.clear_dirty();
        self.last_present_tick = now_ticks;
        self.presented = true;
    }

    /// True when the refresh floor allows a flush now.
    fn due(&self, now_ticks: u64) -> bool {
        !self.presented || now_ticks.saturating_sub(self.last_present_tick) >= self.min_ticks
    }

    fn format_matches<S: Source + ?Sized>(&self, back: &S) -> bool {
        self.canvas.format().compatible(back.format())
    }

    /// Common tail of both `present` paths: choose full-frame or per-rect
    /// presentation, flush the write-combining stores and update the clock.
    fn flush<S: Source + ?Sized>(
        &mut self,
        now_ticks: u64,
        damage: &RectSet<MAX_DIRTY_RECTS>,
        back: &S,
    ) -> RectSet<MAX_DIRTY_RECTS> {
        if damage.is_empty() {
            return *damage;
        }

        // Small rect lists are cheaper only while they stay small: once the
        // damage covers most of the panel, one contiguous copy beats many
        // short blits. This mirrors the old `CanvasBuffer::present` heuristic.
        let canvas_area = self.canvas.dims().area();
        if canvas_area != 0
            && damage.total_area().saturating_mul(10) > canvas_area.saturating_mul(6)
        {
            self.full(back);
        } else {
            self.blit_damage(damage, back);
        }

        // Both paths write through `self.canvas`, which records damage of its
        // own. Those pixels are now on screen.
        self.canvas.clear_dirty();
        self.canvas.fence();
        self.last_present_tick = now_ticks;
        self.presented = true;
        *damage
    }

    /// Copy one rectangle of `back` per damage entry.
    fn blit_damage<S: Source + ?Sized>(&mut self, damage: &RectSet<MAX_DIRTY_RECTS>, back: &S) {
        for rect in damage.iter() {
            let _ = self.canvas.blit(rect, back, rect);
        }
    }

    /// Copy the whole overlap between the scanout and `back`.
    fn full<S: Source + ?Sized>(&mut self, back: &S) {
        let dst = self.canvas.bounds();
        let src = Rect::new(0, 0, back.dims().w, back.dims().h);
        let rect = dst.intersect(src);
        if rect.is_empty() {
            return;
        }
        let _ = self.canvas.blit(rect, back, rect);
        self.canvas.fence();
    }
}
