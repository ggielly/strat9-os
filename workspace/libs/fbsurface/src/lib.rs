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

//! Contiguous framebuffer surfaces for strat9.
//!
//! This crate is the single internal API for pixel buffers: one geometry
//! type, one pixel format, one damage model, one clipping rule. It has no OS
//! dependency (and no allocator unless you use [`OwnedSurface`]), so it
//! builds for the kernel *and* runs its tests on the host:
//!
//! ```text
//! cargo test -p fbsurface
//! ```
//!
//! # Layers
//!
//! | Type | Role |
//! |---|---|
//! | [`Dims`], [`Rect`], [`RectSet`] | geometry and damage, no pixel knowledge |
//! | [`Format`], [`Packed`], [`Rgb`] | native layout and one explicit conversion point |
//! | [`PixelOps`], [`ScalarOps`] | raw 32-bit primitives, monomorphised |
//! | [`Canvas`] | validated surface: fill, blit, blend, convert, damage |
//! | [`View`], [`Source`] | read-only surface and the sealed copy source |
//! | [`OwnedSurface`] | heap 32 bpp back buffer with persistent damage |
//!
//! `Canvas` borrows caller memory or points at MMIO; `OwnedSurface` owns a
//! `Vec<u32>` and builds a temporary `Canvas` for each drawing call, which
//! keeps the borrow checker in charge of the storage lifetime.
//!
//! The kernel adapter lives in `strat9-kernel`'s `framebuffer::surface`:
//! it implements [`PixelOps`] over the existing SSE2 backend and returns an
//! FPU guard from every drawing call. Nothing in this crate knows about
//! interrupts, locks or physical memory.
//!
//! # What is deliberately absent
//!
//! No text, fonts, widgets, Z-order, windows or presentation policy. No
//! trait objects: the storage is a pointer plus a pitch, and the backend is
//! a type parameter. No implicit allocation (except [`OwnedSurface`]) and no
//! implicit format conversion: [`Canvas::blit`] refuses mismatched layouts,
//! and [`Canvas::convert_from`] is the one place that re-encodes pixels.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod canvas;
pub mod format;
pub mod geom;
pub mod ops;
pub mod owned;
pub mod view;

pub use canvas::{Canvas, Error};
pub use format::{Format, Packed, Rgb};
pub use geom::{Dims, Rect, RectSet, DEFAULT_SET_CAPACITY};
pub use ops::{blend_word, NoGuard, PixelGuard, PixelOps, ScalarOps};
pub use owned::OwnedSurface;
pub use view::{Source, View};

/// Maximum number of damage rectangles tracked by default.
pub const MAX_RECTS: usize = DEFAULT_SET_CAPACITY;
