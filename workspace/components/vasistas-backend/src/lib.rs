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

//! Narrow display backend contract (jalon 4 of `docs/GUI_AUDIT_2026-11.md`).
//!
//! This crate owns two pieces used by the display server and nothing else:
//!
//! - [`SharedPixels`]: bounded reads of client shared memory into a private
//!   copy, with no long-lived `&[u8]` over the client mapping (§7).
//! - [`encode`]: the exact `DMG2` presentation message the kernel parses in
//!   `workspace/kernel/src/hardware/video/vasistas_scheme.rs`.
//!
//! The `/dev/vasistas` adapter itself (`vasistas_scheme_backend`), the private
//! backbuffer and composition are deliberately out of scope here.
//!
//! # Backend contract
//!
//! **One writer.** Only the display server calls the backend. `present` never
//! allocates, never blocks on a client and never retains the `&[Rect]` or any
//! pixel slice past the call. The server is the single process that owns
//! `/dev/vasistas`; the standalone console is not a concurrent writer.
//!
//! **Lifecycle.** `DisplayCore::allocate_buffer` → backend allocates the region
//! and imports it for the client; `commit` validates the metadata and installs
//! the buffer; the server copies the commit's [`vasistas_protocol::Rect`] damage
//! from client
//! mapping into its private backbuffer with [`SharedPixels::copy_damage`],
//! encodes it with [`encode`], calls `present`, then `frame_done` returns
//! presentation credit. The previous buffer stays `Ready` until the core
//! surfaces it through `take_release`, which is what emits `BUFFER_RELEASE`
//! to the client: the server never releases a buffer on its own.
//!
//! **Region lifetime.** `Backend::free` (via `DisplayCore::take_retired`) runs
//! only after the client mapping and every reference to the region are gone.
//! A region is never reused while a client can still map or write it; a client
//! that keeps writing after release writes into retired frames only.
//!
//! **Errors.** Every operation is per-call and never panics. Client-controlled
//! fields (rects, strides, buffer descriptor) are revalidated here even when the
//! protocol already decoded them. Reads are bounded and land in a private copy,
//! so a client mutating its pixels mid-copy can only produce torn pixels in the
//! backbuffer, never an out-of-bounds read.
//!
//! **No long-lived borrow.** [`SharedPixels`] wraps the client mapping per
//! frame and is dropped before the next protocol step; nothing keeps a `&[u8]`
//! over remotely writable memory across calls.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod dmg2;
pub mod pixels;

pub use dmg2::{encode, encoded_len, Dmg2Error, DMG2_HEADER, DMG2_MAX_RECTS, DMG2_RECORD};
pub use pixels::{DamageStats, PixelError, SharedPixels};
