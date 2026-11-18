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

//! Display server metadata state machine.
//!
//! Implements the object lifecycle, commit credit, atomically accepted
//! `COMMIT` and pixel quota rules of Annexe A.4/A.6 of
//! `docs/GUI_AUDIT_2026-11.md`. It owns no pixels and performs no wire
//! encoding: surfaces, buffers and regions are metadata, and the backend
//! supplies regions and presentation. `vasistas-protocol` supplies the
//! decoded [`Commit`](vasistas_protocol::Commit) body and the damage
//! rectangles.
//!
//! No allocation, fixed capacities, deterministic results. The only `unsafe`
//! is the audited in-place initializer ([`DisplayCore::init_at`]) that avoids a
//! whole-state temporary on a small user stack.

#![no_std]
#![deny(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod backend;
pub mod core;
pub mod server;
pub mod types;

pub use backend::{Backend, RegionHandle};
pub use core::{CommitOutcome, CoreError, CoreStats, DisplayCore};
pub use server::{PeerId, Server, ServerError, Transport};
pub use types::{
    Buffer, BufferId, BufferState, Damage, RetiredRegion, Session, SessionId, Surface, SurfaceId,
};

/// Maximum concurrent sessions (A.6).
pub const MAX_SESSIONS: usize = 8;

/// Tile grid columns on the screen: session slots 0..3 on the top row, 4..7
/// on the bottom row. Width times [`TILE_COLUMNS`] is the screen width.
pub const TILE_COLUMNS: u32 = 4;

/// Tile grid rows on the screen.
pub const TILE_ROWS: u32 = 2;

/// Width in pixels of one session tile.
pub const TILE_WIDTH: u32 = 400;

/// Height in pixels of one session tile.
pub const TILE_HEIGHT: u32 = 300;

/// The tile grid must cover every session slot exactly.
const _: () = assert!(TILE_COLUMNS * TILE_ROWS == MAX_SESSIONS as u32);

/// Maximum surfaces per session (A.6).
pub const MAX_SURFACES_PER_SESSION: usize = 4;

/// Maximum buffers per session (A.6).
pub const MAX_BUFFERS_PER_SESSION: usize = 16;

/// A.6: at most 4 buffers per surface.
pub const MAX_BUFFERS_PER_SURFACE: usize = 4;

/// Per-session pixel quota in bytes (A.6): 8 MiB.
pub const PIXEL_QUOTA_BYTES: usize = 8 * 1024 * 1024;

/// Maximum rectangles in one commit (A.4).
pub const MAX_RECTS: usize = vasistas_protocol::MAX_RECTS;

/// Maximum buffer regions awaiting an explicit backend free.
///
/// Regions are not freed while a client mapping may still reference them: they
/// are parked in a bounded core-level queue (one slot per possible live buffer,
/// `MAX_SESSIONS * MAX_BUFFERS_PER_SESSION`) and released through
/// [`DisplayCore::take_retired`]. When the queue is full, the operation that
/// would retire a region fails with [`CoreError::Limit`] instead of unmapping
/// memory behind the client's back.
pub const MAX_RETIRED_REGIONS: usize = MAX_SESSIONS * MAX_BUFFERS_PER_SESSION;

/// Maximum surface dimension accepted by `CREATE_SURFACE` (A.3.1).
pub const MAX_SURFACE_DIM: u32 = vasistas_protocol::constants::MAX_SURFACE_DIM;

/// Maximum surface title length in bytes (A.3.1).
pub const MAX_TITLE: usize = vasistas_protocol::constants::MAX_TITLE;

/// The only format of protocol v1: `XRGB8888` (A.3.1).
pub const FORMAT_XRGB8888: u32 = vasistas_protocol::constants::FORMAT_XRGB8888;
