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

//! Object metadata: opaque ids, buffer/surface/session records and damage.

use vasistas_protocol::Rect;

use crate::{
    backend::RegionHandle, MAX_BUFFERS_PER_SESSION, MAX_RECTS, MAX_SESSIONS,
    MAX_SURFACES_PER_SESSION,
};

const INDEX_MASK: u64 = 0xFFFF_FFFF;

/// Interior state of a buffer (A.4).
///
/// Lifecycle: `Allocating -> ImportPending -> Available -> Current -> Ready ->
/// Available`, and `Retired` when the client loses the buffer. The core passes
/// through `Allocating` inside
/// [`allocate_buffer`](crate::DisplayCore::allocate_buffer), and removes a
/// retired buffer immediately, so neither is observable. `Ready` is observable:
/// it is the replaced current buffer until
/// [`take_release`](crate::DisplayCore::take_release) hands it back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferState {
    /// Backend allocation in progress.
    Allocating,
    /// Region allocated, client import not yet reported.
    ImportPending,
    /// Imported and free to be committed.
    Available,
    /// Imported, not currently committable.
    Ready,
    /// Last image of the surface; released when replaced.
    Current,
    /// Released and unusable.
    Retired,
}

macro_rules! opaque_id {
    ($name:ident, $max:expr, $doc:expr) => {
        #[doc = $doc]
        ///
        /// The value packs a slot index and a generation. A slot reuse bumps
        /// the generation, so a stale value is rejected as
        /// [`CoreError::BadObject`](crate::CoreError::BadObject).
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $name(u64);

        impl $name {
            /// Build the id of `slot` at `generation`.
            pub(crate) const fn from_slot(slot: usize, generation: u32) -> Self {
                Self(((generation as u64) << 32) | (slot as u64 + 1))
            }

            /// Construct from a raw value received on the wire.
            pub const fn from_raw(raw: u64) -> Self {
                Self(raw)
            }

            /// The raw value, safe to send on the wire.
            pub const fn raw(self) -> u64 {
                self.0
            }

            /// Decode the slot index, `None` when out of range or zero.
            pub(crate) fn slot(self) -> Option<usize> {
                let low = self.0 & INDEX_MASK;
                if low == 0 {
                    return None;
                }
                let index = (low - 1) as usize;
                if index >= $max {
                    None
                } else {
                    Some(index)
                }
            }
        }
    };
}

opaque_id!(SessionId, MAX_SESSIONS, "Opaque session handle.");
opaque_id!(
    SurfaceId,
    MAX_SURFACES_PER_SESSION,
    "Opaque surface handle."
);
opaque_id!(BufferId, MAX_BUFFERS_PER_SESSION, "Opaque buffer handle.");

/// A buffer region waiting for the backend to free it.
///
/// The core never frees a region while a client mapping may still reference it:
/// it parks the region here and the server calls
/// [`take_retired`](crate::DisplayCore::take_retired) after revoking and
/// unmapping the client mapping, then calls [`Backend::free`](crate::Backend::free).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetiredRegion {
    /// Session that owned the buffer.
    pub session: SessionId,
    /// Buffer handle the region belonged to.
    pub buffer: BufferId,
    /// Backend region to free once the client mapping is gone.
    pub region: RegionHandle,
}

/// Damage carried by an accepted commit (A.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Damage {
    /// The whole surface changed: first commit, first after configure, or
    /// `FULL_DAMAGE`.
    Full,
    /// Exactly `count` rects in `rects`, in commit order.
    Rects {
        /// Number of valid rects, `<= MAX_RECTS`.
        count: u8,
        /// Fixed-capacity rect storage; entries past `count` are zero.
        rects: [Rect; MAX_RECTS],
    },
}

impl Default for Damage {
    fn default() -> Self {
        Self::Full
    }
}

/// Result of a geometry change: what the GEOMETRY event must echo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeometryOutcome {
    /// New configure serial, to be acknowledged by the next commit.
    pub serial: u64,
    /// Final clamped screen-space origin x.
    pub x: u32,
    /// Final clamped screen-space origin y.
    pub y: u32,
    /// Final width.
    pub width: u32,
    /// Final height.
    pub height: u32,
}

/// One imported-or-not client buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Buffer {
    /// Stable handle, generation included.
    pub id: BufferId,
    /// Owning surface.
    pub surface: SurfaceId,
    /// Pixel width, equal to the surface width.
    pub width: u32,
    /// Pixel height, equal to the surface height.
    pub height: u32,
    /// Pixel format, equal to the surface format.
    pub format: u32,
    /// Row stride in bytes, backend-owned.
    pub stride: u32,
    /// Allocated bytes charged to the session quota (`stride * height`).
    pub bytes: usize,
    /// Backend region.
    pub region: RegionHandle,
    /// Lifecycle state.
    pub state: BufferState,
}

/// One surface: dimensions, serials, commit credit and last presentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Surface {
    /// Stable handle, generation included.
    pub id: SurfaceId,
    /// Screen-space origin x, from the owning session's tile.
    pub x: u32,
    /// Screen-space origin y, from the owning session's tile.
    pub y: u32,
    /// Current pixel width.
    pub width: u32,
    /// Current pixel height.
    pub height: u32,
    /// Current pixel format.
    pub format: u32,
    /// Last serial emitted by `set_configure`.
    pub configure_serial: u64,
    /// Last serial accepted by a commit.
    pub acked_serial: u64,
    /// Buffer holding the surface's last image.
    pub current: Option<BufferId>,
    /// Commit credit, 0 or 1.
    pub credit: u8,
    /// Last accepted commit id.
    pub last_commit_id: u64,
    /// The next accepted commit must report full damage.
    pub full_damage_next: bool,
    /// Set when the surface is destroyed.
    pub destroyed: bool,
    /// Hidden by `MINIMIZE`: skipped by picking and composition until
    /// `RESTORE`.
    pub hidden: bool,
    /// Damage of the last accepted commit.
    pub damage: Damage,
    /// Damage accumulated since the last successful presentation.
    pub pending_damage: Damage,
    /// Commit id last presented, 0 when nothing was presented.
    pub presented_commit: u64,
    /// Serial acknowledged by the last presentation.
    pub presented_serial: u64,
}

/// One client session and all its objects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    /// Stable handle, generation included.
    pub(crate) id: SessionId,
    /// Fixed capacity surface slots.
    pub(crate) surfaces: [Option<Surface>; MAX_SURFACES_PER_SESSION],
    /// Fixed capacity buffer slots.
    pub(crate) buffers: [Option<Buffer>; MAX_BUFFERS_PER_SESSION],
    /// Bytes charged against [`PIXEL_QUOTA_BYTES`](crate::PIXEL_QUOTA_BYTES).
    pub(crate) used_bytes: usize,
    /// Pending `BUFFER_RELEASE` notifications, oldest at `release_head`.
    pub(crate) releases: [Option<BufferId>; MAX_BUFFERS_PER_SESSION],
    /// Head of the release ring.
    pub(crate) release_head: usize,
    /// Number of queued releases.
    pub(crate) release_len: usize,
    /// Set when a release notification was dropped because the ring was full.
    pub(crate) release_overflow: bool,
}

impl Session {
    pub(crate) const fn new(id: SessionId) -> Self {
        Self {
            id,
            surfaces: [const { None }; MAX_SURFACES_PER_SESSION],
            buffers: [const { None }; MAX_BUFFERS_PER_SESSION],
            used_bytes: 0,
            releases: [const { None }; MAX_BUFFERS_PER_SESSION],
            release_head: 0,
            release_len: 0,
            release_overflow: false,
        }
    }

    /// Queue a release notification; drops it when the ring is full and
    /// records the loss in `release_overflow`.
    ///
    /// A dropped notification never affects usability: the buffer is already
    /// `Ready` when it is queued.
    pub(crate) fn push_release(&mut self, buffer: BufferId) {
        if self.release_len >= self.releases.len() {
            self.release_overflow = true;
            return;
        }
        let index = (self.release_head + self.release_len) % self.releases.len();
        self.releases[index] = Some(buffer);
        self.release_len += 1;
    }

    /// Remove every queued notification for `buffer`, compacting the ring.
    pub(crate) fn remove_release(&mut self, buffer: BufferId) {
        let capacity = self.releases.len();
        let mut kept = 0usize;
        for read in 0..self.release_len {
            let index = (self.release_head + read) % capacity;
            match self.releases[index].take() {
                Some(queued) if queued != buffer => {
                    let target = (self.release_head + kept) % capacity;
                    self.releases[target] = Some(queued);
                    kept += 1;
                }
                _ => {}
            }
        }
        self.release_len = kept;
    }

    /// Pop the oldest release notification.
    pub(crate) fn pop_release(&mut self) -> Option<BufferId> {
        if self.release_len == 0 {
            return None;
        }
        let value = self.releases[self.release_head].take();
        self.release_head = (self.release_head + 1) % self.releases.len();
        self.release_len -= 1;
        value
    }
}
