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

//! Sessions, surfaces, buffers, commit acceptance and presentation.
//!
//! ## Deferred region free
//!
//! The core never calls [`Backend::free`] while a client mapping may still
//! exist. Destroyed, failed-import and closed-session regions are parked in a
//! bounded `retired` queue of [`MAX_RETIRED_REGIONS`] entries (one per possible
//! live buffer, so the queue is bounded at 128 regions) and handed back by
//! [`DisplayCore::take_retired`]; the server frees them once the client mapping
//! is revoked. [`Drop`] frees whatever is still live or retired.

use core::{mem::MaybeUninit, ptr};

use vasistas_protocol::{
    Commit, Rect, FLAG_FULL_DAMAGE, WINDOW_ACTION_LOWER, WINDOW_ACTION_MAXIMIZE,
    WINDOW_ACTION_MINIMIZE, WINDOW_ACTION_RAISE, WINDOW_ACTION_RESTORE,
};

use crate::{
    backend::{Backend, Layer, RegionHandle},
    types::{
        Buffer, BufferId, BufferState, Damage, GeometryOutcome, RetiredRegion, Session, SessionId,
        Surface, SurfaceId,
    },
    FORMAT_XRGB8888, MAX_BUFFERS_PER_SESSION, MAX_RECTS, MAX_RETIRED_REGIONS, MAX_SCREEN_DIRTY,
    MAX_SESSIONS, MAX_SURFACES_PER_SESSION, MAX_SURFACE_DIM, MAX_TITLE, MAX_Z, PIXEL_QUOTA_BYTES,
    TILE_COLUMNS, TILE_HEIGHT, TILE_ROWS, TILE_WIDTH,
};

/// Aggregate resource counters of a [`DisplayCore`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoreStats {
    /// Live sessions.
    pub sessions: usize,
    /// Live surfaces across every session.
    pub surfaces: usize,
    /// Live buffers across every session.
    pub buffers: usize,
    /// Bytes charged against the per-session pixel quotas, summed.
    pub used_bytes: usize,
}

/// Failure of a core operation. Stable, comparable, copyable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreError {
    /// The session is unknown or closed.
    NoSession,
    /// The surface slot is empty.
    NoSurface,
    /// The buffer slot is empty.
    NoBuffer,
    /// The handle is stale (generation mismatch) or malformed, or the object
    /// belongs to another session/surface.
    BadObject,
    /// The object is not in a state that allows the operation.
    BadState,
    /// Flags are not those accepted by this operation.
    BadFlags,
    /// Dimensions are outside bounds or inconsistent with the target.
    BadDimensions,
    /// The pixel format is not [`FORMAT_XRGB8888`].
    BadFormat,
    /// The stride is smaller than `width * 4` or overflows.
    BadStride,
    /// The session pixel quota would be exceeded.
    Quota,
    /// The surface has no commit credit (`credit == 0`).
    NoCredit,
    /// `ack_serial` is not the current configure serial, or regresses.
    BadSerial,
    /// `commit_id` is not strictly greater than the last accepted one.
    BadCommitId,
    /// A fixed capacity is exhausted.
    Limit,
    /// The backend refused an operation.
    BackendError,
}

/// Result of an accepted commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitOutcome {
    /// The commit was accepted atomically.
    Accepted {
        /// Damage since the surface's previous image.
        damage: Damage,
        /// The buffer that stopped being current, now available.
        released: Option<BufferId>,
    },
}

/// Metadata state machine for one display server.
///
/// Generic over the [`Backend`] that owns regions and presentation; the core
/// itself never touches pixels.
pub struct DisplayCore<B: Backend> {
    backend: B,
    sessions: [Option<Session>; MAX_SESSIONS],
    session_gen: [u32; MAX_SESSIONS],
    surface_gen: [u32; MAX_SURFACES_PER_SESSION],
    buffer_gen: [u32; MAX_BUFFERS_PER_SESSION],
    /// Regions awaiting an explicit [`Backend::free`] (bounded).
    retired: [Option<RetiredRegion>; MAX_RETIRED_REGIONS],
    /// Server-wide pixel budget in bytes, across every session; `0` disables
    /// the check (A.6).
    global_budget: usize,
    /// Per-session pixel quota in bytes (A.6), derived from the output size by
    /// the server when it is larger than [`PIXEL_QUOTA_BYTES`].
    pixel_quota: usize,
    /// Screen-space width of the single output.
    output_width: u32,
    /// Screen-space height of the single output.
    output_height: u32,
    /// Z order, topmost first; the first `zlen` entries are live.
    zlist: [(SessionId, SurfaceId); MAX_Z],
    /// Number of live z-order entries.
    zlen: usize,
    /// Screen rects dirtied since the last repaint; the first
    /// `screen_dirty_len` entries are live.
    screen_dirty: [Rect; MAX_SCREEN_DIRTY],
    /// Number of live screen-damage rects.
    screen_dirty_len: usize,
}

/// Ids pack a slot index and a 32-bit generation; generations wrap after
/// `u32::MAX` reuses of the same slot, skipping zero. A stale handle is then
/// accepted again only after ~4 billion reuses of that one slot.
const fn next_generation(generation: u32) -> u32 {
    let next = generation.wrapping_add(1);
    if next == 0 {
        1
    } else {
        next
    }
}

/// True when `rect` is non-empty and lies inside a `width x height` surface.
fn rect_in_bounds(rect: &Rect, width: u32, height: u32) -> bool {
    rect.x >= 0
        && rect.y >= 0
        && rect.w > 0
        && rect.h > 0
        && rect.x as i64 + rect.w as i64 <= width as i64
        && rect.y as i64 + rect.h as i64 <= height as i64
}

/// Screen-space origin of the session occupying `slot` of the tile grid.
///
/// `slot` is the session's index in the fixed session table, so `slot 0` is the
/// top-left tile and `slot 7` the bottom-right one. Tiles are disjoint.
fn tile_origin(slot: usize) -> (u32, u32) {
    let slot = slot as u32;
    (
        (slot % TILE_COLUMNS) * TILE_WIDTH,
        (slot / TILE_COLUMNS) * TILE_HEIGHT,
    )
}

/// Screen-space rect currently covered by `surface`.
fn surface_rect(surface: &Surface) -> Rect {
    Rect {
        x: surface.x as i32,
        y: surface.y as i32,
        w: surface.width,
        h: surface.height,
    }
}

/// Intersection of `rect` with the `width x height` output, `None` if empty.
fn clip_rect(rect: &Rect, width: u32, height: u32) -> Option<Rect> {
    let x0 = rect.x.max(0) as i64;
    let y0 = rect.y.max(0) as i64;
    let x1 = (rect.x as i64)
        .saturating_add(rect.w as i64)
        .min(width as i64);
    let y1 = (rect.y as i64)
        .saturating_add(rect.h as i64)
        .min(height as i64);
    if x1 <= x0 || y1 <= y0 {
        return None;
    }
    Some(Rect {
        x: x0 as i32,
        y: y0 as i32,
        w: (x1 - x0) as u32,
        h: (y1 - y0) as u32,
    })
}

/// Merge commit damage into the accumulated surface damage.
///
/// `Full` dominates; rect lists append in commit order and collapse to `Full`
/// once the union would exceed [`MAX_RECTS`].
fn merge_damage(pending: &mut Damage, add: Damage) {
    *pending = match (*pending, add) {
        (Damage::Full, _) | (_, Damage::Full) => Damage::Full,
        (
            Damage::Rects {
                count: first,
                rects: mut merged,
            },
            Damage::Rects {
                count: second,
                rects: added,
            },
        ) => {
            let total = first as usize + second as usize;
            if total > MAX_RECTS {
                Damage::Full
            } else {
                merged[first as usize..total].copy_from_slice(&added[..second as usize]);
                Damage::Rects {
                    count: total as u8,
                    rects: merged,
                }
            }
        }
    };
}

fn free_retired_slots(retired: &[Option<RetiredRegion>; MAX_RETIRED_REGIONS]) -> usize {
    retired.iter().filter(|slot| slot.is_none()).count()
}

fn retire_region(
    retired: &mut [Option<RetiredRegion>; MAX_RETIRED_REGIONS],
    session: SessionId,
    buffer: BufferId,
    region: RegionHandle,
) -> Result<(), CoreError> {
    let slot = retired
        .iter_mut()
        .find(|slot| slot.is_none())
        .ok_or(CoreError::Limit)?;
    *slot = Some(RetiredRegion {
        session,
        buffer,
        region,
    });
    Ok(())
}

fn surface_index(session: &Session, id: SurfaceId) -> Result<usize, CoreError> {
    let index = id.slot().ok_or(CoreError::BadObject)?;
    match &session.surfaces[index] {
        None => Err(CoreError::NoSurface),
        Some(surface) if surface.id == id => Ok(index),
        Some(_) => Err(CoreError::BadObject),
    }
}

fn buffer_index(session: &Session, id: BufferId) -> Result<usize, CoreError> {
    let index = id.slot().ok_or(CoreError::BadObject)?;
    match &session.buffers[index] {
        None => Err(CoreError::NoBuffer),
        Some(buffer) if buffer.id == id => Ok(index),
        Some(_) => Err(CoreError::BadObject),
    }
}

fn check_dimensions(width: u32, height: u32) -> Result<(), CoreError> {
    if width == 0 || height == 0 || width > MAX_SURFACE_DIM || height > MAX_SURFACE_DIM {
        return Err(CoreError::BadDimensions);
    }
    Ok(())
}

fn check_format(format: u32) -> Result<(), CoreError> {
    if format != FORMAT_XRGB8888 {
        return Err(CoreError::BadFormat);
    }
    Ok(())
}

impl<B: Backend> DisplayCore<B> {
    /// Create an empty core over `backend`.
    pub const fn new(backend: B) -> Self {
        Self {
            backend,
            sessions: [const { None }; MAX_SESSIONS],
            session_gen: [1; MAX_SESSIONS],
            surface_gen: [1; MAX_SURFACES_PER_SESSION],
            buffer_gen: [1; MAX_BUFFERS_PER_SESSION],
            retired: [const { None }; MAX_RETIRED_REGIONS],
            global_budget: 0,
            pixel_quota: PIXEL_QUOTA_BYTES,
            output_width: TILE_COLUMNS * TILE_WIDTH,
            output_height: TILE_ROWS * TILE_HEIGHT,
            zlist: [(SessionId::from_raw(0), SurfaceId::from_raw(0)); MAX_Z],
            zlen: 0,
            screen_dirty: [Rect { x: 0, y: 0, w: 0, h: 0 }; MAX_SCREEN_DIRTY],
            screen_dirty_len: 0,
        }
    }

    /// Initialise `this` in place, without building a `Self` temporary.
    ///
    /// [`DisplayCore::new`] returns the whole (~44 KiB) state machine by value,
    /// which overflows a 64 KiB user stack when the caller stores it in a
    /// static (`Option<Server<..>>` needs a second copy). This constructor
    /// writes every field of `this` exactly once through [`ptr::write`], so the
    /// largest stack temporary is one [`Option<Session>`] slot, and only the
    /// caller-owned storage is filled.
    ///
    /// Call it once on a fresh [`MaybeUninit`]; it returns the now-initialised
    /// core.
    #[allow(unsafe_code)]
    pub fn init_at(this: &mut MaybeUninit<Self>, backend: B) -> &mut Self {
        // SAFETY: `this` is valid for writes of `Self`, and `write_in` writes
        // every field exactly once before the value is observed.
        unsafe {
            Self::write_in(this.as_mut_ptr(), backend);
            // SAFETY: every field was initialised by `write_in` just above.
            this.assume_init_mut()
        }
    }

    /// Write every field of `this` in place; the sole `unsafe` of this crate.
    ///
    /// Split out so [`DisplayCore::init_at`] and
    /// [`Server::init_at`](crate::Server::init_at) share one audited writer.
    #[allow(unsafe_code)]
    pub(crate) unsafe fn write_in(this: *mut Self, backend: B) {
        // SAFETY: `this` points to caller-owned, writable, properly aligned
        // storage for `Self`; each field is written exactly once.
        unsafe {
            ptr::write(ptr::addr_of_mut!((*this).backend), backend);

            let sessions = ptr::addr_of_mut!((*this).sessions).cast::<Option<Session>>();
            for index in 0..MAX_SESSIONS {
                sessions.add(index).write(None);
            }
            let retired = ptr::addr_of_mut!((*this).retired).cast::<Option<RetiredRegion>>();
            for index in 0..MAX_RETIRED_REGIONS {
                retired.add(index).write(None);
            }
            let session_gen = ptr::addr_of_mut!((*this).session_gen).cast::<u32>();
            for index in 0..MAX_SESSIONS {
                session_gen.add(index).write(1);
            }
            let surface_gen = ptr::addr_of_mut!((*this).surface_gen).cast::<u32>();
            for index in 0..MAX_SURFACES_PER_SESSION {
                surface_gen.add(index).write(1);
            }
            let buffer_gen = ptr::addr_of_mut!((*this).buffer_gen).cast::<u32>();
            for index in 0..MAX_BUFFERS_PER_SESSION {
                buffer_gen.add(index).write(1);
            }
            ptr::addr_of_mut!((*this).global_budget).write(0);
            ptr::addr_of_mut!((*this).pixel_quota).write(PIXEL_QUOTA_BYTES);
            ptr::addr_of_mut!((*this).output_width).write(TILE_COLUMNS * TILE_WIDTH);
            ptr::addr_of_mut!((*this).output_height).write(TILE_ROWS * TILE_HEIGHT);
            let zlist =
                ptr::addr_of_mut!((*this).zlist).cast::<(SessionId, SurfaceId)>();
            for index in 0..MAX_Z {
                zlist.add(index).write((SessionId::from_raw(0), SurfaceId::from_raw(0)));
            }
            ptr::addr_of_mut!((*this).zlen).write(0);
            let screen_dirty = ptr::addr_of_mut!((*this).screen_dirty).cast::<Rect>();
            for index in 0..MAX_SCREEN_DIRTY {
                screen_dirty.add(index).write(Rect::default());
            }
            ptr::addr_of_mut!((*this).screen_dirty_len).write(0);
        }
    }

    /// Per-session pixel quota currently enforced.
    pub fn pixel_quota(&self) -> usize {
        self.pixel_quota
    }

    /// Set the per-session quota; never below [`PIXEL_QUOTA_BYTES`].
    pub fn set_pixel_quota(&mut self, quota: usize) {
        self.pixel_quota = quota.max(PIXEL_QUOTA_BYTES);
    }

    /// Borrow the backend, for tests and diagnostics.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Mutably borrow the backend.
    ///
    /// Trusted, diagnostics-only escape hatch: callers must not free, reuse or
    /// reallocate a region the core still owns. The safe free path is
    /// [`DisplayCore::take_retired`].
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Open a session, bounded by [`MAX_SESSIONS`].
    pub fn create_session(&mut self) -> Result<SessionId, CoreError> {
        let index = self
            .sessions
            .iter()
            .position(|session| session.is_none())
            .ok_or(CoreError::Limit)?;
        let id = SessionId::from_slot(index, self.session_gen[index]);
        self.session_gen[index] = next_generation(self.session_gen[index]);
        self.sessions[index] = Some(Session::new(id));
        Ok(id)
    }

    /// Close a session: every buffer region is retired, not freed.
    ///
    /// Fails with [`CoreError::Limit`] when the retired queue cannot hold all
    /// of the session's regions; the session is then left untouched.
    pub fn close_session(&mut self, session_id: SessionId) -> Result<(), CoreError> {
        let index = self.session_slot(session_id)?;
        let session = self.sessions[index].as_mut().ok_or(CoreError::NoSession)?;
        let count = session.buffers.iter().flatten().count();
        if free_retired_slots(&self.retired) < count {
            return Err(CoreError::Limit);
        }
        for slot in session.buffers.iter_mut() {
            if let Some(buffer) = slot.take() {
                retire_region(&mut self.retired, session_id, buffer.id, buffer.region)?;
            }
        }
        // Capture every surface before the session is dropped: each leaves
        // the z order and the visible ones repaint the area they covered.
        let mut removed = [(SurfaceId::from_raw(0), false, Rect::default());
            MAX_SURFACES_PER_SESSION];
        let mut removed_len = 0usize;
        for surface in session.surfaces.iter().flatten() {
            removed[removed_len] = (surface.id, surface.hidden, surface_rect(surface));
            removed_len += 1;
        }
        self.sessions[index] = None;
        for (id, hidden, rect) in &removed[..removed_len] {
            self.z_remove(session_id, *id);
            if !hidden {
                self.push_screen_dirty(*rect);
            }
        }
        Ok(())
    }

    /// Pop one region awaiting an explicit [`Backend::free`].
    ///
    /// Call this after revoking and unmapping the client's mapping of
    /// `region`; then call `backend.free(region)`.
    pub fn take_retired(&mut self) -> Option<RetiredRegion> {
        let slot = self.retired.iter().position(|slot| slot.is_some())?;
        self.retired[slot].take()
    }

    /// Create a surface on `session`, bounded by 4 per session.
    pub fn create_surface(
        &mut self,
        session_id: SessionId,
        width: u32,
        height: u32,
        format: u32,
        title_len: usize,
    ) -> Result<SurfaceId, CoreError> {
        let index = self.session_slot(session_id)?;
        let DisplayCore {
            sessions,
            surface_gen,
            ..
        } = self;
        let session = sessions[index].as_mut().ok_or(CoreError::NoSession)?;
        check_dimensions(width, height)?;
        check_format(format)?;
        if title_len > MAX_TITLE {
            return Err(CoreError::BadFlags);
        }
        let slot = session
            .surfaces
            .iter()
            .position(|surface| surface.is_none())
            .ok_or(CoreError::Limit)?;
        let id = SurfaceId::from_slot(slot, surface_gen[slot]);
        surface_gen[slot] = next_generation(surface_gen[slot]);
        let (x, y) = tile_origin(index);
        session.surfaces[slot] = Some(Surface {
            id,
            x,
            y,
            width,
            height,
            format,
            configure_serial: 0,
            acked_serial: 0,
            current: None,
            credit: 1,
            last_commit_id: 0,
            full_damage_next: true,
            destroyed: false,
            hidden: false,
            damage: Damage::Full,
            pending_damage: Damage::Full,
            presented_commit: 0,
            presented_serial: 0,
        });
        self.z_insert_front(session_id, id);
        Ok(id)
    }

    /// Destroy a surface and retire every buffer it owns.
    ///
    /// Refused while a commit is pending (`credit == 0`): the current buffer
    /// must be acknowledged by `FRAME_DONE` first. Buffers are removed from the
    /// session and their regions parked in the retired queue, not freed; the
    /// surface is left intact when the queue cannot hold them all.
    pub fn destroy_surface(
        &mut self,
        session_id: SessionId,
        surface_id: SurfaceId,
    ) -> Result<(), CoreError> {
        let index = self.session_slot(session_id)?;
        let session = self.sessions[index].as_mut().ok_or(CoreError::NoSession)?;
        let surface_slot = surface_index(session, surface_id)?;
        let (hidden, rect) = {
            let surface = session.surfaces[surface_slot]
                .as_ref()
                .ok_or(CoreError::NoSurface)?;
            if surface.destroyed || surface.credit == 0 {
                return Err(CoreError::BadState);
            }
            (surface.hidden, surface_rect(surface))
        };
        let mut doomed = [false; MAX_BUFFERS_PER_SESSION];
        let mut freed = 0usize;
        for (slot, buffer) in session.buffers.iter().enumerate() {
            if matches!(buffer, Some(buffer) if buffer.surface == surface_id) {
                doomed[slot] = true;
                freed += buffer.as_ref().map_or(0, |buffer| buffer.bytes);
            }
        }
        let new_used = session
            .used_bytes
            .checked_sub(freed)
            .ok_or(CoreError::BadState)?;
        if free_retired_slots(&self.retired) < doomed.iter().filter(|slot| **slot).count() {
            return Err(CoreError::Limit);
        }
        for (slot, doomed) in doomed.iter().enumerate() {
            if !doomed {
                continue;
            }
            if let Some(buffer) = session.buffers[slot].take() {
                session.remove_release(buffer.id);
                retire_region(&mut self.retired, session_id, buffer.id, buffer.region)?;
            }
        }
        session.used_bytes = new_used;
        session.surfaces[surface_slot] = None;
        // The destroyed surface leaves the z order; the area it covered
        // repaints when it was visible.
        self.z_remove(session_id, surface_id);
        if !hidden {
            self.push_screen_dirty(rect);
        }
        Ok(())
    }

    /// Move the surface to new dimensions, bumping its configure serial.
    ///
    /// The next accepted commit reports full damage. Buffers allocated for the
    /// previous dimensions keep their old size and are then rejected at
    /// commit time with [`CoreError::BadDimensions`].
    ///
    /// The serial is 64-bit and monotonic; `checked_add` overflow is reported as
    /// [`CoreError::BadState`] and leaves the surface untouched.
    pub fn set_configure(
        &mut self,
        session_id: SessionId,
        surface_id: SurfaceId,
        width: u32,
        height: u32,
        format: u32,
    ) -> Result<u64, CoreError> {
        let index = self.session_slot(session_id)?;
        let session = self.sessions[index].as_mut().ok_or(CoreError::NoSession)?;
        let slot = surface_index(session, surface_id)?;
        check_dimensions(width, height)?;
        check_format(format)?;
        let surface = session.surfaces[slot]
            .as_mut()
            .ok_or(CoreError::NoSurface)?;
        if surface.destroyed {
            return Err(CoreError::BadState);
        }
        let serial = surface
            .configure_serial
            .checked_add(1)
            .ok_or(CoreError::BadState)?;
        surface.configure_serial = serial;
        surface.width = width;
        surface.height = height;
        surface.format = format;
        surface.full_damage_next = true;
        Ok(serial)
    }

    /// Set the screen-space size of the single output; never below 1.
    pub fn set_output_size(&mut self, width: u32, height: u32) {
        self.output_width = width.max(1);
        self.output_height = height.max(1);
    }

    /// Move `surface` to `(x, y)` with a new size, bumping its configure
    /// serial (`SET_GEOMETRY`).
    ///
    /// The position is clamped into the output and the final values are
    /// reported; the serial is the same counter as
    /// [`set_configure`](DisplayCore::set_configure) and is acknowledged by the
    /// next commit. The next accepted commit reports full damage; the covered
    /// and revealed screen areas are queued for repaint and the surface is
    /// raised.
    pub fn set_geometry(
        &mut self,
        session_id: SessionId,
        surface_id: SurfaceId,
        x: i32,
        y: i32,
        width: u32,
        height: u32,
        format: u32,
    ) -> Result<GeometryOutcome, CoreError> {
        let index = self.session_slot(session_id)?;
        let session = self.sessions[index].as_mut().ok_or(CoreError::NoSession)?;
        let slot = surface_index(session, surface_id)?;
        check_dimensions(width, height)?;
        check_format(format)?;
        let x_max = (self.output_width - 1).min(i32::MAX as u32) as i32;
        let y_max = (self.output_height - 1).min(i32::MAX as u32) as i32;
        let x_final = x.clamp(0, x_max) as u32;
        let y_final = y.clamp(0, y_max) as u32;
        let (serial, old_rect) = {
            let surface = session.surfaces[slot]
                .as_ref()
                .ok_or(CoreError::NoSurface)?;
            if surface.destroyed {
                return Err(CoreError::BadState);
            }
            (
                surface
                    .configure_serial
                    .checked_add(1)
                    .ok_or(CoreError::BadState)?,
                surface_rect(surface),
            )
        };
        {
            let surface = session.surfaces[slot]
                .as_mut()
                .ok_or(CoreError::NoSurface)?;
            surface.x = x_final;
            surface.y = y_final;
            surface.width = width;
            surface.height = height;
            surface.configure_serial = serial;
            surface.full_damage_next = true;
        }
        // The covered and the revealed areas repaint, in that order.
        self.push_screen_dirty(old_rect);
        self.z_move_to_front(session_id, surface_id);
        self.push_screen_dirty(Rect {
            x: x_final as i32,
            y: y_final as i32,
            w: width,
            h: height,
        });
        Ok(GeometryOutcome {
            serial,
            x: x_final,
            y: y_final,
            width,
            height,
        })
    }

    /// Apply a window action (`REQUEST_WINDOW_ACTION`).
    ///
    /// `MINIMIZE` hides the surface until `RESTORE`; both queue the covered
    /// area for repaint, `RESTORE` also raises. `MAXIMIZE` is the
    /// [`set_geometry`](DisplayCore::set_geometry) logic applied to the whole
    /// output and reports the new geometry. `RAISE`/`LOWER` reorder the z
    /// order and queue the covered area. Acknowledged actions that change no
    /// geometry return `Ok(None)`.
    pub fn window_action(
        &mut self,
        session_id: SessionId,
        surface_id: SurfaceId,
        action: u32,
    ) -> Result<Option<GeometryOutcome>, CoreError> {
        let index = self.session_slot(session_id)?;
        let session = self.sessions[index].as_mut().ok_or(CoreError::NoSession)?;
        let slot = surface_index(session, surface_id)?;
        let (format, rect) = {
            let surface = session.surfaces[slot]
                .as_ref()
                .ok_or(CoreError::NoSurface)?;
            if surface.destroyed {
                return Err(CoreError::BadState);
            }
            (surface.format, surface_rect(surface))
        };
        match action {
            WINDOW_ACTION_MINIMIZE => {
                let surface = session.surfaces[slot]
                    .as_mut()
                    .ok_or(CoreError::NoSurface)?;
                surface.hidden = true;
                self.push_screen_dirty(rect);
                Ok(None)
            }
            WINDOW_ACTION_RESTORE => {
                let surface = session.surfaces[slot]
                    .as_mut()
                    .ok_or(CoreError::NoSurface)?;
                surface.hidden = false;
                self.z_move_to_front(session_id, surface_id);
                self.push_screen_dirty(rect);
                Ok(None)
            }
            WINDOW_ACTION_MAXIMIZE => self
                .set_geometry(
                    session_id,
                    surface_id,
                    0,
                    0,
                    self.output_width,
                    self.output_height,
                    format,
                )
                .map(Some),
            WINDOW_ACTION_RAISE => {
                self.z_move_to_front(session_id, surface_id);
                self.push_screen_dirty(rect);
                Ok(None)
            }
            WINDOW_ACTION_LOWER => {
                self.z_move_to_back(session_id, surface_id);
                self.push_screen_dirty(rect);
                Ok(None)
            }
            // The decoder already restricts the action range.
            _ => Err(CoreError::BadState),
        }
    }

    /// Queue `rect`, clipped to the output, for the next screen repaint.
    ///
    /// A full queue collapses to the single whole-output rect, which covers
    /// everything previously queued.
    fn push_screen_dirty(&mut self, rect: Rect) {
        let Some(clipped) = clip_rect(&rect, self.output_width, self.output_height) else {
            return;
        };
        if self.screen_dirty_len == MAX_SCREEN_DIRTY {
            self.screen_dirty[0] = Rect {
                x: 0,
                y: 0,
                w: self.output_width,
                h: self.output_height,
            };
            self.screen_dirty_len = 1;
        } else {
            self.screen_dirty[self.screen_dirty_len] = clipped;
            self.screen_dirty_len += 1;
        }
    }

    /// Take the accumulated screen-damage rects, clearing the set.
    pub fn take_screen_dirty(&mut self) -> ([Rect; MAX_SCREEN_DIRTY], usize) {
        let rects = self.screen_dirty;
        let len = self.screen_dirty_len;
        self.screen_dirty_len = 0;
        (rects, len)
    }

    /// Put `surface` on top of the z order (surface creation).
    fn z_insert_front(&mut self, session: SessionId, surface: SurfaceId) {
        if self.zlen == MAX_Z {
            return;
        }
        self.zlist.copy_within(0..self.zlen, 1);
        self.zlist[0] = (session, surface);
        self.zlen += 1;
    }

    /// Drop `surface` from the z order (destroy, session close).
    fn z_remove(&mut self, session: SessionId, surface: SurfaceId) {
        let Some(index) = (0..self.zlen).find(|slot| self.zlist[*slot] == (session, surface))
        else {
            return;
        };
        self.zlist.copy_within(index + 1..self.zlen, index);
        self.zlen -= 1;
    }

    /// Move `surface` to the top of the z order.
    fn z_move_to_front(&mut self, session: SessionId, surface: SurfaceId) {
        let Some(index) = (0..self.zlen).find(|slot| self.zlist[*slot] == (session, surface))
        else {
            return;
        };
        if index == 0 {
            return;
        }
        let entry = self.zlist[index];
        self.zlist.copy_within(0..index, 1);
        self.zlist[0] = entry;
    }

    /// Move `surface` to the bottom of the z order.
    fn z_move_to_back(&mut self, session: SessionId, surface: SurfaceId) {
        let Some(index) = (0..self.zlen).find(|slot| self.zlist[*slot] == (session, surface))
        else {
            return;
        };
        if index == self.zlen - 1 {
            return;
        }
        let entry = self.zlist[index];
        self.zlist.copy_within(index + 1..self.zlen, index);
        self.zlist[self.zlen - 1] = entry;
    }

    /// Compositable layers of the z order, bottom first.
    ///
    /// Hidden surfaces and surfaces without a current buffer are skipped; each
    /// entry is the current buffer's region at the surface's screen origin.
    pub fn layers_bottom_to_top(&self) -> ([Layer; MAX_Z], usize) {
        let mut layers = [Layer {
            region: RegionHandle::new(0),
            x: 0,
            y: 0,
        }; MAX_Z];
        let mut count = 0usize;
        for &(session_id, surface_id) in self.zlist[..self.zlen].iter().rev() {
            let Some(session) = self.sessions.iter().flatten().find(|s| s.id == session_id)
            else {
                continue;
            };
            let Some(surface) = session.surfaces.iter().flatten().find(|s| s.id == surface_id)
            else {
                continue;
            };
            if surface.hidden {
                continue;
            }
            let Some(current) = surface.current else {
                continue;
            };
            let Some(buffer) = session.buffers.iter().flatten().find(|b| b.id == current) else {
                continue;
            };
            layers[count] = Layer {
                region: buffer.region,
                x: surface.x,
                y: surface.y,
            };
            count += 1;
        }
        (layers, count)
    }

    /// Allocate a buffer for `surface` and start its import.
    ///
    /// Checks run in a fixed order, so a request with several defects always
    /// reports the same one:
    ///
    /// 1. ownership and state (session, surface, `destroyed`);
    /// 2. dimensions match the surface;
    /// 3. format matches the surface;
    /// 4. `width * 4` does not overflow;
    /// 5. `stride >= width * 4` and `stride % 4 == 0` (4-byte pixels);
    /// 6. per-surface buffer count;
    /// 7. session pixel quota;
    /// 8. server-wide pixel budget (A.6), when enabled.
    ///
    /// `stride * height` is charged to the session quota.
    pub fn allocate_buffer(
        &mut self,
        session_id: SessionId,
        surface_id: SurfaceId,
        width: u32,
        height: u32,
        format: u32,
        stride: u32,
    ) -> Result<BufferId, CoreError> {
        let index = self.session_slot(session_id)?;
        let global_budget = self.global_budget;
        let pixel_quota = self.pixel_quota;
        let total_used = self.total_used_bytes();
        let session = self.sessions[index].as_mut().ok_or(CoreError::NoSession)?;
        let surface_slot = surface_index(session, surface_id)?;
        let (surface_width, surface_height, surface_format) = {
            let surface = session.surfaces[surface_slot]
                .as_ref()
                .ok_or(CoreError::NoSurface)?;
            if surface.destroyed {
                return Err(CoreError::BadState);
            }
            (surface.width, surface.height, surface.format)
        };
        if width != surface_width || height != surface_height {
            return Err(CoreError::BadDimensions);
        }
        if format != surface_format {
            return Err(CoreError::BadFormat);
        }
        let minimum_stride = width.checked_mul(4).ok_or(CoreError::BadStride)?;
        if stride < minimum_stride || stride % 4 != 0 {
            return Err(CoreError::BadStride);
        }
        let bytes = (stride as u64)
            .checked_mul(height as u64)
            .and_then(|bytes| usize::try_from(bytes).ok())
            .ok_or(CoreError::BadStride)?;
        let per_surface = session
            .buffers
            .iter()
            .flatten()
            .filter(|buffer| buffer.surface == surface_id && buffer.state != BufferState::Retired)
            .count();
        if per_surface >= crate::MAX_BUFFERS_PER_SURFACE {
            return Err(CoreError::Limit);
        }
        let used = session
            .used_bytes
            .checked_add(bytes)
            .ok_or(CoreError::Quota)?;
        if used > pixel_quota {
            return Err(CoreError::Quota);
        }
        if global_budget != 0 && total_used.saturating_add(bytes) > global_budget {
            return Err(CoreError::Quota);
        }
        let slot = session
            .buffers
            .iter()
            .position(|buffer| buffer.is_none())
            .ok_or(CoreError::Limit)?;
        let region = self
            .backend
            .allocate(width, height, stride, format)
            .map_err(|_| CoreError::BackendError)?;
        let id = BufferId::from_slot(slot, self.buffer_gen[slot]);
        self.buffer_gen[slot] = next_generation(self.buffer_gen[slot]);
        session.buffers[slot] = Some(Buffer {
            id,
            surface: surface_id,
            width,
            height,
            format,
            stride,
            bytes,
            region,
            state: BufferState::ImportPending,
        });
        session.used_bytes = used;
        Ok(id)
    }

    /// Report the client import result.
    ///
    /// `Allocating` is never observable; a success moves the buffer to
    /// `Available`, a failure removes the buffer, refunds the quota and retires
    /// the region (it is not freed while the client may still map it).
    pub fn import_result(
        &mut self,
        session_id: SessionId,
        buffer_id: BufferId,
        ok: bool,
    ) -> Result<(), CoreError> {
        let index = self.session_slot(session_id)?;
        let session = self.sessions[index].as_mut().ok_or(CoreError::NoSession)?;
        let slot = buffer_index(session, buffer_id)?;
        match session.buffers[slot]
            .as_ref()
            .ok_or(CoreError::NoBuffer)?
            .state
        {
            BufferState::ImportPending => {}
            _ => return Err(CoreError::BadState),
        }
        if ok {
            if let Some(buffer) = session.buffers[slot].as_mut() {
                buffer.state = BufferState::Available;
            }
            return Ok(());
        }
        let buffer = session.buffers[slot].as_ref().ok_or(CoreError::NoBuffer)?;
        let (bytes, region) = (buffer.bytes, buffer.region);
        let new_used = session
            .used_bytes
            .checked_sub(bytes)
            .ok_or(CoreError::BadState)?;
        if free_retired_slots(&self.retired) == 0 {
            return Err(CoreError::Limit);
        }
        session.buffers[slot] = None;
        session.remove_release(buffer_id);
        session.used_bytes = new_used;
        retire_region(&mut self.retired, session_id, buffer_id, region)
    }

    /// Destroy a non-current buffer, refund its quota and retire its region.
    ///
    /// The region is parked for [`DisplayCore::take_retired`]; when the retired
    /// queue is full the buffer is left in place and [`CoreError::Limit`] is
    /// returned.
    pub fn destroy_buffer(
        &mut self,
        session_id: SessionId,
        buffer_id: BufferId,
    ) -> Result<(), CoreError> {
        let index = self.session_slot(session_id)?;
        let session = self.sessions[index].as_mut().ok_or(CoreError::NoSession)?;
        let slot = buffer_index(session, buffer_id)?;
        let (bytes, region) = {
            let buffer = session.buffers[slot].as_ref().ok_or(CoreError::NoBuffer)?;
            if buffer.state == BufferState::Current {
                return Err(CoreError::BadState);
            }
            let surface_slot = surface_index(session, buffer.surface)?;
            if session.surfaces[surface_slot]
                .as_ref()
                .map_or(false, |surface| {
                    surface.credit == 0 && surface.current == Some(buffer_id)
                })
            {
                return Err(CoreError::BadState);
            }
            (buffer.bytes, buffer.region)
        };
        let new_used = session
            .used_bytes
            .checked_sub(bytes)
            .ok_or(CoreError::BadState)?;
        if free_retired_slots(&self.retired) == 0 {
            return Err(CoreError::Limit);
        }
        session.buffers[slot] = None;
        session.remove_release(buffer_id);
        session.used_bytes = new_used;
        retire_region(&mut self.retired, session_id, buffer_id, region)
    }

    /// Accept a commit atomically (A.4).
    ///
    /// Every check runs before the first mutation, so a rejection leaves
    /// credit, current buffer, serials and commit id untouched. Rects must be
    /// non-empty, non-negative and fully inside the surface. Only
    /// [`FLAG_FULL_DAMAGE`] is accepted.
    ///
    /// On success the previous current buffer becomes `Ready` and is queued for
    /// [`DisplayCore::take_release`], and the commit damage is merged into the
    /// surface's pending damage (reported by
    /// [`DisplayCore::present_current`]).
    pub fn commit(
        &mut self,
        session_id: SessionId,
        surface_id: SurfaceId,
        commit: &Commit,
    ) -> Result<CommitOutcome, CoreError> {
        let index = self.session_slot(session_id)?;
        let session = self.sessions[index].as_mut().ok_or(CoreError::NoSession)?;
        let surface_slot = surface_index(session, surface_id)?;
        let buffer_id = BufferId::from_raw(commit.buffer);
        let buffer_slot = buffer_index(session, buffer_id)?;

        {
            let surface = session.surfaces[surface_slot]
                .as_ref()
                .ok_or(CoreError::NoSurface)?;
            let buffer = session.buffers[buffer_slot]
                .as_ref()
                .ok_or(CoreError::NoBuffer)?;

            if commit.flags & !FLAG_FULL_DAMAGE != 0 {
                return Err(CoreError::BadFlags);
            }
            if buffer.surface != surface_id {
                return Err(CoreError::BadObject);
            }
            if commit.ack_serial != surface.configure_serial
                || commit.ack_serial < surface.acked_serial
            {
                return Err(CoreError::BadSerial);
            }
            if commit.commit_id <= surface.last_commit_id {
                return Err(CoreError::BadCommitId);
            }
            if surface.credit == 0 {
                return Err(CoreError::NoCredit);
            }
            if buffer.state != BufferState::Available {
                return Err(CoreError::BadState);
            }
            if buffer.width != surface.width || buffer.height != surface.height {
                return Err(CoreError::BadDimensions);
            }
            if buffer.format != surface.format {
                return Err(CoreError::BadFormat);
            }
            if commit.rect_count as usize > MAX_RECTS
                || (commit.is_full_damage() && commit.rect_count != 0)
            {
                return Err(CoreError::BadFlags);
            }
            for rect in commit.rects() {
                rect.check_extent().map_err(|_| CoreError::BadDimensions)?;
                if !rect_in_bounds(rect, surface.width, surface.height) {
                    return Err(CoreError::BadDimensions);
                }
            }
        }

        let count = commit.rect_count as usize;

        let surface = session.surfaces[surface_slot]
            .as_mut()
            .ok_or(CoreError::NoSurface)?;
        let damage = if surface.full_damage_next || commit.is_full_damage() {
            // Full commits are the common first frame: do not build the
            // 32-rectangle array (512 bytes) on the stack for them.
            Damage::Full
        } else {
            let mut rects = [Rect::default(); MAX_RECTS];
            rects[..count].copy_from_slice(&commit.rects[..count]);
            Damage::Rects {
                count: count as u8,
                rects,
            }
        };
        merge_damage(&mut surface.pending_damage, damage);
        let released = surface.current;
        surface.last_commit_id = commit.commit_id;
        surface.acked_serial = commit.ack_serial;
        surface.credit = 0;
        surface.full_damage_next = false;
        surface.current = Some(buffer_id);
        surface.damage = damage;

        if let Some(previous) = released {
            if let Ok(slot) = buffer_index(session, previous) {
                if let Some(buffer) = session.buffers[slot].as_mut() {
                    if buffer.state == BufferState::Current {
                        buffer.state = BufferState::Ready;
                    }
                }
            }
            session.push_release(previous);
        }
        if let Some(buffer) = session.buffers[buffer_slot].as_mut() {
            buffer.state = BufferState::Current;
        }
        Ok(CommitOutcome::Accepted { damage, released })
    }

    /// Return commit credit for the surface's current buffer.
    ///
    /// Not a buffer release: the buffer stays current and is only released
    /// when replaced by a subsequent accepted commit.
    pub fn frame_done(
        &mut self,
        session_id: SessionId,
        surface_id: SurfaceId,
        buffer_id: BufferId,
        commit_id: u64,
    ) -> Result<(), CoreError> {
        let index = self.session_slot(session_id)?;
        let session = self.sessions[index].as_mut().ok_or(CoreError::NoSession)?;
        let surface_slot = surface_index(session, surface_id)?;
        let buffer_slot = buffer_index(session, buffer_id)?;
        let surface = session.surfaces[surface_slot]
            .as_mut()
            .ok_or(CoreError::NoSurface)?;
        let buffer = session.buffers[buffer_slot]
            .as_ref()
            .ok_or(CoreError::NoBuffer)?;
        if buffer.surface != surface_id || buffer.state != BufferState::Current {
            return Err(CoreError::BadState);
        }
        if surface.current != Some(buffer_id) {
            return Err(CoreError::BadState);
        }
        if commit_id != surface.last_commit_id {
            return Err(CoreError::BadCommitId);
        }
        if surface.credit != 0 {
            return Err(CoreError::BadState);
        }
        surface.credit = 1;
        Ok(())
    }

    /// Present the surface's current buffer once per accepted commit.
    ///
    /// Composites every layer of the z order over the pending damage of the
    /// surface, translated to screen space and clipped to the output. Full
    /// damage covers the current buffer's dimensions (a configure may have
    /// changed the surface since the commit); stored rects are revalidated
    /// against those dimensions and a stale out-of-bounds rect yields
    /// [`CoreError::BadDimensions`] before the backend is called. When no rect
    /// survives the clipping the backend is not called at all. Repeated calls
    /// without a new commit return [`CoreError::BadState`].
    pub fn present_current(
        &mut self,
        session_id: SessionId,
        surface_id: SurfaceId,
    ) -> Result<(), CoreError> {
        let index = self.session_slot(session_id)?;
        let (damage, width, height, commit_id, acked_serial, origin_x, origin_y) = {
            let session = self.sessions[index].as_ref().ok_or(CoreError::NoSession)?;
            let surface_slot = surface_index(session, surface_id)?;
            let surface = session.surfaces[surface_slot]
                .as_ref()
                .ok_or(CoreError::NoSurface)?;
            let current = surface.current.ok_or(CoreError::BadState)?;
            if surface.presented_commit == surface.last_commit_id {
                return Err(CoreError::BadState);
            }
            let buffer_slot = buffer_index(session, current)?;
            let buffer = session.buffers[buffer_slot]
                .as_ref()
                .ok_or(CoreError::NoBuffer)?;
            (
                surface.pending_damage,
                buffer.width,
                buffer.height,
                surface.last_commit_id,
                surface.acked_serial,
                surface.x,
                surface.y,
            )
        };

        let mut rects = [Rect::default(); MAX_RECTS];
        let mut rect_count = 0usize;
        match damage {
            Damage::Full => {
                let full = Rect {
                    x: origin_x as i32,
                    y: origin_y as i32,
                    w: width,
                    h: height,
                };
                if let Some(clipped) = clip_rect(&full, self.output_width, self.output_height) {
                    rects[rect_count] = clipped;
                    rect_count += 1;
                }
            }
            Damage::Rects { count, rects: stored } => {
                for rect in &stored[..count as usize] {
                    if !rect_in_bounds(rect, width, height) {
                        return Err(CoreError::BadDimensions);
                    }
                }
                for rect in &stored[..count as usize] {
                    let screen = Rect {
                        x: rect.x.saturating_add(origin_x as i32),
                        y: rect.y.saturating_add(origin_y as i32),
                        w: rect.w,
                        h: rect.h,
                    };
                    if let Some(clipped) =
                        clip_rect(&screen, self.output_width, self.output_height)
                    {
                        rects[rect_count] = clipped;
                        rect_count += 1;
                    }
                }
            }
        }

        if rect_count > 0 {
            // Copy the layers out first: the backend borrow must not overlap
            // the core state the layers were built from.
            let (layers, layer_len) = self.layers_bottom_to_top();
            self.backend
                .composite(&layers[..layer_len], &rects[..rect_count])
                .map_err(|_| CoreError::BackendError)?;
        }

        let session = self.sessions[index].as_mut().ok_or(CoreError::NoSession)?;
        let surface_slot = surface_index(session, surface_id)?;
        if let Some(surface) = session.surfaces[surface_slot].as_mut() {
            surface.presented_commit = commit_id;
            surface.presented_serial = acked_serial;
            surface.pending_damage = Damage::Rects {
                count: 0,
                rects: [Rect::default(); MAX_RECTS],
            };
        }
        Ok(())
    }

    /// Pop the oldest pending `BUFFER_RELEASE` notification of a session.
    ///
    /// Transitions the buffer `Ready -> Available` and returns it. Notifications
    /// whose buffer no longer exists, or is no longer `Ready`, are skipped.
    pub fn take_release(&mut self, session_id: SessionId) -> Result<Option<BufferId>, CoreError> {
        let index = self.session_slot(session_id)?;
        let session = self.sessions[index].as_mut().ok_or(CoreError::NoSession)?;
        while let Some(id) = session.pop_release() {
            let slot = match buffer_index(session, id) {
                Ok(slot) => slot,
                Err(_) => continue,
            };
            let buffer = match session.buffers[slot].as_mut() {
                Some(buffer) => buffer,
                None => continue,
            };
            if buffer.state == BufferState::Ready {
                buffer.state = BufferState::Available;
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    /// Whether a release notification was dropped for `session` since the last
    /// [`DisplayCore::clear_release_overflow`].
    pub fn release_overflow(&self, session_id: SessionId) -> Result<bool, CoreError> {
        let index = self.session_slot(session_id)?;
        Ok(self.sessions[index]
            .as_ref()
            .ok_or(CoreError::NoSession)?
            .release_overflow)
    }

    /// Clear the dropped-release flag of `session`.
    pub fn clear_release_overflow(&mut self, session_id: SessionId) -> Result<(), CoreError> {
        let index = self.session_slot(session_id)?;
        self.sessions[index]
            .as_mut()
            .ok_or(CoreError::NoSession)?
            .release_overflow = false;
        Ok(())
    }

    /// Bytes currently charged to a session's pixel quota.
    pub fn used_bytes(&self, session_id: SessionId) -> Result<usize, CoreError> {
        let index = self.session_slot(session_id)?;
        Ok(self.sessions[index]
            .as_ref()
            .ok_or(CoreError::NoSession)?
            .used_bytes)
    }

    /// Set the server-wide pixel budget in bytes; `0` disables the check.
    pub fn set_global_budget(&mut self, bytes: usize) {
        self.global_budget = bytes;
    }

    /// Server-wide pixel budget in bytes (`0` = disabled).
    pub fn global_budget(&self) -> usize {
        self.global_budget
    }

    /// Saturating sum of `used_bytes` over every live session.
    pub fn total_used_bytes(&self) -> usize {
        self.sessions
            .iter()
            .flatten()
            .fold(0usize, |total, session| {
                total.saturating_add(session.used_bytes)
            })
    }

    /// Number of live sessions.
    pub fn session_count(&self) -> usize {
        self.sessions
            .iter()
            .filter(|session| session.is_some())
            .count()
    }

    /// Number of live surfaces of a session.
    pub fn surface_count(&self, session_id: SessionId) -> Result<usize, CoreError> {
        let index = self.session_slot(session_id)?;
        let session = self.sessions[index].as_ref().ok_or(CoreError::NoSession)?;
        Ok(session
            .surfaces
            .iter()
            .filter(|slot| slot.is_some())
            .count())
    }

    /// Aggregate counters, for the display server's diagnostics line.
    ///
    /// Never includes pixels, titles or peer identities.
    pub fn stats(&self) -> CoreStats {
        let mut stats = CoreStats::default();
        for session in self.sessions.iter().flatten() {
            stats.sessions += 1;
            stats.surfaces += session.surfaces.iter().flatten().count();
            stats.buffers += session.buffers.iter().flatten().count();
            stats.used_bytes += session.used_bytes;
        }
        stats
    }

    /// Number of live buffers of a session.
    pub fn buffer_count(&self, session_id: SessionId) -> Result<usize, CoreError> {
        let index = self.session_slot(session_id)?;
        let session = self.sessions[index].as_ref().ok_or(CoreError::NoSession)?;
        Ok(session.buffers.iter().filter(|slot| slot.is_some()).count())
    }

    /// Read a surface record.
    pub fn surface(
        &self,
        session_id: SessionId,
        surface_id: SurfaceId,
    ) -> Result<&Surface, CoreError> {
        let index = self.session_slot(session_id)?;
        let session = self.sessions[index].as_ref().ok_or(CoreError::NoSession)?;
        let slot = surface_index(session, surface_id)?;
        session.surfaces[slot].as_ref().ok_or(CoreError::NoSurface)
    }

    /// Screen-space origin of `surface_id`'s tile.
    ///
    /// Every surface of a session shares the session's tile origin. Fails with
    /// the usual stale/foreign-handle errors ([`CoreError::BadObject`],
    /// [`CoreError::NoSession`], [`CoreError::NoSurface`]).
    pub fn surface_origin(
        &self,
        session_id: SessionId,
        surface_id: SurfaceId,
    ) -> Result<(u32, u32), CoreError> {
        let surface = self.surface(session_id, surface_id)?;
        Ok((surface.x, surface.y))
    }

    /// Topmost surface whose geometry contains the screen point `(x, y)`.
    ///
    /// Walks the z order from the top; the first non-hidden surface covering
    /// the point wins, with or without a current image. Destroyed surfaces
    /// never stay in the z order, so they cannot be picked.
    pub fn surface_at(&self, x: u32, y: u32) -> Option<(SessionId, SurfaceId)> {
        for &(session_id, surface_id) in self.zlist[..self.zlen].iter() {
            let Some(session) = self.sessions.iter().flatten().find(|s| s.id == session_id)
            else {
                continue;
            };
            let Some(surface) = session.surfaces.iter().flatten().find(|s| s.id == surface_id)
            else {
                continue;
            };
            if surface.hidden {
                continue;
            }
            if x >= surface.x
                && x - surface.x < surface.width
                && y >= surface.y
                && y - surface.y < surface.height
            {
                return Some((session_id, surface_id));
            }
        }
        None
    }

    /// Read a buffer record.
    pub fn buffer(&self, session_id: SessionId, buffer_id: BufferId) -> Result<&Buffer, CoreError> {
        let index = self.session_slot(session_id)?;
        let session = self.sessions[index].as_ref().ok_or(CoreError::NoSession)?;
        let slot = buffer_index(session, buffer_id)?;
        session.buffers[slot].as_ref().ok_or(CoreError::NoBuffer)
    }

    fn session_slot(&self, id: SessionId) -> Result<usize, CoreError> {
        let index = id.slot().ok_or(CoreError::BadObject)?;
        match &self.sessions[index] {
            None => Err(CoreError::NoSession),
            Some(session) if session.id == id => Ok(index),
            Some(_) => Err(CoreError::BadObject),
        }
    }
}

impl<B: Backend> Drop for DisplayCore<B> {
    /// Free every live and every retired region exactly once.
    fn drop(&mut self) {
        let Self {
            backend,
            sessions,
            retired,
            ..
        } = self;
        for session in sessions.iter_mut().flatten() {
            for slot in session.buffers.iter_mut() {
                if let Some(buffer) = slot.take() {
                    backend.free(buffer.region);
                }
            }
        }
        for slot in retired.iter_mut() {
            if let Some(region) = slot.take() {
                backend.free(region.region);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RegionHandle, MAX_RECTS, MAX_SESSIONS, PIXEL_QUOTA_BYTES, TILE_ROWS};
    use vasistas_protocol::{FLAG_FULL_DAMAGE, MAX_RECTS as PROTOCOL_MAX_RECTS};

    #[derive(Default)]
    struct Fake {
        next_region: u64,
        allocations: u32,
        frees: u32,
        presents: u32,
        last_damage: usize,
        last_layers: usize,
        last_rects: [Rect; MAX_RECTS],
        fail_allocation: bool,
    }

    impl Backend for Fake {
        type Error = ();

        fn allocate(
            &mut self,
            _width: u32,
            _height: u32,
            _stride: u32,
            _format: u32,
        ) -> Result<RegionHandle, Self::Error> {
            if self.fail_allocation {
                return Err(());
            }
            let region = RegionHandle::new(self.next_region);
            self.next_region += 1;
            self.allocations += 1;
            Ok(region)
        }

        fn free(&mut self, _region: RegionHandle) {
            self.frees += 1;
        }

        fn composite(
            &mut self,
            bottom_to_top: &[Layer],
            rects: &[Rect],
        ) -> Result<(), Self::Error> {
            self.presents += 1;
            self.last_damage = rects.len();
            self.last_layers = bottom_to_top.len();
            let count = rects.len().min(MAX_RECTS);
            self.last_rects[..count].copy_from_slice(&rects[..count]);
            Ok(())
        }
    }

    /// Backend whose free counter outlives the core, for `Drop` tests.
    #[derive(Default)]
    struct DropBackend {
        frees: std::sync::Arc<std::sync::atomic::AtomicU32>,
        next: u64,
    }

    impl Backend for DropBackend {
        type Error = ();
        fn allocate(
            &mut self,
            _width: u32,
            _height: u32,
            _stride: u32,
            _format: u32,
        ) -> Result<RegionHandle, Self::Error> {
            self.next += 1;
            Ok(RegionHandle::new(self.next))
        }
        fn free(&mut self, _region: RegionHandle) {
            self.frees.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        fn composite(
            &mut self,
            _bottom_to_top: &[Layer],
            _rects: &[Rect],
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    const W: u32 = 8;
    const H: u32 = 8;
    const STRIDE: u32 = W * 4;

    fn new_core() -> (DisplayCore<Fake>, SessionId) {
        let mut core = DisplayCore::new(Fake::default());
        let session = core.create_session().unwrap();
        (core, session)
    }

    fn add_surface<B: Backend>(core: &mut DisplayCore<B>, session: SessionId) -> SurfaceId {
        core.create_surface(session, W, H, FORMAT_XRGB8888, 4)
            .unwrap()
    }

    fn add_buffer<B: Backend>(
        core: &mut DisplayCore<B>,
        session: SessionId,
        surface: SurfaceId,
    ) -> BufferId {
        let buffer = core
            .allocate_buffer(session, surface, W, H, FORMAT_XRGB8888, STRIDE)
            .unwrap();
        core.import_result(session, buffer, true).unwrap();
        buffer
    }

    fn commit_body(buffer: BufferId, ack: u64, commit_id: u64) -> Commit {
        Commit {
            buffer: buffer.raw(),
            ack_serial: ack,
            commit_id,
            flags: 0,
            rect_count: 0,
            rects: [Rect::default(); PROTOCOL_MAX_RECTS],
        }
    }

    fn snapshot(
        core: &DisplayCore<Fake>,
        session: SessionId,
        surface: SurfaceId,
    ) -> (u8, Option<BufferId>, u64, u64) {
        let s = core.surface(session, surface).unwrap();
        (s.credit, s.current, s.last_commit_id, s.acked_serial)
    }

    fn assert_rejected_unchanged(
        core: &mut DisplayCore<Fake>,
        session: SessionId,
        surface: SurfaceId,
        commit: &Commit,
        expected: CoreError,
    ) {
        let before = snapshot(core, session, surface);
        let used = core.used_bytes(session).unwrap();
        assert_eq!(core.commit(session, surface, commit), Err(expected));
        assert_eq!(snapshot(core, session, surface), before);
        assert_eq!(core.used_bytes(session).unwrap(), used);
    }

    #[test]
    fn limits_are_enforced() {
        let mut core = DisplayCore::new(Fake::default());
        let mut sessions = [None; MAX_SESSIONS];
        for slot in sessions.iter_mut() {
            *slot = Some(core.create_session().unwrap());
        }
        assert_eq!(core.create_session(), Err(CoreError::Limit));
        assert_eq!(core.session_count(), MAX_SESSIONS);

        let session = sessions[0].unwrap();
        let mut surfaces = [None; 4];
        for slot in surfaces.iter_mut() {
            *slot = Some(add_surface(&mut core, session));
        }
        assert_eq!(
            core.create_surface(session, W, H, FORMAT_XRGB8888, 0),
            Err(CoreError::Limit)
        );
        assert_eq!(core.surface_count(session).unwrap(), 4);

        // A.6: at most 4 buffers per surface, 16 per session.
        for surface in surfaces.iter().flatten() {
            for _ in 0..crate::MAX_BUFFERS_PER_SURFACE {
                add_buffer(&mut core, session, *surface);
            }
        }
        assert_eq!(core.buffer_count(session).unwrap(), MAX_BUFFERS_PER_SESSION);
        let surface = surfaces[0].unwrap();
        assert_eq!(
            core.allocate_buffer(session, surface, W, H, FORMAT_XRGB8888, STRIDE),
            Err(CoreError::Limit),
            "per-surface cap"
        );
    }

    #[test]
    fn stale_ids_are_rejected_after_reuse() {
        let mut core = DisplayCore::new(Fake::default());
        let first_session = core.create_session().unwrap();
        let stale_surface = add_surface(&mut core, first_session);
        let stale_buffer = add_buffer(&mut core, first_session, stale_surface);
        core.close_session(first_session).unwrap();

        let second_session = core.create_session().unwrap();
        assert_ne!(first_session, second_session);
        assert_eq!(
            core.create_surface(first_session, W, H, FORMAT_XRGB8888, 0),
            Err(CoreError::BadObject)
        );

        let surface = add_surface(&mut core, second_session);
        assert_eq!(
            core.surface(second_session, stale_surface),
            Err(CoreError::BadObject)
        );
        let buffer = add_buffer(&mut core, second_session, surface);
        assert_eq!(
            core.buffer(second_session, stale_buffer),
            Err(CoreError::BadObject)
        );

        core.destroy_buffer(second_session, buffer).unwrap();
        let reused = add_buffer(&mut core, second_session, surface);
        assert_ne!(buffer, reused);
        assert_eq!(
            core.buffer(second_session, buffer),
            Err(CoreError::BadObject)
        );
    }

    #[test]
    fn commit_credit_cycle_and_release() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        let first = add_buffer(&mut core, session, surface);
        let second = add_buffer(&mut core, session, surface);

        assert_eq!(core.surface(session, surface).unwrap().credit, 1);
        let outcome = core
            .commit(session, surface, &commit_body(first, 0, 1))
            .unwrap();
        assert_eq!(
            outcome,
            CommitOutcome::Accepted {
                damage: Damage::Full,
                released: None
            }
        );
        let state = core.surface(session, surface).unwrap();
        assert_eq!(state.credit, 0);
        assert_eq!(state.current, Some(first));
        assert_eq!(
            core.buffer(session, first).unwrap().state,
            BufferState::Current
        );

        assert_eq!(
            core.commit(session, surface, &commit_body(second, 0, 2)),
            Err(CoreError::NoCredit)
        );
        assert_eq!(core.surface(session, surface).unwrap().current, Some(first));

        core.frame_done(session, surface, first, 1).unwrap();
        assert_eq!(core.surface(session, surface).unwrap().credit, 1);
        assert_eq!(
            core.buffer(session, first).unwrap().state,
            BufferState::Current
        );

        let outcome = core
            .commit(session, surface, &commit_body(second, 0, 2))
            .unwrap();
        assert_eq!(
            outcome,
            CommitOutcome::Accepted {
                damage: Damage::Rects {
                    count: 0,
                    rects: [Rect::default(); MAX_RECTS]
                },
                released: Some(first)
            }
        );
        assert_eq!(
            core.surface(session, surface).unwrap().current,
            Some(second)
        );
        assert_eq!(
            core.buffer(session, first).unwrap().state,
            BufferState::Ready,
            "replaced current is Ready until released"
        );
        assert_eq!(core.take_release(session), Ok(Some(first)));
        assert_eq!(
            core.buffer(session, first).unwrap().state,
            BufferState::Available
        );
        assert_eq!(core.take_release(session), Ok(None));
    }

    #[test]
    fn every_commit_rejection_is_atomic() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        let current = add_buffer(&mut core, session, surface);
        core.commit(session, surface, &commit_body(current, 0, 1))
            .unwrap();
        core.frame_done(session, surface, current, 1).unwrap();
        let other = add_buffer(&mut core, session, surface);

        // Malformed buffer id: slot 0 is not a valid encoding.
        assert_rejected_unchanged(
            &mut core,
            session,
            surface,
            &commit_body(BufferId::from_raw(0), 0, 2),
            CoreError::BadObject,
        );

        // Buffer not imported yet.
        let pending = core
            .allocate_buffer(session, surface, W, H, FORMAT_XRGB8888, STRIDE)
            .unwrap();
        assert_rejected_unchanged(
            &mut core,
            session,
            surface,
            &commit_body(pending, 0, 2),
            CoreError::BadState,
        );

        // Dimensions drift after configure.
        assert_eq!(
            core.set_configure(session, surface, 16, 16, FORMAT_XRGB8888)
                .unwrap(),
            1
        );
        assert_rejected_unchanged(
            &mut core,
            session,
            surface,
            &commit_body(other, 1, 2),
            CoreError::BadDimensions,
        );
        assert_eq!(
            core.set_configure(session, surface, W, H, FORMAT_XRGB8888)
                .unwrap(),
            2
        );
        let before = snapshot(&mut core, session, surface);
        assert_eq!(
            core.set_configure(session, surface, 0, H, FORMAT_XRGB8888),
            Err(CoreError::BadDimensions)
        );

        // Future serial.
        assert_rejected_unchanged(
            &mut core,
            session,
            surface,
            &commit_body(other, 3, 2),
            CoreError::BadSerial,
        );
        // Regressive serial (equals nothing current).
        assert_rejected_unchanged(
            &mut core,
            session,
            surface,
            &commit_body(other, 1, 2),
            CoreError::BadSerial,
        );
        // Non-increasing commit id.
        assert_rejected_unchanged(
            &mut core,
            session,
            surface,
            &commit_body(other, 2, 1),
            CoreError::BadCommitId,
        );
        // Unsupported flags combination.
        let mut flags = commit_body(other, 2, 2);
        flags.flags = FLAG_FULL_DAMAGE;
        flags.rect_count = 1;
        assert_rejected_unchanged(&mut core, session, surface, &flags, CoreError::BadFlags);
        // Unknown flag bit.
        let mut unknown = commit_body(other, 2, 2);
        unknown.flags = FLAG_FULL_DAMAGE << 1;
        assert_rejected_unchanged(&mut core, session, surface, &unknown, CoreError::BadFlags);
        assert_eq!(snapshot(&mut core, session, surface), before);

        // No credit: make a first accepted commit, then retry with a third
        // available buffer, which never touches state.
        let third = add_buffer(&mut core, session, surface);
        core.commit(session, surface, &commit_body(other, 2, 2))
            .unwrap();
        assert_rejected_unchanged(
            &mut core,
            session,
            surface,
            &commit_body(third, 2, 3),
            CoreError::NoCredit,
        );

        // BadStride is an allocation-time failure: nothing is charged.
        let used = core.used_bytes(session).unwrap();
        assert_eq!(
            core.allocate_buffer(session, surface, W, H, FORMAT_XRGB8888, STRIDE - 1),
            Err(CoreError::BadStride)
        );
        assert_eq!(core.used_bytes(session).unwrap(), used);
    }

    #[test]
    fn serials_configure_and_ack() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        let buffer = add_buffer(&mut core, session, surface);

        assert_eq!(
            core.set_configure(session, surface, W, H, FORMAT_XRGB8888)
                .unwrap(),
            1
        );
        assert_eq!(
            core.set_configure(session, surface, W, H, FORMAT_XRGB8888)
                .unwrap(),
            2
        );

        assert_eq!(
            core.commit(session, surface, &commit_body(buffer, 1, 1)),
            Err(CoreError::BadSerial)
        );
        core.commit(session, surface, &commit_body(buffer, 2, 1))
            .unwrap();
        core.frame_done(session, surface, buffer, 1).unwrap();
        assert_eq!(
            core.commit(session, surface, &commit_body(buffer, 1, 2)),
            Err(CoreError::BadSerial)
        );
        assert_eq!(core.surface(session, surface).unwrap().acked_serial, 2);
    }

    #[test]
    fn pixel_quota_derives_from_output_and_keeps_its_floor() {
        let mut core = DisplayCore::new(Fake::default());
        let session = core.create_session().unwrap();
        let surface = core
            .create_surface(session, 1600, 1200, FORMAT_XRGB8888, 0)
            .unwrap();
        let stride = 1600u32 * 4;
        let frame = (stride as u64 * 1200) as usize;

        // Default quota (8 MiB) fits one full-screen buffer but not two.
        core.allocate_buffer(session, surface, 1600, 1200, FORMAT_XRGB8888, stride)
            .unwrap();
        assert_eq!(core.used_bytes(session).unwrap(), frame);
        assert!(
            matches!(
                core.allocate_buffer(session, surface, 1600, 1200, FORMAT_XRGB8888, stride),
                Err(CoreError::Quota)
            ),
            "8 MiB cannot host a full-screen ping-pong pair"
        );

        // A quota derived from the output (two full-screen buffers) admits
        // the pair, and never drops below the 8 MiB floor.
        core.set_pixel_quota(frame * 2);
        assert_eq!(core.pixel_quota(), frame * 2);
        core.allocate_buffer(session, surface, 1600, 1200, FORMAT_XRGB8888, stride)
            .unwrap();
        assert_eq!(core.used_bytes(session).unwrap(), frame * 2);

        core.set_pixel_quota(0);
        assert_eq!(core.pixel_quota(), PIXEL_QUOTA_BYTES, "floor holds");
    }

    #[test]
    fn quota_is_per_session_and_refunded() {
        let mut core = DisplayCore::new(Fake::default());
        let session = core.create_session().unwrap();
        let surface = core
            .create_surface(session, 4096, 512, FORMAT_XRGB8888, 0)
            .unwrap();
        let stride = 4096u32 * 4;
        let bytes = (stride as u64 * 512) as usize;
        assert_eq!(bytes, PIXEL_QUOTA_BYTES);

        let buffer = core
            .allocate_buffer(session, surface, 4096, 512, FORMAT_XRGB8888, stride)
            .unwrap();
        assert_eq!(core.used_bytes(session).unwrap(), PIXEL_QUOTA_BYTES);

        // A second session has its own quota.
        let other_session = core.create_session().unwrap();
        let other_surface = core
            .create_surface(other_session, 4096, 512, FORMAT_XRGB8888, 0)
            .unwrap();
        core.allocate_buffer(
            other_session,
            other_surface,
            4096,
            512,
            FORMAT_XRGB8888,
            stride,
        )
        .unwrap();
        assert_eq!(core.used_bytes(other_session).unwrap(), PIXEL_QUOTA_BYTES);

        // A tiny second surface cannot squeeze another byte out of session one.
        let tiny = core
            .create_surface(session, 1, 1, FORMAT_XRGB8888, 0)
            .unwrap();
        assert_eq!(
            core.allocate_buffer(session, tiny, 1, 1, FORMAT_XRGB8888, 4),
            Err(CoreError::Quota)
        );
        assert_eq!(core.used_bytes(session).unwrap(), PIXEL_QUOTA_BYTES);

        core.import_result(session, buffer, true).unwrap();
        core.destroy_buffer(session, buffer).unwrap();
        assert_eq!(core.used_bytes(session).unwrap(), 0);
        assert!(core
            .allocate_buffer(session, tiny, 1, 1, FORMAT_XRGB8888, 4)
            .is_ok());

        // Import failure refunds too.
        let failing = core
            .allocate_buffer(session, tiny, 1, 1, FORMAT_XRGB8888, 4)
            .unwrap();
        assert_eq!(core.used_bytes(session).unwrap(), 8);
        core.import_result(session, failing, false).unwrap();
        assert_eq!(core.used_bytes(session).unwrap(), 4);
        assert!(core.buffer(session, failing).is_err());
    }

    #[test]
    fn global_budget_is_shared_and_refunded() {
        const MIB: usize = 1024 * 1024;
        let mut core = DisplayCore::new(Fake::default());
        let first = core.create_session().unwrap();
        let second = core.create_session().unwrap();
        assert_eq!(core.global_budget(), 0, "budget starts disabled");
        // Per-session quotas stay 8 MiB; the server-wide budget is 9 MiB.
        core.set_global_budget(9 * MIB);
        assert_eq!(core.global_budget(), 9 * MIB);
        let surface_a = core
            .create_surface(first, 1024, 1024, FORMAT_XRGB8888, 0)
            .unwrap();
        let surface_b = core
            .create_surface(second, 1024, 1024, FORMAT_XRGB8888, 0)
            .unwrap();
        let buffer_a = core
            .allocate_buffer(first, surface_a, 1024, 1024, FORMAT_XRGB8888, 4096)
            .unwrap();
        let buffer_b = core
            .allocate_buffer(second, surface_b, 1024, 1024, FORMAT_XRGB8888, 4096)
            .unwrap();
        assert_eq!(core.total_used_bytes(), 8 * MIB);

        // A third 4 MiB buffer crosses the global budget: rejected, and both
        // sessions keep their charge.
        assert_eq!(
            core.allocate_buffer(first, surface_a, 1024, 1024, FORMAT_XRGB8888, 4096),
            Err(CoreError::Quota)
        );
        assert_eq!(core.used_bytes(first).unwrap(), 4 * MIB);
        assert_eq!(core.used_bytes(second).unwrap(), 4 * MIB);
        assert_eq!(core.total_used_bytes(), 8 * MIB);

        // Destroying a buffer refunds the global budget.
        core.import_result(first, buffer_a, true).unwrap();
        core.destroy_buffer(first, buffer_a).unwrap();
        assert_eq!(core.total_used_bytes(), 4 * MIB);
        let recycled = core
            .allocate_buffer(first, surface_a, 1024, 1024, FORMAT_XRGB8888, 4096)
            .unwrap();
        assert_eq!(core.total_used_bytes(), 8 * MIB);
        core.import_result(first, recycled, true).unwrap();
        let _ = buffer_b;

        // Zero disables the check: both sessions reach their 8 MiB quota,
        // i.e. 16 MiB total, well past the 9 MiB budget.
        core.set_global_budget(0);
        let extra_a = core
            .create_surface(first, 1024, 1024, FORMAT_XRGB8888, 0)
            .unwrap();
        let extra_b = core
            .create_surface(second, 1024, 1024, FORMAT_XRGB8888, 0)
            .unwrap();
        assert!(core
            .allocate_buffer(first, extra_a, 1024, 1024, FORMAT_XRGB8888, 4096)
            .is_ok());
        assert!(core
            .allocate_buffer(second, extra_b, 1024, 1024, FORMAT_XRGB8888, 4096)
            .is_ok());
        assert_eq!(core.total_used_bytes(), 16 * MIB);
    }

    #[test]
    fn destroy_rules() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        let first = add_buffer(&mut core, session, surface);
        core.commit(session, surface, &commit_body(first, 0, 1))
            .unwrap();

        assert_eq!(
            core.destroy_buffer(session, first),
            Err(CoreError::BadState)
        );
        // A pending commit also blocks surface destruction.
        assert_eq!(
            core.destroy_surface(session, surface),
            Err(CoreError::BadState)
        );
        core.frame_done(session, surface, first, 1).unwrap();
        core.destroy_surface(session, surface).unwrap();
        assert_eq!(core.used_bytes(session).unwrap(), 0);
        assert_eq!(core.surface_count(session).unwrap(), 0);
        assert_eq!(core.buffer_count(session).unwrap(), 0);
        assert_eq!(
            core.backend().frees,
            0,
            "regions are retired, not freed while a client may map them"
        );
        let retired = core.take_retired().expect("surface buffer retired");
        assert_eq!(retired.session, session);
        assert_eq!(retired.buffer, first);
        core.backend_mut().free(retired.region);
        assert_eq!(core.backend().frees, 1);
        assert!(core.take_retired().is_none());

        // Foreign buffer is rejected.
        let surface_b = add_surface(&mut core, session);
        let buffer_b = add_buffer(&mut core, session, surface_b);
        let session_two = core.create_session().unwrap();
        assert_eq!(
            core.destroy_buffer(session_two, buffer_b),
            Err(CoreError::NoBuffer)
        );
        let surface_two = add_surface(&mut core, session_two);
        let buffer_two = add_buffer(&mut core, session_two, surface_two);
        assert!(matches!(
            core.destroy_buffer(session, buffer_two),
            Err(CoreError::NoBuffer) | Err(CoreError::BadObject)
        ));

        // Destroying a surface retires and frees its current buffer.
        core.commit(session, surface_b, &commit_body(buffer_b, 0, 1))
            .unwrap();
        core.frame_done(session, surface_b, buffer_b, 1).unwrap();
        assert_eq!(
            core.used_bytes(session).unwrap(),
            STRIDE as usize * H as usize
        );
        core.destroy_surface(session, surface_b).unwrap();
        assert_eq!(core.used_bytes(session).unwrap(), 0);
        assert!(core.buffer(session, buffer_b).is_err());
    }

    #[test]
    fn damage_first_commit_rects_and_configure() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        let first = add_buffer(&mut core, session, surface);
        let second = add_buffer(&mut core, session, surface);

        let outcome = core
            .commit(session, surface, &commit_body(first, 0, 1))
            .unwrap();
        assert!(matches!(
            outcome,
            CommitOutcome::Accepted {
                damage: Damage::Full,
                ..
            }
        ));

        core.frame_done(session, surface, first, 1).unwrap();
        let mut commit = commit_body(second, 0, 2);
        commit.rect_count = 2;
        commit.rects[0] = Rect {
            x: 1,
            y: 2,
            w: 3,
            h: 4,
        };
        commit.rects[1] = Rect {
            x: 5,
            y: 6,
            w: 1,
            h: 1,
        };
        match core.commit(session, surface, &commit).unwrap() {
            CommitOutcome::Accepted {
                damage: Damage::Rects { count, rects },
                ..
            } => {
                assert_eq!(count, 2);
                assert_eq!(rects[0], commit.rects[0]);
                assert_eq!(rects[1], commit.rects[1]);
            }
            other => panic!("unexpected outcome: {:?}", other),
        }

        core.frame_done(session, surface, second, 2).unwrap();
        assert_eq!(core.take_release(session), Ok(Some(first)));
        assert_eq!(
            core.set_configure(session, surface, W, H, FORMAT_XRGB8888)
                .unwrap(),
            1
        );
        let mut third = commit_body(first, 1, 3);
        third.rect_count = 1;
        third.rects[0] = Rect {
            x: 0,
            y: 0,
            w: 1,
            h: 1,
        };
        match core.commit(session, surface, &third).unwrap() {
            CommitOutcome::Accepted {
                damage: Damage::Full,
                ..
            } => {}
            other => panic!("configure must force full damage: {:?}", other),
        }

        // FULL_DAMAGE also yields Full even without full_damage_next.
        core.frame_done(session, surface, first, 3).unwrap();
        assert_eq!(core.take_release(session), Ok(Some(second)));
        let mut fourth = commit_body(second, 1, 4);
        fourth.flags = FLAG_FULL_DAMAGE;
        match core.commit(session, surface, &fourth).unwrap() {
            CommitOutcome::Accepted {
                damage: Damage::Full,
                ..
            } => {}
            other => panic!("FULL_DAMAGE must force full damage: {:?}", other),
        }
    }

    #[test]
    fn backend_calls_and_presentation() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        assert_eq!(core.backend().allocations, 0);
        let buffer = add_buffer(&mut core, session, surface);
        assert_eq!(core.backend().allocations, 1);

        core.commit(session, surface, &commit_body(buffer, 0, 1))
            .unwrap();
        assert_eq!(core.present_current(session, surface), Ok(()));
        assert_eq!(core.backend().presents, 1);
        assert_eq!(
            core.backend().last_damage,
            1,
            "first present is full surface"
        );

        assert_eq!(
            core.present_current(session, surface),
            Err(CoreError::BadState),
            "no new commit"
        );
        assert_eq!(core.backend().presents, 1);

        core.frame_done(session, surface, buffer, 1).unwrap();
        let second = add_buffer(&mut core, session, surface);
        let mut commit = commit_body(second, 0, 2);
        commit.rect_count = 1;
        commit.rects[0] = Rect {
            x: 0,
            y: 0,
            w: 2,
            h: 2,
        };
        core.commit(session, surface, &commit).unwrap();
        core.present_current(session, surface).unwrap();
        assert_eq!(core.backend().presents, 2);
        assert_eq!(core.backend().last_damage, 1);
        assert_eq!(core.surface(session, surface).unwrap().presented_commit, 2);
        assert_eq!(core.surface(session, surface).unwrap().presented_serial, 0);
    }

    #[test]
    fn backend_allocation_failure_leaves_quota_untouched() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        core.backend_mut().fail_allocation = true;
        assert_eq!(
            core.allocate_buffer(session, surface, W, H, FORMAT_XRGB8888, STRIDE),
            Err(CoreError::BackendError)
        );
        assert_eq!(core.used_bytes(session).unwrap(), 0);
        assert_eq!(core.buffer_count(session).unwrap(), 0);
        core.backend_mut().fail_allocation = false;
        core.allocate_buffer(session, surface, W, H, FORMAT_XRGB8888, STRIDE)
            .unwrap();
        assert_eq!(
            core.used_bytes(session).unwrap(),
            STRIDE as usize * H as usize
        );
    }

    #[test]
    fn max_rects_are_accepted_and_overflow_rejected() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        let first = add_buffer(&mut core, session, surface);
        let second = add_buffer(&mut core, session, surface);
        let mut commit = commit_body(first, 0, 1);
        commit.rect_count = MAX_RECTS as u16;
        commit.rects = [Rect {
            x: 0,
            y: 0,
            w: 1,
            h: 1,
        }; PROTOCOL_MAX_RECTS];
        // First commit is always full damage, whatever the rects say.
        match core.commit(session, surface, &commit).unwrap() {
            CommitOutcome::Accepted {
                damage: Damage::Full,
                ..
            } => {}
            other => panic!("unexpected: {:?}", other),
        }
        core.frame_done(session, surface, first, 1).unwrap();

        let mut commit = commit_body(second, 0, 2);
        commit.rect_count = MAX_RECTS as u16;
        commit.rects = [Rect {
            x: 1,
            y: 1,
            w: 1,
            h: 1,
        }; PROTOCOL_MAX_RECTS];
        match core.commit(session, surface, &commit).unwrap() {
            CommitOutcome::Accepted {
                damage: Damage::Rects { count, rects },
                ..
            } => {
                assert_eq!(count as usize, MAX_RECTS);
                assert_eq!(rects[MAX_RECTS - 1], commit.rects[MAX_RECTS - 1]);
            }
            other => panic!("unexpected: {:?}", other),
        }
        core.frame_done(session, surface, second, 2).unwrap();
        assert_eq!(core.take_release(session), Ok(Some(first)));

        let mut too_many = commit_body(first, 0, 3);
        too_many.rect_count = MAX_RECTS as u16 + 1;
        assert_eq!(
            core.commit(session, surface, &too_many),
            Err(CoreError::BadFlags)
        );
        assert_eq!(core.surface(session, surface).unwrap().credit, 1);
    }

    #[test]
    fn commit_rect_bounds_are_rejected() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        let first = add_buffer(&mut core, session, surface);
        core.commit(session, surface, &commit_body(first, 0, 1))
            .unwrap();
        core.frame_done(session, surface, first, 1).unwrap();
        let second = add_buffer(&mut core, session, surface);

        let invalid = [
            Rect {
                x: -1,
                y: 0,
                w: 1,
                h: 1,
            },
            Rect {
                x: 0,
                y: -1,
                w: 1,
                h: 1,
            },
            Rect {
                x: -8,
                y: -8,
                w: 2,
                h: 2,
            },
            Rect {
                x: W as i32,
                y: 0,
                w: 1,
                h: 1,
            },
            Rect {
                x: 0,
                y: H as i32,
                w: 1,
                h: 1,
            },
            Rect {
                x: W as i32 - 1,
                y: 0,
                w: 2,
                h: 1,
            },
            Rect {
                x: 0,
                y: H as i32 - 1,
                w: 1,
                h: 2,
            },
            Rect {
                x: 0,
                y: 0,
                w: 0,
                h: 1,
            },
            Rect {
                x: 0,
                y: 0,
                w: 1,
                h: 0,
            },
            Rect {
                x: 0,
                y: 0,
                w: u32::MAX,
                h: 1,
            },
        ];
        for rect in invalid {
            let mut commit = commit_body(second, 0, 2);
            commit.rect_count = 1;
            commit.rects[0] = rect;
            assert_rejected_unchanged(
                &mut core,
                session,
                surface,
                &commit,
                CoreError::BadDimensions,
            );
        }

        // A rect exactly filling the surface is accepted.
        let mut exact = commit_body(second, 0, 2);
        exact.rect_count = 1;
        exact.rects[0] = Rect {
            x: 0,
            y: 0,
            w: W,
            h: H,
        };
        assert!(core.commit(session, surface, &exact).is_ok());
    }

    #[test]
    fn fuzz_out_of_bounds_rects_never_mutate_state() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        let first = add_buffer(&mut core, session, surface);
        core.commit(session, surface, &commit_body(first, 0, 1))
            .unwrap();
        core.frame_done(session, surface, first, 1).unwrap();
        let second = add_buffer(&mut core, session, surface);

        let mut lcg: u64 = 0x0123_4567_89AB_CDEF;
        for _ in 0..1_000 {
            lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1);
            let rect = match (lcg >> 33) % 6 {
                0 => Rect {
                    x: -((lcg % 100) as i32) - 1,
                    y: 0,
                    w: 1,
                    h: 1,
                },
                1 => Rect {
                    x: 0,
                    y: -((lcg % 100) as i32) - 1,
                    w: 1,
                    h: 1,
                },
                2 => Rect {
                    x: W as i32 + (lcg % 8) as i32,
                    y: 0,
                    w: 1,
                    h: 1,
                },
                3 => Rect {
                    x: 0,
                    y: H as i32 + (lcg % 8) as i32,
                    w: 1,
                    h: 1,
                },
                4 => Rect {
                    x: (lcg % 8) as i32,
                    y: 0,
                    w: 0,
                    h: 1,
                },
                _ => Rect {
                    x: 0,
                    y: (lcg % 8) as i32,
                    w: 1,
                    h: 0,
                },
            };
            let mut commit = commit_body(second, 0, 2);
            commit.rect_count = 1;
            commit.rects[0] = rect;
            assert_rejected_unchanged(
                &mut core,
                session,
                surface,
                &commit,
                CoreError::BadDimensions,
            );
        }
        assert_eq!(
            core.used_bytes(session).unwrap(),
            2 * STRIDE as usize * H as usize
        );
        assert_eq!(core.surface(session, surface).unwrap().current, Some(first));
    }

    #[test]
    fn present_full_uses_current_buffer_dimensions() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        let buffer = add_buffer(&mut core, session, surface);
        core.commit(session, surface, &commit_body(buffer, 0, 1))
            .unwrap();
        assert_eq!(
            core.set_configure(session, surface, 16, 16, FORMAT_XRGB8888)
                .unwrap(),
            1
        );
        core.present_current(session, surface).unwrap();
        assert_eq!(
            core.backend().last_rects[0],
            Rect {
                x: 0,
                y: 0,
                w: W,
                h: H
            },
            "full damage follows the current buffer, not the surface"
        );
    }

    #[test]
    fn present_revalidates_stored_rects() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        let buffer = add_buffer(&mut core, session, surface);
        core.commit(session, surface, &commit_body(buffer, 0, 1))
            .unwrap();
        core.frame_done(session, surface, buffer, 1).unwrap();

        let out_of_bounds = Rect {
            x: -1,
            y: 0,
            w: 1,
            h: 1,
        };
        core.sessions[0].as_mut().unwrap().surfaces[0]
            .as_mut()
            .unwrap()
            .pending_damage = Damage::Rects {
            count: 1,
            rects: [out_of_bounds; MAX_RECTS],
        };
        assert_eq!(
            core.present_current(session, surface),
            Err(CoreError::BadDimensions)
        );
        assert_eq!(core.backend().presents, 0, "backend is not called");

        core.sessions[0].as_mut().unwrap().surfaces[0]
            .as_mut()
            .unwrap()
            .pending_damage = Damage::Full;
        core.present_current(session, surface).unwrap();
        assert_eq!(core.backend().presents, 1);
    }

    #[test]
    fn retired_regions_are_deferred() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        let buffer = add_buffer(&mut core, session, surface);
        core.destroy_buffer(session, buffer).unwrap();
        assert_eq!(core.backend().frees, 0, "destroy does not free");
        let retired = core.take_retired().expect("destroyed buffer retired");
        assert_eq!(retired.session, session);
        assert_eq!(retired.buffer, buffer);
        core.backend_mut().free(retired.region);
        assert_eq!(core.backend().frees, 1);
        assert!(core.take_retired().is_none());

        let failing = core
            .allocate_buffer(session, surface, W, H, FORMAT_XRGB8888, STRIDE)
            .unwrap();
        core.import_result(session, failing, false).unwrap();
        assert_eq!(core.backend().frees, 1, "import failure does not free");

        let live = add_buffer(&mut core, session, surface);
        core.close_session(session).unwrap();
        assert_eq!(core.backend().frees, 1, "close does not free");
        assert_eq!(core.retired.iter().flatten().count(), 2);
        assert_eq!(core.take_retired().unwrap().buffer, failing);
        assert_eq!(core.take_retired().unwrap().buffer, live);
        assert!(core.take_retired().is_none());
    }

    #[test]
    fn drop_frees_live_and_retired_regions_once() {
        let frees = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        {
            let mut core = DisplayCore::new(DropBackend {
                frees: frees.clone(),
                next: 0,
            });
            let session = core.create_session().unwrap();
            let surface = add_surface(&mut core, session);
            let destroyed = add_buffer(&mut core, session, surface);
            let _live = add_buffer(&mut core, session, surface);
            core.destroy_buffer(session, destroyed).unwrap();
            assert_eq!(core.retired.iter().flatten().count(), 1);
            assert_eq!(
                frees.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "nothing freed before drop"
            );
        }
        assert_eq!(
            frees.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "one free per live and per retired region"
        );
    }

    #[test]
    fn retired_queue_limit_leaves_state_unchanged() {
        let mut core = DisplayCore::new(Fake::default());
        let mut sessions = [None; MAX_SESSIONS];
        for slot in sessions.iter_mut() {
            let session = core.create_session().unwrap();
            *slot = Some(session);
            for _ in 0..MAX_SURFACES_PER_SESSION {
                let surface = add_surface(&mut core, session);
                for _ in 0..crate::MAX_BUFFERS_PER_SURFACE {
                    add_buffer(&mut core, session, surface);
                }
            }
        }
        for session in sessions.iter().flatten() {
            core.close_session(*session).unwrap();
        }
        assert_eq!(core.retired.iter().flatten().count(), MAX_RETIRED_REGIONS);

        let session = core.create_session().unwrap();
        let surface = add_surface(&mut core, session);
        for _ in 0..crate::MAX_BUFFERS_PER_SURFACE {
            add_buffer(&mut core, session, surface);
        }
        let used = core.used_bytes(session).unwrap();
        let buffer = first_available(&core, session).unwrap();
        assert_eq!(core.destroy_buffer(session, buffer), Err(CoreError::Limit));
        assert_eq!(core.used_bytes(session).unwrap(), used);
        assert_eq!(core.buffer_count(session).unwrap(), 4);

        assert_eq!(core.close_session(session), Err(CoreError::Limit));
        assert_eq!(core.session_count(), 1);
        assert_eq!(core.surface_count(session).unwrap(), 1);
    }

    #[test]
    fn ready_buffer_release_lifecycle() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        let first = add_buffer(&mut core, session, surface);
        let second = add_buffer(&mut core, session, surface);

        core.commit(session, surface, &commit_body(first, 0, 1))
            .unwrap();
        core.frame_done(session, surface, first, 1).unwrap();
        core.commit(session, surface, &commit_body(second, 0, 2))
            .unwrap();
        assert_eq!(
            core.buffer(session, first).unwrap().state,
            BufferState::Ready
        );

        core.frame_done(session, surface, second, 2).unwrap();
        let retry = commit_body(first, 0, 3);
        assert_eq!(
            core.commit(session, surface, &retry),
            Err(CoreError::BadState),
            "a Ready buffer is not committable"
        );
        assert_eq!(
            core.surface(session, surface).unwrap().current,
            Some(second)
        );

        assert_eq!(core.take_release(session), Ok(Some(first)));
        assert_eq!(
            core.buffer(session, first).unwrap().state,
            BufferState::Available
        );
        assert!(core.commit(session, surface, &retry).is_ok());
    }

    #[test]
    fn destroy_purges_queued_release() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        let first = add_buffer(&mut core, session, surface);
        let second = add_buffer(&mut core, session, surface);

        core.commit(session, surface, &commit_body(first, 0, 1))
            .unwrap();
        core.frame_done(session, surface, first, 1).unwrap();
        core.commit(session, surface, &commit_body(second, 0, 2))
            .unwrap();
        assert_eq!(
            core.buffer(session, first).unwrap().state,
            BufferState::Ready
        );

        core.destroy_buffer(session, first).unwrap();
        assert_eq!(core.take_release(session), Ok(None));
        assert!(core.buffer(session, first).is_err());
    }

    #[test]
    fn quota_underflow_reports_bad_state() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        let buffer = add_buffer(&mut core, session, surface);
        core.sessions[0].as_mut().unwrap().used_bytes = 0;
        assert_eq!(
            core.destroy_buffer(session, buffer),
            Err(CoreError::BadState)
        );
        assert_eq!(core.buffer_count(session).unwrap(), 1);
    }

    #[test]
    fn pending_damage_accumulates_until_present() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        let first = add_buffer(&mut core, session, surface);
        let second = add_buffer(&mut core, session, surface);
        let third = add_buffer(&mut core, session, surface);

        core.commit(session, surface, &commit_body(first, 0, 1))
            .unwrap();
        core.present_current(session, surface).unwrap();
        core.frame_done(session, surface, first, 1).unwrap();

        let r1 = Rect {
            x: 0,
            y: 0,
            w: 1,
            h: 1,
        };
        let r2 = Rect {
            x: 1,
            y: 1,
            w: 2,
            h: 2,
        };
        let mut a = commit_body(second, 0, 2);
        a.rect_count = 1;
        a.rects[0] = r1;
        core.commit(session, surface, &a).unwrap();
        core.frame_done(session, surface, second, 2).unwrap();

        let mut b = commit_body(third, 0, 3);
        b.rect_count = 1;
        b.rects[0] = r2;
        core.commit(session, surface, &b).unwrap();

        core.present_current(session, surface).unwrap();
        assert_eq!(core.backend().last_damage, 2);
        assert_eq!(core.backend().last_rects[0], r1);
        assert_eq!(core.backend().last_rects[1], r2);
        assert_eq!(
            core.surface(session, surface).unwrap().pending_damage,
            Damage::Rects {
                count: 0,
                rects: [Rect::default(); MAX_RECTS]
            },
            "pending damage resets after a successful present"
        );
    }

    #[test]
    fn configure_serial_overflow_is_bad_state() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        core.sessions[0].as_mut().unwrap().surfaces[0]
            .as_mut()
            .unwrap()
            .configure_serial = u64::MAX;
        assert_eq!(
            core.set_configure(session, surface, 16, 16, FORMAT_XRGB8888),
            Err(CoreError::BadState)
        );
        let state = core.surface(session, surface).unwrap();
        assert_eq!(state.width, W);
        assert_eq!(state.configure_serial, u64::MAX);
    }

    #[test]
    fn release_ring_overflow_is_reported() {
        let (mut core, session) = new_core();
        assert_eq!(core.release_overflow(session), Ok(false));
        let session_state = core.sessions[0].as_mut().unwrap();
        let id = BufferId::from_raw(1);
        for _ in 0..=MAX_BUFFERS_PER_SESSION {
            session_state.push_release(id);
        }
        assert_eq!(session_state.release_len, MAX_BUFFERS_PER_SESSION);
        assert_eq!(core.release_overflow(session), Ok(true));
        core.clear_release_overflow(session).unwrap();
        assert_eq!(core.release_overflow(session), Ok(false));
        assert_eq!(core.take_release(session), Ok(None), "stale id is skipped");
    }

    #[test]
    fn fuzz_state_machine_never_breaks_invariants() {
        let mut core = DisplayCore::new(Fake::default());
        let session = core.create_session().unwrap();
        let surface = add_surface(&mut core, session);
        let mut lcg: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next_commit = 1u64;
        for _ in 0..4_000 {
            lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1);
            match (lcg >> 33) % 8 {
                0 => {
                    let _ = core.allocate_buffer(session, surface, W, H, FORMAT_XRGB8888, STRIDE);
                }
                1 => {
                    if let Some(buffer) = first_import_pending(&core, session) {
                        let _ = core.import_result(session, buffer, (lcg & 1) == 0);
                    }
                }
                2 => {
                    if let Some(buffer) = first_available(&core, session) {
                        let ack = core.surface(session, surface).unwrap().configure_serial;
                        let mut commit = commit_body(buffer, ack, next_commit);
                        commit.rect_count = ((lcg >> 20) % 3) as u16;
                        for i in 0..commit.rect_count as usize {
                            commit.rects[i] = Rect {
                                x: i as i32,
                                y: i as i32,
                                w: 1,
                                h: 1,
                            };
                        }
                        if core.commit(session, surface, &commit).is_ok() {
                            next_commit += 1;
                        }
                    }
                }
                3 => {
                    let current = core.surface(session, surface).unwrap().current;
                    if let Some(buffer) = current {
                        let commit_id = core.surface(session, surface).unwrap().last_commit_id;
                        let _ = core.frame_done(session, surface, buffer, commit_id);
                    }
                }
                4 => {
                    let _ = core.present_current(session, surface);
                }
                5 => {
                    let _ = core.take_release(session);
                }
                6 => {
                    if let Some(buffer) = first_available(&core, session) {
                        let _ = core.destroy_buffer(session, buffer);
                    }
                }
                _ => {
                    if let Some(retired) = core.take_retired() {
                        core.backend_mut().free(retired.region);
                    }
                }
            }

            let sess = core.sessions[0].as_ref().unwrap();
            assert!(sess.used_bytes <= PIXEL_QUOTA_BYTES as usize);
            let count = sess.buffers.iter().flatten().count();
            assert!(count <= MAX_BUFFERS_PER_SESSION);
            assert!(sess.release_len <= sess.releases.len());
            let retired_count = core.retired.iter().flatten().count();
            assert!(retired_count <= MAX_RETIRED_REGIONS);
            for retired in core.retired.iter().flatten() {
                assert!(
                    !core
                        .sessions
                        .iter()
                        .flatten()
                        .flat_map(|s| s.buffers.iter().flatten())
                        .any(|buffer| buffer.region == retired.region),
                    "a retired region is no longer owned by a live buffer"
                );
            }
            if let Some(surface) = sess.surfaces[0].as_ref() {
                assert!(surface.credit <= 1);
                if let Some(current) = surface.current {
                    let buffer = sess
                        .buffers
                        .iter()
                        .flatten()
                        .find(|buffer| buffer.id == current)
                        .expect("current buffer must exist");
                    assert_eq!(buffer.state, BufferState::Current);
                }
            }
        }
    }

    fn first_import_pending(core: &DisplayCore<Fake>, session: SessionId) -> Option<BufferId> {
        let sess = core.sessions.iter().flatten().find(|s| s.id == session)?;
        sess.buffers
            .iter()
            .flatten()
            .find(|buffer| buffer.state == BufferState::ImportPending)
            .map(|buffer| buffer.id)
    }

    fn first_available(core: &DisplayCore<Fake>, session: SessionId) -> Option<BufferId> {
        let sess = core.sessions.iter().flatten().find(|s| s.id == session)?;
        sess.buffers
            .iter()
            .flatten()
            .find(|buffer| buffer.state == BufferState::Available)
            .map(|buffer| buffer.id)
    }

    struct PixelBackend {
        src: [u32; (W as usize) * (H as usize)],
        front: [u32; (W as usize) * (H as usize)],
        /// Dimensions of the last allocated region; every test region is W x H.
        region_w: u32,
        region_h: u32,
    }

    impl Default for PixelBackend {
        fn default() -> Self {
            Self {
                src: [0; (W as usize) * (H as usize)],
                front: [0; (W as usize) * (H as usize)],
                region_w: 0,
                region_h: 0,
            }
        }
    }

    impl Backend for PixelBackend {
        type Error = ();
        fn allocate(
            &mut self,
            width: u32,
            height: u32,
            _stride: u32,
            _format: u32,
        ) -> Result<RegionHandle, Self::Error> {
            self.region_w = width;
            self.region_h = height;
            Ok(RegionHandle::new(1))
        }
        fn free(&mut self, _region: RegionHandle) {}
        fn composite(
            &mut self,
            bottom_to_top: &[Layer],
            rects: &[Rect],
        ) -> Result<(), Self::Error> {
            for rect in rects {
                for layer in bottom_to_top {
                    // Intersection of the dirty rect with the layer's bounds;
                    // the screen-sized front buffer clips everything else.
                    let lx = layer.x as i64;
                    let ly = layer.y as i64;
                    let x0 = (rect.x as i64).max(lx);
                    let y0 = (rect.y as i64).max(ly);
                    let x1 = ((rect.x as i64) + rect.w as i64)
                        .min(lx + self.region_w as i64);
                    let y1 = ((rect.y as i64) + rect.h as i64)
                        .min(ly + self.region_h as i64);
                    if x0 < 0
                        || y0 < 0
                        || x1 <= x0
                        || y1 <= y0
                        || x1 > W as i64
                        || y1 > H as i64
                    {
                        continue;
                    }
                    for y in y0..y1 {
                        for x in x0..x1 {
                            let src_index =
                                ((y - ly) * self.region_w as i64 + (x - lx)) as usize;
                            let dst_index = (y * W as i64 + x) as usize;
                            self.front[dst_index] = self.src[src_index];
                        }
                    }
                }
            }
            Ok(())
        }
    }

    #[test]
    fn damage_present_matches_full_reference() {
        let mut core = DisplayCore::new(PixelBackend::default());
        let session = core.create_session().unwrap();
        let surface = add_surface(&mut core, session);

        let first = add_buffer(&mut core, session, surface);
        let mut full = commit_body(first, 0, 1);
        full.flags = FLAG_FULL_DAMAGE;
        full.rect_count = 0;
        core.commit(session, surface, &full).unwrap();
        core.present_current(session, surface).unwrap();
        assert_eq!(core.backend.front, core.backend.src);
        core.frame_done(session, surface, first, 1).unwrap();

        // Change two pixels but advertise only one of them.
        core.backend.src[2 * W as usize + 2] = 0xAA00_00AA;
        core.backend.src[5 * W as usize + 5] = 0xBB00_00BB;

        let second = add_buffer(&mut core, session, surface);
        let mut partial = commit_body(second, 0, 2);
        partial.flags = 0;
        partial.rect_count = 1;
        partial.rects[0] = Rect {
            x: 2,
            y: 2,
            w: 1,
            h: 1,
        };
        core.commit(session, surface, &partial).unwrap();
        core.present_current(session, surface).unwrap();
        assert_eq!(core.backend.front[2 * W as usize + 2], 0xAA00_00AA);
        assert_ne!(core.backend.front[5 * W as usize + 5], 0xBB00_00BB);
        core.frame_done(session, surface, second, 2).unwrap();

        // A full commit must converge to the reference image.
        let third = add_buffer(&mut core, session, surface);
        let mut full2 = commit_body(third, 0, 3);
        full2.flags = FLAG_FULL_DAMAGE;
        full2.rect_count = 0;
        core.commit(session, surface, &full2).unwrap();
        core.present_current(session, surface).unwrap();
        assert_eq!(core.backend.front, core.backend.src);
    }

    #[test]
    fn session_slots_map_to_tile_origins() {
        let mut core = DisplayCore::new(Fake::default());
        let mut sessions = [None; MAX_SESSIONS];
        for slot in sessions.iter_mut() {
            *slot = Some(core.create_session().unwrap());
        }
        for (slot, session) in sessions.iter().enumerate() {
            let session = session.expect("session created");
            let surface = add_surface(&mut core, session);
            let expected = (
                (slot as u32 % TILE_COLUMNS) * TILE_WIDTH,
                (slot as u32 / TILE_COLUMNS) * TILE_HEIGHT,
            );
            assert_eq!(
                core.surface_origin(session, surface),
                Ok(expected),
                "slot {slot}"
            );
            let record = core.surface(session, surface).unwrap();
            assert_eq!((record.x, record.y), expected, "surface record slot {slot}");
        }
        assert_eq!(
            (TILE_COLUMNS, TILE_ROWS),
            (4, 2),
            "the grid must cover MAX_SESSIONS"
        );
        let last_session = sessions[MAX_SESSIONS - 1].unwrap();
        let last_surface = core
            .create_surface(last_session, W, H, FORMAT_XRGB8888, 0)
            .unwrap();
        assert_eq!(
            core.surface_origin(last_session, last_surface),
            Ok((1200, 300)),
            "slot 7 is the bottom-right tile"
        );

        // Every surface of one session shares the session origin.
        let session = sessions[5].unwrap();
        let a = add_surface(&mut core, session);
        let b = add_surface(&mut core, session);
        assert_eq!(core.surface_origin(session, a), Ok((400, 300)));
        assert_eq!(core.surface_origin(session, b), Ok((400, 300)));
    }

    #[test]
    fn surface_origin_rejects_stale_and_foreign_ids() {
        let mut core = DisplayCore::new(Fake::default());
        let session = core.create_session().unwrap();
        let first = add_surface(&mut core, session);
        core.destroy_surface(session, first).unwrap();
        let second = add_surface(&mut core, session);
        assert_ne!(first, second, "surface slot reuse bumps the generation");
        assert_eq!(
            core.surface_origin(session, first),
            Err(CoreError::BadObject),
            "destroyed surface handle is stale"
        );
        // Unknown raw handles never resolve.
        assert_eq!(
            core.surface_origin(session, SurfaceId::from_raw(0)),
            Err(CoreError::BadObject)
        );
        assert_eq!(
            core.surface_origin(session, SurfaceId::from_raw(u64::MAX)),
            Err(CoreError::BadObject)
        );

        // A closed session's handle is stale even after the slot is reused.
        core.close_session(session).unwrap();
        let fresh = core.create_session().unwrap();
        assert_ne!(session, fresh);
        assert_eq!(
            core.surface_origin(session, second),
            Err(CoreError::BadObject)
        );
        assert_eq!(
            core.surface_origin(fresh, second),
            Err(CoreError::NoSurface),
            "the reused session slot has no surface yet"
        );
    }

    #[test]
    fn surface_at_maps_points_to_tiles() {
        let mut core = DisplayCore::new(Fake::default());
        let mut sessions = [None; MAX_SESSIONS];
        let mut surfaces = [None; MAX_SESSIONS];
        for slot in 0..MAX_SESSIONS {
            let session = core.create_session().unwrap();
            sessions[slot] = Some(session);
            surfaces[slot] = Some(add_surface(&mut core, session));
        }
        for slot in 0..MAX_SESSIONS {
            let (x, y) = tile_origin(slot);
            let expected = (sessions[slot].unwrap(), surfaces[slot].unwrap());
            assert_eq!(core.surface_at(x, y), Some(expected), "slot {slot} origin");
            assert_eq!(
                core.surface_at(x + W - 1, y + H - 1),
                Some(expected),
                "slot {slot} last pixel"
            );
        }
        // Half-open geometry: the pixel past a surface belongs to no one
        // until the next tile's origin.
        assert_eq!(core.surface_at(W, 0), None);
        assert_eq!(
            core.surface_at(TILE_WIDTH, 0),
            Some((sessions[1].unwrap(), surfaces[1].unwrap()))
        );
        // The bottom edge of the top row is the first pixel of the bottom row.
        assert_eq!(
            core.surface_at(0, TILE_HEIGHT),
            Some((sessions[4].unwrap(), surfaces[4].unwrap()))
        );
        // Outside the tile grid.
        assert_eq!(core.surface_at(TILE_COLUMNS * TILE_WIDTH, 0), None);
        assert_eq!(core.surface_at(0, TILE_ROWS * TILE_HEIGHT), None);
        assert_eq!(core.surface_at(u32::MAX, u32::MAX), None);
    }

    #[test]
    fn surface_at_follows_z_order_and_skips_destroyed() {
        let (mut core, session) = new_core();
        let first = add_surface(&mut core, session);
        let second = add_surface(&mut core, session);
        let buffer = add_buffer(&mut core, session, first);
        core.commit(session, first, &commit_body(buffer, 0, 1))
            .unwrap();
        assert_eq!(
            core.surface_at(1, 1),
            Some((session, second)),
            "the z order decides picking, with or without a current image"
        );

        core.frame_done(session, first, buffer, 1).unwrap();
        core.destroy_surface(session, second).unwrap();
        assert_eq!(core.surface_at(1, 1), Some((session, first)));

        // No image anywhere: the topmost live surface still wins.
        let (mut core, session) = new_core();
        let lower = add_surface(&mut core, session);
        let upper = add_surface(&mut core, session);
        assert_eq!(core.surface_at(1, 1), Some((session, upper)));
        core.destroy_surface(session, upper).unwrap();
        assert_eq!(core.surface_at(1, 1), Some((session, lower)));
    }

    #[test]
    fn present_current_forwards_the_surface_origin() {
        let mut core = DisplayCore::new(Fake::default());
        let mut last = None;
        for _ in 0..MAX_SESSIONS {
            last = Some(core.create_session().unwrap());
        }
        let session = last.unwrap();
        let surface = add_surface(&mut core, session);
        let buffer = add_buffer(&mut core, session, surface);
        core.commit(session, surface, &commit_body(buffer, 0, 1))
            .unwrap();
        core.present_current(session, surface).unwrap();
        assert_eq!(core.backend().presents, 1);
        assert_eq!(core.backend().last_layers, 1, "one compositable layer");
        assert_eq!(
            core.backend().last_rects[0],
            Rect {
                x: 1200,
                y: 300,
                w: W,
                h: H
            },
            "slot 7 tile origin is folded into the screen-space damage rect"
        );
    }

    #[test]
    fn set_geometry_clamps_and_reports_final_values() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        let outcome = core
            .set_geometry(session, surface, -8, 5000, 16, 16, FORMAT_XRGB8888)
            .unwrap();
        assert_eq!(
            outcome,
            GeometryOutcome {
                serial: 1,
                x: 0,
                y: TILE_ROWS * TILE_HEIGHT - 1,
                width: 16,
                height: 16,
            }
        );
        let record = core.surface(session, surface).unwrap();
        assert_eq!((record.x, record.y, record.width, record.height), (0, 599, 16, 16));
        assert_eq!(record.configure_serial, 1);
        assert!(record.full_damage_next);

        // The upper clamp bounds use the last output pixel.
        let outcome = core
            .set_geometry(session, surface, 5000, -1, 8, 8, FORMAT_XRGB8888)
            .unwrap();
        assert_eq!(
            outcome,
            GeometryOutcome {
                serial: 2,
                x: TILE_COLUMNS * TILE_WIDTH - 1,
                y: 0,
                width: 8,
                height: 8,
            }
        );

        // Validation follows the set_configure rules and conventions.
        assert_eq!(
            core.set_geometry(session, surface, 0, 0, 0, 8, FORMAT_XRGB8888),
            Err(CoreError::BadDimensions)
        );
        assert_eq!(
            core.set_geometry(session, surface, 0, 0, 8, 8, 1),
            Err(CoreError::BadFormat)
        );
        assert_eq!(
            core.set_geometry(
                session,
                SurfaceId::from_raw(0xdead_beef),
                0,
                0,
                8,
                8,
                FORMAT_XRGB8888
            ),
            Err(CoreError::BadObject)
        );
    }

    #[test]
    fn set_geometry_serial_gates_commits() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        let buffer = add_buffer(&mut core, session, surface);
        let stale = add_buffer(&mut core, session, surface);
        core.commit(session, surface, &commit_body(buffer, 0, 1))
            .unwrap();
        core.frame_done(session, surface, buffer, 1).unwrap();

        let outcome = core
            .set_geometry(session, surface, 4, 6, 16, 16, FORMAT_XRGB8888)
            .unwrap();
        // The old serial is rejected, whatever the buffer.
        assert_eq!(
            core.commit(session, surface, &commit_body(stale, 0, 2)),
            Err(CoreError::BadSerial)
        );
        // The new serial is accepted only with a matching buffer size.
        assert_eq!(
            core.commit(session, surface, &commit_body(stale, outcome.serial, 2)),
            Err(CoreError::BadDimensions)
        );
        let fresh = core
            .allocate_buffer(session, surface, 16, 16, FORMAT_XRGB8888, 16 * 4)
            .unwrap();
        core.import_result(session, fresh, true).unwrap();
        core.commit(session, surface, &commit_body(fresh, outcome.serial, 2))
            .unwrap();
        assert_eq!(
            core.surface(session, surface).unwrap().acked_serial,
            outcome.serial
        );
    }

    #[test]
    fn minimize_hides_and_restore_returns() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        let buffer = add_buffer(&mut core, session, surface);
        core.commit(session, surface, &commit_body(buffer, 0, 1))
            .unwrap();

        assert_eq!(core.surface_at(1, 1), Some((session, surface)));
        let (_, len) = core.layers_bottom_to_top();
        assert_eq!(len, 1);

        assert_eq!(
            core.window_action(session, surface, WINDOW_ACTION_MINIMIZE),
            Ok(None)
        );
        assert!(core.surface(session, surface).unwrap().hidden);
        assert_eq!(core.surface_at(1, 1), None, "hidden surfaces are not picked");
        let (_, len) = core.layers_bottom_to_top();
        assert_eq!(len, 0, "hidden surfaces are not composited");
        let (rects, count) = core.take_screen_dirty();
        assert_eq!(count, 1, "the covered area repaints");
        assert_eq!(rects[0], Rect { x: 0, y: 0, w: W, h: H });

        assert_eq!(
            core.window_action(session, surface, WINDOW_ACTION_RESTORE),
            Ok(None)
        );
        assert!(!core.surface(session, surface).unwrap().hidden);
        assert_eq!(core.surface_at(1, 1), Some((session, surface)));
        let (_, len) = core.layers_bottom_to_top();
        assert_eq!(len, 1);
        assert_eq!(core.take_screen_dirty().1, 1, "restore repaints");
    }

    #[test]
    fn maximize_returns_output_geometry_and_bumps_serial() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        core.set_output_size(640, 480);
        let outcome = core
            .window_action(session, surface, WINDOW_ACTION_MAXIMIZE)
            .unwrap()
            .expect("MAXIMIZE reports geometry");
        assert_eq!(
            outcome,
            GeometryOutcome {
                serial: 1,
                x: 0,
                y: 0,
                width: 640,
                height: 480,
            }
        );
        let record = core.surface(session, surface).unwrap();
        assert_eq!((record.x, record.y, record.width, record.height), (0, 0, 640, 480));
        assert_eq!(record.configure_serial, 1);
        // The covered and the revealed rects are queued, in that order.
        let (rects, count) = core.take_screen_dirty();
        assert_eq!(count, 2);
        assert_eq!(rects[0], Rect { x: 0, y: 0, w: W, h: H });
        assert_eq!(rects[1], Rect { x: 0, y: 0, w: 640, h: 480 });
    }

    #[test]
    fn raise_and_lower_reorder_overlapping_surfaces() {
        let (mut core, session) = new_core();
        let bottom = add_surface(&mut core, session);
        let top = add_surface(&mut core, session);
        // Both surfaces sit on the same tile: the z order decides picking.
        assert_eq!(
            core.surface_at(1, 1),
            Some((session, top)),
            "the surface created last is on top"
        );

        assert_eq!(
            core.window_action(session, bottom, WINDOW_ACTION_RAISE),
            Ok(None)
        );
        assert_eq!(core.surface_at(1, 1), Some((session, bottom)));

        assert_eq!(
            core.window_action(session, bottom, WINDOW_ACTION_LOWER),
            Ok(None)
        );
        assert_eq!(core.surface_at(1, 1), Some((session, top)));
    }

    #[test]
    fn layers_bottom_to_top_is_reversed_z() {
        let (mut core, session) = new_core();
        let a = add_surface(&mut core, session);
        let _b = add_surface(&mut core, session);
        let c = add_surface(&mut core, session);
        let buffer_a = add_buffer(&mut core, session, a);
        core.commit(session, a, &commit_body(buffer_a, 0, 1))
            .unwrap();
        let buffer_c = add_buffer(&mut core, session, c);
        core.commit(session, c, &commit_body(buffer_c, 0, 1))
            .unwrap();

        let (layers, len) = core.layers_bottom_to_top();
        assert_eq!(len, 2, "only surfaces with a current image composite");
        // The z order is c, b, a top first: the reversed walk yields a, c.
        assert_eq!(layers[0].region.raw(), 0, "bottom layer is the first created");
        assert_eq!(layers[1].region.raw(), 1, "top layer is the last created");
        assert_eq!((layers[0].x, layers[0].y), (0, 0));

        // Raising a flips the compositing order.
        core.window_action(session, a, WINDOW_ACTION_RAISE).unwrap();
        let (layers, len) = core.layers_bottom_to_top();
        assert_eq!(len, 2);
        assert_eq!(layers[0].region.raw(), 1);
        assert_eq!(layers[1].region.raw(), 0);
    }

    #[test]
    fn screen_dirty_drains_destroy_dirties_and_collapses() {
        let (mut core, session) = new_core();
        let surface = add_surface(&mut core, session);
        assert_eq!(core.take_screen_dirty().1, 0, "starts empty");

        // A move queues the covered and the revealed rect.
        core.set_geometry(session, surface, 40, 20, 8, 8, FORMAT_XRGB8888)
            .unwrap();
        let (rects, count) = core.take_screen_dirty();
        assert_eq!(count, 2);
        assert_eq!(rects[0], Rect { x: 0, y: 0, w: W, h: H });
        assert_eq!(rects[1], Rect { x: 40, y: 20, w: W, h: H });
        assert_eq!(core.take_screen_dirty().1, 0, "take drains");

        // Destroying a visible surface queues its covered rect once.
        core.destroy_surface(session, surface).unwrap();
        let (rects, count) = core.take_screen_dirty();
        assert_eq!(count, 1);
        assert_eq!(rects[0], Rect { x: 40, y: 20, w: W, h: H });

        // An overfull queue collapses to the whole output.
        let surface = add_surface(&mut core, session);
        for _ in 0..MAX_SCREEN_DIRTY + 1 {
            core.window_action(session, surface, WINDOW_ACTION_MINIMIZE)
                .unwrap();
        }
        let (rects, count) = core.take_screen_dirty();
        assert_eq!(count, 1, "the whole set collapses to one rect");
        assert_eq!(
            rects[0],
            Rect {
                x: 0,
                y: 0,
                w: TILE_COLUMNS * TILE_WIDTH,
                h: TILE_ROWS * TILE_HEIGHT,
            }
        );
    }
}
