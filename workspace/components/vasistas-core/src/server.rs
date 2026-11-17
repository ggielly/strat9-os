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

//! Transport and session dispatch layer (A.1/A.3/A.4).
//!
//! [`Server`] owns the [`DisplayCore`] metadata machine and the fixed
//! peer-to-session table. [`Server::handle`] takes one complete wire message
//! from one peer, decodes it with `vasistas-protocol`, dispatches it to the
//! core, and writes every reply through a [`Transport`]. One call produces
//! zero or more complete messages (header included); the transport never sees
//! a partial frame.
//!
//! No allocation, no `unsafe`, fixed capacities, no panics on wire input:
//! every failure is reported to the peer as `ERROR` (A.3.1) when that message
//! can be encoded.
//!
//! ## Decode error to wire code
//!
//! A.3.1 has no dedicated code for a bad magic or a bad dimension, so:
//!
//! | `DecodeError` | `ERROR` code |
//! | --- | --- |
//! | `Truncated`, `SizeMismatch`, `Overflow`, `TooManyRects`, `BadValue` | `BAD_LENGTH` |
//! | `BadFlags`, `ReservedNonZero`, `BadMagic` | `BAD_FLAGS` |
//! | `UnsupportedVersion`, `UnknownOpcode` | `UNSUPPORTED` |
//! | `BadObject` | `BAD_OBJECT` |
//!
//! `BadValue` is a range/format/enum violation at the protocol layer and is
//! not distinguishable from a length violation, hence `BAD_LENGTH`.
//!
//! ## Core error to wire code
//!
//! | `CoreError` | `ERROR` code |
//! | --- | --- |
//! | `NoSurface`, `NoBuffer`, `BadObject` | `BAD_OBJECT` |
//! | `NoSession`, `BadState`, `BadSerial`, `BadCommitId` | `BAD_STATE` |
//! | `BadFlags` | `BAD_FLAGS` |
//! | `BadDimensions`, `BadStride` | `BAD_LENGTH` |
//! | `BadFormat` | `BAD_FORMAT` |
//! | `Quota`, `Limit` | `QUOTA` |
//! | `NoCredit` | `NO_CREDIT` |
//! | `BackendError`, anything else | `INTERNAL` |
//!
//! `BadDimensions`/`BadStride` map to `BAD_LENGTH`: A.3.1 defines no dimension
//! code and the specification writes the stride rule as a length check.
//!
//! ## `request_id`
//!
//! A.3.1 reserves `request_id = 0` for events and echoes the request id in
//! `ACK`/`ERROR`. This layer echoes it in `WELCOME` too (it answers `HELLO`
//! directly) and keeps `0` on the other events (`PONG`, `SURFACE_CREATED`,
//! `SURFACE_DESTROYED`, `BUFFER_CREATED`, `BUFFER_DESTROYED`, `FRAME_DONE`,
//! `BUFFER_RELEASE`).
//!
//! ## Commit credit
//!
//! Presentation is synchronous here: an accepted `COMMIT` is presented at
//! once and `FRAME_DONE` returns the credit before `handle` returns, so
//! `NO_CREDIT` is only reachable after a failed presentation (the backend
//! error is reported and the credit stays consumed) or when a caller drives
//! [`DisplayCore`] directly.

use core::{mem::MaybeUninit, ptr};

use vasistas_protocol::{
    constants::{
        ERROR_BAD_FLAGS, ERROR_BAD_FORMAT, ERROR_BAD_LENGTH, ERROR_BAD_OBJECT, ERROR_BAD_STATE,
        ERROR_INTERNAL, ERROR_NO_CREDIT, ERROR_QUOTA, ERROR_UNSUPPORTED,
        FRAME_DONE_PRESENT_SUBMITTED, MAX_MESSAGE_BYTES,
    },
    Body, DecodeError, Header, Opcode, FEATURE_PRESENT_FEEDBACK, HEADER_LEN, IMPORT_OK,
    VERSION_MAJOR, VERSION_MINOR,
};

use crate::{
    backend::Backend,
    core::{CommitOutcome, CoreError, DisplayCore},
    types::{BufferId, SessionId, SurfaceId},
    MAX_BUFFERS_PER_SESSION, MAX_BUFFERS_PER_SURFACE, MAX_SESSIONS, MAX_SURFACES_PER_SESSION,
    PIXEL_QUOTA_BYTES,
};

/// Compile-time message capacity of one datagram (A.1).
const CAPACITY: usize = MAX_MESSAGE_BYTES as usize;

/// Features this server implements and may announce in `WELCOME`.
///
/// Only `PRESENT_FEEDBACK` is implemented: `FRAME_DONE` reports that the
/// frame was submitted, never that it is visible.
pub const SUPPORTED_FEATURES: u32 = FEATURE_PRESENT_FEEDBACK;

/// Opaque identity of a client, supplied by the IPC layer (A.1: badge).
///
/// Never received from a message body; the transport identifies the sender.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerId(u64);

impl PeerId {
    /// Wrap a transport-owned identifier.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// The transport-owned value.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// One complete wire message (header included) per call.
///
/// Implementations are expected to deliver or drop the message atomically; a
/// short or failing send must not leave the server waiting.
pub trait Transport {
    /// Send `message`, one whole protocol frame.
    fn send(&mut self, message: &[u8]);

    /// Grant `server_region` (the backend's exported memory handle) to
    /// `client_pid`; return the capability id as seen by the client, or
    /// `None` when the grant fails. The core never interprets either value.
    fn transfer_region(&mut self, server_region: u64, client_pid: u32) -> Option<u64>;
}

/// Failure that prevented the server from answering at all.
///
/// Protocol and core rejections are not errors: they are sent to the peer as
/// `ERROR` and `handle` returns `Ok(())`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerError {
    /// A reply did not fit the bounded stack buffer or was rejected by the
    /// encoder (a bug guard, not a client error).
    Encode,
}

/// One peer-to-session binding plus the untrusted PID from `HELLO`.
#[derive(Clone, Copy)]
struct PeerSlot {
    peer: PeerId,
    session: SessionId,
    pid: u32,
}

/// Dispatch layer over one [`DisplayCore`] and a fixed peer table.
pub struct Server<B: Backend> {
    core: DisplayCore<B>,
    peers: [Option<PeerSlot>; MAX_SESSIONS],
    /// Negotiated features of `peers[i]`, same index.
    peer_features: [u32; MAX_SESSIONS],
}

impl<B: Backend> Server<B> {
    /// Create an empty server over `backend`.
    pub const fn new(backend: B) -> Self {
        Self {
            core: DisplayCore::new(backend),
            peers: [None; MAX_SESSIONS],
            peer_features: [0; MAX_SESSIONS],
        }
    }

    /// Initialise `this` in place, without a large stack temporary.
    ///
    /// Same purpose as [`DisplayCore::init_at`], for the whole server: the core
    /// array and the peer tables are written field by field into `this`, so a
    /// 64 KiB user stack is enough to host the (~54 KiB) state machine in a
    /// static. Call it once on a fresh [`MaybeUninit`].
    #[allow(unsafe_code)]
    pub fn init_at(this: &mut MaybeUninit<Self>, backend: B) -> &mut Self {
        let base = this.as_mut_ptr();
        // SAFETY: `base` is valid for writes of `Self`; every field is written
        // exactly once and `init_at` is documented as single-shot.
        unsafe {
            DisplayCore::<B>::write_in(ptr::addr_of_mut!((*base).core), backend);
            let peers = ptr::addr_of_mut!((*base).peers).cast::<Option<PeerSlot>>();
            for index in 0..MAX_SESSIONS {
                peers.add(index).write(None);
            }
            let features = ptr::addr_of_mut!((*base).peer_features).cast::<u32>();
            for index in 0..MAX_SESSIONS {
                features.add(index).write(0);
            }
            // SAFETY: all fields were initialised just above.
            this.assume_init_mut()
        }
    }

    /// The core, for diagnostics.
    pub fn core(&self) -> &DisplayCore<B> {
        &self.core
    }

    /// Pop one retired region awaiting an explicit free.
    ///
    /// The server must first revoke/unmap the client's mapping of
    /// `region.region`, then call [`Server::free_retired`].
    pub fn take_retired(&mut self) -> Option<crate::RetiredRegion> {
        self.core.take_retired()
    }

    /// Free a region previously returned by [`Server::take_retired`].
    pub fn free_retired(&mut self, region: crate::RetiredRegion) {
        self.core.backend_mut().free(region.region);
    }

    /// The session of `peer`, `None` before `HELLO` and after `GOODBYE`.
    pub fn session_of(&self, peer: PeerId) -> Option<SessionId> {
        self.peer_slot(peer)
            .and_then(|slot| self.peers[slot])
            .map(|slot| slot.session)
    }

    /// The untrusted `HELLO` PID of `peer`, for the cooperative grant adapter.
    pub fn peer_pid(&self, peer: PeerId) -> Option<u32> {
        self.peer_slot(peer)
            .and_then(|slot| self.peers[slot])
            .map(|slot| slot.pid)
    }

    /// The untrusted `HELLO` PID of `session`, for the cooperative grant adapter.
    pub fn session_pid(&self, session: SessionId) -> Option<u32> {
        self.peer_slot_of_session(session)
            .and_then(|slot| self.peers[slot])
            .map(|slot| slot.pid)
    }

    /// Close the session of `peer` and clear its slot.
    ///
    /// Used by the adapter when a peer's transport is dead (client vanished or
    /// its event port closed): the peer can no longer receive anything, so the
    /// session is closed without an answer. A peer that has no session is a
    /// no-op, so the call is idempotent.
    ///
    /// The slot is cleared even when closing the session fails (the retired
    /// queue is full): a dead peer can never retry, and keeping the binding
    /// would leak the slot. The error is still reported to the caller.
    pub fn disconnect(&mut self, peer: PeerId) -> Result<(), crate::CoreError> {
        let slot = match self.peer_slot(peer) {
            Some(slot) => slot,
            None => return Ok(()),
        };
        let closed = match self.peers[slot] {
            Some(entry) => self.core.close_session(entry.session),
            None => Ok(()),
        };
        self.peers[slot] = None;
        self.peer_features[slot] = 0;
        closed
    }

    /// Handle one complete wire message from `peer` (A.1).
    ///
    /// Decodes, dispatches to the core and writes every reply through
    /// `transport`. Over-long, truncated, malformed and unsupported input is
    /// answered with `ERROR`; it never panics.
    pub fn handle(
        &mut self,
        peer: PeerId,
        message: &[u8],
        transport: &mut dyn Transport,
    ) -> Result<(), ServerError> {
        let (header, body) = match Header::decode_message(message) {
            Ok(decoded) => decoded,
            Err(error) => {
                // The frame is untrusted: no object or request id is echoed.
                return send_error(transport, 0, 0, decode_code(error));
            }
        };

        let opcode = Opcode(header.opcode);
        if opcode.is_event() {
            return send_error(transport, 0, header.request_id, ERROR_UNSUPPORTED);
        }
        // A.1: request_id 0 is reserved for spontaneous events.
        if header.request_id == 0 {
            return send_error(transport, 0, 0, ERROR_BAD_FLAGS);
        }

        let body = match Body::decode(header.opcode, header.object_id, body) {
            Ok(body) => body,
            Err(error) => {
                return send_error(
                    transport,
                    header.object_id,
                    header.request_id,
                    decode_code(error),
                );
            }
        };

        match body {
            Body::Hello {
                major,
                features,
                pid,
                ..
            } => {
                if header.object_id != 0 {
                    return send_error(transport, 0, header.request_id, ERROR_BAD_OBJECT);
                }
                if major != VERSION_MAJOR {
                    return send_error(transport, 0, header.request_id, ERROR_UNSUPPORTED);
                }
                self.hello(peer, features, pid, &header, transport)
            }
            Body::Ping { cookie } => {
                if header.object_id != 0 {
                    return send_error(transport, 0, header.request_id, ERROR_BAD_OBJECT);
                }
                send(transport, Opcode::PONG, 0, 0, &Body::Pong { cookie })
            }
            Body::Goodbye => {
                if header.object_id != 0 {
                    return send_error(transport, 0, header.request_id, ERROR_BAD_OBJECT);
                }
                self.goodbye(peer, &header, transport)
            }
            _ => {
                let session = match self.session_of(peer) {
                    Some(session) => session,
                    None => {
                        return send_error(transport, 0, header.request_id, ERROR_BAD_STATE);
                    }
                };
                self.dispatch(session, &header, &body, transport)
            }
        }
    }

    /// `HELLO`: negotiate, open a session, answer `WELCOME`.
    fn hello(
        &mut self,
        peer: PeerId,
        features: u32,
        pid: u32,
        header: &Header,
        transport: &mut dyn Transport,
    ) -> Result<(), ServerError> {
        if self.peer_slot(peer).is_some() {
            return send_error(transport, 0, header.request_id, ERROR_BAD_STATE);
        }
        let slot = match self.peers.iter().position(|entry| entry.is_none()) {
            Some(slot) => slot,
            None => return send_error(transport, 0, header.request_id, ERROR_QUOTA),
        };
        let session = match self.core.create_session() {
            Ok(session) => session,
            Err(error) => {
                return send_error(transport, 0, header.request_id, core_code(error));
            }
        };
        let negotiated = features & SUPPORTED_FEATURES;
        self.peers[slot] = Some(PeerSlot { peer, session, pid });
        self.peer_features[slot] = negotiated;

        send(
            transport,
            Opcode::WELCOME,
            0,
            header.request_id,
            &Body::Welcome {
                major: VERSION_MAJOR,
                minor: VERSION_MINOR,
                features: negotiated,
                max_message_bytes: MAX_MESSAGE_BYTES,
                max_surfaces: MAX_SURFACES_PER_SESSION as u16,
                max_buffers_per_surface: MAX_BUFFERS_PER_SURFACE as u16,
                max_buffers_per_session: MAX_BUFFERS_PER_SESSION as u16,
                pixel_quota_bytes: PIXEL_QUOTA_BYTES as u64,
                session: session.raw(),
            },
        )
    }

    /// `GOODBYE`: close the session, forget the peer, acknowledge.
    fn goodbye(
        &mut self,
        peer: PeerId,
        header: &Header,
        transport: &mut dyn Transport,
    ) -> Result<(), ServerError> {
        if let Some(slot) = self.peer_slot(peer) {
            if let Some(entry) = self.peers[slot] {
                if let Err(error) = self.core.close_session(entry.session) {
                    return send_error(transport, 0, header.request_id, core_code(error));
                }
            }
            // Drops the peer, its session and its untrusted pid together.
            self.peers[slot] = None;
            self.peer_features[slot] = 0;
        }
        send(
            transport,
            Opcode::ACK,
            0,
            header.request_id,
            &Body::Ack { status: 0 },
        )
    }

    /// Dispatch a request of an established session.
    fn dispatch(
        &mut self,
        session: SessionId,
        header: &Header,
        body: &Body<'_>,
        transport: &mut dyn Transport,
    ) -> Result<(), ServerError> {
        let object = header.object_id;
        let request_id = header.request_id;
        match *body {
            Body::CreateSurface {
                width,
                height,
                format,
                title,
                ..
            } => {
                if object != 0 {
                    return send_error(transport, 0, request_id, ERROR_BAD_OBJECT);
                }
                match self
                    .core
                    .create_surface(session, width, height, format, title.len())
                {
                    Ok(surface) => {
                        let record = match self.core.surface(session, surface) {
                            Ok(record) => (record.width, record.height, record.format),
                            Err(error) => {
                                return send_error(transport, object, request_id, core_code(error));
                            }
                        };
                        send(
                            transport,
                            Opcode::SURFACE_CREATED,
                            surface.raw(),
                            0,
                            &Body::SurfaceCreated {
                                width: record.0,
                                height: record.1,
                                format: record.2,
                            },
                        )
                    }
                    Err(error) => send_error(transport, object, request_id, core_code(error)),
                }
            }
            Body::AllocBuffer {
                width,
                height,
                format,
                stride,
                ..
            } => {
                let surface = SurfaceId::from_raw(object);
                let pid = match self.session_pid(session) {
                    Some(pid) => pid,
                    None => return send_error(transport, object, request_id, ERROR_BAD_STATE),
                };
                match self
                    .core
                    .allocate_buffer(session, surface, width, height, format, stride)
                {
                    Ok(buffer) => {
                        let record = match self.core.buffer(session, buffer) {
                            Ok(record) => (
                                record.surface.raw(),
                                record.width,
                                record.height,
                                record.format,
                                record.stride,
                                record.bytes as u64,
                                record.region.raw(),
                            ),
                            Err(error) => {
                                return send_error(transport, object, request_id, core_code(error));
                            }
                        };
                        let region_handle = match transport.transfer_region(record.6, pid) {
                            Some(handle) => handle,
                            None => {
                                // The client never learns about the buffer:
                                // release it rather than charging the session.
                                let _ = self.core.destroy_buffer(session, buffer);
                                return send_error(transport, object, request_id, ERROR_INTERNAL);
                            }
                        };
                        send(
                            transport,
                            Opcode::BUFFER_CREATED,
                            buffer.raw(),
                            0,
                            &Body::BufferCreated {
                                surface: record.0,
                                width: record.1,
                                height: record.2,
                                format: record.3,
                                stride: record.4,
                                region_len: record.5,
                                region_handle,
                            },
                        )
                    }
                    Err(error) => send_error(transport, object, request_id, core_code(error)),
                }
            }
            Body::ImportResult { status } => {
                let buffer = BufferId::from_raw(object);
                match self
                    .core
                    .import_result(session, buffer, status == IMPORT_OK)
                {
                    Ok(()) => ack(transport, object, request_id),
                    Err(error) => send_error(transport, object, request_id, core_code(error)),
                }
            }
            Body::DestroyBuffer => {
                let buffer = BufferId::from_raw(object);
                match self.core.destroy_buffer(session, buffer) {
                    Ok(()) => send(
                        transport,
                        Opcode::BUFFER_DESTROYED,
                        object,
                        0,
                        &Body::BufferDestroyed,
                    ),
                    Err(error) => send_error(transport, object, request_id, core_code(error)),
                }
            }
            Body::DestroySurface => {
                let surface = SurfaceId::from_raw(object);
                match self.core.destroy_surface(session, surface) {
                    Ok(()) => send(
                        transport,
                        Opcode::SURFACE_DESTROYED,
                        object,
                        0,
                        &Body::SurfaceDestroyed,
                    ),
                    Err(error) => send_error(transport, object, request_id, core_code(error)),
                }
            }
            Body::SetCursorShape { .. } => {
                if object != 0 {
                    return send_error(transport, object, request_id, ERROR_BAD_OBJECT);
                }
                ack(transport, object, request_id)
            }
            Body::SetTitle { .. } | Body::RequestWindowAction { .. } => {
                match self.core.surface(session, SurfaceId::from_raw(object)) {
                    Ok(_) => ack(transport, object, request_id),
                    Err(error) => send_error(transport, object, request_id, core_code(error)),
                }
            }
            Body::Commit(commit) => {
                let surface = SurfaceId::from_raw(object);
                let buffer = BufferId::from_raw(commit.buffer);
                match self.core.commit(session, surface, &commit) {
                    Ok(CommitOutcome::Accepted { .. }) => {
                        // The commit is accepted atomically. Presentation is
                        // attempted synchronously; a backend failure does not
                        // roll the commit back: credit is still returned
                        // (`FRAME_DONE`, without PRESENT_SUBMITTED) and the
                        // peer receives a spontaneous ERROR before the ACK.
                        let presented = match self.core.present_current(session, surface) {
                            Ok(()) => true,
                            Err(_) => false,
                        };
                        if let Err(error) =
                            self.core
                                .frame_done(session, surface, buffer, commit.commit_id)
                        {
                            return send_error(transport, object, request_id, core_code(error));
                        }
                        let (serial, last_commit_id) = match self.core.surface(session, surface) {
                            Ok(record) => (record.acked_serial, record.last_commit_id),
                            Err(error) => {
                                return send_error(transport, object, request_id, core_code(error));
                            }
                        };
                        let flags = if presented {
                            match self.peer_slot_of_session(session) {
                                Some(slot)
                                    if self.peer_features[slot] & FEATURE_PRESENT_FEEDBACK != 0 =>
                                {
                                    FRAME_DONE_PRESENT_SUBMITTED
                                }
                                _ => 0,
                            }
                        } else {
                            0
                        };
                        send(
                            transport,
                            Opcode::FRAME_DONE,
                            object,
                            0,
                            &Body::FrameDone {
                                buffer: commit.buffer,
                                commit_id: commit.commit_id,
                                serial,
                                flags,
                            },
                        )?;
                        if !presented {
                            // Spontaneous event: request_id 0, offending object.
                            send_error(transport, object, 0, ERROR_INTERNAL)?;
                        }
                        loop {
                            match self.core.take_release(session) {
                                Ok(Some(released)) => send(
                                    transport,
                                    Opcode::BUFFER_RELEASE,
                                    released.raw(),
                                    0,
                                    &Body::BufferRelease {
                                        commit_id: last_commit_id,
                                        serial,
                                    },
                                )?,
                                Ok(None) | Err(_) => break,
                            }
                        }
                        ack(transport, object, request_id)
                    }
                    Err(error) => send_error(transport, object, request_id, core_code(error)),
                }
            }
            Body::UnmapSurface => match self.core.surface(session, SurfaceId::from_raw(object)) {
                Ok(_) => ack(transport, object, request_id),
                Err(error) => send_error(transport, object, request_id, core_code(error)),
            },
            _ => send_error(transport, object, request_id, ERROR_UNSUPPORTED),
        }
    }

    fn peer_slot(&self, peer: PeerId) -> Option<usize> {
        self.peers
            .iter()
            .position(|entry| matches!(entry, Some(slot) if slot.peer == peer))
    }

    fn peer_slot_of_session(&self, session: SessionId) -> Option<usize> {
        self.peers
            .iter()
            .position(|entry| matches!(entry, Some(slot) if slot.session == session))
    }
}

/// Encode `body` and send it as one complete message.
fn send(
    transport: &mut dyn Transport,
    opcode: Opcode,
    object_id: u64,
    request_id: u64,
    body: &Body<'_>,
) -> Result<(), ServerError> {
    let mut out = [0u8; CAPACITY];
    let body_len = body
        .encode(&mut out[HEADER_LEN..])
        .map_err(|_| ServerError::Encode)?;
    let total = HEADER_LEN + body_len;
    if total > CAPACITY {
        return Err(ServerError::Encode);
    }
    let header = Header {
        opcode: opcode.value(),
        flags: 0,
        message_bytes: total as u32,
        object_id,
        request_id,
    };
    header.encode(&mut out).map_err(|_| ServerError::Encode)?;
    transport.send(&out[..total]);
    Ok(())
}

fn ack(transport: &mut dyn Transport, object_id: u64, request_id: u64) -> Result<(), ServerError> {
    send(
        transport,
        Opcode::ACK,
        object_id,
        request_id,
        &Body::Ack { status: 0 },
    )
}

fn send_error(
    transport: &mut dyn Transport,
    object_id: u64,
    request_id: u64,
    code: u32,
) -> Result<(), ServerError> {
    let body = Body::Error { code, detail: &[] };
    send(transport, Opcode::ERROR, object_id, request_id, &body)
}

/// Wire `ERROR` code for a protocol decode failure (see module docs).
fn decode_code(error: DecodeError) -> u32 {
    match error {
        DecodeError::Truncated
        | DecodeError::SizeMismatch
        | DecodeError::Overflow
        | DecodeError::TooManyRects
        | DecodeError::BadValue => ERROR_BAD_LENGTH,
        DecodeError::BadFlags | DecodeError::ReservedNonZero | DecodeError::BadMagic => {
            ERROR_BAD_FLAGS
        }
        DecodeError::UnsupportedVersion | DecodeError::UnknownOpcode => ERROR_UNSUPPORTED,
        DecodeError::BadObject => ERROR_BAD_OBJECT,
    }
}

/// Wire `ERROR` code for a core failure (see module docs).
fn core_code(error: CoreError) -> u32 {
    match error {
        CoreError::NoSurface | CoreError::NoBuffer | CoreError::BadObject => ERROR_BAD_OBJECT,
        CoreError::NoSession
        | CoreError::BadState
        | CoreError::BadSerial
        | CoreError::BadCommitId => ERROR_BAD_STATE,
        CoreError::BadFlags => ERROR_BAD_FLAGS,
        CoreError::BadDimensions | CoreError::BadStride => ERROR_BAD_LENGTH,
        CoreError::BadFormat => ERROR_BAD_FORMAT,
        CoreError::Quota | CoreError::Limit => ERROR_QUOTA,
        CoreError::NoCredit => ERROR_NO_CREDIT,
        CoreError::BackendError => ERROR_INTERNAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vasistas_protocol::{Rect, FEATURES_KNOWN, FLAG_FULL_DAMAGE};
    use std::vec::Vec;

    use crate::backend::RegionHandle;

    struct FakeBackend {
        next_region: u64,
        allocations: u32,
        presents: u32,
        frees: u32,
        fail_present: bool,
    }

    impl FakeBackend {
        const fn new() -> Self {
            Self {
                next_region: 0x1000,
                allocations: 0,
                presents: 0,
                frees: 0,
                fail_present: false,
            }
        }
    }

    impl Backend for FakeBackend {
        type Error = ();

        fn allocate(
            &mut self,
            width: u32,
            height: u32,
            stride: u32,
            _format: u32,
        ) -> Result<RegionHandle, Self::Error> {
            if width == 0 || height == 0 || stride == 0 {
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

        fn present(
            &mut self,
            _surface: SurfaceId,
            _region: RegionHandle,
            _damage: &[Rect],
        ) -> Result<(), Self::Error> {
            if self.fail_present {
                return Err(());
            }
            self.presents += 1;
            Ok(())
        }
    }

    struct FakeTransport {
        messages: Vec<Vec<u8>>,
        /// `(server_region, client_pid, returned_handle)` per grant attempt.
        transfers: Vec<(u64, u32, u64)>,
        next_handle: u64,
        fail_transfer: bool,
    }

    impl Default for FakeTransport {
        fn default() -> Self {
            Self {
                messages: Vec::new(),
                transfers: Vec::new(),
                next_handle: 0x8000,
                fail_transfer: false,
            }
        }
    }

    impl Transport for FakeTransport {
        fn send(&mut self, message: &[u8]) {
            self.messages.push(message.to_vec());
        }

        fn transfer_region(&mut self, server_region: u64, client_pid: u32) -> Option<u64> {
            if self.fail_transfer {
                self.transfers.push((server_region, client_pid, 0));
                return None;
            }
            let handle = self.next_handle;
            self.next_handle += 1;
            self.transfers.push((server_region, client_pid, handle));
            Some(handle)
        }
    }

    /// Encode one request frame.
    fn frame(opcode: Opcode, object_id: u64, request_id: u64, body: &Body<'_>) -> Vec<u8> {
        let mut out = [0u8; CAPACITY];
        let len = body.encode(&mut out[HEADER_LEN..]).expect("encode body");
        let total = HEADER_LEN + len;
        let header = Header {
            opcode: opcode.value(),
            flags: 0,
            message_bytes: total as u32,
            object_id,
            request_id,
        };
        header.encode(&mut out).expect("encode header");
        out[..total].to_vec()
    }

    fn parse(message: &[u8]) -> (Header, Body<'_>) {
        let (header, rest) = Header::decode_message(message).expect("header decodes");
        let body = Body::decode(header.opcode, header.object_id, rest).expect("body decodes");
        (header, body)
    }

    fn error_code_of(message: &[u8]) -> u32 {
        let (header, body) = parse(message);
        assert_eq!(header.opcode, Opcode::ERROR.value());
        match body {
            Body::Error { code, .. } => code,
            other => panic!("expected ERROR, got {:?}", other),
        }
    }

    /// PID reported by the test `HELLO`.
    const HELLO_PID: u32 = 0x2A;

    fn hello(server: &mut Server<FakeBackend>, transport: &mut FakeTransport, peer: PeerId) {
        let message = frame(
            Opcode::HELLO,
            0,
            1,
            &Body::Hello {
                major: 1,
                minor: 0,
                features: FEATURES_KNOWN,
                pid: HELLO_PID,
                name: b"client",
                path: b"/srv/vasistas",
            },
        );
        server.handle(peer, &message, transport).expect("hello");
        transport.messages.clear();
    }

    fn create_surface(
        server: &mut Server<FakeBackend>,
        transport: &mut FakeTransport,
        peer: PeerId,
        request_id: u64,
        width: u32,
        height: u32,
    ) -> u64 {
        let message = frame(
            Opcode::CREATE_SURFACE,
            0,
            request_id,
            &Body::CreateSurface {
                width,
                height,
                format: 0,
                flags: 0,
                title: b"win",
            },
        );
        server.handle(peer, &message, transport).expect("create");
        let message = transport.messages.pop().expect("surface created");
        let (header, body) = parse(&message);
        assert_eq!(header.opcode, Opcode::SURFACE_CREATED.value());
        assert_eq!(header.request_id, 0);
        match body {
            Body::SurfaceCreated {
                width: w,
                height: h,
                format,
            } => {
                assert_eq!((w, h, format), (width, height, 0));
            }
            other => panic!("expected SURFACE_CREATED, got {:?}", other),
        }
        header.object_id
    }

    fn alloc_buffer(
        server: &mut Server<FakeBackend>,
        transport: &mut FakeTransport,
        peer: PeerId,
        surface: u64,
        request_id: u64,
        width: u32,
        height: u32,
    ) -> (u64, u64) {
        let stride = width * 4;
        let message = frame(
            Opcode::ALLOC_BUFFER,
            surface,
            request_id,
            &Body::AllocBuffer {
                width,
                height,
                format: 0,
                flags: 0,
                stride,
            },
        );
        server.handle(peer, &message, transport).expect("alloc");
        let message = transport.messages.pop().expect("buffer created");
        let (header, body) = parse(&message);
        assert_eq!(header.opcode, Opcode::BUFFER_CREATED.value());
        match body {
            Body::BufferCreated {
                surface: s,
                width: w,
                height: h,
                format,
                stride: st,
                region_len,
                region_handle,
            } => {
                assert_eq!(s, surface);
                assert_eq!((w, h, format, st), (width, height, 0, stride));
                assert_eq!(region_len, (stride * height) as u64);
                assert_ne!(region_handle, 0);
                let transfer = transport.transfers.last().copied().expect("grant recorded");
                assert_ne!(transfer.0, 0, "server region is the backend handle");
                assert_eq!(region_handle, transfer.2, "handle is the transferred one");
            }
            other => panic!("expected BUFFER_CREATED, got {:?}", other),
        }
        (header.object_id, (stride * height) as u64)
    }

    fn import_ok(
        server: &mut Server<FakeBackend>,
        transport: &mut FakeTransport,
        peer: PeerId,
        buffer: u64,
        request_id: u64,
    ) {
        let message = frame(
            Opcode::IMPORT_RESULT,
            buffer,
            request_id,
            &Body::ImportResult { status: IMPORT_OK },
        );
        server.handle(peer, &message, transport).expect("import");
        let message = transport.messages.pop().expect("ack");
        let (header, body) = parse(&message);
        assert_eq!(header.opcode, Opcode::ACK.value());
        assert_eq!(header.object_id, buffer);
        assert_eq!(header.request_id, request_id);
        assert_eq!(body, Body::Ack { status: 0 });
    }

    fn commit_frame(
        surface: u64,
        buffer: u64,
        ack_serial: u64,
        commit_id: u64,
        request_id: u64,
    ) -> Vec<u8> {
        let commit = vasistas_protocol::Commit {
            buffer,
            ack_serial,
            commit_id,
            flags: FLAG_FULL_DAMAGE,
            rect_count: 0,
            rects: [Rect::default(); vasistas_protocol::MAX_RECTS],
        };
        frame(Opcode::COMMIT, surface, request_id, &Body::Commit(commit))
    }

    #[test]
    fn init_at_matches_new() {
        // Regression: the in-place initializer must produce an empty server
        // that accepts the normal HELLO flow, without `Server::new`.
        let mut slot = core::mem::MaybeUninit::<Server<FakeBackend>>::uninit();
        let server = Server::init_at(&mut slot, FakeBackend::new());
        assert_eq!(server.core().stats(), crate::CoreStats::default());
        let mut transport = FakeTransport::default();
        let peer = PeerId::new(90);
        hello(server, &mut transport, peer);
        assert_eq!(server.peer_pid(peer), Some(HELLO_PID));
        assert_eq!(server.core().stats().sessions, 1);
    }

    #[test]
    fn hello_negotiates_and_duplicate_is_rejected() {
        let mut server = Server::new(FakeBackend::new());
        let mut transport = FakeTransport::default();
        let peer = PeerId::new(1);

        let message = frame(
            Opcode::HELLO,
            0,
            7,
            &Body::Hello {
                major: 1,
                minor: 0,
                features: FEATURES_KNOWN,
                pid: 0x11,
                name: b"alice",
                path: b"",
            },
        );
        server
            .handle(peer, &message, &mut transport)
            .expect("hello");
        assert_eq!(transport.messages.len(), 1);
        let (header, body) = parse(&transport.messages[0]);
        assert_eq!(header.opcode, Opcode::WELCOME.value());
        assert_eq!(header.object_id, 0);
        assert_eq!(header.request_id, 7);
        let session = server.session_of(peer).expect("session recorded");
        assert_eq!(server.peer_pid(peer), Some(0x11));
        assert_eq!(server.session_pid(session), Some(0x11));
        match body {
            Body::Welcome {
                major,
                minor,
                features,
                max_message_bytes,
                max_surfaces,
                max_buffers_per_surface,
                max_buffers_per_session,
                pixel_quota_bytes,
                session: welcome_session,
            } => {
                assert_eq!((major, minor), (VERSION_MAJOR, VERSION_MINOR));
                assert_eq!(features, FEATURE_PRESENT_FEEDBACK);
                assert_eq!(features & !SUPPORTED_FEATURES, 0);
                assert_eq!(max_message_bytes, 1008);
                assert_eq!(max_surfaces, 4);
                assert_eq!(max_buffers_per_surface, 4);
                assert_eq!(max_buffers_per_session, 16);
                assert_eq!(pixel_quota_bytes, 8 * 1024 * 1024);
                assert_eq!(welcome_session, session.raw());
            }
            other => panic!("expected WELCOME, got {:?}", other),
        }

        // Second HELLO on the same peer keeps the first session.
        transport.messages.clear();
        let duplicate = frame(
            Opcode::HELLO,
            0,
            8,
            &Body::Hello {
                major: 1,
                minor: 0,
                features: 0,
                pid: 0x11,
                name: b"alice",
                path: b"",
            },
        );
        server
            .handle(peer, &duplicate, &mut transport)
            .expect("duplicate");
        assert_eq!(transport.messages.len(), 1);
        let (header, _) = parse(&transport.messages[0]);
        assert_eq!(header.object_id, 0);
        assert_eq!(header.request_id, 8);
        assert_eq!(error_code_of(&transport.messages[0]), ERROR_BAD_STATE);
        assert_eq!(server.session_of(peer), Some(session));
    }

    #[test]
    fn ping_and_malformed_input() {
        let mut server = Server::new(FakeBackend::new());
        let mut transport = FakeTransport::default();
        let peer = PeerId::new(2);

        let cookie = 0x0123_4567_89AB_CDEF;
        let ping = frame(Opcode::PING, 0, 3, &Body::Ping { cookie });
        server.handle(peer, &ping, &mut transport).expect("ping");
        let (header, body) = parse(&transport.messages[0]);
        assert_eq!(header.opcode, Opcode::PONG.value());
        assert_eq!(header.object_id, 0);
        assert_eq!(body, Body::Pong { cookie });

        // Empty frame: header cannot be decoded.
        transport.messages.clear();
        server.handle(peer, &[], &mut transport).expect("empty");
        assert_eq!(transport.messages.len(), 1);
        let (header, _) = parse(&transport.messages[0]);
        assert_eq!(header.object_id, 0);
        assert_eq!(header.request_id, 0);
        assert_eq!(error_code_of(&transport.messages[0]), ERROR_BAD_LENGTH);

        // Truncated PING body: header decodes, body does not.
        transport.messages.clear();
        let mut short = frame(Opcode::PING, 0, 4, &Body::Ping { cookie });
        short.truncate(short.len() - 1);
        let short_len = short.len() as u32;
        short[12..16].copy_from_slice(&short_len.to_le_bytes());
        server.handle(peer, &short, &mut transport).expect("short");
        assert_eq!(error_code_of(&transport.messages[0]), ERROR_BAD_LENGTH);

        // Unsupported version.
        transport.messages.clear();
        let mut version = frame(Opcode::PING, 0, 5, &Body::Ping { cookie });
        version[4..6].copy_from_slice(&2u16.to_le_bytes());
        server
            .handle(peer, &version, &mut transport)
            .expect("version");
        assert_eq!(error_code_of(&transport.messages[0]), ERROR_UNSUPPORTED);

        // Non-zero header flags.
        transport.messages.clear();
        let mut flags = frame(Opcode::PING, 0, 6, &Body::Ping { cookie });
        flags[10..12].copy_from_slice(&1u16.to_le_bytes());
        server.handle(peer, &flags, &mut transport).expect("flags");
        assert_eq!(error_code_of(&transport.messages[0]), ERROR_BAD_FLAGS);

        // Trailing bytes: declared length disagrees with the datagram.
        transport.messages.clear();
        let mut long = frame(Opcode::PING, 0, 7, &Body::Ping { cookie });
        long.push(0);
        server.handle(peer, &long, &mut transport).expect("long");
        assert_eq!(error_code_of(&transport.messages[0]), ERROR_BAD_LENGTH);
    }

    #[test]
    fn full_flow_commit_presents_and_releases() {
        let mut server = Server::new(FakeBackend::new());
        let mut transport = FakeTransport::default();
        let peer = PeerId::new(3);
        hello(&mut server, &mut transport, peer);
        assert_eq!(server.peer_pid(peer), Some(HELLO_PID));

        let surface = create_surface(&mut server, &mut transport, peer, 2, 64, 32);
        let (first, first_len) =
            alloc_buffer(&mut server, &mut transport, peer, surface, 3, 64, 32);
        assert_eq!(first_len, 64 * 4 * 32);
        assert_eq!(transport.transfers.last().expect("granted").1, HELLO_PID);
        import_ok(&mut server, &mut transport, peer, first, 4);

        // First commit: FRAME_DONE then ACK, no release.
        let commit = commit_frame(surface, first, 0, 1, 5);
        server
            .handle(peer, &commit, &mut transport)
            .expect("commit");
        assert_eq!(transport.messages.len(), 2);
        let (header, body) = parse(&transport.messages[0]);
        assert_eq!(header.opcode, Opcode::FRAME_DONE.value());
        assert_eq!(header.object_id, surface);
        assert_eq!(header.request_id, 0);
        assert_eq!(
            body,
            Body::FrameDone {
                buffer: first,
                commit_id: 1,
                serial: 0,
                flags: FRAME_DONE_PRESENT_SUBMITTED,
            }
        );
        let (header, body) = parse(&transport.messages[1]);
        assert_eq!(header.opcode, Opcode::ACK.value());
        assert_eq!(header.object_id, surface);
        assert_eq!(header.request_id, 5);
        assert_eq!(body, Body::Ack { status: 0 });
        transport.messages.clear();

        // Second buffer, second commit: FRAME_DONE + BUFFER_RELEASE + ACK.
        let (second, _) = alloc_buffer(&mut server, &mut transport, peer, surface, 6, 64, 32);
        import_ok(&mut server, &mut transport, peer, second, 7);
        let commit = commit_frame(surface, second, 0, 2, 8);
        server
            .handle(peer, &commit, &mut transport)
            .expect("commit");
        assert_eq!(transport.messages.len(), 3);
        let (header, body) = parse(&transport.messages[0]);
        assert_eq!(header.opcode, Opcode::FRAME_DONE.value());
        assert_eq!(header.object_id, surface);
        assert_eq!(
            body,
            Body::FrameDone {
                buffer: second,
                commit_id: 2,
                serial: 0,
                flags: FRAME_DONE_PRESENT_SUBMITTED,
            }
        );
        let (header, body) = parse(&transport.messages[1]);
        assert_eq!(header.opcode, Opcode::BUFFER_RELEASE.value());
        assert_eq!(header.object_id, first);
        assert_eq!(header.request_id, 0);
        assert_eq!(
            body,
            Body::BufferRelease {
                commit_id: 2,
                serial: 0,
            }
        );
        let (header, body) = parse(&transport.messages[2]);
        assert_eq!(header.opcode, Opcode::ACK.value());
        assert_eq!(header.request_id, 8);
        assert_eq!(body, Body::Ack { status: 0 });
        assert_eq!(server.core().backend().presents, 2);
    }

    #[test]
    fn failed_region_grant_reports_internal_and_creates_nothing() {
        let mut server = Server::new(FakeBackend::new());
        let mut transport = FakeTransport::default();
        let peer = PeerId::new(40);
        let other = PeerId::new(41);
        hello(&mut server, &mut transport, peer);
        hello(&mut server, &mut transport, other);
        let surface = create_surface(&mut server, &mut transport, peer, 2, 8, 8);
        let other_surface = create_surface(&mut server, &mut transport, other, 2, 8, 8);

        transport.fail_transfer = true;
        transport.messages.clear();
        let message = frame(
            Opcode::ALLOC_BUFFER,
            surface,
            3,
            &Body::AllocBuffer {
                width: 8,
                height: 8,
                format: 0,
                flags: 0,
                stride: 32,
            },
        );
        server
            .handle(peer, &message, &mut transport)
            .expect("alloc");
        assert_eq!(transport.messages.len(), 1, "no BUFFER_CREATED");
        assert_eq!(error_code_of(&transport.messages[0]), ERROR_INTERNAL);
        assert_eq!(
            transport.transfers.last().expect("grant attempted").1,
            HELLO_PID
        );

        // The other session is unaffected by the failed grant.
        transport.fail_transfer = false;
        let (buffer, _) = alloc_buffer(&mut server, &mut transport, other, other_surface, 4, 8, 8);
        import_ok(&mut server, &mut transport, other, buffer, 5);
        transport.messages.clear();
        let commit = commit_frame(other_surface, buffer, 0, 1, 6);
        server
            .handle(other, &commit, &mut transport)
            .expect("commit");
        assert_eq!(
            parse(&transport.messages[0]).0.opcode,
            Opcode::FRAME_DONE.value()
        );
    }

    #[test]
    fn commit_present_failure_and_bad_serial() {
        let mut backend = FakeBackend::new();
        backend.fail_present = true;
        let mut server = Server::new(backend);
        let mut transport = FakeTransport::default();
        let peer = PeerId::new(4);
        hello(&mut server, &mut transport, peer);

        let surface = create_surface(&mut server, &mut transport, peer, 2, 16, 16);
        let (first, _) = alloc_buffer(&mut server, &mut transport, peer, surface, 3, 16, 16);
        import_ok(&mut server, &mut transport, peer, first, 4);

        // Presentation fails after the commit was accepted: FRAME_DONE
        // (without PRESENT_SUBMITTED), a spontaneous ERROR, then the ACK.
        // The commit is not rolled back and the credit is returned.
        let commit = commit_frame(surface, first, 0, 1, 5);
        server
            .handle(peer, &commit, &mut transport)
            .expect("commit");
        assert_eq!(transport.messages.len(), 3);
        let (header, body) = parse(&transport.messages[0]);
        assert_eq!(header.opcode, Opcode::FRAME_DONE.value());
        assert_eq!(header.object_id, surface);
        assert_eq!(header.request_id, 0);
        assert!(matches!(body, Body::FrameDone { flags: 0, .. }));
        let (header, _) = parse(&transport.messages[1]);
        assert_eq!(header.opcode, Opcode::ERROR.value());
        assert_eq!(header.object_id, surface);
        assert_eq!(header.request_id, 0);
        assert_eq!(error_code_of(&transport.messages[1]), ERROR_INTERNAL);
        let (header, body) = parse(&transport.messages[2]);
        assert_eq!(header.opcode, Opcode::ACK.value());
        assert_eq!(header.request_id, 5);
        assert_eq!(body, Body::Ack { status: 0 });

        // The credit was returned: the next commit is accepted (and also
        // reports the backend presentation failure).
        transport.messages.clear();
        let (second, _) = alloc_buffer(&mut server, &mut transport, peer, surface, 6, 16, 16);
        import_ok(&mut server, &mut transport, peer, second, 7);
        let commit = commit_frame(surface, second, 0, 2, 8);
        server
            .handle(peer, &commit, &mut transport)
            .expect("commit");
        assert_eq!(transport.messages.len(), 4);
        assert_eq!(error_code_of(&transport.messages[1]), ERROR_INTERNAL);
        let (header, _) = parse(&transport.messages[2]);
        assert_eq!(header.opcode, Opcode::BUFFER_RELEASE.value());

        // Healthy server: a wrong ack serial is rejected without state change.
        let mut server = Server::new(FakeBackend::new());
        let mut transport = FakeTransport::default();
        let peer = PeerId::new(5);
        hello(&mut server, &mut transport, peer);
        let surface = create_surface(&mut server, &mut transport, peer, 2, 16, 16);
        let (buffer, _) = alloc_buffer(&mut server, &mut transport, peer, surface, 3, 16, 16);
        import_ok(&mut server, &mut transport, peer, buffer, 4);

        transport.messages.clear();
        let commit = commit_frame(surface, buffer, 9, 1, 5);
        server
            .handle(peer, &commit, &mut transport)
            .expect("commit");
        assert_eq!(transport.messages.len(), 1);
        assert_eq!(error_code_of(&transport.messages[0]), ERROR_BAD_STATE);

        // The rejection left the surface untouched: the same commit with the
        // right serial is accepted.
        transport.messages.clear();
        let commit = commit_frame(surface, buffer, 0, 1, 6);
        server
            .handle(peer, &commit, &mut transport)
            .expect("commit");
        let (header, _) = parse(&transport.messages[0]);
        assert_eq!(header.opcode, Opcode::FRAME_DONE.value());
        transport.messages.clear();

        // A repeat commit of the buffer that is already current is BAD_STATE.
        let commit = commit_frame(surface, buffer, 0, 2, 7);
        server
            .handle(peer, &commit, &mut transport)
            .expect("commit");
        assert_eq!(error_code_of(&transport.messages[0]), ERROR_BAD_STATE);
    }

    #[test]
    fn cross_session_object_is_rejected() {
        let mut server = Server::new(FakeBackend::new());
        let mut transport = FakeTransport::default();
        let peer_a = PeerId::new(6);
        let peer_b = PeerId::new(7);
        hello(&mut server, &mut transport, peer_a);
        hello(&mut server, &mut transport, peer_b);

        let surface_a = create_surface(&mut server, &mut transport, peer_a, 2, 16, 16);
        let (buffer_a, _) = alloc_buffer(&mut server, &mut transport, peer_a, surface_a, 3, 16, 16);
        import_ok(&mut server, &mut transport, peer_a, buffer_a, 4);
        let surface_b = create_surface(&mut server, &mut transport, peer_b, 2, 16, 16);

        transport.messages.clear();
        let commit = commit_frame(surface_b, buffer_a, 0, 1, 5);
        server
            .handle(peer_b, &commit, &mut transport)
            .expect("commit");
        assert_eq!(transport.messages.len(), 1);
        assert_eq!(error_code_of(&transport.messages[0]), ERROR_BAD_OBJECT);

        // Peer A's commit of the same buffer still works.
        transport.messages.clear();
        let commit = commit_frame(surface_a, buffer_a, 0, 1, 6);
        server
            .handle(peer_a, &commit, &mut transport)
            .expect("commit");
        assert_eq!(
            parse(&transport.messages[0]).0.opcode,
            Opcode::FRAME_DONE.value()
        );
    }

    #[test]
    fn client_events_and_unknown_opcodes_are_unsupported() {
        let mut server = Server::new(FakeBackend::new());
        let mut transport = FakeTransport::default();
        let peer = PeerId::new(8);
        hello(&mut server, &mut transport, peer);

        transport.messages.clear();
        let event = frame(Opcode::ACK, 0, 9, &Body::Ack { status: 0 });
        server.handle(peer, &event, &mut transport).expect("event");
        assert_eq!(transport.messages.len(), 1);
        let (header, _) = parse(&transport.messages[0]);
        assert_eq!(header.object_id, 0);
        assert_eq!(error_code_of(&transport.messages[0]), ERROR_UNSUPPORTED);

        transport.messages.clear();
        let mut unknown = frame(Opcode::PING, 0, 10, &Body::Ping { cookie: 0 });
        unknown[8..10].copy_from_slice(&0x0099u16.to_le_bytes());
        unknown[12..16].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
        unknown.truncate(HEADER_LEN);
        server
            .handle(peer, &unknown, &mut transport)
            .expect("unknown");
        assert_eq!(error_code_of(&transport.messages[0]), ERROR_UNSUPPORTED);

        // WRITE_TILE is host-tests-only: rejected, never dispatched.
        transport.messages.clear();
        let tile = frame(
            Opcode::WRITE_TILE,
            1,
            11,
            &Body::WriteTile {
                x: 0,
                y: 0,
                w: 1,
                h: 1,
                stride: 4,
                pixels: &[0, 0, 0, 0],
            },
        );
        server.handle(peer, &tile, &mut transport).expect("tile");
        assert_eq!(error_code_of(&transport.messages[0]), ERROR_UNSUPPORTED);
    }

    #[test]
    fn goodbye_closes_session() {
        let mut server = Server::new(FakeBackend::new());
        let mut transport = FakeTransport::default();
        let peer = PeerId::new(9);
        hello(&mut server, &mut transport, peer);
        let surface = create_surface(&mut server, &mut transport, peer, 2, 8, 8);
        let (buffer, _) = alloc_buffer(&mut server, &mut transport, peer, surface, 3, 8, 8);
        import_ok(&mut server, &mut transport, peer, buffer, 4);

        transport.messages.clear();
        let goodbye = frame(Opcode::GOODBYE, 0, 5, &Body::Goodbye);
        server
            .handle(peer, &goodbye, &mut transport)
            .expect("goodbye");
        assert_eq!(transport.messages.len(), 1);
        let (header, body) = parse(&transport.messages[0]);
        assert_eq!(header.opcode, Opcode::ACK.value());
        assert_eq!(header.request_id, 5);
        assert_eq!(body, Body::Ack { status: 0 });
        assert_eq!(server.session_of(peer), None);
        assert_eq!(server.peer_pid(peer), None);

        transport.messages.clear();
        let message = frame(
            Opcode::CREATE_SURFACE,
            0,
            6,
            &Body::CreateSurface {
                width: 8,
                height: 8,
                format: 0,
                flags: 0,
                title: b"",
            },
        );
        server
            .handle(peer, &message, &mut transport)
            .expect("after goodbye");
        assert_eq!(transport.messages.len(), 1);
        assert_eq!(error_code_of(&transport.messages[0]), ERROR_BAD_STATE);
    }

    #[test]
    fn ninth_hello_hits_the_limit() {
        let mut server = Server::new(FakeBackend::new());
        let mut transport = FakeTransport::default();
        for index in 0..MAX_SESSIONS as u64 {
            let message = frame(
                Opcode::HELLO,
                0,
                1,
                &Body::Hello {
                    major: 1,
                    minor: 0,
                    features: 0,
                    pid: 0,
                    name: b"",
                    path: b"",
                },
            );
            server
                .handle(PeerId::new(index + 1), &message, &mut transport)
                .expect("hello");
            if let Some(last) = transport.messages.last() {
                assert_eq!(parse(last).0.opcode, Opcode::WELCOME.value());
            }
        }
        assert_eq!(transport.messages.len(), MAX_SESSIONS);

        transport.messages.clear();
        let message = frame(
            Opcode::HELLO,
            0,
            2,
            &Body::Hello {
                major: 1,
                minor: 0,
                features: 0,
                pid: 0,
                name: b"",
                path: b"",
            },
        );
        server
            .handle(PeerId::new(99), &message, &mut transport)
            .expect("ninth hello");
        assert_eq!(transport.messages.len(), 1);
        assert_eq!(error_code_of(&transport.messages[0]), ERROR_QUOTA);
        assert_eq!(server.session_of(PeerId::new(99)), None);
    }

    #[test]
    fn random_input_never_panics_and_replies_are_well_formed() {
        let mut server = Server::new(FakeBackend::new());
        let mut transport = FakeTransport::default();
        let peer = PeerId::new(10);
        hello(&mut server, &mut transport, peer);
        let surface = create_surface(&mut server, &mut transport, peer, 2, 8, 8);

        let mut state: u64 = 0x0DDB_1A5E_5BAD_5EED;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };

        let mut buffer = [0u8; CAPACITY];
        for _ in 0..2_000 {
            let seed = next();
            let len = (next() as usize) % (CAPACITY + 1);
            for byte in buffer[..len].iter_mut() {
                *byte = next() as u8;
            }
            let message: &[u8] = if seed % 3 == 0 && len >= HEADER_LEN {
                // Valid header, random opcode/object/body, to reach dispatch.
                let header = Header {
                    opcode: (next() % 0x0070) as u16,
                    flags: 0,
                    message_bytes: (len as u32).max(HEADER_LEN as u32),
                    object_id: if next() % 4 == 0 { surface } else { next() },
                    request_id: next() | 1,
                };
                buffer[..HEADER_LEN].fill(0);
                header.encode(&mut buffer).expect("header");
                &buffer[..len.max(HEADER_LEN)]
            } else {
                &buffer[..len]
            };

            transport.messages.clear();
            let result = server.handle(peer, message, &mut transport);
            assert!(result.is_ok() || result == Err(ServerError::Encode));
            for reply in &transport.messages {
                let (header, rest) = Header::decode_message(reply).expect("reply header");
                assert_eq!(header.message_bytes as usize, reply.len());
                Body::decode(header.opcode, header.object_id, rest).expect("reply body");
            }
        }
    }

    #[test]
    fn request_id_version_and_object_are_validated() {
        let mut server = Server::new(FakeBackend::new());
        let mut transport = FakeTransport::default();
        let peer = PeerId::new(20);

        // request_id 0 is reserved for events.
        let message = frame(
            Opcode::HELLO,
            0,
            0,
            &Body::Hello {
                major: 1,
                minor: 0,
                features: 0,
                pid: 0,
                name: b"c",
                path: b"",
            },
        );
        server
            .handle(peer, &message, &mut transport)
            .expect("hello");
        assert_eq!(transport.messages.len(), 1);
        assert_eq!(error_code_of(&transport.messages[0]), ERROR_BAD_FLAGS);
        transport.messages.clear();

        // Unsupported major version.
        let message = frame(
            Opcode::HELLO,
            0,
            2,
            &Body::Hello {
                major: 2,
                minor: 0,
                features: 0,
                pid: 0,
                name: b"c",
                path: b"",
            },
        );
        server
            .handle(peer, &message, &mut transport)
            .expect("hello");
        assert_eq!(error_code_of(&transport.messages[0]), ERROR_UNSUPPORTED);
        transport.messages.clear();

        // HELLO must use object 0.
        let message = frame(
            Opcode::HELLO,
            7,
            3,
            &Body::Hello {
                major: 1,
                minor: 0,
                features: 0,
                pid: 0,
                name: b"c",
                path: b"",
            },
        );
        server
            .handle(peer, &message, &mut transport)
            .expect("hello");
        assert_eq!(error_code_of(&transport.messages[0]), ERROR_BAD_OBJECT);
        transport.messages.clear();

        hello(&mut server, &mut transport, peer);
        let surface = create_surface(&mut server, &mut transport, peer, 4, 8, 8);

        // CREATE_SURFACE must use object 0.
        let message = frame(
            Opcode::CREATE_SURFACE,
            surface,
            5,
            &Body::CreateSurface {
                width: 8,
                height: 8,
                format: 0,
                flags: 0,
                title: b"t",
            },
        );
        server
            .handle(peer, &message, &mut transport)
            .expect("surface");
        assert_eq!(error_code_of(&transport.messages[0]), ERROR_BAD_OBJECT);
        transport.messages.clear();

        // SET_TITLE on an object that is not this session's surface.
        let message = frame(
            Opcode::SET_TITLE,
            surface + 1,
            6,
            &Body::SetTitle { title: b"t" },
        );
        server
            .handle(peer, &message, &mut transport)
            .expect("title");
        assert_eq!(error_code_of(&transport.messages[0]), ERROR_BAD_OBJECT);
        transport.messages.clear();

        // SET_CURSOR_SHAPE must use object 0.
        let message = frame(
            Opcode::SET_CURSOR_SHAPE,
            1,
            7,
            &Body::SetCursorShape { shape: 1 },
        );
        server
            .handle(peer, &message, &mut transport)
            .expect("cursor");
        assert_eq!(error_code_of(&transport.messages[0]), ERROR_BAD_OBJECT);
    }

    #[test]
    fn disconnect_closes_session_and_frees_the_peer_slot() {
        let mut server = Server::new(FakeBackend::new());
        let mut transport = FakeTransport::default();
        let peer = PeerId::new(31);
        hello(&mut server, &mut transport, peer);
        let surface = create_surface(&mut server, &mut transport, peer, 2, 16, 16);
        let _ = alloc_buffer(&mut server, &mut transport, peer, surface, 3, 16, 16);
        assert_eq!(server.core().stats().sessions, 1);
        assert_eq!(server.core().stats().surfaces, 1);
        assert_eq!(server.core().stats().buffers, 1);
        assert!(server.core().stats().used_bytes > 0);

        server.disconnect(peer).expect("disconnect");
        assert_eq!(server.session_of(peer), None);
        assert_eq!(server.peer_pid(peer), None);
        assert_eq!(server.core().stats(), crate::CoreStats::default());
        // The dead session's region is retired, not leaked.
        let retired = server.take_retired().expect("region retired");
        server.free_retired(retired);
        assert!(server.take_retired().is_none());

        // Idempotent on an unknown peer.
        server.disconnect(peer).expect("second disconnect");

        // The slot is reusable: the same peer can open a new session.
        hello(&mut server, &mut transport, peer);
        assert!(server.session_of(peer).is_some());
    }

    #[test]
    fn goodbye_retires_and_server_frees() {
        let mut server = Server::new(FakeBackend::new());
        let mut transport = FakeTransport::default();
        let peer = PeerId::new(30);
        hello(&mut server, &mut transport, peer);
        let surface = create_surface(&mut server, &mut transport, peer, 2, 8, 8);
        let _ = alloc_buffer(&mut server, &mut transport, peer, surface, 3, 8, 8);
        let _ = alloc_buffer(&mut server, &mut transport, peer, surface, 4, 8, 8);
        assert_eq!(server.core().backend().frees, 0);

        let message = frame(Opcode::GOODBYE, 0, 5, &Body::Goodbye);
        server
            .handle(peer, &message, &mut transport)
            .expect("goodbye");
        assert_eq!(server.core().backend().frees, 0, "free is deferred");

        let mut freed = 0;
        while let Some(region) = server.take_retired() {
            server.free_retired(region);
            freed += 1;
        }
        assert_eq!(freed, 2);
        assert_eq!(server.core().backend().frees, 2);
        assert!(server.take_retired().is_none());
    }
}
