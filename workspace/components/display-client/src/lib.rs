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

//! Client side of the strat9-os native display server (`displayd`).
//!
//! [`Client::connect`] creates a private event port, binds it to
//! `/srv/display/c/<pid>`, connects to the server path and sends one `HELLO`
//! whose `path` is the event port path. All replies and spontaneous events
//! arrive on that port, so the client never uses `ipc_call`/`ipc_reply`.
//!
//! The client is synchronous: a request blocks until its matching event
//! arrives (or a fixed request timeout expires). `SURFACE_CREATED`,
//! `BUFFER_CREATED`, `FRAME_DONE` and `BUFFER_RELEASE` carry `request_id = 0`
//! (A.3.1 reserves 0 for events), so they are matched by opcode and object,
//! not by request id. `ACK`/`ERROR` echo the request id and are matched on it.
//!
//! Uploaded pixels are shared memory: [`Client::alloc_buffer`] maps the
//! region the server transferred and returns a [`Buffer`] whose `pixels()`
//! accessors cover `stride * height` bytes.
//!
//! Everything here is `no_std`; only the demo binary needs the extra
//! scaffolding (panic handler, `_start`).

#![no_std]

#[cfg(test)]
extern crate std;

use core::slice;

use display_protocol::{
    constants::FRAME_DONE_PRESENT_SUBMITTED, Body, Commit, Header, Opcode, Rect,
    FEATURE_PRESENT_FEEDBACK, FLAG_FULL_DAMAGE, FORMAT_XRGB8888, HEADER_LEN, IMPORT_OK,
    MAX_MESSAGE_BYTES, MAX_RECTS,
};
use strat9_syscall::{
    call,
    data::{IpcMessage, TimeSpec},
    error::Error,
    CLOCK_MONOTONIC,
};

/// Namespace prefix of the per-client display event ports.
pub const CLIENT_PATH_PREFIX: &[u8] = b"/srv/display/c/";
/// Maximum length of the per-client event path.
pub const CLIENT_PATH_MAX: usize = 64;

/// One complete protocol frame, header included (A.1).
const MAX_MESSAGE: usize = MAX_MESSAGE_BYTES as usize;

/// Timeout used by the synchronous request helpers, which take no timeout.
const REQUEST_TIMEOUT_NS: u64 = 1_000_000_000;

/// Bound on retries when a port queue is momentarily full.
const SEND_RETRIES: usize = 4;

/// Bound on events consumed while waiting for a specific reply.
const MATCH_TRIES: usize = 64;

/// One server-to-client event, decoded into owned fixed-size data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Welcome {
        features: u32,
        max_message_bytes: u32,
        session: u64,
    },
    SurfaceCreated {
        surface: u64,
        width: u32,
        height: u32,
    },
    BufferCreated {
        buffer: u64,
        surface: u64,
        width: u32,
        height: u32,
        stride: u32,
        region_handle: u64,
        region_len: u64,
    },
    Configure {
        surface: u64,
        serial: u64,
        width: u32,
        height: u32,
    },
    FrameDone {
        buffer: u64,
        commit_id: u64,
        serial: u64,
        flags: u32,
    },
    BufferRelease {
        buffer: u64,
        commit_id: u64,
    },
    CloseRequest {
        surface: u64,
        reason: u32,
    },
    Error {
        code: u32,
        object: u64,
    },
    Ack {
        status: u32,
        request_id: u64,
    },
    /// Valid frame whose body carries nothing this client models.
    Other,
}

/// Owner of one `COMMIT` response sequence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CommitResult {
    /// Last `FRAME_DONE` seen while waiting for the `ACK`.
    pub frame: Option<FrameDone>,
    /// Buffer the server released during this commit, if any.
    pub released: Option<u64>,
    /// `ACK` observed with status `0`.
    pub acknowledged: bool,
}

/// `FRAME_DONE` payload (A.3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameDone {
    pub buffer: u64,
    pub commit_id: u64,
    pub serial: u64,
    pub flags: u32,
}

impl FrameDone {
    /// True when the server reported that the frame was submitted.
    pub fn present_submitted(&self) -> bool {
        self.flags & FRAME_DONE_PRESENT_SUBMITTED != 0
    }
}

/// A mapped, writable pixel buffer owned by the server.
#[derive(Debug)]
pub struct Buffer {
    /// Protocol buffer id.
    pub id: u64,
    /// Capability handle the server used when transferring the region.
    pub region_handle: u64,
    /// User virtual address of the mapping.
    pub addr: usize,
    /// Mapped length in bytes (`>= stride * height`).
    pub len: usize,
    pub stride: u32,
    pub width: u32,
    pub height: u32,
}

impl Buffer {
    /// Byte length of the pixels covered by [`Buffer::pixels`].
    pub fn pixel_len(&self) -> usize {
        self.stride as usize * self.height as usize
    }

    /// Read-only view of `stride * height` bytes.
    pub fn pixels(&self) -> &[u8] {
        // SAFETY: `addr` is the base of a region the kernel mapped for this
        // process with the length validated in `alloc_buffer`; the mapping is
        // live for at least as long as this `Buffer` value can be used.
        unsafe { slice::from_raw_parts(self.addr as *const u8, self.pixel_len()) }
    }

    /// Writable view of `stride * height` bytes.
    pub fn pixels_mut(&mut self) -> &mut [u8] {
        // SAFETY: same mapping as `pixels`; `&mut self` guarantees exclusive
        // access to this buffer value for the returned lifetime.
        unsafe { slice::from_raw_parts_mut(self.addr as *mut u8, self.pixel_len()) }
    }
}

/// A connected display client.
pub struct Client {
    server: usize,
    event: usize,
    pid: u32,
    session: u64,
    path: [u8; CLIENT_PATH_MAX],
    path_len: u8,
    next_request: u64,
}

impl Client {
    /// Connect to the display server at `server_path` and wait for `WELCOME`.
    ///
    /// Returns `None` on any failure or when `timeout_ns` expires; the caller
    /// is expected to retry. Every partially created port is closed first.
    pub fn connect(server_path: &[u8], timeout_ns: u64) -> Option<Self> {
        let event = match call::ipc_create_port(0) {
            Ok(event) => event,
            Err(error) => {
                let _ = call::write(2, b"display-client: create_port failed: ");
                let _ = call::write(2, error.name().as_bytes());
                let _ = call::write(2, b"\n");
                return None;
            }
        };
        let pid = match call::getpid() {
            Ok(pid) => pid as u32,
            Err(_) => {
                close_handle(event);
                return None;
            }
        };

        let mut path = [0u8; CLIENT_PATH_MAX];
        let path_len = match client_path(pid, &mut path) {
            Some(len) => len,
            None => {
                close_handle(event);
                return None;
            }
        };
        let bound_path = &path[..path_len as usize];
        if call::ipc_bind_port(event, bound_path).is_err() {
            Self::debug(b"display-client: bind event path failed");
            close_handle(event);
            return None;
        }

        let server = match call::ipc_connect(server_path) {
            Ok(server) => server,
            Err(_) => {
                Self::debug(b"display-client: connect server failed");
                let _ = call::ipc_unbind_port(bound_path);
                close_handle(event);
                return None;
            }
        };

        let hello_ok = send_frame(
            server,
            Opcode::HELLO,
            0,
            1,
            &Body::Hello {
                major: display_protocol::VERSION_MAJOR,
                minor: display_protocol::VERSION_MINOR,
                features: FEATURE_PRESENT_FEEDBACK,
                pid,
                name: b"demo",
                path: bound_path,
            },
        );
        if !hello_ok {
            Self::debug(b"display-client: HELLO send failed");
            let _ = call::ipc_unbind_port(bound_path);
            close_handle(server);
            close_handle(event);
            return None;
        }

        let mut client = Client {
            server,
            event,
            pid,
            session: 0,
            path,
            path_len,
            next_request: 2,
        };
        let deadline = now_ns().saturating_add(timeout_ns);
        for _ in 0..MATCH_TRIES {
            let now = now_ns();
            if now >= deadline {
                break;
            }
            match client.recv(deadline - now) {
                Some(Event::Welcome { session, .. }) => {
                    client.session = session;
                    return Some(client);
                }
                Some(Event::Error { .. }) => break,
                Some(_) => continue,
                None => break,
            }
        }
        Self::debug(b"display-client: WELCOME timeout");
        client.cleanup();
        None
    }

    fn debug(text: &[u8]) {
    let _ = call::write(2, text);
    let _ = call::write(2, b"\n");
}

/// Process id this client reported in `HELLO`.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Session id assigned by `WELCOME`.
    pub fn session(&self) -> u64 {
        self.session
    }

    /// Path this client bound for its event port.
    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len as usize]
    }

    /// Wait up to `timeout_ns` and decode one event.
    pub fn recv(&mut self, timeout_ns: u64) -> Option<Event> {
        self.frame(timeout_ns).map(|(_, event)| event)
    }

    /// `CREATE_SURFACE` bound to the connection (`object_id = 0`).
    pub fn create_surface(&mut self, width: u32, height: u32, title: &[u8]) -> Option<u64> {
        self.request(
            Opcode::CREATE_SURFACE,
            0,
            &Body::CreateSurface {
                width,
                height,
                format: FORMAT_XRGB8888,
                flags: 0,
                title,
            },
        )?;

        let deadline = now_ns().saturating_add(REQUEST_TIMEOUT_NS);
        for _ in 0..MATCH_TRIES {
            let now = now_ns();
            if now >= deadline {
                return None;
            }
            match self.recv(deadline - now)? {
                Event::SurfaceCreated { surface, .. } => return Some(surface),
                Event::Error { .. } => return None,
                _ => {}
            }
        }
        None
    }

    /// `ALLOC_BUFFER` for `surface`, then map the transferred region.
    ///
    /// The returned [`Buffer`] covers `stride * height` bytes; `width * 4`
    /// gives a tight stride.
    pub fn alloc_buffer(
        &mut self,
        surface: u64,
        width: u32,
        height: u32,
        stride: u32,
    ) -> Option<Buffer> {
        self.request(
            Opcode::ALLOC_BUFFER,
            surface,
            &Body::AllocBuffer {
                width,
                height,
                format: FORMAT_XRGB8888,
                flags: 0,
                stride,
            },
        )?;

        let deadline = now_ns().saturating_add(REQUEST_TIMEOUT_NS);
        for _ in 0..MATCH_TRIES {
            let now = now_ns();
            if now >= deadline {
                return None;
            }
            match self.recv(deadline - now)? {
                Event::BufferCreated {
                    buffer,
                    surface: created_surface,
                    width: created_width,
                    height: created_height,
                    stride: created_stride,
                    region_handle,
                    region_len,
                } => {
                    if created_surface != surface {
                        self.destroy_buffer(buffer);
                        return None;
                    }
                    let required = (created_stride as u64).checked_mul(created_height as u64)?;
                    if region_len < required || region_handle == 0 {
                        self.destroy_buffer(buffer);
                        return None;
                    }
                    let mut addr = 0usize;
                    if call::mem_region_map(region_handle as usize, 0, &mut addr).is_err()
                        || addr == 0
                    {
                        self.destroy_buffer(buffer);
                        return None;
                    }
                    // A.4: the buffer stays `ImportPending` until the client
                    // reports the mapping result. Without this the first commit
                    // would be rejected as BAD_STATE.
                    if !self.import_ok(buffer) {
                        self.destroy_buffer(buffer);
                        return None;
                    }
                    return Some(Buffer {
                        id: buffer,
                        region_handle,
                        addr,
                        len: region_len as usize,
                        stride: created_stride,
                        width: created_width,
                        height: created_height,
                    });
                }
                Event::Error { .. } => return None,
                _ => {}
            }
        }
        None
    }

    /// Commit `buffer` to `surface`.
    ///
    /// `full` requests `FULL_DAMAGE` and ignores `damage`; otherwise `damage`
    /// must hold at most [`MAX_RECTS`] rects with representable extents.
    /// Waits until the matching `ACK` (or `ERROR`) and keeps the last
    /// `FRAME_DONE` seen. A spontaneous `ERROR` (request id 0, e.g. a failed
    /// presentation) is recorded as failure but the wait continues for the
    /// `ACK` that follows it.
    pub fn commit(
        &mut self,
        surface: u64,
        buffer: u64,
        damage: &[Rect],
        full: bool,
        ack_serial: u64,
        commit_id: u64,
    ) -> Option<CommitResult> {
        let mut commit = Commit {
            buffer,
            ack_serial,
            commit_id,
            ..Commit::default()
        };
        if full {
            commit.flags = FLAG_FULL_DAMAGE;
        } else {
            if damage.len() > MAX_RECTS {
                return None;
            }
            for (slot, rect) in damage.iter().enumerate() {
                rect.check_extent().ok()?;
                commit.rects[slot] = *rect;
            }
            commit.rect_count = damage.len() as u16;
        }

        let request = self.request(Opcode::COMMIT, surface, &Body::Commit(commit))?;
        let deadline = now_ns().saturating_add(REQUEST_TIMEOUT_NS);
        let mut result = CommitResult::default();
        let mut failed = false;
        for _ in 0..MATCH_TRIES {
            let now = now_ns();
            if now >= deadline {
                return None;
            }
            let Some((header, event)) = self.frame(deadline - now) else {
                return None;
            };
            match event {
                Event::FrameDone {
                    buffer,
                    commit_id,
                    serial,
                    flags,
                } => {
                    result.frame = Some(FrameDone {
                        buffer,
                        commit_id,
                        serial,
                        flags,
                    });
                }
                Event::BufferRelease { buffer, .. } => result.released = Some(buffer),
                Event::Ack { status, request_id } if request_id == request => {
                    result.acknowledged = status == 0;
                    return if failed { None } else { Some(result) };
                }
                Event::Error { .. } if header.request_id == request => return None,
                Event::Error { .. } => failed = true,
                _ => {}
            }
        }
        None
    }

    /// Report `IMPORT_OK` for `buffer` and wait for its `ACK`.
    fn import_ok(&mut self, buffer: u64) -> bool {
        let Some(request) = self.request(
            Opcode::IMPORT_RESULT,
            buffer,
            &Body::ImportResult { status: IMPORT_OK },
        ) else {
            return false;
        };
        let deadline = now_ns().saturating_add(REQUEST_TIMEOUT_NS);
        for _ in 0..MATCH_TRIES {
            let now = now_ns();
            if now >= deadline {
                return false;
            }
            let Some((header, event)) = self.frame(deadline - now) else {
                return false;
            };
            match event {
                Event::Ack { status, request_id } if request_id == request => return status == 0,
                Event::Error { .. } if header.request_id == request => return false,
                _ => {}
            }
        }
        false
    }

    /// `DESTROY_BUFFER`; returns `true` on `BUFFER_DESTROYED`.
    pub fn destroy_buffer(&mut self, buffer: u64) -> bool {
        let Some(request) = self.request(Opcode::DESTROY_BUFFER, buffer, &Body::DestroyBuffer)
        else {
            return false;
        };
        let deadline = now_ns().saturating_add(REQUEST_TIMEOUT_NS);
        for _ in 0..MATCH_TRIES {
            let now = now_ns();
            if now >= deadline {
                return false;
            }
            let Some((header, _)) = self.frame(deadline - now) else {
                return false;
            };
            if header.opcode == Opcode::BUFFER_DESTROYED.value() && header.object_id == buffer {
                return true;
            }
            if header.opcode == Opcode::ERROR.value() && header.request_id == request {
                return false;
            }
        }
        false
    }

    /// `DESTROY_SURFACE`; returns `true` on `SURFACE_DESTROYED`.
    pub fn destroy_surface(&mut self, surface: u64) -> bool {
        let Some(request) = self.request(Opcode::DESTROY_SURFACE, surface, &Body::DestroySurface)
        else {
            return false;
        };
        let deadline = now_ns().saturating_add(REQUEST_TIMEOUT_NS);
        for _ in 0..MATCH_TRIES {
            let now = now_ns();
            if now >= deadline {
                return false;
            }
            let Some((header, _)) = self.frame(deadline - now) else {
                return false;
            };
            if header.opcode == Opcode::SURFACE_DESTROYED.value() && header.object_id == surface {
                return true;
            }
            if header.opcode == Opcode::ERROR.value() && header.request_id == request {
                return false;
            }
        }
        false
    }

    /// Send `GOODBYE`, unbind the event path and close both ports.
    pub fn close(mut self) {
        let _ = self.request(Opcode::GOODBYE, 0, &Body::Goodbye);
        self.cleanup();
    }

    fn request(&mut self, opcode: Opcode, object_id: u64, body: &Body<'_>) -> Option<u64> {
        let request_id = self.next_request;
        self.next_request = self.next_request.wrapping_add(1).max(1);
        if send_frame(self.server, opcode, object_id, request_id, body) {
            Some(request_id)
        } else {
            None
        }
    }

    /// Wait and return the decoded frame with its header.
    fn frame(&mut self, timeout_ns: u64) -> Option<(Header, Event)> {
        use strat9_syscall::data::{
            WaitSource, WAIT_EVENT_READABLE, WAIT_SOURCE_HANDLE,
        };
        // A port handle is always WRITABLE, so SYS_HANDLE_WAIT would return
        // immediately on an empty queue. Wait for READABLE explicitly.
        let mut source = [WaitSource {
            kind: WAIT_SOURCE_HANDLE,
            events: WAIT_EVENT_READABLE,
            id: self.event as u64,
            revents: 0,
        }];
        match call::handle_wait_many(&mut source, timeout_ns) {
            Ok(_) => {}
            Err(Error::TimedOut | Error::Interrupted | Error::Again) => return None,
            Err(_) => return None,
        }

        let mut msg = IpcMessage::new(0);
        loop {
            match call::ipc_try_recv(self.event, &mut msg) {
                Ok(_) => {
                    if let Some(frame) = decode_frame(&msg.payload) {
                        return Some(frame);
                    }
                }
                Err(Error::Interrupted) => continue,
                Err(Error::Again) => return None,
                Err(_) => return None,
            }
        }
    }

    fn cleanup(&mut self) {
        let _ = call::ipc_unbind_port(&self.path[..self.path_len as usize]);
        close_handle(self.server);
        close_handle(self.event);
    }
}

/// Format `/srv/display/c/<pid>` into `out` without allocating.
pub(crate) fn client_path(pid: u32, out: &mut [u8; CLIENT_PATH_MAX]) -> Option<u8> {
    let mut digits = [0u8; 10];
    let mut count = 0usize;
    let mut value = pid;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }

    let len = CLIENT_PATH_PREFIX.len() + count;
    if len > CLIENT_PATH_MAX {
        return None;
    }
    out[..CLIENT_PATH_PREFIX.len()].copy_from_slice(CLIENT_PATH_PREFIX);
    for index in 0..count {
        out[CLIENT_PATH_PREFIX.len() + index] = digits[count - 1 - index];
    }
    Some(len as u8)
}

/// True when `damage` fits a `width x height` surface and the protocol cap.
pub fn damage_fits(damage: &[Rect], width: u32, height: u32) -> bool {
    if damage.len() > MAX_RECTS {
        return false;
    }
    for rect in damage {
        if rect.x < 0 || rect.y < 0 || rect.w == 0 || rect.h == 0 {
            return false;
        }
        if rect.x as i64 + rect.w as i64 > width as i64
            || rect.y as i64 + rect.h as i64 > height as i64
        {
            return false;
        }
    }
    true
}

/// Encode a complete frame (header + body) into `out`.
fn encode_message(
    opcode: Opcode,
    object_id: u64,
    request_id: u64,
    body: &Body<'_>,
    out: &mut [u8; MAX_MESSAGE],
) -> Option<usize> {
    let body_len = body.encode(&mut out[HEADER_LEN..]).ok()?;
    let total = HEADER_LEN.checked_add(body_len)?;
    if total > MAX_MESSAGE {
        return None;
    }
    Header {
        opcode: opcode.value(),
        flags: 0,
        message_bytes: total as u32,
        object_id,
        request_id,
    }
    .encode(out)
    .ok()?;
    Some(total)
}

/// Send one frame as a `msg_type = 0` IPC payload, retrying `EAGAIN`.
fn send_frame(
    port: usize,
    opcode: Opcode,
    object_id: u64,
    request_id: u64,
    body: &Body<'_>,
) -> bool {
    let mut out = [0u8; MAX_MESSAGE];
    let Some(total) = encode_message(opcode, object_id, request_id, body, &mut out) else {
        return false;
    };
    let mut msg = IpcMessage::new(0);
    msg.payload[..total].copy_from_slice(&out[..total]);
    try_send(port, &msg)
}

fn try_send(port: usize, msg: &IpcMessage) -> bool {
    for _ in 0..SEND_RETRIES {
        match call::ipc_try_send(port, msg) {
            Ok(_) => return true,
            Err(Error::Again | Error::Interrupted) => {
                let _ = call::sched_yield();
            }
            Err(_) => return false,
        }
    }
    false
}

/// Decode one complete frame from a fixed-size IPC payload.
fn decode_frame(payload: &[u8]) -> Option<(Header, Event)> {
    let header = Header::decode(payload).ok()?;
    let total = header.message_bytes as usize;
    if total < HEADER_LEN || total > payload.len() {
        return None;
    }
    let (header, body) = Header::decode_message(&payload[..total]).ok()?;
    let body = Body::decode(header.opcode, header.object_id, body).ok()?;
    let event = map_event(&header, &body);
    Some((header, event))
}

fn map_event(header: &Header, body: &Body<'_>) -> Event {
    match *body {
        Body::Welcome {
            features,
            max_message_bytes,
            session,
            ..
        } => Event::Welcome {
            features,
            max_message_bytes,
            session,
        },
        Body::SurfaceCreated { width, height, .. } => Event::SurfaceCreated {
            surface: header.object_id,
            width,
            height,
        },
        Body::BufferCreated {
            surface,
            width,
            height,
            stride,
            region_len,
            region_handle,
            ..
        } => Event::BufferCreated {
            buffer: header.object_id,
            surface,
            width,
            height,
            stride,
            region_handle,
            region_len,
        },
        Body::Configure {
            serial,
            width,
            height,
            ..
        } => Event::Configure {
            surface: header.object_id,
            serial,
            width,
            height,
        },
        Body::FrameDone {
            buffer,
            commit_id,
            serial,
            flags,
        } => Event::FrameDone {
            buffer,
            commit_id,
            serial,
            flags,
        },
        Body::BufferRelease { commit_id, .. } => Event::BufferRelease {
            buffer: header.object_id,
            commit_id,
        },
        Body::CloseRequest { reason } => Event::CloseRequest {
            surface: header.object_id,
            reason,
        },
        Body::Error { code, .. } => Event::Error {
            code,
            object: header.object_id,
        },
        Body::Ack { status } => Event::Ack {
            status,
            request_id: header.request_id,
        },
        _ => Event::Other,
    }
}

fn now_ns() -> u64 {
    let mut ts = TimeSpec::zero();
    match call::clock_gettime(CLOCK_MONOTONIC, &mut ts) {
        Ok(_) => ts.to_nanos(),
        Err(_) => 0,
    }
}

fn close_handle(handle: usize) {
    let _ = call::handle_close(handle);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn frame(opcode: Opcode, object_id: u64, request_id: u64, body: &Body<'_>) -> Vec<u8> {
        let mut out = [0u8; MAX_MESSAGE];
        let total =
            encode_message(opcode, object_id, request_id, body, &mut out).expect("frame encodes");
        out[..total].to_vec()
    }

    #[test]
    fn path_is_formatted_without_alloc() {
        let mut buf = [0u8; CLIENT_PATH_MAX];
        let len = client_path(0, &mut buf).unwrap();
        assert_eq!(&buf[..len as usize], b"/srv/display/c/0");
        let len = client_path(1234, &mut buf).unwrap();
        assert_eq!(&buf[..len as usize], b"/srv/display/c/1234");
        let len = client_path(u32::MAX, &mut buf).unwrap();
        assert_eq!(&buf[..len as usize], b"/srv/display/c/4294967295");
        assert!(len as usize <= CLIENT_PATH_MAX);
    }

    #[test]
    fn hello_frame_roundtrips_through_header_and_body() {
        let message = frame(
            Opcode::HELLO,
            0,
            7,
            &Body::Hello {
                major: 1,
                minor: 0,
                features: FEATURE_PRESENT_FEEDBACK,
                pid: 42,
                name: b"demo",
                path: b"/srv/display/c/42",
            },
        );
        let (header, body) = Header::decode_message(&message).unwrap();
        assert_eq!(header.opcode, Opcode::HELLO.value());
        assert_eq!(header.message_bytes as usize, message.len());
        assert_eq!(header.request_id, 7);
        assert_eq!(
            Body::decode(header.opcode, header.object_id, body).unwrap(),
            Body::Hello {
                major: 1,
                minor: 0,
                features: FEATURE_PRESENT_FEEDBACK,
                pid: 42,
                name: b"demo",
                path: b"/srv/display/c/42",
            }
        );
    }

    #[test]
    fn import_result_frame_roundtrips() {
        let message = frame(
            Opcode::IMPORT_RESULT,
            6,
            4,
            &Body::ImportResult { status: IMPORT_OK },
        );
        let (header, body) = Header::decode_message(&message).unwrap();
        assert_eq!(header.opcode, Opcode::IMPORT_RESULT.value());
        assert_eq!(header.object_id, 6);
        assert_eq!(header.request_id, 4);
        assert_eq!(
            Body::decode(header.opcode, header.object_id, body).unwrap(),
            Body::ImportResult { status: IMPORT_OK }
        );
    }

    #[test]
    fn welcome_maps_to_owned_event() {
        let message = frame(
            Opcode::WELCOME,
            0,
            9,
            &Body::Welcome {
                major: 1,
                minor: 0,
                features: FEATURE_PRESENT_FEEDBACK,
                max_message_bytes: MAX_MESSAGE_BYTES,
                max_surfaces: 4,
                max_buffers_per_surface: 4,
                max_buffers_per_session: 16,
                pixel_quota_bytes: 8 * 1024 * 1024,
                session: 0x55,
            },
        );
        let (header, event) = decode_frame(&message).unwrap();
        assert_eq!(header.request_id, 9);
        assert_eq!(
            event,
            Event::Welcome {
                features: FEATURE_PRESENT_FEEDBACK,
                max_message_bytes: MAX_MESSAGE_BYTES,
                session: 0x55,
            }
        );
    }

    #[test]
    fn created_and_frame_events_carry_their_object() {
        let message = frame(
            Opcode::SURFACE_CREATED,
            5,
            0,
            &Body::SurfaceCreated {
                width: 320,
                height: 200,
                format: FORMAT_XRGB8888,
            },
        );
        assert_eq!(
            decode_frame(&message).unwrap().1,
            Event::SurfaceCreated {
                surface: 5,
                width: 320,
                height: 200,
            }
        );

        let message = frame(
            Opcode::BUFFER_CREATED,
            6,
            0,
            &Body::BufferCreated {
                surface: 5,
                width: 320,
                height: 200,
                format: FORMAT_XRGB8888,
                stride: 1280,
                region_len: 1280 * 200,
                region_handle: 0x9000,
            },
        );
        assert_eq!(
            decode_frame(&message).unwrap().1,
            Event::BufferCreated {
                buffer: 6,
                surface: 5,
                width: 320,
                height: 200,
                stride: 1280,
                region_handle: 0x9000,
                region_len: 1280 * 200,
            }
        );

        let message = frame(
            Opcode::FRAME_DONE,
            5,
            0,
            &Body::FrameDone {
                buffer: 6,
                commit_id: 3,
                serial: 11,
                flags: FRAME_DONE_PRESENT_SUBMITTED,
            },
        );
        assert_eq!(
            decode_frame(&message).unwrap().1,
            Event::FrameDone {
                buffer: 6,
                commit_id: 3,
                serial: 11,
                flags: FRAME_DONE_PRESENT_SUBMITTED,
            }
        );

        let message = frame(
            Opcode::BUFFER_RELEASE,
            6,
            0,
            &Body::BufferRelease {
                commit_id: 3,
                serial: 11,
            },
        );
        assert_eq!(
            decode_frame(&message).unwrap().1,
            Event::BufferRelease {
                buffer: 6,
                commit_id: 3,
            }
        );
    }

    #[test]
    fn error_ack_and_configure_map() {
        let message = frame(
            Opcode::ERROR,
            6,
            4,
            &Body::Error {
                code: display_protocol::ERROR_BAD_OBJECT,
                detail: &[],
            },
        );
        assert_eq!(
            decode_frame(&message).unwrap().1,
            Event::Error {
                code: display_protocol::ERROR_BAD_OBJECT,
                object: 6,
            }
        );

        let message = frame(Opcode::ACK, 6, 4, &Body::Ack { status: 0 });
        assert_eq!(
            decode_frame(&message).unwrap().1,
            Event::Ack {
                status: 0,
                request_id: 4,
            }
        );

        let message = frame(
            Opcode::CONFIGURE,
            5,
            0,
            &Body::Configure {
                serial: 2,
                width: 640,
                height: 400,
                format: FORMAT_XRGB8888,
                flags: 0,
            },
        );
        assert_eq!(
            decode_frame(&message).unwrap().1,
            Event::Configure {
                surface: 5,
                serial: 2,
                width: 640,
                height: 400,
            }
        );

        let message = frame(
            Opcode::CLOSE_REQUEST,
            5,
            0,
            &Body::CloseRequest {
                reason: display_protocol::CLOSE_REASON_REQUESTED,
            },
        );
        assert_eq!(
            decode_frame(&message).unwrap().1,
            Event::CloseRequest {
                surface: 5,
                reason: display_protocol::CLOSE_REASON_REQUESTED,
            }
        );
    }

    #[test]
    fn unmodelled_and_malformed_frames_are_safe() {
        let message = frame(Opcode::SURFACE_DESTROYED, 5, 0, &Body::SurfaceDestroyed);
        assert_eq!(decode_frame(&message).unwrap().1, Event::Other);

        assert!(decode_frame(&[]).is_none());
        assert!(decode_frame(&[0u8; HEADER_LEN]).is_none());

        let mut bad = frame(Opcode::ACK, 0, 1, &Body::Ack { status: 0 });
        bad[0] = b'X';
        assert!(decode_frame(&bad).is_none());

        let mut short = frame(Opcode::ACK, 0, 1, &Body::Ack { status: 0 });
        short.truncate(HEADER_LEN - 1);
        assert!(decode_frame(&short).is_none());
    }

    #[test]
    fn damage_validation_caps_count_and_bounds() {
        let rect = |x, y, w, h| Rect { x, y, w, h };
        assert!(damage_fits(&[rect(0, 0, 16, 16)], 320, 200));
        assert!(damage_fits(&[rect(304, 184, 16, 16)], 320, 200));
        assert!(damage_fits(&[], 320, 200));

        assert!(!damage_fits(&[rect(305, 0, 16, 16)], 320, 200));
        assert!(!damage_fits(&[rect(0, 185, 16, 16)], 320, 200));
        assert!(!damage_fits(&[rect(-1, 0, 16, 16)], 320, 200));
        assert!(!damage_fits(&[rect(0, 0, 0, 16)], 320, 200));

        let too_many: [Rect; MAX_RECTS + 1] = [rect(0, 0, 1, 1); MAX_RECTS + 1];
        assert!(!damage_fits(&too_many, 320, 200));
    }

    #[test]
    fn commit_encoding_respects_full_and_capacity() {
        // Full damage uses no rects even when damage is supplied.
        let mut commit = Commit {
            buffer: 1,
            flags: FLAG_FULL_DAMAGE,
            ..Commit::default()
        };
        let mut out = [0u8; MAX_MESSAGE];
        let len = Body::Commit(commit).encode(&mut out[HEADER_LEN..]).unwrap();
        assert_eq!(len, 32);
        let decoded = Commit::decode(&out[HEADER_LEN..HEADER_LEN + len]).unwrap();
        assert_eq!(decoded, commit);
        assert!(decoded.is_full_damage());

        // A maximum damage list still fits one datagram.
        commit = Commit::default();
        commit.rect_count = MAX_RECTS as u16;
        let body_len = HEADER_LEN + commit.encoded_len();
        assert!(body_len <= MAX_MESSAGE);
    }

    #[test]
    fn frame_done_present_flag() {
        let done = FrameDone {
            buffer: 1,
            commit_id: 2,
            serial: 3,
            flags: FRAME_DONE_PRESENT_SUBMITTED,
        };
        assert!(done.present_submitted());
        assert!(!FrameDone { flags: 0, ..done }.present_submitted());
    }
}
