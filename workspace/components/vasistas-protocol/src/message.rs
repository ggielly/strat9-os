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

//! Message bodies for every opcode of Annexe A.3.1.
//!
//! [`Body`] borrows strings and pixels from the decoded input, so decoding
//! never allocates. [`Body::encode`] writes into a caller-provided slice and
//! returns the number of bytes written; it never panics on a short slice.
//!
//! ## Enforced invariants
//!
//! - Exact body length: no trailing bytes. Declared-length messages require
//!   `body.len() == fixed + declared`.
//! - Reserved fields must be zero, and flag fields may only use documented
//!   bits (unknown bits yield [`DecodeError::BadFlags`]).
//! - Documented limits (name/path/title/detail, rects, input records, counts,
//!   ranges, formats).
//! - Messages whose primary object is a surface, buffer or output reject
//!   `object_id == 0` with [`DecodeError::BadObject`]. `ACK`/`ERROR` accept
//!   any object, and the connection-scoped messages accept any value (only
//!   the non-zero requirement is enforced, not a zero requirement). The
//!   `GEOMETRY` event is the one surface exception: it carries its surface
//!   without requiring a non-zero `object_id`.
//!
//! ## Resolved ambiguities in A.3.1
//!
//! A.3.1 defines no flag bits for `CONFIGURE.flags` nor for
//! `FRAME_DONE.flags` (it only mentions that `PRESENT_FEEDBACK` is reported
//! when negotiated). Per the general "unknown flag ⇒ `BAD_FLAGS`
//! convention, both fields are therefore required to be zero until the
//! specification defines their bits; `GEOMETRY.flags` (v1 extension) keeps
//! the same rule. This is flagged, not invented.

use crate::commit::Commit;
use crate::constants::*;
use crate::error::DecodeError;
use crate::opcode::{Opcode, FEATURES_KNOWN};

/// One 48-byte `INPUT_BATCH` record.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct InputRecord {
    pub timestamp_ns: u64,
    pub sequence: u64,
    pub device_id: u32,
    pub event_type: u16,
    pub code: u16,
    pub value: i32,
    pub flags: u32,
    /// `TEXT` payload, UTF-8, zero-padded past `value`.
    pub text: [u8; INPUT_TEXT_LEN],
}

impl core::fmt::Debug for InputRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InputRecord")
            .field("timestamp_ns", &self.timestamp_ns)
            .field("sequence", &self.sequence)
            .field("device_id", &self.device_id)
            .field("event_type", &self.event_type)
            .field("code", &self.code)
            .field("value", &self.value)
            .field("flags", &self.flags)
            .field("text_len", &if self.event_type == INPUT_EVENT_TEXT {
                self.value.max(0) as u32
            } else {
                0
            })
            .finish()
    }
}

impl InputRecord {
    /// Validate this record against the A.3.1 record rules.
    pub fn check(&self) -> Result<(), DecodeError> {
        if !(INPUT_EVENT_POINTER_ENTER..=INPUT_EVENT_FOCUS_LOST).contains(&self.event_type) {
            return Err(DecodeError::BadValue);
        }
        let absolute_motion =
            self.event_type == INPUT_EVENT_POINTER_MOTION && self.flags == INPUT_FLAG_ABSOLUTE;
        if self.flags != 0 && !absolute_motion {
            return Err(DecodeError::BadFlags);
        }
        if self.event_type == INPUT_EVENT_TEXT {
            let len = self.value;
            if !(1..=INPUT_TEXT_LEN as i32).contains(&len) {
                return Err(DecodeError::BadValue);
            }
            let len = len as usize;
            if core::str::from_utf8(&self.text[..len]).is_err() {
                return Err(DecodeError::BadValue);
            }
            if self.text[len..].iter().any(|&byte| byte != 0) {
                return Err(DecodeError::BadValue);
            }
        } else if self.text.iter().any(|&byte| byte != 0) {
            // `zéro sinon`: only `TEXT` uses the text area.
            return Err(DecodeError::BadValue);
        }
        if self.event_type == INPUT_EVENT_POINTER_MOTION {
            if self.value < i16::MIN as i32 || self.value > i16::MAX as i32 {
                return Err(DecodeError::Overflow);
            }
        }
        Ok(())
    }
}

/// `INPUT_BATCH` body: fixed record capacity, `count` valid entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InputBatch {
    pub focus_epoch: u32,
    pub count: u16,
    pub records: [InputRecord; MAX_INPUT_RECORDS],
}

impl InputBatch {
    /// The `count` valid records, in wire order.
    pub fn records(&self) -> &[InputRecord] {
        &self.records[..(self.count as usize).min(MAX_INPUT_RECORDS)]
    }

    fn check(&self) -> Result<usize, DecodeError> {
        if self.count as usize > MAX_INPUT_RECORDS {
            return Err(DecodeError::BadValue);
        }
        for record in self.records() {
            record.check()?;
        }
        let len = INPUT_BATCH_FIXED_LEN
            .checked_add(
                (self.count as usize)
                    .checked_mul(INPUT_RECORD_LEN)
                    .ok_or(DecodeError::Overflow)?,
            )
            .ok_or(DecodeError::Overflow)?;
        Ok(len)
    }
}

/// A decoded message body (A.3.1). All variable-length data borrows `'a`.
///
/// `Debug` is deliberately redacted: titles, client names, error details and
/// pixel/input buffers are never printed. Log only the variant name and
/// scalar metadata.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Body<'a> {
    // Requests.
    Hello {
        major: u16,
        minor: u16,
        features: u32,
        /// Client-reported PID. Untrusted: it only seeds the cooperative
        /// `handle_grant` bootstrap, never the session identity.
        pid: u32,
        name: &'a [u8],
        path: &'a [u8],
    },
    Ping {
        cookie: u64,
    },
    Goodbye,
    CreateSurface {
        width: u32,
        height: u32,
        format: u32,
        flags: u32,
        title: &'a [u8],
    },
    DestroySurface,
    SetTitle {
        title: &'a [u8],
    },
    RequestWindowAction {
        action: u32,
    },
    SetCursorShape {
        shape: u32,
    },
    /// Ask the server to move `surface` to a new size. The server answers
    /// with `ACK` then a `CONFIGURE` event whose serial is acknowledged by the
    /// next `COMMIT.ack_serial`.
    RequestResize {
        width: u32,
        height: u32,
        format: u32,
    },
    /// Ask the server to move `surface` to `x`,`y` and resize it. The server
    /// clamps the position; the codec accepts the full `i32` range.
    SetGeometry {
        x: i32,
        y: i32,
        width: u32,
        height: u32,
        format: u32,
    },
    AllocBuffer {
        width: u32,
        height: u32,
        format: u32,
        flags: u32,
        stride: u32,
    },
    ImportResult {
        status: u32,
    },
    DestroyBuffer,
    WriteTile {
        x: u16,
        y: u16,
        w: u16,
        h: u16,
        stride: u32,
        pixels: &'a [u8],
    },
    Commit(Commit),
    UnmapSurface,

    // Events.
    Welcome {
        major: u16,
        minor: u16,
        features: u32,
        max_message_bytes: u32,
        max_surfaces: u16,
        max_buffers_per_surface: u16,
        max_buffers_per_session: u16,
        pixel_quota_bytes: u64,
        session: u64,
    },
    Pong {
        cookie: u64,
    },
    Error {
        code: u32,
        detail: &'a [u8],
    },
    Ack {
        status: u32,
    },
    SurfaceCreated {
        width: u32,
        height: u32,
        format: u32,
    },
    Configure {
        serial: u64,
        width: u32,
        height: u32,
        format: u32,
        flags: u32,
    },
    SurfaceDestroyed,
    CloseRequest {
        reason: u32,
    },
    /// Geometry as applied by the server. `flags` has no defined bits yet.
    Geometry {
        serial: u64,
        x: i32,
        y: i32,
        width: u32,
        height: u32,
        format: u32,
        flags: u32,
    },
    BufferCreated {
        surface: u64,
        width: u32,
        height: u32,
        format: u32,
        stride: u32,
        region_len: u64,
        region_handle: u64,
    },
    BufferRelease {
        commit_id: u64,
        serial: u64,
    },
    BufferDestroyed,
    FrameDone {
        buffer: u64,
        commit_id: u64,
        serial: u64,
        flags: u32,
    },
    InputBatch(InputBatch),
    InputReset {
        focus_epoch: u32,
        reason: u32,
    },
    OutputInfo {
        width: u32,
        height: u32,
        stride: u32,
        format: u32,
        scale: u32,
    },
    OutputRemoved,
}

impl core::fmt::Debug for Body<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Body::Hello { major, minor, features, pid, name, path } => f
                .debug_struct("Hello")
                .field("major", major)
                .field("minor", minor)
                .field("features", features)
                .field("pid", pid)
                .field("name_len", &name.len())
                .field("path_len", &path.len())
                .finish(),
            Body::Ping { cookie } => f.debug_struct("Ping").field("cookie", cookie).finish(),
            Body::Goodbye => f.write_str("Goodbye"),
            Body::CreateSurface { width, height, format, flags, title } => f
                .debug_struct("CreateSurface")
                .field("width", width)
                .field("height", height)
                .field("format", format)
                .field("flags", flags)
                .field("title_len", &title.len())
                .finish(),
            Body::DestroySurface => f.write_str("DestroySurface"),
            Body::SetTitle { title } => f
                .debug_struct("SetTitle")
                .field("title_len", &title.len())
                .finish(),
            Body::RequestWindowAction { action } => f
                .debug_struct("RequestWindowAction")
                .field("action", action)
                .finish(),
            Body::SetCursorShape { shape } => f
                .debug_struct("SetCursorShape")
                .field("shape", shape)
                .finish(),
            Body::RequestResize {
                width,
                height,
                format,
            } => f
                .debug_struct("RequestResize")
                .field("width", width)
                .field("height", height)
                .field("format", format)
                .finish(),
            Body::SetGeometry { x, y, width, height, format } => f
                .debug_struct("SetGeometry")
                .field("x", x)
                .field("y", y)
                .field("width", width)
                .field("height", height)
                .field("format", format)
                .finish(),
            Body::AllocBuffer { width, height, format, flags, stride } => f
                .debug_struct("AllocBuffer")
                .field("width", width)
                .field("height", height)
                .field("format", format)
                .field("flags", flags)
                .field("stride", stride)
                .finish(),
            Body::ImportResult { status } => f
                .debug_struct("ImportResult")
                .field("status", status)
                .finish(),
            Body::DestroyBuffer => f.write_str("DestroyBuffer"),
            Body::WriteTile { x, y, w, h, stride, pixels } => f
                .debug_struct("WriteTile")
                .field("x", x)
                .field("y", y)
                .field("w", w)
                .field("h", h)
                .field("stride", stride)
                .field("pixels_len", &pixels.len())
                .finish(),
            Body::Commit(commit) => f.debug_tuple("Commit").field(commit).finish(),
            Body::UnmapSurface => f.write_str("UnmapSurface"),
            Body::Welcome { major, minor, features, max_message_bytes, max_surfaces, max_buffers_per_surface, max_buffers_per_session, pixel_quota_bytes, session } => f
                .debug_struct("Welcome")
                .field("major", major)
                .field("minor", minor)
                .field("features", features)
                .field("max_message_bytes", max_message_bytes)
                .field("max_surfaces", max_surfaces)
                .field("max_buffers_per_surface", max_buffers_per_surface)
                .field("max_buffers_per_session", max_buffers_per_session)
                .field("pixel_quota_bytes", pixel_quota_bytes)
                .field("session", session)
                .finish(),
            Body::Pong { cookie } => f.debug_struct("Pong").field("cookie", cookie).finish(),
            Body::Error { code, detail } => f
                .debug_struct("Error")
                .field("code", code)
                .field("detail_len", &detail.len())
                .finish(),
            Body::Ack { status } => f.debug_struct("Ack").field("status", status).finish(),
            Body::SurfaceCreated { width, height, format } => f
                .debug_struct("SurfaceCreated")
                .field("width", width)
                .field("height", height)
                .field("format", format)
                .finish(),
            Body::Configure { serial, width, height, format, flags } => f
                .debug_struct("Configure")
                .field("serial", serial)
                .field("width", width)
                .field("height", height)
                .field("format", format)
                .field("flags", flags)
                .finish(),
            Body::SurfaceDestroyed => f.write_str("SurfaceDestroyed"),
            Body::CloseRequest { reason } => f
                .debug_struct("CloseRequest")
                .field("reason", reason)
                .finish(),
            Body::Geometry { serial, x, y, width, height, format, flags } => f
                .debug_struct("Geometry")
                .field("serial", serial)
                .field("x", x)
                .field("y", y)
                .field("width", width)
                .field("height", height)
                .field("format", format)
                .field("flags", flags)
                .finish(),
            Body::BufferCreated { surface, width, height, format, stride, region_len, region_handle } => f
                .debug_struct("BufferCreated")
                .field("surface", surface)
                .field("width", width)
                .field("height", height)
                .field("format", format)
                .field("stride", stride)
                .field("region_len", region_len)
                .field("region_handle", region_handle)
                .finish(),
            Body::BufferRelease { commit_id, serial } => f
                .debug_struct("BufferRelease")
                .field("commit_id", commit_id)
                .field("serial", serial)
                .finish(),
            Body::BufferDestroyed => f.write_str("BufferDestroyed"),
            Body::FrameDone { buffer, commit_id, serial, flags } => f
                .debug_struct("FrameDone")
                .field("buffer", buffer)
                .field("commit_id", commit_id)
                .field("serial", serial)
                .field("flags", flags)
                .finish(),
            Body::InputBatch(batch) => f.debug_tuple("InputBatch").field(batch).finish(),
            Body::InputReset { focus_epoch, reason } => f
                .debug_struct("InputReset")
                .field("focus_epoch", focus_epoch)
                .field("reason", reason)
                .finish(),
            Body::OutputInfo { width, height, stride, format, scale } => f
                .debug_struct("OutputInfo")
                .field("width", width)
                .field("height", height)
                .field("stride", stride)
                .field("format", format)
                .field("scale", scale)
                .finish(),
            Body::OutputRemoved => f.write_str("OutputRemoved"),
        }
    }
}

// ---------------------------------------------------------------------------
// Byte helpers. Every helper is only called after a length check.
// ---------------------------------------------------------------------------

fn rd16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn rd32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn rd64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        bytes[at],
        bytes[at + 1],
        bytes[at + 2],
        bytes[at + 3],
        bytes[at + 4],
        bytes[at + 5],
        bytes[at + 6],
        bytes[at + 7],
    ])
}

fn wr16(out: &mut [u8], at: usize, value: u16) {
    out[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn wr32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn wr64(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// Require at least `len` bytes (fixed fields / prefix reads).
fn need(bytes: &[u8], len: usize) -> Result<(), DecodeError> {
    if bytes.len() < len {
        Err(DecodeError::Truncated)
    } else {
        Ok(())
    }
}

/// Require the body to be exactly `expected` bytes.
fn exact(bytes: &[u8], expected: usize) -> Result<(), DecodeError> {
    if bytes.len() < expected {
        Err(DecodeError::Truncated)
    } else if bytes.len() > expected {
        Err(DecodeError::SizeMismatch)
    } else {
        Ok(())
    }
}

/// Require `out` to hold at least `len` bytes.
fn ensure(out: &[u8], len: usize) -> Result<(), DecodeError> {
    if out.len() < len {
        Err(DecodeError::Truncated)
    } else {
        Ok(())
    }
}

fn require_object(object_id: u64) -> Result<(), DecodeError> {
    if object_id == 0 {
        Err(DecodeError::BadObject)
    } else {
        Ok(())
    }
}

/// Validate flags: only `allowed` bits may be set.
fn check_flags(flags: u32, allowed: u32) -> Result<(), DecodeError> {
    if flags & !allowed != 0 {
        Err(DecodeError::BadFlags)
    } else {
        Ok(())
    }
}

fn check_reserved16(bytes: &[u8], at: usize) -> Result<(), DecodeError> {
    if rd16(bytes, at) != 0 {
        Err(DecodeError::ReservedNonZero)
    } else {
        Ok(())
    }
}

fn check_reserved32(bytes: &[u8], at: usize) -> Result<(), DecodeError> {
    if rd32(bytes, at) != 0 {
        Err(DecodeError::ReservedNonZero)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Body decoding / encoding.
// ---------------------------------------------------------------------------

impl<'a> Body<'a> {
    /// Decode `body` (header excluded) for `opcode`, bound to `object_id`.
    pub fn decode(opcode: u16, object_id: u64, body: &'a [u8]) -> Result<Body<'a>, DecodeError> {
        match Opcode(opcode) {
            Opcode::HELLO => {
                need(body, 16)?;
                let features = rd32(body, 4);
                if features & !FEATURES_KNOWN != 0 {
                    return Err(DecodeError::BadFlags);
                }
                let name_len = rd16(body, 12) as usize;
                let path_len = rd16(body, 14) as usize;
                if name_len > MAX_NAME || path_len > MAX_PATH {
                    return Err(DecodeError::BadValue);
                }
                let expected = 16usize
                    .checked_add(name_len)
                    .and_then(|len| len.checked_add(path_len))
                    .ok_or(DecodeError::Overflow)?;
                exact(body, expected)?;
                Ok(Body::Hello {
                    major: rd16(body, 0),
                    minor: rd16(body, 2),
                    features,
                    pid: rd32(body, 8),
                    name: &body[16..16 + name_len],
                    path: &body[16 + name_len..expected],
                })
            }
            Opcode::PING => {
                exact(body, 8)?;
                Ok(Body::Ping { cookie: rd64(body, 0) })
            }
            Opcode::GOODBYE => {
                exact(body, 0)?;
                Ok(Body::Goodbye)
            }
            Opcode::CREATE_SURFACE => {
                need(body, 20)?;
                check_reserved16(body, 18)?;
                let flags = rd32(body, 12);
                check_flags(flags, 0)?;
                let width = rd32(body, 0);
                let height = rd32(body, 4);
                if !(1..=MAX_SURFACE_DIM).contains(&width) || !(1..=MAX_SURFACE_DIM).contains(&height)
                {
                    return Err(DecodeError::BadValue);
                }
                if rd32(body, 8) != FORMAT_XRGB8888 {
                    return Err(DecodeError::BadValue);
                }
                let title = string(body, 20, rd16(body, 16) as usize, MAX_TITLE)?;
                Ok(Body::CreateSurface {
                    width,
                    height,
                    format: FORMAT_XRGB8888,
                    flags,
                    title,
                })
            }
            Opcode::DESTROY_SURFACE => {
                require_object(object_id)?;
                exact(body, 0)?;
                Ok(Body::DestroySurface)
            }
            Opcode::SET_TITLE => {
                require_object(object_id)?;
                need(body, 4)?;
                check_reserved16(body, 2)?;
                let title = string(body, 4, rd16(body, 0) as usize, MAX_TITLE)?;
                Ok(Body::SetTitle { title })
            }
            Opcode::REQUEST_WINDOW_ACTION => {
                require_object(object_id)?;
                exact(body, 8)?;
                check_reserved32(body, 4)?;
                let action = rd32(body, 0);
                if !(WINDOW_ACTION_MINIMIZE..=WINDOW_ACTION_LOWER).contains(&action) {
                    return Err(DecodeError::BadValue);
                }
                Ok(Body::RequestWindowAction { action })
            }
            Opcode::SET_CURSOR_SHAPE => {
                exact(body, 8)?;
                check_reserved32(body, 4)?;
                let shape = rd32(body, 0);
                if !(CURSOR_SHAPE_DEFAULT..=CURSOR_SHAPE_POINTER).contains(&shape) {
                    return Err(DecodeError::BadValue);
                }
                Ok(Body::SetCursorShape { shape })
            }
            Opcode::REQUEST_RESIZE => {
                require_object(object_id)?;
                exact(body, 16)?;
                check_reserved32(body, 12)?;
                let width = rd32(body, 0);
                let height = rd32(body, 4);
                if !(1..=MAX_SURFACE_DIM).contains(&width) || !(1..=MAX_SURFACE_DIM).contains(&height)
                {
                    return Err(DecodeError::BadValue);
                }
                if rd32(body, 8) != FORMAT_XRGB8888 {
                    return Err(DecodeError::BadValue);
                }
                Ok(Body::RequestResize {
                    width,
                    height,
                    format: FORMAT_XRGB8888,
                })
            }
            Opcode::SET_GEOMETRY => {
                require_object(object_id)?;
                exact(body, 24)?;
                check_reserved32(body, 20)?;
                let width = rd32(body, 8);
                let height = rd32(body, 12);
                if !(1..=MAX_SURFACE_DIM).contains(&width) || !(1..=MAX_SURFACE_DIM).contains(&height)
                {
                    return Err(DecodeError::BadValue);
                }
                if rd32(body, 16) != FORMAT_XRGB8888 {
                    return Err(DecodeError::BadValue);
                }
                Ok(Body::SetGeometry {
                    x: rd32(body, 0) as i32,
                    y: rd32(body, 4) as i32,
                    width,
                    height,
                    format: FORMAT_XRGB8888,
                })
            }
            Opcode::ALLOC_BUFFER => {
                require_object(object_id)?;
                exact(body, 24)?;
                check_reserved32(body, 20)?;
                let width = rd32(body, 0);
                let height = rd32(body, 4);
                let flags = rd32(body, 12);
                check_flags(flags, 0)?;
                if width == 0 || height == 0 {
                    return Err(DecodeError::BadValue);
                }
                if rd32(body, 8) != FORMAT_XRGB8888 {
                    return Err(DecodeError::BadValue);
                }
                let stride = rd32(body, 16);
                if (stride as u64) < (width as u64) * 4 || stride % 4 != 0 {
                    return Err(DecodeError::BadValue);
                }
                Ok(Body::AllocBuffer {
                    width,
                    height,
                    format: FORMAT_XRGB8888,
                    flags,
                    stride,
                })
            }
            Opcode::IMPORT_RESULT => {
                require_object(object_id)?;
                exact(body, 8)?;
                check_reserved32(body, 4)?;
                let status = rd32(body, 0);
                if status != IMPORT_OK && status != IMPORT_FAILED {
                    return Err(DecodeError::BadValue);
                }
                Ok(Body::ImportResult { status })
            }
            Opcode::DESTROY_BUFFER => {
                require_object(object_id)?;
                exact(body, 0)?;
                Ok(Body::DestroyBuffer)
            }
            Opcode::WRITE_TILE => {
                require_object(object_id)?;
                need(body, 16)?;
                let flags = rd32(body, 12);
                check_flags(flags, 0)?;
                let x = rd16(body, 0);
                let y = rd16(body, 2);
                let w = rd16(body, 4);
                let h = rd16(body, 6);
                let stride = rd32(body, 8);
                if w == 0 || h == 0 {
                    return Err(DecodeError::BadValue);
                }
                if (stride as u64) < (w as u64) * 4 || stride % 4 != 0 {
                    return Err(DecodeError::BadValue);
                }
                let expected = (stride as u64)
                    .checked_mul(h as u64)
                    .and_then(|len| len.checked_add(16))
                    .ok_or(DecodeError::Overflow)?;
                if expected > usize::MAX as u64 {
                    return Err(DecodeError::Overflow);
                }
                exact(body, expected as usize)?;
                Ok(Body::WriteTile {
                    x,
                    y,
                    w,
                    h,
                    stride,
                    pixels: &body[16..],
                })
            }
            Opcode::COMMIT => {
                require_object(object_id)?;
                Ok(Body::Commit(Commit::decode(body)?))
            }
            Opcode::UNMAP_SURFACE => {
                require_object(object_id)?;
                exact(body, 0)?;
                Ok(Body::UnmapSurface)
            }
            Opcode::WELCOME => {
                exact(body, 36)?;
                check_reserved16(body, 18)?;
                let max_message_bytes = rd32(body, 8);
                if max_message_bytes != MAX_MESSAGE_BYTES {
                    return Err(DecodeError::BadValue);
                }
                Ok(Body::Welcome {
                    major: rd16(body, 0),
                    minor: rd16(body, 2),
                    features: rd32(body, 4),
                    max_message_bytes,
                    max_surfaces: rd16(body, 12),
                    max_buffers_per_surface: rd16(body, 14),
                    max_buffers_per_session: rd16(body, 16),
                    pixel_quota_bytes: rd64(body, 20),
                    session: rd64(body, 28),
                })
            }
            Opcode::PONG => {
                exact(body, 8)?;
                Ok(Body::Pong { cookie: rd64(body, 0) })
            }
            Opcode::ERROR => {
                need(body, 12)?;
                check_reserved32(body, 4)?;
                check_reserved16(body, 10)?;
                let code = rd32(body, 0);
                if !(ERROR_BAD_FLAGS..=ERROR_INTERNAL).contains(&code) {
                    return Err(DecodeError::BadValue);
                }
                let detail = string(body, 12, rd16(body, 8) as usize, MAX_ERROR_DETAIL)?;
                Ok(Body::Error { code, detail })
            }
            Opcode::ACK => {
                exact(body, 8)?;
                check_reserved32(body, 4)?;
                Ok(Body::Ack { status: rd32(body, 0) })
            }
            Opcode::SURFACE_CREATED => {
                require_object(object_id)?;
                exact(body, 16)?;
                check_reserved32(body, 12)?;
                Ok(Body::SurfaceCreated {
                    width: rd32(body, 0),
                    height: rd32(body, 4),
                    format: rd32(body, 8),
                })
            }
            Opcode::CONFIGURE => {
                require_object(object_id)?;
                exact(body, 24)?;
                let flags = rd32(body, 20);
                check_flags(flags, 0)?;
                Ok(Body::Configure {
                    serial: rd64(body, 0),
                    width: rd32(body, 8),
                    height: rd32(body, 12),
                    format: rd32(body, 16),
                    flags,
                })
            }
            Opcode::SURFACE_DESTROYED => {
                require_object(object_id)?;
                exact(body, 0)?;
                Ok(Body::SurfaceDestroyed)
            }
            Opcode::CLOSE_REQUEST => {
                require_object(object_id)?;
                exact(body, 8)?;
                check_reserved32(body, 4)?;
                let reason = rd32(body, 0);
                if !(CLOSE_REASON_REQUESTED..=CLOSE_REASON_SHUTDOWN).contains(&reason) {
                    return Err(DecodeError::BadValue);
                }
                Ok(Body::CloseRequest { reason })
            }
            // No require_object: the event carries its surface, zero or not.
            Opcode::GEOMETRY => {
                exact(body, 32)?;
                let flags = rd32(body, 28);
                check_flags(flags, 0)?;
                Ok(Body::Geometry {
                    serial: rd64(body, 0),
                    x: rd32(body, 8) as i32,
                    y: rd32(body, 12) as i32,
                    width: rd32(body, 16),
                    height: rd32(body, 20),
                    format: rd32(body, 24),
                    flags,
                })
            }
            Opcode::BUFFER_CREATED => {
                require_object(object_id)?;
                exact(body, 40)?;
                let height = rd32(body, 12);
                let stride = rd32(body, 20);
                let region_len = rd64(body, 24);
                let required = (stride as u64)
                    .checked_mul(height as u64)
                    .ok_or(DecodeError::Overflow)?;
                if region_len < required {
                    return Err(DecodeError::BadValue);
                }
                Ok(Body::BufferCreated {
                    surface: rd64(body, 0),
                    width: rd32(body, 8),
                    height,
                    format: rd32(body, 16),
                    stride,
                    region_len,
                    region_handle: rd64(body, 32),
                })
            }
            Opcode::BUFFER_RELEASE => {
                require_object(object_id)?;
                exact(body, 16)?;
                Ok(Body::BufferRelease {
                    commit_id: rd64(body, 0),
                    serial: rd64(body, 8),
                })
            }
            Opcode::BUFFER_DESTROYED => {
                require_object(object_id)?;
                exact(body, 0)?;
                Ok(Body::BufferDestroyed)
            }
            Opcode::FRAME_DONE => {
                require_object(object_id)?;
                exact(body, 32)?;
                check_reserved32(body, 28)?;
                let flags = rd32(body, 24);
                check_flags(flags, crate::constants::FRAME_DONE_PRESENT_SUBMITTED)?;
                Ok(Body::FrameDone {
                    buffer: rd64(body, 0),
                    commit_id: rd64(body, 8),
                    serial: rd64(body, 16),
                    flags,
                })
            }
            Opcode::INPUT_BATCH => {
                require_object(object_id)?;
                need(body, INPUT_BATCH_FIXED_LEN)?;
                check_reserved16(body, 2)?;
                let count = rd16(body, 0);
                if count as usize > MAX_INPUT_RECORDS {
                    return Err(DecodeError::BadValue);
                }
                let expected = INPUT_BATCH_FIXED_LEN
                    .checked_add(
                        (count as usize)
                            .checked_mul(INPUT_RECORD_LEN)
                            .ok_or(DecodeError::Overflow)?,
                    )
                    .ok_or(DecodeError::Overflow)?;
                exact(body, expected)?;

                let mut records = [InputRecord::default(); MAX_INPUT_RECORDS];
                for (index, record) in records.iter_mut().enumerate().take(count as usize) {
                    let at = INPUT_BATCH_FIXED_LEN + index * INPUT_RECORD_LEN;
                    let mut text = [0u8; INPUT_TEXT_LEN];
                    text.copy_from_slice(&body[at + 32..at + 32 + INPUT_TEXT_LEN]);
                    let decoded = InputRecord {
                        timestamp_ns: rd64(body, at),
                        sequence: rd64(body, at + 8),
                        device_id: rd32(body, at + 16),
                        event_type: rd16(body, at + 20),
                        code: rd16(body, at + 22),
                        value: rd32(body, at + 24) as i32,
                        flags: rd32(body, at + 28),
                        text,
                    };
                    decoded.check()?;
                    *record = decoded;
                }
                Ok(Body::InputBatch(InputBatch {
                    focus_epoch: rd32(body, 4),
                    count,
                    records,
                }))
            }
            Opcode::INPUT_RESET => {
                require_object(object_id)?;
                exact(body, 8)?;
                let reason = rd32(body, 4);
                if !(INPUT_RESET_RESYNC..=INPUT_RESET_SERVICE_CHANGED).contains(&reason) {
                    return Err(DecodeError::BadValue);
                }
                Ok(Body::InputReset {
                    focus_epoch: rd32(body, 0),
                    reason,
                })
            }
            Opcode::OUTPUT_INFO => {
                require_object(object_id)?;
                exact(body, 24)?;
                check_reserved32(body, 20)?;
                if rd32(body, 12) != FORMAT_XRGB8888 {
                    return Err(DecodeError::BadValue);
                }
                Ok(Body::OutputInfo {
                    width: rd32(body, 0),
                    height: rd32(body, 4),
                    stride: rd32(body, 8),
                    format: FORMAT_XRGB8888,
                    scale: rd32(body, 16),
                })
            }
            Opcode::OUTPUT_REMOVED => {
                require_object(object_id)?;
                exact(body, 0)?;
                Ok(Body::OutputRemoved)
            }
            _ => Err(DecodeError::UnknownOpcode),
        }
    }

    /// Encode this body into `out`, returning the number of bytes written.
    ///
    /// All decode-time invariants are re-checked; a short `out` yields
    /// [`DecodeError::Truncated`] and writes nothing.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, DecodeError> {
        match self {
            Body::Hello {
                major,
                minor,
                features,
                pid,
                name,
                path,
            } => {
                check_flags(*features, FEATURES_KNOWN)?;
                let len = string_len(16, name.len(), MAX_NAME)?;
                let len = string_len(len, path.len(), MAX_PATH)?;
                ensure(out, len)?;
                wr16(out, 0, *major);
                wr16(out, 2, *minor);
                wr32(out, 4, *features);
                wr32(out, 8, *pid);
                wr16(out, 12, name.len() as u16);
                wr16(out, 14, path.len() as u16);
                out[16..16 + name.len()].copy_from_slice(name);
                out[16 + name.len()..len].copy_from_slice(path);
                Ok(len)
            }
            Body::Ping { cookie } => {
                ensure(out, 8)?;
                wr64(out, 0, *cookie);
                Ok(8)
            }
            Body::Goodbye => Ok(0),
            Body::CreateSurface {
                width,
                height,
                format,
                flags,
                title,
            } => {
                check_flags(*flags, 0)?;
                if !(1..=MAX_SURFACE_DIM).contains(width) || !(1..=MAX_SURFACE_DIM).contains(height)
                {
                    return Err(DecodeError::BadValue);
                }
                if *format != FORMAT_XRGB8888 {
                    return Err(DecodeError::BadValue);
                }
                let len = string_len(20, title.len(), MAX_TITLE)?;
                ensure(out, len)?;
                wr32(out, 0, *width);
                wr32(out, 4, *height);
                wr32(out, 8, *format);
                wr32(out, 12, *flags);
                wr16(out, 16, title.len() as u16);
                wr16(out, 18, 0);
                out[20..len].copy_from_slice(title);
                Ok(len)
            }
            Body::DestroySurface => Ok(0),
            Body::SetTitle { title } => {
                let len = string_len(4, title.len(), MAX_TITLE)?;
                ensure(out, len)?;
                wr16(out, 0, title.len() as u16);
                wr16(out, 2, 0);
                out[4..len].copy_from_slice(title);
                Ok(len)
            }
            Body::RequestWindowAction { action } => {
                if !(WINDOW_ACTION_MINIMIZE..=WINDOW_ACTION_LOWER).contains(action) {
                    return Err(DecodeError::BadValue);
                }
                ensure(out, 8)?;
                wr32(out, 0, *action);
                wr32(out, 4, 0);
                Ok(8)
            }
            Body::SetCursorShape { shape } => {
                if !(CURSOR_SHAPE_DEFAULT..=CURSOR_SHAPE_POINTER).contains(shape) {
                    return Err(DecodeError::BadValue);
                }
                ensure(out, 8)?;
                wr32(out, 0, *shape);
                wr32(out, 4, 0);
                Ok(8)
            }
            Body::RequestResize {
                width,
                height,
                format,
            } => {
                if !(1..=MAX_SURFACE_DIM).contains(width)
                    || !(1..=MAX_SURFACE_DIM).contains(height)
                    || *format != FORMAT_XRGB8888
                {
                    return Err(DecodeError::BadValue);
                }
                ensure(out, 16)?;
                wr32(out, 0, *width);
                wr32(out, 4, *height);
                wr32(out, 8, *format);
                wr32(out, 12, 0);
                Ok(16)
            }
            Body::SetGeometry {
                x,
                y,
                width,
                height,
                format,
            } => {
                if !(1..=MAX_SURFACE_DIM).contains(width)
                    || !(1..=MAX_SURFACE_DIM).contains(height)
                    || *format != FORMAT_XRGB8888
                {
                    return Err(DecodeError::BadValue);
                }
                ensure(out, 24)?;
                wr32(out, 0, *x as u32);
                wr32(out, 4, *y as u32);
                wr32(out, 8, *width);
                wr32(out, 12, *height);
                wr32(out, 16, *format);
                wr32(out, 20, 0);
                Ok(24)
            }
            Body::AllocBuffer {
                width,
                height,
                format,
                flags,
                stride,
            } => {
                check_flags(*flags, 0)?;
                if *width == 0 || *height == 0 {
                    return Err(DecodeError::BadValue);
                }
                if *format != FORMAT_XRGB8888 {
                    return Err(DecodeError::BadValue);
                }
                if (*stride as u64) < (*width as u64) * 4 || *stride % 4 != 0 {
                    return Err(DecodeError::BadValue);
                }
                ensure(out, 24)?;
                wr32(out, 0, *width);
                wr32(out, 4, *height);
                wr32(out, 8, *format);
                wr32(out, 12, *flags);
                wr32(out, 16, *stride);
                wr32(out, 20, 0);
                Ok(24)
            }
            Body::ImportResult { status } => {
                if *status != IMPORT_OK && *status != IMPORT_FAILED {
                    return Err(DecodeError::BadValue);
                }
                ensure(out, 8)?;
                wr32(out, 0, *status);
                wr32(out, 4, 0);
                Ok(8)
            }
            Body::DestroyBuffer => Ok(0),
            Body::WriteTile {
                x,
                y,
                w,
                h,
                stride,
                pixels,
            } => {
                if *w == 0 || *h == 0 {
                    return Err(DecodeError::BadValue);
                }
                if (*stride as u64) < (*w as u64) * 4 || *stride % 4 != 0 {
                    return Err(DecodeError::BadValue);
                }
                let expected = (*stride as u64)
                    .checked_mul(*h as u64)
                    .and_then(|len| len.checked_add(16))
                    .ok_or(DecodeError::Overflow)?;
                if expected > usize::MAX as u64 {
                    return Err(DecodeError::Overflow);
                }
                let len = expected as usize;
                if pixels.len() != len - 16 {
                    return Err(DecodeError::SizeMismatch);
                }
                ensure(out, len)?;
                wr16(out, 0, *x);
                wr16(out, 2, *y);
                wr16(out, 4, *w);
                wr16(out, 6, *h);
                wr32(out, 8, *stride);
                wr32(out, 12, 0);
                out[16..len].copy_from_slice(pixels);
                Ok(len)
            }
            Body::Commit(commit) => {
                let len = commit.encoded_len();
                ensure(out, len)?;
                commit.encode(out)?;
                Ok(len)
            }
            Body::UnmapSurface => Ok(0),
            Body::Welcome {
                major,
                minor,
                features,
                max_message_bytes,
                max_surfaces,
                max_buffers_per_surface,
                max_buffers_per_session,
                pixel_quota_bytes,
                session,
            } => {
                if *max_message_bytes != MAX_MESSAGE_BYTES {
                    return Err(DecodeError::BadValue);
                }
                ensure(out, 36)?;
                wr16(out, 0, *major);
                wr16(out, 2, *minor);
                wr32(out, 4, *features);
                wr32(out, 8, *max_message_bytes);
                wr16(out, 12, *max_surfaces);
                wr16(out, 14, *max_buffers_per_surface);
                wr16(out, 16, *max_buffers_per_session);
                wr16(out, 18, 0);
                wr64(out, 20, *pixel_quota_bytes);
                wr64(out, 28, *session);
                Ok(36)
            }
            Body::Pong { cookie } => {
                ensure(out, 8)?;
                wr64(out, 0, *cookie);
                Ok(8)
            }
            Body::Error { code, detail } => {
                if !(ERROR_BAD_FLAGS..=ERROR_INTERNAL).contains(code) {
                    return Err(DecodeError::BadValue);
                }
                let len = string_len(12, detail.len(), MAX_ERROR_DETAIL)?;
                ensure(out, len)?;
                wr32(out, 0, *code);
                wr32(out, 4, 0);
                wr16(out, 8, detail.len() as u16);
                wr16(out, 10, 0);
                out[12..len].copy_from_slice(detail);
                Ok(len)
            }
            Body::Ack { status } => {
                ensure(out, 8)?;
                wr32(out, 0, *status);
                wr32(out, 4, 0);
                Ok(8)
            }
            Body::SurfaceCreated {
                width,
                height,
                format,
            } => {
                ensure(out, 16)?;
                wr32(out, 0, *width);
                wr32(out, 4, *height);
                wr32(out, 8, *format);
                wr32(out, 12, 0);
                Ok(16)
            }
            Body::Configure {
                serial,
                width,
                height,
                format,
                flags,
            } => {
                check_flags(*flags, 0)?;
                ensure(out, 24)?;
                wr64(out, 0, *serial);
                wr32(out, 8, *width);
                wr32(out, 12, *height);
                wr32(out, 16, *format);
                wr32(out, 20, *flags);
                Ok(24)
            }
            Body::SurfaceDestroyed => Ok(0),
            Body::CloseRequest { reason } => {
                if !(CLOSE_REASON_REQUESTED..=CLOSE_REASON_SHUTDOWN).contains(reason) {
                    return Err(DecodeError::BadValue);
                }
                ensure(out, 8)?;
                wr32(out, 0, *reason);
                wr32(out, 4, 0);
                Ok(8)
            }
            Body::Geometry {
                serial,
                x,
                y,
                width,
                height,
                format,
                flags,
            } => {
                check_flags(*flags, 0)?;
                ensure(out, 32)?;
                wr64(out, 0, *serial);
                wr32(out, 8, *x as u32);
                wr32(out, 12, *y as u32);
                wr32(out, 16, *width);
                wr32(out, 20, *height);
                wr32(out, 24, *format);
                wr32(out, 28, *flags);
                Ok(32)
            }
            Body::BufferCreated {
                surface,
                width,
                height,
                format,
                stride,
                region_len,
                region_handle,
            } => {
                let required = (*stride as u64)
                    .checked_mul(*height as u64)
                    .ok_or(DecodeError::Overflow)?;
                if *region_len < required {
                    return Err(DecodeError::BadValue);
                }
                ensure(out, 40)?;
                wr64(out, 0, *surface);
                wr32(out, 8, *width);
                wr32(out, 12, *height);
                wr32(out, 16, *format);
                wr32(out, 20, *stride);
                wr64(out, 24, *region_len);
                wr64(out, 32, *region_handle);
                Ok(40)
            }
            Body::BufferRelease { commit_id, serial } => {
                ensure(out, 16)?;
                wr64(out, 0, *commit_id);
                wr64(out, 8, *serial);
                Ok(16)
            }
            Body::BufferDestroyed => Ok(0),
            Body::FrameDone {
                buffer,
                commit_id,
                serial,
                flags,
            } => {
                check_flags(*flags, crate::constants::FRAME_DONE_PRESENT_SUBMITTED)?;
                ensure(out, 32)?;
                wr64(out, 0, *buffer);
                wr64(out, 8, *commit_id);
                wr64(out, 16, *serial);
                wr32(out, 24, *flags);
                wr32(out, 28, 0);
                Ok(32)
            }
            Body::InputBatch(batch) => {
                let len = batch.check()?;
                ensure(out, len)?;
                wr16(out, 0, batch.count);
                wr16(out, 2, 0);
                wr32(out, 4, batch.focus_epoch);
                for (index, record) in batch.records().iter().enumerate() {
                    let at = INPUT_BATCH_FIXED_LEN + index * INPUT_RECORD_LEN;
                    wr64(out, at, record.timestamp_ns);
                    wr64(out, at + 8, record.sequence);
                    wr32(out, at + 16, record.device_id);
                    wr16(out, at + 20, record.event_type);
                    wr16(out, at + 22, record.code);
                    wr32(out, at + 24, record.value as u32);
                    wr32(out, at + 28, record.flags);
                    out[at + 32..at + 32 + INPUT_TEXT_LEN].copy_from_slice(&record.text);
                }
                Ok(len)
            }
            Body::InputReset {
                focus_epoch,
                reason,
            } => {
                if !(INPUT_RESET_RESYNC..=INPUT_RESET_SERVICE_CHANGED).contains(reason) {
                    return Err(DecodeError::BadValue);
                }
                ensure(out, 8)?;
                wr32(out, 0, *focus_epoch);
                wr32(out, 4, *reason);
                Ok(8)
            }
            Body::OutputInfo {
                width,
                height,
                stride,
                format,
                scale,
            } => {
                if *format != FORMAT_XRGB8888 {
                    return Err(DecodeError::BadValue);
                }
                ensure(out, 24)?;
                wr32(out, 0, *width);
                wr32(out, 4, *height);
                wr32(out, 8, *stride);
                wr32(out, 12, *format);
                wr32(out, 16, *scale);
                wr32(out, 20, 0);
                Ok(24)
            }
            Body::OutputRemoved => Ok(0),
        }
    }
}

/// Validate a fixed-prefix + declared-length body and return the payload.
fn string<'a>(
    body: &'a [u8],
    fixed: usize,
    len: usize,
    max: usize,
) -> Result<&'a [u8], DecodeError> {
    if len > max {
        return Err(DecodeError::BadValue);
    }
    let expected = fixed.checked_add(len).ok_or(DecodeError::Overflow)?;
    exact(body, expected)?;
    Ok(&body[fixed..])
}

fn string_len(fixed: usize, len: usize, max: usize) -> Result<usize, DecodeError> {
    if len > max {
        return Err(DecodeError::BadValue);
    }
    fixed.checked_add(len).ok_or(DecodeError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::{FLAG_FULL_DAMAGE, MAX_RECTS};
    use std::vec;
    use std::vec::Vec;

    const ALL_OPCODES: [Opcode; 33] = [
        Opcode::HELLO,
        Opcode::PING,
        Opcode::GOODBYE,
        Opcode::CREATE_SURFACE,
        Opcode::DESTROY_SURFACE,
        Opcode::SET_TITLE,
        Opcode::REQUEST_WINDOW_ACTION,
        Opcode::SET_CURSOR_SHAPE,
        Opcode::REQUEST_RESIZE,
        Opcode::SET_GEOMETRY,
        Opcode::ALLOC_BUFFER,
        Opcode::IMPORT_RESULT,
        Opcode::DESTROY_BUFFER,
        Opcode::WRITE_TILE,
        Opcode::COMMIT,
        Opcode::UNMAP_SURFACE,
        Opcode::WELCOME,
        Opcode::PONG,
        Opcode::ERROR,
        Opcode::ACK,
        Opcode::SURFACE_CREATED,
        Opcode::CONFIGURE,
        Opcode::SURFACE_DESTROYED,
        Opcode::CLOSE_REQUEST,
        Opcode::GEOMETRY,
        Opcode::BUFFER_CREATED,
        Opcode::BUFFER_RELEASE,
        Opcode::BUFFER_DESTROYED,
        Opcode::FRAME_DONE,
        Opcode::INPUT_BATCH,
        Opcode::INPUT_RESET,
        Opcode::OUTPUT_INFO,
        Opcode::OUTPUT_REMOVED,
    ];

    fn opcode_of(body: &Body<'_>) -> u16 {
        match body {
            Body::Hello { .. } => Opcode::HELLO.value(),
            Body::Ping { .. } => Opcode::PING.value(),
            Body::Goodbye => Opcode::GOODBYE.value(),
            Body::CreateSurface { .. } => Opcode::CREATE_SURFACE.value(),
            Body::DestroySurface => Opcode::DESTROY_SURFACE.value(),
            Body::SetTitle { .. } => Opcode::SET_TITLE.value(),
            Body::RequestWindowAction { .. } => Opcode::REQUEST_WINDOW_ACTION.value(),
            Body::SetCursorShape { .. } => Opcode::SET_CURSOR_SHAPE.value(),
            Body::RequestResize { .. } => Opcode::REQUEST_RESIZE.value(),
            Body::SetGeometry { .. } => Opcode::SET_GEOMETRY.value(),
            Body::AllocBuffer { .. } => Opcode::ALLOC_BUFFER.value(),
            Body::ImportResult { .. } => Opcode::IMPORT_RESULT.value(),
            Body::DestroyBuffer => Opcode::DESTROY_BUFFER.value(),
            Body::WriteTile { .. } => Opcode::WRITE_TILE.value(),
            Body::Commit(_) => Opcode::COMMIT.value(),
            Body::UnmapSurface => Opcode::UNMAP_SURFACE.value(),
            Body::Welcome { .. } => Opcode::WELCOME.value(),
            Body::Pong { .. } => Opcode::PONG.value(),
            Body::Error { .. } => Opcode::ERROR.value(),
            Body::Ack { .. } => Opcode::ACK.value(),
            Body::SurfaceCreated { .. } => Opcode::SURFACE_CREATED.value(),
            Body::Configure { .. } => Opcode::CONFIGURE.value(),
            Body::SurfaceDestroyed => Opcode::SURFACE_DESTROYED.value(),
            Body::CloseRequest { .. } => Opcode::CLOSE_REQUEST.value(),
            Body::Geometry { .. } => Opcode::GEOMETRY.value(),
            Body::BufferCreated { .. } => Opcode::BUFFER_CREATED.value(),
            Body::BufferRelease { .. } => Opcode::BUFFER_RELEASE.value(),
            Body::BufferDestroyed => Opcode::BUFFER_DESTROYED.value(),
            Body::FrameDone { .. } => Opcode::FRAME_DONE.value(),
            Body::InputBatch(_) => Opcode::INPUT_BATCH.value(),
            Body::InputReset { .. } => Opcode::INPUT_RESET.value(),
            Body::OutputInfo { .. } => Opcode::OUTPUT_INFO.value(),
            Body::OutputRemoved => Opcode::OUTPUT_REMOVED.value(),
        }
    }

    /// `object_id` accepted for `opcode` (non-zero where required).
    fn object_for(opcode: u16) -> u64 {
        match Opcode(opcode) {
            Opcode::HELLO
            | Opcode::PING
            | Opcode::GOODBYE
            | Opcode::CREATE_SURFACE
            | Opcode::SET_CURSOR_SHAPE
            | Opcode::WELCOME
            | Opcode::PONG => 0,
            _ => 7,
        }
    }

    fn requires_object(opcode: u16) -> bool {
        !matches!(
            Opcode(opcode),
            Opcode::HELLO
                | Opcode::PING
                | Opcode::GOODBYE
                | Opcode::CREATE_SURFACE
                | Opcode::SET_CURSOR_SHAPE
                | Opcode::ERROR
                | Opcode::ACK
                | Opcode::WELCOME
                | Opcode::PONG
                | Opcode::GEOMETRY
        )
    }

    fn hello<'a>(name: &'a [u8], features: u32) -> Body<'a> {
        Body::Hello {
            major: 1,
            minor: 0,
            features,
            pid: 0,
            name,
            path: &[],
        }
    }

    fn record(event_type: u16, code: u16, value: i32, flags: u32, text: [u8; 16]) -> InputRecord {
        InputRecord {
            timestamp_ns: 0x0102_0304_0506_0708,
            sequence: 9,
            device_id: 3,
            event_type,
            code,
            value,
            flags,
            text,
        }
    }

    fn batch(count: usize) -> Body<'static> {
        let mut records = [InputRecord::default(); MAX_INPUT_RECORDS];
        if count > 0 {
            records[0] = record(INPUT_EVENT_POINTER_MOTION, 5, -7, INPUT_FLAG_ABSOLUTE, [0; 16]);
        }
        if count > 1 {
            let mut text = [0u8; 16];
            text[..3].copy_from_slice(b"abc");
            records[1] = record(INPUT_EVENT_TEXT, 0, 3, 0, text);
        }
        for (index, slot) in records.iter_mut().enumerate().take(count).skip(2) {
            *slot = record(INPUT_EVENT_KEY, 30, index as i32 & 1, 0, [0; 16]);
        }
        Body::InputBatch(InputBatch {
            focus_epoch: 42,
            count: count as u16,
            records,
        })
    }

    fn samples() -> Vec<Body<'static>> {
        static NAME_BUF: [u8; MAX_NAME] = [b'N'; MAX_NAME];
        static PATH_BUF: [u8; MAX_PATH] = [b'P'; MAX_PATH];
        static TITLE_BUF: [u8; MAX_TITLE] = [b'T'; MAX_TITLE];
        static DETAIL_BUF: [u8; MAX_ERROR_DETAIL] = [b'E'; MAX_ERROR_DETAIL];
        let name = &NAME_BUF[..];
        let path = &PATH_BUF[..];
        let title = &TITLE_BUF[..];
        let detail = &DETAIL_BUF[..];
        let mut rects = [crate::Rect::default(); MAX_RECTS];
        for (i, rect) in rects.iter_mut().enumerate() {
            *rect = crate::Rect {
                x: i as i32,
                y: i as i32,
                w: 2,
                h: 3,
            };
        }
        let mut commit = Commit::default();
        commit.buffer = 1;
        commit.ack_serial = 2;
        commit.commit_id = 3;
        commit.flags = FLAG_FULL_DAMAGE;
        let mut full_commit = commit;
        full_commit.rect_count = MAX_RECTS as u16;
        full_commit.rects = rects;
        full_commit.flags = 0;

        vec![
            hello(&[], 0),
            hello(name, FEATURES_KNOWN),
            Body::Hello {
                major: 1,
                minor: 0,
                features: FEATURES_KNOWN,
                pid: u32::MAX,
                name,
                path,
            },
            Body::Ping { cookie: 0 },
            Body::Ping {
                cookie: u64::MAX,
            },
            Body::Goodbye,
            Body::CreateSurface {
                width: 1,
                height: 1,
                format: FORMAT_XRGB8888,
                flags: 0,
                title: &[],
            },
            Body::CreateSurface {
                width: MAX_SURFACE_DIM,
                height: MAX_SURFACE_DIM,
                format: FORMAT_XRGB8888,
                flags: 0,
                title,
            },
            Body::DestroySurface,
            Body::SetTitle { title: &[] },
            Body::SetTitle { title },
            Body::RequestWindowAction {
                action: WINDOW_ACTION_MINIMIZE,
            },
            Body::RequestWindowAction {
                action: WINDOW_ACTION_MAXIMIZE,
            },
            Body::SetCursorShape {
                shape: CURSOR_SHAPE_DEFAULT,
            },
            Body::SetCursorShape {
                shape: CURSOR_SHAPE_POINTER,
            },
            Body::RequestResize {
                width: 1,
                height: 1,
                format: FORMAT_XRGB8888,
            },
            Body::RequestResize {
                width: MAX_SURFACE_DIM,
                height: MAX_SURFACE_DIM,
                format: FORMAT_XRGB8888,
            },
            Body::SetGeometry {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
                format: FORMAT_XRGB8888,
            },
            Body::SetGeometry {
                x: i32::MIN,
                y: i32::MAX,
                width: MAX_SURFACE_DIM,
                height: MAX_SURFACE_DIM,
                format: FORMAT_XRGB8888,
            },
            Body::AllocBuffer {
                width: 1,
                height: 1,
                format: FORMAT_XRGB8888,
                flags: 0,
                stride: 4,
            },
            Body::AllocBuffer {
                width: MAX_SURFACE_DIM,
                height: MAX_SURFACE_DIM,
                format: FORMAT_XRGB8888,
                flags: 0,
                stride: MAX_SURFACE_DIM * 4,
            },
            Body::ImportResult { status: IMPORT_OK },
            Body::ImportResult {
                status: IMPORT_FAILED,
            },
            Body::DestroyBuffer,
            Body::WriteTile {
                x: 0,
                y: 0,
                w: 1,
                h: 1,
                stride: 4,
                pixels: &[0, 0, 0, 0],
            },
            Body::WriteTile {
                x: 1,
                y: 2,
                w: 2,
                h: 2,
                stride: 8,
                pixels: &[0xAA; 16],
            },
            Body::Commit(commit),
            Body::Commit(full_commit),
            Body::UnmapSurface,
            Body::Welcome {
                major: 1,
                minor: 0,
                features: FEATURES_KNOWN,
                max_message_bytes: MAX_MESSAGE_BYTES,
                max_surfaces: 4,
                max_buffers_per_surface: 4,
                max_buffers_per_session: 16,
                pixel_quota_bytes: 8 * 1024 * 1024,
                session: u64::MAX,
            },
            Body::Pong {
                cookie: 0xDEAD_BEEF,
            },
            Body::Error { code: 1, detail: &[] },
            Body::Error {
                code: ERROR_INTERNAL,
                detail,
            },
            Body::Ack { status: 0 },
            Body::SurfaceCreated {
                width: 800,
                height: 600,
                format: FORMAT_XRGB8888,
            },
            Body::Configure {
                serial: 1,
                width: 800,
                height: 600,
                format: FORMAT_XRGB8888,
                flags: 0,
            },
            Body::SurfaceDestroyed,
            Body::CloseRequest {
                reason: CLOSE_REASON_REQUESTED,
            },
            Body::CloseRequest {
                reason: CLOSE_REASON_SHUTDOWN,
            },
            Body::Geometry {
                serial: 0,
                x: 0,
                y: 0,
                width: 1,
                height: 1,
                format: FORMAT_XRGB8888,
                flags: 0,
            },
            Body::Geometry {
                serial: u64::MAX,
                x: i32::MIN,
                y: i32::MAX,
                width: MAX_SURFACE_DIM,
                height: MAX_SURFACE_DIM,
                format: FORMAT_XRGB8888,
                flags: 0,
            },
            Body::BufferCreated {
                surface: 1,
                width: 2,
                height: 2,
                format: FORMAT_XRGB8888,
                stride: 8,
                region_len: 16,
                region_handle: 0x55,
            },
            Body::BufferCreated {
                surface: u64::MAX,
                width: 1,
                height: 1,
                format: FORMAT_XRGB8888,
                stride: 4,
                region_len: u64::MAX,
                region_handle: u64::MAX,
            },
            Body::BufferRelease {
                commit_id: 1,
                serial: 2,
            },
            Body::BufferDestroyed,
            Body::FrameDone {
                buffer: 1,
                commit_id: 2,
                serial: 3,
                flags: 0,
            },
            batch(0),
            batch(1),
            batch(2),
            batch(MAX_INPUT_RECORDS),
            Body::InputReset {
                focus_epoch: 1,
                reason: INPUT_RESET_RESYNC,
            },
            Body::InputReset {
                focus_epoch: 2,
                reason: INPUT_RESET_SERVICE_CHANGED,
            },
            Body::OutputInfo {
                width: 1920,
                height: 1080,
                stride: 1920 * 4,
                format: FORMAT_XRGB8888,
                scale: 100,
            },
            Body::OutputRemoved,
        ]
    }

    #[test]
    fn roundtrip_every_variant_min_and_max() {
        let mut seen = [false; ALL_OPCODES.len()];
        for body in samples() {
            let opcode = opcode_of(&body);
            let object = object_for(opcode);
            let mut out = [0u8; 1024];
            let len = body.encode(&mut out).unwrap();
            assert!(len <= MAX_MESSAGE_BYTES as usize);

            let decoded = Body::decode(opcode, object, &out[..len]).unwrap();
            assert_eq!(decoded, body, "opcode {opcode:#06x}");

            // A short output slice is an error, never a panic.
            if len > 0 {
                assert_eq!(
                    body.encode(&mut out[..len - 1]),
                    Err(DecodeError::Truncated),
                    "opcode {opcode:#06x}"
                );
            }

            let index = ALL_OPCODES
                .iter()
                .position(|candidate| candidate.value() == opcode)
                .unwrap();
            seen[index] = true;
        }
        assert!(seen.iter().all(|&hit| hit), "every opcode covered");
    }

    #[test]
    fn truncated_at_every_prefix() {
        for body in samples() {
            let opcode = opcode_of(&body);
            let object = object_for(opcode);
            let mut out = [0u8; 1024];
            let len = body.encode(&mut out).unwrap();
            for prefix in 0..len {
                assert!(
                    Body::decode(opcode, object, &out[..prefix]).is_err(),
                    "opcode {opcode:#06x} prefix {prefix}/{len}"
                );
            }
            // One trailing byte is malformed for fixed-length bodies and for
            // declared-length bodies alike.
            if len < out.len() {
                assert_eq!(
                    Body::decode(opcode, object, &out[..len + 1]),
                    Err(DecodeError::SizeMismatch),
                    "opcode {opcode:#06x}"
                );
            }
        }
    }

    #[test]
    fn object_zero_rejected_where_required() {
        for body in samples() {
            let opcode = opcode_of(&body);
            if !requires_object(opcode) {
                continue;
            }
            let mut out = [0u8; 1024];
            let len = body.encode(&mut out).unwrap();
            assert_eq!(
                Body::decode(opcode, 0, &out[..len]),
                Err(DecodeError::BadObject),
                "opcode {opcode:#06x}"
            );
        }
    }

    #[test]
    fn rejects_limit_violations() {
        let long_name = [b'N'; MAX_NAME + 1];
        assert_eq!(
            hello(&long_name, 0).encode(&mut [0u8; 200]),
            Err(DecodeError::BadValue)
        );

        let long_path = [b'P'; MAX_PATH + 1];
        assert_eq!(
            Body::Hello {
                major: 1,
                minor: 0,
                features: 0,
                pid: 1,
                name: b"n",
                path: &long_path,
            }
            .encode(&mut [0u8; 200]),
            Err(DecodeError::BadValue)
        );

        let long_title = [b'T'; MAX_TITLE + 1];
        assert_eq!(
            Body::SetTitle { title: &long_title }.encode(&mut [0u8; 300]),
            Err(DecodeError::BadValue)
        );
        assert_eq!(
            Body::CreateSurface {
                width: 1,
                height: 1,
                format: FORMAT_XRGB8888,
                flags: 0,
                title: &long_title,
            }
            .encode(&mut [0u8; 300]),
            Err(DecodeError::BadValue)
        );

        let long_detail = [b'E'; MAX_ERROR_DETAIL + 1];
        assert_eq!(
            Body::Error {
                code: 1,
                detail: &long_detail,
            }
            .encode(&mut [0u8; 300]),
            Err(DecodeError::BadValue)
        );

        // 33 rects.
        let mut commit = Commit::default();
        commit.rect_count = MAX_RECTS as u16 + 1;
        assert_eq!(
            Body::Commit(commit).encode(&mut [0u8; 600]),
            Err(DecodeError::TooManyRects)
        );

        // 17 input records.
        let mut input = match batch(0) {
            Body::InputBatch(batch) => batch,
            _ => unreachable!(),
        };
        input.count = MAX_INPUT_RECORDS as u16 + 1;
        assert_eq!(
            Body::InputBatch(input).encode(&mut [0u8; 900]),
            Err(DecodeError::BadValue)
        );

        // Surface dimension bounds.
        assert_eq!(
            Body::CreateSurface {
                width: 0,
                height: 1,
                format: FORMAT_XRGB8888,
                flags: 0,
                title: &[],
            }
            .encode(&mut [0u8; 32]),
            Err(DecodeError::BadValue)
        );
        assert_eq!(
            Body::CreateSurface {
                width: MAX_SURFACE_DIM + 1,
                height: 1,
                format: FORMAT_XRGB8888,
                flags: 0,
                title: &[],
            }
            .encode(&mut [0u8; 32]),
            Err(DecodeError::BadValue)
        );
    }

    #[test]
    fn rejects_write_tile_violations() {
        let pixel = [0u8; 64];
        // stride < w*4.
        assert_eq!(
            Body::WriteTile {
                x: 0,
                y: 0,
                w: 2,
                h: 1,
                stride: 4,
                pixels: &pixel[..4],
            }
            .encode(&mut [0u8; 64]),
            Err(DecodeError::BadValue)
        );
        // Zero dimensions.
        assert_eq!(
            Body::WriteTile {
                x: 0,
                y: 0,
                w: 0,
                h: 1,
                stride: 4,
                pixels: &[],
            }
            .encode(&mut [0u8; 64]),
            Err(DecodeError::BadValue)
        );

        // Wire size must be exactly 16 + stride*h.
        let mut truncated = [0u8; 16];
        truncated[4..6].copy_from_slice(&1u16.to_le_bytes());
        truncated[6..8].copy_from_slice(&1u16.to_le_bytes());
        truncated[8..12].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(
            Body::decode(Opcode::WRITE_TILE.value(), 7, &truncated),
            Err(DecodeError::Truncated)
        );
        let mut oversized = [0u8; 24];
        oversized[4..6].copy_from_slice(&1u16.to_le_bytes());
        oversized[6..8].copy_from_slice(&1u16.to_le_bytes());
        oversized[8..12].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(
            Body::decode(Opcode::WRITE_TILE.value(), 7, &oversized),
            Err(DecodeError::SizeMismatch)
        );

        // flags must be zero.
        let mut flagged = [0u8; 20];
        flagged[4..6].copy_from_slice(&1u16.to_le_bytes());
        flagged[6..8].copy_from_slice(&1u16.to_le_bytes());
        flagged[8..12].copy_from_slice(&4u32.to_le_bytes());
        flagged[12..16].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            Body::decode(Opcode::WRITE_TILE.value(), 7, &flagged),
            Err(DecodeError::BadFlags)
        );
    }

    #[test]
    fn rejects_unaligned_stride() {
        // ALLOC_BUFFER: 4-byte pixels require stride % 4 == 0, both ways.
        assert_eq!(
            Body::AllocBuffer {
                width: 2,
                height: 1,
                format: FORMAT_XRGB8888,
                flags: 0,
                stride: 10,
            }
            .encode(&mut [0u8; 64]),
            Err(DecodeError::BadValue)
        );
        let mut alloc = [0u8; 24];
        alloc[0..4].copy_from_slice(&2u32.to_le_bytes());
        alloc[4..8].copy_from_slice(&1u32.to_le_bytes());
        alloc[8..12].copy_from_slice(&FORMAT_XRGB8888.to_le_bytes());
        alloc[16..20].copy_from_slice(&10u32.to_le_bytes());
        assert_eq!(
            Body::decode(Opcode::ALLOC_BUFFER.value(), 7, &alloc),
            Err(DecodeError::BadValue)
        );

        // WRITE_TILE: same rule for tile rows.
        let pixels = [0u8; 10];
        assert_eq!(
            Body::WriteTile {
                x: 0,
                y: 0,
                w: 2,
                h: 1,
                stride: 10,
                pixels: &pixels,
            }
            .encode(&mut [0u8; 64]),
            Err(DecodeError::BadValue)
        );
        let mut tile = [0u8; 26];
        tile[4..6].copy_from_slice(&2u16.to_le_bytes());
        tile[6..8].copy_from_slice(&1u16.to_le_bytes());
        tile[8..12].copy_from_slice(&10u32.to_le_bytes());
        assert_eq!(
            Body::decode(Opcode::WRITE_TILE.value(), 7, &tile),
            Err(DecodeError::BadValue)
        );
    }

    #[test]
    fn rejects_bad_input_records() {
        fn input_with(record: InputRecord) -> InputRecord {
            record
        }

        let mut text = [0u8; 16];
        text[0] = b'a';

        // TEXT length 0 and 17.
        assert_eq!(
            input_with(record(INPUT_EVENT_TEXT, 0, 0, 0, text)).check(),
            Err(DecodeError::BadValue)
        );
        assert_eq!(
            input_with(record(INPUT_EVENT_TEXT, 0, 17, 0, text)).check(),
            Err(DecodeError::BadValue)
        );
        // Invalid UTF-8 and non-zero padding.
        assert_eq!(
            input_with(record(INPUT_EVENT_TEXT, 0, 1, 0, [0xFF; 16])).check(),
            Err(DecodeError::BadValue)
        );
        let mut padded = [0u8; 16];
        padded[0] = b'a';
        padded[1] = 1;
        assert_eq!(
            input_with(record(INPUT_EVENT_TEXT, 0, 1, 0, padded)).check(),
            Err(DecodeError::BadValue)
        );
        // TEXT is never valid on motion.
        assert_eq!(
            input_with(record(INPUT_EVENT_POINTER_MOTION, 0, 1, 0, [0xAB; 16])).check(),
            Err(DecodeError::BadValue)
        );
        // Motion coordinate out of i16.
        assert_eq!(
            input_with(record(
                INPUT_EVENT_POINTER_MOTION,
                0,
                i16::MAX as i32 + 1,
                0,
                [0; 16],
            ))
            .check(),
            Err(DecodeError::Overflow)
        );
        assert_eq!(
            input_with(record(
                INPUT_EVENT_POINTER_MOTION,
                0,
                i16::MIN as i32,
                INPUT_FLAG_ABSOLUTE,
                [0; 16],
            ))
            .check(),
            Ok(())
        );
        // ABSOLUTE only on motion.
        assert_eq!(
            input_with(record(INPUT_EVENT_KEY, 30, 1, INPUT_FLAG_ABSOLUTE, [0; 16])).check(),
            Err(DecodeError::BadFlags)
        );
        // Unknown event type.
        assert_eq!(
            input_with(record(10, 0, 0, 0, [0; 16])).check(),
            Err(DecodeError::BadValue)
        );

        // 17 records on the wire (declared count).
        let mut body = [0u8; 8 + 48 * (MAX_INPUT_RECORDS + 1)];
        body[0..2].copy_from_slice(&(MAX_INPUT_RECORDS as u16 + 1).to_le_bytes());
        assert_eq!(
            Body::decode(Opcode::INPUT_BATCH.value(), 7, &body),
            Err(DecodeError::BadValue)
        );
    }

    #[test]
    fn rejects_reserved_and_flag_violations() {
        // HELLO declares name_len 1 / path_len 1 but the body is too short.
        let mut hello_body = [0u8; 16];
        hello_body[12] = 1;
        hello_body[14] = 1;
        assert_eq!(
            Body::decode(Opcode::HELLO.value(), 0, &hello_body),
            Err(DecodeError::Truncated)
        );
        // ... and one trailing byte is malformed too.
        let mut hello_extra = [0u8; 17];
        hello_extra[14] = 0;
        assert_eq!(
            Body::decode(Opcode::HELLO.value(), 0, &hello_extra),
            Err(DecodeError::SizeMismatch)
        );

        // HELLO unknown feature bit.
        let mut hello_features = [0u8; 16];
        hello_features[4] = 0x40;
        assert_eq!(
            Body::decode(Opcode::HELLO.value(), 0, &hello_features),
            Err(DecodeError::BadFlags)
        );

        // CREATE_SURFACE unknown flag and bad format.
        let mut surface = [0u8; 20];
        surface[0..4].copy_from_slice(&1u32.to_le_bytes());
        surface[4..8].copy_from_slice(&1u32.to_le_bytes());
        surface[12] = 1;
        assert_eq!(
            Body::decode(Opcode::CREATE_SURFACE.value(), 0, &surface),
            Err(DecodeError::BadFlags)
        );
        surface[12] = 0;
        surface[8] = 1;
        assert_eq!(
            Body::decode(Opcode::CREATE_SURFACE.value(), 0, &surface),
            Err(DecodeError::BadValue)
        );

        // ALLOC_BUFFER reserved u32.
        let mut alloc = [0u8; 24];
        alloc[0..4].copy_from_slice(&1u32.to_le_bytes());
        alloc[4..8].copy_from_slice(&1u32.to_le_bytes());
        alloc[16..20].copy_from_slice(&4u32.to_le_bytes());
        alloc[20] = 1;
        assert_eq!(
            Body::decode(Opcode::ALLOC_BUFFER.value(), 7, &alloc),
            Err(DecodeError::ReservedNonZero)
        );

        // REQUEST_WINDOW_ACTION out of range and reserved.
        let mut action = [0u8; 8];
        assert_eq!(
            Body::decode(Opcode::REQUEST_WINDOW_ACTION.value(), 7, &action),
            Err(DecodeError::BadValue)
        );
        action[0..4].copy_from_slice(&1u32.to_le_bytes());
        action[4] = 1;
        assert_eq!(
            Body::decode(Opcode::REQUEST_WINDOW_ACTION.value(), 7, &action),
            Err(DecodeError::ReservedNonZero)
        );

        // FRAME_DONE permits only PRESENT_SUBMITTED (bit 0); other bits are
        // reserved and must be rejected.
        let mut frame = [0u8; 32];
        frame[24] = 1;
        assert!(matches!(
            Body::decode(Opcode::FRAME_DONE.value(), 7, &frame),
            Ok(Body::FrameDone { flags: 1, .. })
        ));
        frame[24] = 2;
        assert_eq!(
            Body::decode(Opcode::FRAME_DONE.value(), 7, &frame),
            Err(DecodeError::BadFlags)
        );

        // WELCOME max_message_bytes is fixed.
        let mut welcome = [0u8; 36];
        welcome[8..12].copy_from_slice(&1007u32.to_le_bytes());
        assert_eq!(
            Body::decode(Opcode::WELCOME.value(), 0, &welcome),
            Err(DecodeError::BadValue)
        );
    }

    #[test]
    fn pseudo_random_bodies_never_panic() {
        let mut state: u64 = 0x0DDB_1A5E_5BAD_5EED;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };

        let mut buf = [0u8; MAX_MESSAGE_BYTES as usize];
        for opcode in ALL_OPCODES {
            for len in 0..=buf.len() {
                for byte in buf[..len].iter_mut() {
                    *byte = next() as u8;
                }
                let object = next();
                let _ = Body::decode(opcode.value(), object, &buf[..len]);
            }
        }
    }

    #[test]
    fn hello_body_is_exact_and_bounded() {
        let body = Body::Hello {
            major: 1,
            minor: 2,
            features: FEATURES_KNOWN,
            pid: 0x1234,
            name: b"alice",
            path: b"/srv/d",
        };
        let mut out = [0u8; 64];
        let len = body.encode(&mut out).unwrap();
        assert_eq!(len, 16 + 5 + 6);
        assert_eq!(Body::decode(Opcode::HELLO.value(), 0, &out[..len]), Ok(body));

        // Empty name and path are allowed: exactly 16 bytes.
        let empty = hello(&[], 0);
        assert_eq!(empty.encode(&mut out), Ok(16));
        assert_eq!(Body::decode(Opcode::HELLO.value(), 0, &out[..16]), Ok(empty));

        // Declared lengths must sum to the body length exactly.
        let mut one_byte_short = [0u8; 16 + 5 + 6 - 1];
        one_byte_short[12..14].copy_from_slice(&5u16.to_le_bytes());
        one_byte_short[14..16].copy_from_slice(&6u16.to_le_bytes());
        assert_eq!(
            Body::decode(Opcode::HELLO.value(), 0, &one_byte_short),
            Err(DecodeError::Truncated)
        );
        let mut one_byte_long = [0u8; 16 + 5 + 6 + 1];
        one_byte_long[12..14].copy_from_slice(&5u16.to_le_bytes());
        one_byte_long[14..16].copy_from_slice(&6u16.to_le_bytes());
        assert_eq!(
            Body::decode(Opcode::HELLO.value(), 0, &one_byte_long),
            Err(DecodeError::SizeMismatch)
        );

        // 65-byte name and 65-byte path are rejected on both sides.
        let long = [b'x'; MAX_NAME + 1];
        let mut wire = [0u8; 16 + MAX_NAME + 1];
        wire[12..14].copy_from_slice(&(MAX_NAME as u16 + 1).to_le_bytes());
        assert_eq!(
            Body::decode(Opcode::HELLO.value(), 0, &wire[..16 + MAX_NAME + 1]),
            Err(DecodeError::BadValue)
        );
        wire[12..14].copy_from_slice(&0u16.to_le_bytes());
        wire[14..16].copy_from_slice(&(MAX_PATH as u16 + 1).to_le_bytes());
        assert_eq!(
            Body::decode(Opcode::HELLO.value(), 0, &wire[..16 + MAX_PATH + 1]),
            Err(DecodeError::BadValue)
        );
        assert_eq!(
            Body::Hello {
                major: 1,
                minor: 0,
                features: 0,
                pid: 0,
                name: &long[..MAX_NAME],
                path: &long[..MAX_PATH + 1],
            }
            .encode(&mut [0u8; 256]),
            Err(DecodeError::BadValue)
        );
    }

    #[test]
    fn debug_output_is_redacted() {
        let hello = std::format!(
            "{:?}",
            Body::Hello {
                major: 1,
                minor: 0,
                features: 0,
                pid: 7,
                name: b"SECRETNAME",
                path: b"/secret/path",
            }
        );
        assert!(!hello.contains("SECRETNAME"));
        assert!(!hello.contains("/secret/path"));
        assert!(hello.contains("name_len"));
        assert!(hello.contains("path_len"));

        let title = b"TOPSECRET";
        let text = std::format!("{:?}", Body::SetTitle { title });
        assert!(!text.contains("TOPSECRET"));

        let pixels = [0xABu8; 8];
        let text = std::format!(
            "{:?}",
            Body::WriteTile {
                x: 1,
                y: 2,
                w: 2,
                h: 1,
                stride: 8,
                pixels: &pixels,
            }
        );
        assert!(text.contains("pixels_len"));
        assert!(!text.contains("pixels:"));

        let record = InputRecord {
            event_type: INPUT_EVENT_TEXT,
            value: 3,
            text: *b"abc\0\0\0\0\0\0\0\0\0\0\0\0\0",
            ..InputRecord::default()
        };
        let text = std::format!("{:?}", record);
        assert!(!text.contains("abc"));
        assert!(text.contains("text_len"));

        let text = std::format!(
            "{:?}",
            Body::Error {
                code: 7,
                detail: b"very-secret-detail"
            }
        );
        assert!(!text.contains("very-secret-detail"));
    }

    #[test]
    fn request_resize_body_is_exact_and_validated() {
        let body = Body::RequestResize {
            width: 400,
            height: 240,
            format: FORMAT_XRGB8888,
        };
        let mut out = [0u8; 16];
        assert_eq!(body.encode(&mut out), Ok(16));
        assert_eq!(
            Body::decode(Opcode::REQUEST_RESIZE.value(), 7, &out),
            Ok(body)
        );

        // Truncated and over-long bodies are rejected.
        assert_eq!(
            Body::decode(Opcode::REQUEST_RESIZE.value(), 7, &out[..15]),
            Err(DecodeError::Truncated)
        );
        let mut long = [0u8; 17];
        long[..16].copy_from_slice(&out);
        assert_eq!(
            Body::decode(Opcode::REQUEST_RESIZE.value(), 7, &long),
            Err(DecodeError::SizeMismatch)
        );

        // Reserved word must stay zero.
        let mut reserved = out;
        reserved[12..16].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            Body::decode(Opcode::REQUEST_RESIZE.value(), 7, &reserved),
            Err(DecodeError::ReservedNonZero)
        );

        // Zero dimension and foreign format are rejected.
        let mut zero = out;
        zero[0..4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            Body::decode(Opcode::REQUEST_RESIZE.value(), 7, &zero),
            Err(DecodeError::BadValue)
        );
        let mut format = out;
        format[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            Body::decode(Opcode::REQUEST_RESIZE.value(), 7, &format),
            Err(DecodeError::BadValue)
        );

        // Object id 0 is refused: the resize targets a surface.
        assert_eq!(
            Body::decode(Opcode::REQUEST_RESIZE.value(), 0, &out),
            Err(DecodeError::BadObject)
        );
    }

    #[test]
    fn window_action_raise_and_lower_are_valid() {
        for action in [WINDOW_ACTION_RAISE, WINDOW_ACTION_LOWER] {
            let body = Body::RequestWindowAction { action };
            let mut out = [0u8; 8];
            assert_eq!(body.encode(&mut out), Ok(8));
            assert_eq!(
                Body::decode(Opcode::REQUEST_WINDOW_ACTION.value(), 7, &out),
                Ok(body)
            );
        }

        // The widened range stops at LOWER, on both sides.
        let mut beyond = [0u8; 8];
        beyond[0..4].copy_from_slice(&(WINDOW_ACTION_LOWER + 1).to_le_bytes());
        assert_eq!(
            Body::decode(Opcode::REQUEST_WINDOW_ACTION.value(), 7, &beyond),
            Err(DecodeError::BadValue)
        );
        let beyond_body = Body::RequestWindowAction {
            action: WINDOW_ACTION_LOWER + 1,
        };
        assert_eq!(beyond_body.encode(&mut [0u8; 8]), Err(DecodeError::BadValue));
    }

    #[test]
    fn set_geometry_and_geometry_bodies_are_validated() {
        assert!(Opcode::GEOMETRY.is_event());
        assert!(!Opcode::SET_GEOMETRY.is_event());

        // Clean roundtrip with negative coordinates, both directions.
        let set = Body::SetGeometry {
            x: -5,
            y: -17,
            width: 320,
            height: 240,
            format: FORMAT_XRGB8888,
        };
        let mut set_wire = [0u8; 24];
        assert_eq!(set.encode(&mut set_wire), Ok(24));
        assert_eq!(
            Body::decode(Opcode::SET_GEOMETRY.value(), 7, &set_wire),
            Ok(set)
        );
        let extreme = Body::SetGeometry {
            x: i32::MIN,
            y: i32::MAX,
            width: 1,
            height: 1,
            format: FORMAT_XRGB8888,
        };
        assert_eq!(extreme.encode(&mut set_wire), Ok(24));
        assert_eq!(
            Body::decode(Opcode::SET_GEOMETRY.value(), 7, &set_wire),
            Ok(extreme)
        );

        let geometry = Body::Geometry {
            serial: 9,
            x: -5,
            y: -17,
            width: 320,
            height: 240,
            format: FORMAT_XRGB8888,
            flags: 0,
        };
        let mut geometry_wire = [0u8; 32];
        assert_eq!(geometry.encode(&mut geometry_wire), Ok(32));
        assert_eq!(
            Body::decode(Opcode::GEOMETRY.value(), 7, &geometry_wire),
            Ok(geometry)
        );

        // Exact length: truncation and one trailing byte.
        assert_eq!(
            Body::decode(Opcode::SET_GEOMETRY.value(), 7, &set_wire[..23]),
            Err(DecodeError::Truncated)
        );
        let mut set_long = [0u8; 25];
        set_long[..24].copy_from_slice(&set_wire);
        assert_eq!(
            Body::decode(Opcode::SET_GEOMETRY.value(), 7, &set_long),
            Err(DecodeError::SizeMismatch)
        );
        assert_eq!(
            Body::decode(Opcode::GEOMETRY.value(), 7, &geometry_wire[..31]),
            Err(DecodeError::Truncated)
        );
        let mut geometry_long = [0u8; 33];
        geometry_long[..32].copy_from_slice(&geometry_wire);
        assert_eq!(
            Body::decode(Opcode::GEOMETRY.value(), 7, &geometry_long),
            Err(DecodeError::SizeMismatch)
        );

        // Reserved word must stay zero.
        let mut reserved = set_wire;
        reserved[20] = 1;
        assert_eq!(
            Body::decode(Opcode::SET_GEOMETRY.value(), 7, &reserved),
            Err(DecodeError::ReservedNonZero)
        );

        // Bad flags on GEOMETRY yield the same error as on CONFIGURE.
        let mut flagged = geometry_wire;
        flagged[28] = 1;
        let mut configure = [0u8; 24];
        configure[20] = 1;
        assert_eq!(
            Body::decode(Opcode::CONFIGURE.value(), 7, &configure),
            Err(DecodeError::BadFlags)
        );
        assert_eq!(
            Body::decode(Opcode::GEOMETRY.value(), 7, &flagged),
            Err(DecodeError::BadFlags)
        );
        assert_eq!(
            Body::Geometry {
                serial: 0,
                x: 0,
                y: 0,
                width: 1,
                height: 1,
                format: FORMAT_XRGB8888,
                flags: 1,
            }
            .encode(&mut [0u8; 32]),
            Err(DecodeError::BadFlags)
        );

        // Object id 0 is refused: SET_GEOMETRY targets a surface.
        assert_eq!(
            Body::decode(Opcode::SET_GEOMETRY.value(), 0, &set_wire),
            Err(DecodeError::BadObject)
        );
        // GEOMETRY carries its surface and accepts object 0.
        assert_eq!(
            Body::decode(Opcode::GEOMETRY.value(), 0, &geometry_wire),
            Ok(geometry)
        );

        // Dimensions out of range and foreign formats are rejected.
        let mut zero_width = set_wire;
        zero_width[8..12].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            Body::decode(Opcode::SET_GEOMETRY.value(), 7, &zero_width),
            Err(DecodeError::BadValue)
        );
        let mut too_tall = set_wire;
        too_tall[12..16].copy_from_slice(&(MAX_SURFACE_DIM + 1).to_le_bytes());
        assert_eq!(
            Body::decode(Opcode::SET_GEOMETRY.value(), 7, &too_tall),
            Err(DecodeError::BadValue)
        );
        let mut bad_format = set_wire;
        bad_format[16..20].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            Body::decode(Opcode::SET_GEOMETRY.value(), 7, &bad_format),
            Err(DecodeError::BadValue)
        );
        for invalid in [
            Body::SetGeometry {
                x: 0,
                y: 0,
                width: 0,
                height: 1,
                format: FORMAT_XRGB8888,
            },
            Body::SetGeometry {
                x: 0,
                y: 0,
                width: 1,
                height: MAX_SURFACE_DIM + 1,
                format: FORMAT_XRGB8888,
            },
            Body::SetGeometry {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
                format: 1,
            },
        ] {
            assert_eq!(invalid.encode(&mut [0u8; 24]), Err(DecodeError::BadValue));
        }
    }
}
