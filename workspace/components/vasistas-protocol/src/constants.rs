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

//! Numeric constants from `docs/GUI_AUDIT_2026-11.md` Annexe A.3.1.
//!
//! Everything here is copied verbatim from the specification; no value is
//! inferred.

/// `XRGB8888`: logical value `0x00RRGGBB`, little-endian bytes `B,G,R,X`.
pub const FORMAT_XRGB8888: u32 = 0;

/// `REQUEST_WINDOW_ACTION` action: minimize.
pub const WINDOW_ACTION_MINIMIZE: u32 = 1;
/// `REQUEST_WINDOW_ACTION` action: restore.
pub const WINDOW_ACTION_RESTORE: u32 = 2;
/// `REQUEST_WINDOW_ACTION` action: maximize.
pub const WINDOW_ACTION_MAXIMIZE: u32 = 3;
/// `REQUEST_WINDOW_ACTION` action: raise.
pub const WINDOW_ACTION_RAISE: u32 = 4;
/// `REQUEST_WINDOW_ACTION` action: lower.
pub const WINDOW_ACTION_LOWER: u32 = 5;

/// `SET_CURSOR_SHAPE` shape: default arrow.
pub const CURSOR_SHAPE_DEFAULT: u32 = 0;
/// `SET_CURSOR_SHAPE` shape: text caret.
pub const CURSOR_SHAPE_TEXT: u32 = 1;
/// `SET_CURSOR_SHAPE` shape: pointer hand.
pub const CURSOR_SHAPE_POINTER: u32 = 2;

/// `IMPORT_RESULT` status: the buffer was imported.
pub const IMPORT_OK: u32 = 0;
/// `IMPORT_RESULT` status: the buffer import failed.
pub const IMPORT_FAILED: u32 = 1;

/// `CLOSE_REQUEST` reason: the client requested the close.
pub const CLOSE_REASON_REQUESTED: u32 = 1;
/// `CLOSE_REQUEST` reason: the surface was destroyed.
pub const CLOSE_REASON_DESTROYED: u32 = 2;
/// `CLOSE_REQUEST` reason: the server is shutting down.
pub const CLOSE_REASON_SHUTDOWN: u32 = 3;

/// `INPUT_RESET` reason: input state must be resynchronised.
pub const INPUT_RESET_RESYNC: u32 = 1;
/// `INPUT_RESET` reason: the input service changed.
pub const INPUT_RESET_SERVICE_CHANGED: u32 = 2;

/// `ERROR` code: unknown flag or non-zero reserved field.
pub const ERROR_BAD_FLAGS: u32 = 1;
/// `ERROR` code: declared length is inconsistent.
pub const ERROR_BAD_LENGTH: u32 = 2;
/// `ERROR` code: unknown or foreign object.
pub const ERROR_BAD_OBJECT: u32 = 3;
/// `ERROR` code: the object is not in a valid state.
pub const ERROR_BAD_STATE: u32 = 4;
/// `ERROR` code: no commit credit available.
pub const ERROR_NO_CREDIT: u32 = 5;
/// `ERROR` code: pixel quota exceeded.
pub const ERROR_QUOTA: u32 = 6;
/// `ERROR` code: unsupported operation or version.
pub const ERROR_UNSUPPORTED: u32 = 7;
/// `ERROR` code: unsupported pixel format.
pub const ERROR_BAD_FORMAT: u32 = 8;
/// `ERROR` code: internal server failure.
pub const ERROR_INTERNAL: u32 = 9;

/// Input record event type: pointer entered the surface.
pub const INPUT_EVENT_POINTER_ENTER: u16 = 1;
/// Input record event type: pointer left the surface.
pub const INPUT_EVENT_POINTER_LEAVE: u16 = 2;
/// Input record event type: pointer moved.
pub const INPUT_EVENT_POINTER_MOTION: u16 = 3;
/// Input record event type: pointer button changed.
pub const INPUT_EVENT_POINTER_BUTTON: u16 = 4;
/// Input record event type: pointer axis (wheel) moved.
pub const INPUT_EVENT_POINTER_AXIS: u16 = 5;
/// Input record event type: physical key changed.
pub const INPUT_EVENT_KEY: u16 = 6;
/// Input record event type: composed text.
pub const INPUT_EVENT_TEXT: u16 = 7;
/// Input record event type: focus gained.
pub const INPUT_EVENT_FOCUS_GAINED: u16 = 8;
/// Input record event type: focus lost.
pub const INPUT_EVENT_FOCUS_LOST: u16 = 9;

/// `INPUT_BATCH` record flag bit 0: motion coordinates are absolute.
pub const INPUT_FLAG_ABSOLUTE: u32 = 1 << 0;

/// Maximum client name length in bytes (`HELLO`).
pub const MAX_NAME: usize = 64;
/// Maximum client path length in bytes (`HELLO`).
pub const MAX_PATH: usize = 64;
/// Maximum surface title length in bytes.
pub const MAX_TITLE: usize = 128;
/// Maximum `ERROR` detail length in bytes.
pub const MAX_ERROR_DETAIL: usize = 128;
/// Maximum number of `INPUT_BATCH` records.
pub const MAX_INPUT_RECORDS: usize = 16;
/// Encoded size of one `INPUT_BATCH` record.
pub const INPUT_RECORD_LEN: usize = 48;
/// Fixed `INPUT_BATCH` body size, records excluded.
pub const INPUT_BATCH_FIXED_LEN: usize = 8;
/// Maximum protocol message size, header included.
pub const MAX_MESSAGE_BYTES: u32 = 1008;

/// `FRAME_DONE.flags` bit 0: presentation was submitted (only when
/// `PRESENT_FEEDBACK` was negotiated). Other bits are reserved.
pub const FRAME_DONE_PRESENT_SUBMITTED: u32 = 1;
/// Maximum surface dimension accepted by `CREATE_SURFACE`.
pub const MAX_SURFACE_DIM: u32 = 4096;

/// Size of the `INPUT_BATCH` record text area.
pub const INPUT_TEXT_LEN: usize = 16;
