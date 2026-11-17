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

//! Wire constants for the normalized input protocol (A.5).

/// Encoded size of a [`crate::NormalizedEvent`].
pub const NORMALIZED_EVENT_LEN: usize = 32;
/// Encoded size of the text area of an [`crate::InputRecord`].
pub const INPUT_TEXT_LEN: usize = 16;
/// Encoded size of an [`crate::InputRecord`].
pub const INPUT_RECORD_LEN: usize = NORMALIZED_EVENT_LEN + INPUT_TEXT_LEN;
/// Maximum number of records in an [`crate::InputBatch`].
pub const MAX_INPUT_RECORDS: usize = 16;
/// Fixed `InputBatch` header size, records excluded.
pub const INPUT_BATCH_FIXED_LEN: usize = 8;
/// Maximum encoded subscription path length.
pub const MAX_SUBSCRIBE_PATH: usize = 64;
/// Fixed `Subscribe` header size, path excluded.
pub const SUBSCRIBE_FIXED_LEN: usize = 8;
/// Encoded size of a `SubscribeAck`.
pub const SUBSCRIBE_ACK_LEN: usize = 4;
/// Encoded size of a `Reset`.
pub const RESET_LEN: usize = 8;
/// Maximum encoded `Focus` path length.
pub const MAX_FOCUS_PATH: usize = 64;
/// Fixed `Focus` header size, path excluded.
pub const FOCUS_FIXED_LEN: usize = 8;

/// `POINTER_ENTER`: pointer entered the surface.
pub const INPUT_EVENT_POINTER_ENTER: u16 = 1;
/// `POINTER_LEAVE`: pointer left the surface.
pub const INPUT_EVENT_POINTER_LEAVE: u16 = 2;
/// `POINTER_MOTION`: `value` = x/dx, `code` = y/dy.
pub const INPUT_EVENT_POINTER_MOTION: u16 = 3;
/// `POINTER_BUTTON`: `code` = button, `value` = pressed/released.
pub const INPUT_EVENT_POINTER_BUTTON: u16 = 4;
/// `POINTER_AXIS`: `code` = axis, `value` = delta.
pub const INPUT_EVENT_POINTER_AXIS: u16 = 5;
/// `KEY`: `code` = physical key, `value` = pressed/released.
pub const INPUT_EVENT_KEY: u16 = 6;
/// `TEXT`: `text` holds `value` UTF-8 bytes.
pub const INPUT_EVENT_TEXT: u16 = 7;
/// `FOCUS_GAINED`.
pub const INPUT_EVENT_FOCUS_GAINED: u16 = 8;
/// `FOCUS_LOST`.
pub const INPUT_EVENT_FOCUS_LOST: u16 = 9;

/// Record flag bit 0: motion coordinates are absolute.
///
/// Only valid on [`INPUT_EVENT_POINTER_MOTION`].
pub const INPUT_FLAG_ABSOLUTE: u32 = 1 << 0;

/// `Subscribe` tag.
pub const INPUTD_MSG_SUBSCRIBE: u16 = 1;
/// `SubscribeAck` tag.
pub const INPUTD_MSG_SUBSCRIBE_ACK: u16 = 2;
/// `Unsubscribe` tag.
pub const INPUTD_MSG_UNSUBSCRIBE: u16 = 3;
/// `InputBatch` payload tag.
pub const INPUTD_MSG_BATCH: u16 = 4;
/// `Reset` tag.
pub const INPUTD_MSG_RESET: u16 = 5;
/// `Focus` tag: a subscriber asks to take input focus.
pub const INPUTD_MSG_FOCUS: u16 = 6;

/// `SubscribeAck` status: subscription accepted.
pub const SUBSCRIBE_STATUS_ACCEPTED: u32 = 0;
/// `SubscribeAck` status: subscription table is full.
pub const SUBSCRIBE_STATUS_TABLE_FULL: u32 = 1;
/// `SubscribeAck` status: path is invalid.
pub const SUBSCRIBE_STATUS_BAD_PATH: u32 = 2;
/// `SubscribeAck` status: internal error.
pub const SUBSCRIBE_STATUS_INTERNAL: u32 = 3;

/// `Reset` reason: input state must be resynchronised.
pub const RESET_REASON_RESYNC: u32 = 1;
/// `Reset` reason: the input service changed.
pub const RESET_REASON_SERVICE_CHANGED: u32 = 2;
