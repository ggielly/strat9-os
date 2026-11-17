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

//! 32-byte normalized input event (A.5).
//!
//! | Offset | Field          | Type |
//! |--------|----------------|------|
//! | 0      | `timestamp_ns` | u64  |
//! | 8      | `sequence`     | u64  |
//! | 16     | `device_id`    | u32  |
//! | 20     | `event_type`   | u16  |
//! | 22     | `code`         | u16  |
//! | 24     | `value`        | i32  |
//! | 28     | `flags`        | u32  |

use crate::constants::*;
use crate::error::InputError;

/// One normalized input event.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct NormalizedEvent {
    pub timestamp_ns: u64,
    pub sequence: u64,
    pub device_id: u32,
    pub event_type: u16,
    pub code: u16,
    pub value: i32,
    pub flags: u32,
}

impl core::fmt::Debug for NormalizedEvent {
    /// Redacted: no keycode, value, timestamp or sequence is printed.
    /// The document forbids logging typed content, keycodes and typing timing.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NormalizedEvent")
            .field("device_id", &self.device_id)
            .field("event_type", &self.event_type)
            .field("flags", &self.flags)
            .finish_non_exhaustive()
    }
}

/// Validate the fields shared by every event and record.
///
/// The text area is not considered here; only [`crate::InputRecord`] owns it.
pub(crate) fn check_fields(
    event_type: u16,
    code: u16,
    value: i32,
    flags: u32,
) -> Result<(), InputError> {
    if !(INPUT_EVENT_POINTER_ENTER..=INPUT_EVENT_FOCUS_LOST).contains(&event_type) {
        return Err(InputError::UnknownEvent);
    }

    let absolute_motion = event_type == INPUT_EVENT_POINTER_MOTION && flags == INPUT_FLAG_ABSOLUTE;
    if flags != 0 && !absolute_motion {
        return Err(InputError::BadFlags);
    }

    match event_type {
        INPUT_EVENT_POINTER_MOTION => {
            if !(i16::MIN as i32..=i16::MAX as i32).contains(&value) {
                return Err(InputError::Overflow);
            }
        }
        INPUT_EVENT_POINTER_BUTTON | INPUT_EVENT_KEY => {
            if value != 0 && value != 1 {
                return Err(InputError::BadValue);
            }
        }
        INPUT_EVENT_POINTER_AXIS => {
            if code != 0 && code != 1 {
                return Err(InputError::BadValue);
            }
        }
        INPUT_EVENT_TEXT => {
            if code != 0 || !(1..=INPUT_TEXT_LEN as i32).contains(&value) {
                return Err(InputError::BadValue);
            }
        }
        INPUT_EVENT_FOCUS_GAINED | INPUT_EVENT_FOCUS_LOST => {
            if code != 0 || value != 0 {
                return Err(InputError::BadValue);
            }
        }
        // POINTER_ENTER / POINTER_LEAVE: code and value are not constrained.
        _ => {}
    }

    Ok(())
}

impl NormalizedEvent {
    /// Check this event against the A.5 field rules.
    pub fn check(&self) -> Result<(), InputError> {
        check_fields(self.event_type, self.code, self.value, self.flags)
    }

    /// Decode an event. The buffer length must be exactly
    /// [`NORMALIZED_EVENT_LEN`].
    pub fn decode(bytes: &[u8]) -> Result<NormalizedEvent, InputError> {
        if bytes.len() < NORMALIZED_EVENT_LEN {
            return Err(InputError::Truncated);
        }
        if bytes.len() > NORMALIZED_EVENT_LEN {
            return Err(InputError::SizeMismatch);
        }

        let event = NormalizedEvent {
            timestamp_ns: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            sequence: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            device_id: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
            event_type: u16::from_le_bytes(bytes[20..22].try_into().unwrap()),
            code: u16::from_le_bytes(bytes[22..24].try_into().unwrap()),
            value: i32::from_le_bytes(bytes[24..28].try_into().unwrap()),
            flags: u32::from_le_bytes(bytes[28..32].try_into().unwrap()),
        };
        event.check()?;
        Ok(event)
    }

    /// Encode this event into `out`, which must hold at least
    /// [`NORMALIZED_EVENT_LEN`] bytes.
    pub fn encode(&self, out: &mut [u8]) -> Result<(), InputError> {
        self.check()?;
        if out.len() < NORMALIZED_EVENT_LEN {
            return Err(InputError::Truncated);
        }

        out[0..8].copy_from_slice(&self.timestamp_ns.to_le_bytes());
        out[8..16].copy_from_slice(&self.sequence.to_le_bytes());
        out[16..20].copy_from_slice(&self.device_id.to_le_bytes());
        out[20..22].copy_from_slice(&self.event_type.to_le_bytes());
        out[22..24].copy_from_slice(&self.code.to_le_bytes());
        out[24..28].copy_from_slice(&self.value.to_le_bytes());
        out[28..32].copy_from_slice(&self.flags.to_le_bytes());
        Ok(())
    }
}
