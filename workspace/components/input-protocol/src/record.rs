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

//! 48-byte `InputRecord`: a [`NormalizedEvent`] plus a 16-byte text area.
//!
//! `text` is used only by `TEXT`: `value` holds its length in `1..=16`, the
//! bytes `[..value]` must be valid UTF-8 and the rest must be zero. Every
//! other event type must leave the whole text area zero.

use crate::constants::*;
use crate::error::InputError;
use crate::event::NormalizedEvent;

/// One normalized input record.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct InputRecord {
    pub event: NormalizedEvent,
    pub text: [u8; INPUT_TEXT_LEN],
}

impl core::fmt::Debug for InputRecord {
    /// Redacted: the text bytes are never printed, only their length.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text_len = if self.event.event_type == INPUT_EVENT_TEXT {
            self.event.value.max(0) as u32
        } else {
            0
        };
        f.debug_struct("InputRecord")
            .field("event", &self.event)
            .field("text_len", &text_len)
            .finish()
    }
}

impl InputRecord {
    /// Check this record against the A.5 field and text rules.
    pub fn check(&self) -> Result<(), InputError> {
        self.event.check()?;

        if self.event.event_type == INPUT_EVENT_TEXT {
            let len = self.event.value as usize;
            if core::str::from_utf8(&self.text[..len]).is_err() {
                return Err(InputError::NotUtf8);
            }
            if self.text[len..].iter().any(|&byte| byte != 0) {
                return Err(InputError::BadValue);
            }
        } else if self.text.iter().any(|&byte| byte != 0) {
            return Err(InputError::BadValue);
        }

        Ok(())
    }

    /// Decode a record. The buffer length must be exactly
    /// [`INPUT_RECORD_LEN`].
    pub fn decode(bytes: &[u8]) -> Result<InputRecord, InputError> {
        if bytes.len() < INPUT_RECORD_LEN {
            return Err(InputError::Truncated);
        }
        if bytes.len() > INPUT_RECORD_LEN {
            return Err(InputError::SizeMismatch);
        }

        let event = NormalizedEvent::decode(&bytes[..NORMALIZED_EVENT_LEN])?;
        let mut text = [0u8; INPUT_TEXT_LEN];
        text.copy_from_slice(&bytes[NORMALIZED_EVENT_LEN..]);
        let record = InputRecord { event, text };
        record.check()?;
        Ok(record)
    }

    /// Encode this record into `out`, which must hold at least
    /// [`INPUT_RECORD_LEN`] bytes.
    pub fn encode(&self, out: &mut [u8]) -> Result<(), InputError> {
        self.check()?;
        if out.len() < INPUT_RECORD_LEN {
            return Err(InputError::Truncated);
        }

        self.event.encode(&mut out[..NORMALIZED_EVENT_LEN])?;
        out[NORMALIZED_EVENT_LEN..INPUT_RECORD_LEN].copy_from_slice(&self.text);
        Ok(())
    }
}
