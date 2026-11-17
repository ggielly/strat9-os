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

//! `inputd` subscription payloads (A.5), tag excluded.
//!
//! `INPUTD_MSG_BATCH` carries exactly [`crate::InputBatch::encode`] bytes;
//! this module owns the request/ack/reset/focus payloads around it.

use crate::constants::*;
use crate::error::InputError;

/// `Subscribe` payload.
///
/// | Offset | Field         | Type |
/// |--------|---------------|------|
/// | 0      | `focus_epoch` | u32  |
/// | 4      | `path_len`    | u16  |
/// | 6      | reserved = 0  | u16  |
/// | 8      | `path`        | `path_len` bytes |
///
/// `path_len` is `1..=64`. The struct stores the path only; `path_len` and the
/// reserved field are derived at encode time.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Subscribe<'a> {
    pub focus_epoch: u32,
    pub path: &'a [u8],
}

impl core::fmt::Debug for Subscribe<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Subscribe")
            .field("focus_epoch", &self.focus_epoch)
            .field("path_len", &self.path.len())
            .finish()
    }
}

impl<'a> Subscribe<'a> {
    /// Decode a `Subscribe` payload. The length must be exactly
    /// `8 + path_len`.
    pub fn decode(body: &'a [u8]) -> Result<Subscribe<'a>, InputError> {
        if body.len() < SUBSCRIBE_FIXED_LEN {
            return Err(InputError::Truncated);
        }

        let focus_epoch = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
        let path_len = u16::from_le_bytes([body[4], body[5]]) as usize;
        let reserved = u16::from_le_bytes([body[6], body[7]]);
        if path_len > MAX_SUBSCRIBE_PATH {
            return Err(InputError::PathTooLong);
        }
        if path_len == 0 {
            return Err(InputError::BadValue);
        }
        if reserved != 0 {
            return Err(InputError::BadValue);
        }

        let required = SUBSCRIBE_FIXED_LEN + path_len;
        if body.len() < required {
            return Err(InputError::Truncated);
        }
        if body.len() > required {
            return Err(InputError::SizeMismatch);
        }

        Ok(Subscribe {
            focus_epoch,
            path: &body[SUBSCRIBE_FIXED_LEN..],
        })
    }

    /// Encode this payload into `out`, which must hold at least its encoded
    /// length (`8 + path.len()`).
    pub fn encode(&self, out: &mut [u8]) -> Result<(), InputError> {
        if self.path.len() > MAX_SUBSCRIBE_PATH {
            return Err(InputError::PathTooLong);
        }
        if self.path.is_empty() {
            return Err(InputError::BadValue);
        }

        let required = SUBSCRIBE_FIXED_LEN + self.path.len();
        if out.len() < required {
            return Err(InputError::Truncated);
        }

        out[0..4].copy_from_slice(&self.focus_epoch.to_le_bytes());
        out[4..6].copy_from_slice(&(self.path.len() as u16).to_le_bytes());
        out[6..8].copy_from_slice(&0u16.to_le_bytes());
        out[8..required].copy_from_slice(self.path);
        Ok(())
    }
}

/// `SubscribeAck` payload: a single `status` word.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct SubscribeAck {
    pub status: u32,
}

impl SubscribeAck {
    /// Decode a `SubscribeAck` payload. The buffer length must be exactly
    /// [`SUBSCRIBE_ACK_LEN`].
    pub fn decode(body: &[u8]) -> Result<SubscribeAck, InputError> {
        if body.len() < SUBSCRIBE_ACK_LEN {
            return Err(InputError::Truncated);
        }
        if body.len() > SUBSCRIBE_ACK_LEN {
            return Err(InputError::SizeMismatch);
        }

        let status = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
        if status > SUBSCRIBE_STATUS_INTERNAL {
            return Err(InputError::BadValue);
        }
        Ok(SubscribeAck { status })
    }

    /// Encode this payload into `out`, which must hold at least
    /// [`SUBSCRIBE_ACK_LEN`] bytes.
    pub fn encode(&self, out: &mut [u8]) -> Result<(), InputError> {
        if self.status > SUBSCRIBE_STATUS_INTERNAL {
            return Err(InputError::BadValue);
        }
        if out.len() < SUBSCRIBE_ACK_LEN {
            return Err(InputError::Truncated);
        }

        out[..SUBSCRIBE_ACK_LEN].copy_from_slice(&self.status.to_le_bytes());
        Ok(())
    }
}

/// `Focus` payload: a subscriber requests input focus for its own path.
///
/// | Offset | Field         | Type |
/// |--------|---------------|------|
/// | 0      | `focus_epoch` | u32  |
/// | 4      | `path_len`    | u16  |
/// | 6      | reserved = 0  | u16  |
/// | 8      | `path`        | `path_len` bytes |
///
/// `path_len` is `1..=64`. The struct stores the path only; `path_len` and the
/// reserved field are derived at encode time.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Focus<'a> {
    pub focus_epoch: u32,
    pub path: &'a [u8],
}

impl core::fmt::Debug for Focus<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Focus")
            .field("focus_epoch", &self.focus_epoch)
            .field("path_len", &self.path.len())
            .finish()
    }
}

impl<'a> Focus<'a> {
    /// Decode a `Focus` payload. The length must be exactly `8 + path_len`.
    pub fn decode(body: &'a [u8]) -> Result<Focus<'a>, InputError> {
        if body.len() < FOCUS_FIXED_LEN {
            return Err(InputError::Truncated);
        }

        let focus_epoch = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
        let path_len = u16::from_le_bytes([body[4], body[5]]) as usize;
        let reserved = u16::from_le_bytes([body[6], body[7]]);
        if path_len > MAX_FOCUS_PATH {
            return Err(InputError::PathTooLong);
        }
        if path_len == 0 {
            return Err(InputError::BadValue);
        }
        if reserved != 0 {
            return Err(InputError::BadValue);
        }

        let required = FOCUS_FIXED_LEN + path_len;
        if body.len() < required {
            return Err(InputError::Truncated);
        }
        if body.len() > required {
            return Err(InputError::SizeMismatch);
        }

        Ok(Focus {
            focus_epoch,
            path: &body[FOCUS_FIXED_LEN..],
        })
    }

    /// Encode this payload into `out`, which must hold at least its encoded
    /// length (`8 + path.len()`).
    pub fn encode(&self, out: &mut [u8]) -> Result<(), InputError> {
        if self.path.len() > MAX_FOCUS_PATH {
            return Err(InputError::PathTooLong);
        }
        if self.path.is_empty() {
            return Err(InputError::BadValue);
        }

        let required = FOCUS_FIXED_LEN + self.path.len();
        if out.len() < required {
            return Err(InputError::Truncated);
        }

        out[0..4].copy_from_slice(&self.focus_epoch.to_le_bytes());
        out[4..6].copy_from_slice(&(self.path.len() as u16).to_le_bytes());
        out[6..8].copy_from_slice(&0u16.to_le_bytes());
        out[8..required].copy_from_slice(self.path);
        Ok(())
    }
}

/// `Reset` payload: `{ focus_epoch u32, reason u32 }`, exactly 8 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Reset {
    pub focus_epoch: u32,
    pub reason: u32,
}

impl Reset {
    /// Decode a `Reset` payload. The buffer length must be exactly
    /// [`RESET_LEN`].
    pub fn decode(body: &[u8]) -> Result<Reset, InputError> {
        if body.len() < RESET_LEN {
            return Err(InputError::Truncated);
        }
        if body.len() > RESET_LEN {
            return Err(InputError::SizeMismatch);
        }

        let reset = Reset {
            focus_epoch: u32::from_le_bytes([body[0], body[1], body[2], body[3]]),
            reason: u32::from_le_bytes([body[4], body[5], body[6], body[7]]),
        };
        if reset.reason != RESET_REASON_RESYNC && reset.reason != RESET_REASON_SERVICE_CHANGED {
            return Err(InputError::BadValue);
        }
        Ok(reset)
    }

    /// Encode this payload into `out`, which must hold at least [`RESET_LEN`]
    /// bytes.
    pub fn encode(&self, out: &mut [u8]) -> Result<(), InputError> {
        if self.reason != RESET_REASON_RESYNC && self.reason != RESET_REASON_SERVICE_CHANGED {
            return Err(InputError::BadValue);
        }
        if out.len() < RESET_LEN {
            return Err(InputError::Truncated);
        }

        out[0..4].copy_from_slice(&self.focus_epoch.to_le_bytes());
        out[4..8].copy_from_slice(&self.reason.to_le_bytes());
        Ok(())
    }
}
