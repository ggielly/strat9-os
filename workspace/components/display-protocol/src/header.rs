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

//! 32-byte protocol header (Annexe A.2).
//!
//! Fixed layout, little-endian, field by field:
//!
//! | Offset | Field          | Type |
//! |--------|----------------|------|
//! | 0      | `magic`        | u32  |
//! | 4      | `major`        | u16  |
//! | 6      | `minor`        | u16  |
//! | 8      | `opcode`       | u16  |
//! | 10     | `flags`        | u16  |
//! | 12     | `message_bytes`| u32  |
//! | 16     | `object_id`    | u64  |
//! | 24     | `request_id`   | u64  |

use crate::error::DecodeError;

/// Encoded header size in bytes.
pub const HEADER_LEN: usize = 32;

/// Header magic, little-endian value of `b"S9DP"`.
pub const MAGIC: u32 = u32::from_le_bytes(*b"S9DP");

/// Supported protocol major version.
pub const VERSION_MAJOR: u16 = 1;

/// Supported protocol minor version.
pub const VERSION_MINOR: u16 = 0;

/// Protocol header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub opcode: u16,
    /// Reserved in v1: must be `0`.
    pub flags: u16,
    /// Total message size in bytes, header included.
    pub message_bytes: u32,
    /// Target object; `0` means the connection itself.
    pub object_id: u64,
    /// Non-zero request correlation id; `0` for unsolicited events.
    pub request_id: u64,
}

impl Header {
    /// Decode a header from the first 32 bytes of `bytes`.
    ///
    /// Bytes past the header are ignored here; see [`Header::decode_message`]
    /// for the whole-message variant.
    pub fn decode(bytes: &[u8]) -> Result<Header, DecodeError> {
        if bytes.len() < HEADER_LEN {
            return Err(DecodeError::Truncated);
        }

        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != MAGIC {
            return Err(DecodeError::BadMagic);
        }

        let major = u16::from_le_bytes([bytes[4], bytes[5]]);
        let minor = u16::from_le_bytes([bytes[6], bytes[7]]);
        if major != VERSION_MAJOR || minor != VERSION_MINOR {
            return Err(DecodeError::UnsupportedVersion);
        }

        let opcode = u16::from_le_bytes([bytes[8], bytes[9]]);
        let flags = u16::from_le_bytes([bytes[10], bytes[11]]);
        let message_bytes = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let object_id = u64::from_le_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);
        let request_id = u64::from_le_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]);

        if flags != 0 {
            return Err(DecodeError::BadFlags);
        }
        if message_bytes < HEADER_LEN as u32 {
            return Err(DecodeError::SizeMismatch);
        }

        Ok(Header {
            opcode,
            flags,
            message_bytes,
            object_id,
            request_id,
        })
    }

    /// Decode a header and return it with the message body that follows it.
    ///
    /// The declared `message_bytes` must equal `bytes.len()`; the returned
    /// slice is `bytes[HEADER_LEN..]`.
    pub fn decode_message(bytes: &[u8]) -> Result<(Header, &[u8]), DecodeError> {
        let header = Header::decode(bytes)?;
        if header.message_bytes as usize != bytes.len() {
            return Err(DecodeError::SizeMismatch);
        }
        Ok((header, &bytes[HEADER_LEN..]))
    }

    /// Encode this header into `out`, which must hold at least 32 bytes.
    ///
    /// `out` may be longer; only the first 32 bytes are written.
    pub fn encode(&self, out: &mut [u8]) -> Result<(), DecodeError> {
        if out.len() < HEADER_LEN {
            return Err(DecodeError::Truncated);
        }
        if self.flags != 0 {
            return Err(DecodeError::BadFlags);
        }
        if self.message_bytes < HEADER_LEN as u32 {
            return Err(DecodeError::SizeMismatch);
        }

        out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&VERSION_MAJOR.to_le_bytes());
        out[6..8].copy_from_slice(&VERSION_MINOR.to_le_bytes());
        out[8..10].copy_from_slice(&self.opcode.to_le_bytes());
        out[10..12].copy_from_slice(&self.flags.to_le_bytes());
        out[12..16].copy_from_slice(&self.message_bytes.to_le_bytes());
        out[16..24].copy_from_slice(&self.object_id.to_le_bytes());
        out[24..32].copy_from_slice(&self.request_id.to_le_bytes());
        Ok(())
    }
}
