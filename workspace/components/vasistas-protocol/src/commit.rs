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

//! `COMMIT` request body (Annexe A.4).
//!
//! Body layout, header excluded:
//!
//! | Offset | Field         | Type |
//! |--------|---------------|------|
//! | 0      | `buffer`      | u64  |
//! | 8      | `ack_serial`  | u64  |
//! | 16     | `commit_id`   | u64  |
//! | 24     | `flags`       | u32  |
//! | 28     | `rect_count`  | u16  |
//! | 30     | reserved = 0  | u16  |
//! | 32     | `rect_count` rects | 16 bytes each |
//!
//! Each rect is `{x i32, y i32, w u32, h u32}` describing the half-open
//! interval `[x, x + w)` (resp. `[y, y + h)`).
//!
//! ## Coordinate bound
//!
//! Rectangles live in the surface's signed `i32` coordinate space. A rect is
//! accepted only when its *end* coordinate is still representable:
//!
//! ```text
//! x as i64 + w as i64 <= i32::MAX   and   y as i64 + h as i64 <= i32::MAX
//! ```
//!
//! The additions are performed in `i64`, so no intermediate overflow can
//! occur. Width and height are `u32`, so `w <= u32::MAX` and `h <= u32::MAX`
//! hold by construction. The lower bound of the end coordinate cannot
//! underflow (`i32::MIN` plus a non-negative `u32` is `>= i32::MIN`).
//! Negative origins are *not* rejected here: whether a rect must be clipped to
//! the surface is an acceptance policy for `vasistas-core`, not a wire-format
//! rule. A violating rect yields [`DecodeError::Overflow`], both on decode and
//! on encode.

use crate::error::DecodeError;

/// Maximum number of rects in one `COMMIT`.
pub const MAX_RECTS: usize = 32;

/// Encoded size of a single rect.
pub const RECT_LEN: usize = 16;

/// Encoded size of the fixed `COMMIT` body fields, rects excluded.
pub const COMMIT_BODY_LEN: usize = 32;

/// `FULL_DAMAGE`: the whole surface changed, so `rect_count` must be zero.
pub const FLAG_FULL_DAMAGE: u32 = 1 << 0;

/// One damage rectangle, half-open in both axes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: u32,
    pub h: u32,
}

impl Rect {
    /// Check the half-open extent of this rect (see module docs).
    pub fn check_extent(&self) -> Result<(), DecodeError> {
        let end_x = self.x as i64 + self.w as i64;
        let end_y = self.y as i64 + self.h as i64;
        if end_x > i32::MAX as i64 || end_y > i32::MAX as i64 {
            return Err(DecodeError::Overflow);
        }
        Ok(())
    }
}

/// Decoded `COMMIT` body. Fixed capacity: no allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Commit {
    pub buffer: u64,
    pub ack_serial: u64,
    pub commit_id: u64,
    pub flags: u32,
    pub rect_count: u16,
    pub rects: [Rect; MAX_RECTS],
}

impl Commit {
    /// Bytes needed to encode this commit, rects included.
    pub fn encoded_len(&self) -> usize {
        COMMIT_BODY_LEN + RECT_LEN * self.rect_count as usize
    }

    /// True when `FULL_DAMAGE` is set.
    pub fn is_full_damage(&self) -> bool {
        self.flags & FLAG_FULL_DAMAGE != 0
    }

    /// The `rect_count` valid rects, in wire order.
    pub fn rects(&self) -> &[Rect] {
        &self.rects[..(self.rect_count as usize).min(MAX_RECTS)]
    }

    /// Decode a `COMMIT` body (header excluded). The buffer length must be
    /// exactly `32 + 16 * rect_count`.
    pub fn decode(body: &[u8]) -> Result<Commit, DecodeError> {
        if body.len() < COMMIT_BODY_LEN {
            return Err(DecodeError::Truncated);
        }

        let buffer = u64::from_le_bytes([
            body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
        ]);
        let ack_serial = u64::from_le_bytes([
            body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
        ]);
        let commit_id = u64::from_le_bytes([
            body[16], body[17], body[18], body[19], body[20], body[21], body[22], body[23],
        ]);
        let flags = u32::from_le_bytes([body[24], body[25], body[26], body[27]]);
        let rect_count = u16::from_le_bytes([body[28], body[29]]);
        let reserved = u16::from_le_bytes([body[30], body[31]]);

        if reserved != 0 {
            return Err(DecodeError::ReservedNonZero);
        }
        if flags & !FLAG_FULL_DAMAGE != 0 {
            return Err(DecodeError::BadFlags);
        }
        if rect_count as usize > MAX_RECTS {
            return Err(DecodeError::TooManyRects);
        }
        if flags & FLAG_FULL_DAMAGE != 0 && rect_count != 0 {
            return Err(DecodeError::BadFlags);
        }

        let required = COMMIT_BODY_LEN
            .checked_add(
                (rect_count as usize)
                    .checked_mul(RECT_LEN)
                    .ok_or(DecodeError::Overflow)?,
            )
            .ok_or(DecodeError::Overflow)?;
        if body.len() < required {
            return Err(DecodeError::Truncated);
        }
        if body.len() > required {
            return Err(DecodeError::SizeMismatch);
        }

        let mut rects = [Rect::default(); MAX_RECTS];
        for (index, rect) in rects.iter_mut().enumerate().take(rect_count as usize) {
            let at = COMMIT_BODY_LEN + index * RECT_LEN;
            let x = i32::from_le_bytes([body[at], body[at + 1], body[at + 2], body[at + 3]]);
            let y = i32::from_le_bytes([body[at + 4], body[at + 5], body[at + 6], body[at + 7]]);
            let w = u32::from_le_bytes([body[at + 8], body[at + 9], body[at + 10], body[at + 11]]);
            let h =
                u32::from_le_bytes([body[at + 12], body[at + 13], body[at + 14], body[at + 15]]);
            let decoded = Rect { x, y, w, h };
            decoded.check_extent()?;
            *rect = decoded;
        }

        Ok(Commit {
            buffer,
            ack_serial,
            commit_id,
            flags,
            rect_count,
            rects,
        })
    }

    /// Encode this commit into `out`, which must hold at least
    /// [`Commit::encoded_len`] bytes.
    pub fn encode(&self, out: &mut [u8]) -> Result<(), DecodeError> {
        if self.flags & !FLAG_FULL_DAMAGE != 0 {
            return Err(DecodeError::BadFlags);
        }
        if self.rect_count as usize > MAX_RECTS {
            return Err(DecodeError::TooManyRects);
        }
        if self.flags & FLAG_FULL_DAMAGE != 0 && self.rect_count != 0 {
            return Err(DecodeError::BadFlags);
        }
        for rect in self.rects() {
            rect.check_extent()?;
        }

        let required = self.encoded_len();
        if out.len() < required {
            return Err(DecodeError::Truncated);
        }

        out[0..8].copy_from_slice(&self.buffer.to_le_bytes());
        out[8..16].copy_from_slice(&self.ack_serial.to_le_bytes());
        out[16..24].copy_from_slice(&self.commit_id.to_le_bytes());
        out[24..28].copy_from_slice(&self.flags.to_le_bytes());
        out[28..30].copy_from_slice(&self.rect_count.to_le_bytes());
        out[30..32].copy_from_slice(&0u16.to_le_bytes());

        for (index, rect) in self.rects().iter().enumerate() {
            let at = COMMIT_BODY_LEN + index * RECT_LEN;
            out[at..at + 4].copy_from_slice(&rect.x.to_le_bytes());
            out[at + 4..at + 8].copy_from_slice(&rect.y.to_le_bytes());
            out[at + 8..at + 12].copy_from_slice(&rect.w.to_le_bytes());
            out[at + 12..at + 16].copy_from_slice(&rect.h.to_le_bytes());
        }
        Ok(())
    }
}
