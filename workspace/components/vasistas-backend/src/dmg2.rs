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

//! `DMG2` presentation encoding.
//!
//! Exact encoder for the binary damage protocol the kernel parses in
//! `workspace/kernel/src/hardware/video/vasistas_scheme.rs` (`Handle::Damage`):
//!
//! ```text
//! "DMG2" | count u16le | display_id u16le | count * { x u16le, y u16le, w u16le, h u16le }
//! ```
//!
//! The kernel accepts a buffer of `>= 8 + count * 8` bytes with `count <= 1024`
//! and silently skips records with `w == 0 || h == 0`. This encoder never emits
//! such a record: it rejects empty rects instead, so a successful encode maps
//! to exactly one presented rectangle per input rect.

use vasistas_protocol::{Rect, MAX_RECTS};

/// Fixed header size: magic, count, display id.
pub const DMG2_HEADER: usize = 8;

/// Encoded size of one rectangle record.
pub const DMG2_RECORD: usize = 8;

/// Maximum number of rectangles accepted by the protocol layer.
pub const DMG2_MAX_RECTS: usize = MAX_RECTS;

/// Presentation encoding failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dmg2Error {
    /// More rectangles than [`DMG2_MAX_RECTS`].
    TooManyRects,
    /// A rectangle is empty, negative or exceeds the `u16` coordinate space.
    OutOfBounds,
    /// The output slice cannot hold the encoded message.
    ShortBuffer,
    /// Size arithmetic overflowed.
    Overflow,
}

/// Encoded length of a `DMG2` message carrying `count` records.
///
/// Returns `None` on arithmetic overflow (unreachable on 64-bit targets for any
/// realistic count; kept for symmetry with the rest of the layer).
pub fn encoded_len(count: usize) -> Option<usize> {
    count.checked_mul(DMG2_RECORD)?.checked_add(DMG2_HEADER)
}

/// Encode `damage` for display `display_id` into `out`.
///
/// Returns the number of bytes written (always [`encoded_len`] of
/// `damage.len()`). Every rectangle is validated before the first byte is
/// written, so an error leaves `out` untouched.
pub fn encode(display_id: u16, damage: &[Rect], out: &mut [u8]) -> Result<usize, Dmg2Error> {
    if damage.len() > DMG2_MAX_RECTS {
        return Err(Dmg2Error::TooManyRects);
    }
    for rect in damage {
        if rect.x < 0 || rect.y < 0 || rect.w == 0 || rect.h == 0 {
            return Err(Dmg2Error::OutOfBounds);
        }
        let end_x = rect.x as i64 + rect.w as i64;
        let end_y = rect.y as i64 + rect.h as i64;
        if end_x > u16::MAX as i64 || end_y > u16::MAX as i64 {
            return Err(Dmg2Error::OutOfBounds);
        }
    }

    let len = encoded_len(damage.len()).ok_or(Dmg2Error::Overflow)?;
    if out.len() < len {
        return Err(Dmg2Error::ShortBuffer);
    }

    out[0..4].copy_from_slice(b"DMG2");
    out[4..6].copy_from_slice(&(damage.len() as u16).to_le_bytes());
    out[6..8].copy_from_slice(&display_id.to_le_bytes());
    for (index, rect) in damage.iter().enumerate() {
        let off = DMG2_HEADER + index * DMG2_RECORD;
        out[off..off + 2].copy_from_slice(&(rect.x as u16).to_le_bytes());
        out[off + 2..off + 4].copy_from_slice(&(rect.y as u16).to_le_bytes());
        out[off + 4..off + 6].copy_from_slice(&(rect.w as u16).to_le_bytes());
        out[off + 6..off + 8].copy_from_slice(&(rect.h as u16).to_le_bytes());
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn rect(x: i32, y: i32, w: u32, h: u32) -> Rect {
        Rect { x, y, w, h }
    }

    /// Mirrors the kernel decoder in `vasistas_scheme.rs` (Handle::Damage).
    fn kernel_parse(buf: &[u8]) -> Option<(u16, Vec<Rect>)> {
        if buf.len() < DMG2_HEADER || !buf.starts_with(b"DMG2") {
            return None;
        }
        let count = u16::from_le_bytes([buf[4], buf[5]]) as usize;
        let display_id = u16::from_le_bytes([buf[6], buf[7]]);
        if count > 1024 || buf.len() < 8 + count.saturating_mul(8) {
            return None;
        }
        let mut rects = Vec::new();
        for i in 0..count {
            let off = 8 + i * 8;
            let x = u16::from_le_bytes([buf[off], buf[off + 1]]) as i32;
            let y = u16::from_le_bytes([buf[off + 2], buf[off + 3]]) as i32;
            let w = u16::from_le_bytes([buf[off + 4], buf[off + 5]]) as u32;
            let h = u16::from_le_bytes([buf[off + 6], buf[off + 7]]) as u32;
            if w == 0 || h == 0 {
                continue;
            }
            rects.push(Rect { x, y, w, h });
        }
        Some((display_id, rects))
    }

    #[test]
    fn encoded_len_checks() {
        assert_eq!(encoded_len(0), Some(8));
        assert_eq!(encoded_len(1), Some(16));
        assert_eq!(encoded_len(DMG2_MAX_RECTS), Some(8 + 32 * 8));
        assert_eq!(encoded_len(usize::MAX), None);
    }

    #[test]
    fn golden_zero_rects() {
        let mut out = [0u8; 8];
        let n = encode(0x1234, &[], &mut out).unwrap();
        assert_eq!(n, 8);
        assert_eq!(out, [b'D', b'M', b'G', b'2', 0, 0, 0x34, 0x12]);
    }

    #[test]
    fn golden_one_rect() {
        let mut out = [0u8; 16];
        let n = encode(0x0007, &[rect(1, 2, 3, 4)], &mut out).unwrap();
        assert_eq!(n, 16);
        assert_eq!(
            out,
            [
                b'D', b'M', b'G', b'2', 1, 0, 7, 0, //
                1, 0, 2, 0, 3, 0, 4, 0,
            ]
        );
    }

    #[test]
    fn golden_two_rects() {
        let mut out = [0u8; 24];
        let n = encode(
            0xFFFF,
            &[rect(1, 2, 3, 4), rect(0x100, 0x200, 0x300, 0x400)],
            &mut out,
        )
        .unwrap();
        assert_eq!(n, 24);
        assert_eq!(
            out,
            [
                b'D', b'M', b'G', b'2', 2, 0, 0xFF, 0xFF, //
                1, 0, 2, 0, 3, 0, 4, 0, //
                0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
            ]
        );
    }

    #[test]
    fn parser_roundtrip() {
        let rects = [
            rect(0, 0, 1280, 800),
            rect(10, 20, 1, 1),
            rect(65535 - 5, 65535 - 7, 5, 7),
        ];
        let mut out = [0u8; 8 + 3 * 8];
        let n = encode(42, &rects, &mut out).unwrap();
        assert_eq!(n, out.len());
        let (id, parsed) = kernel_parse(&out).unwrap();
        assert_eq!(id, 42);
        assert_eq!(parsed, rects.to_vec());
    }

    #[test]
    fn too_many_rects_rejected() {
        let damage = [rect(0, 0, 1, 1); DMG2_MAX_RECTS + 1];
        let mut out = [0u8; 8 + (DMG2_MAX_RECTS + 1) * 8];
        let before = out;
        assert_eq!(encode(0, &damage, &mut out), Err(Dmg2Error::TooManyRects));
        assert_eq!(out, before);
    }

    #[test]
    fn exact_max_rects_accepted() {
        let damage = [rect(0, 0, 1, 1); DMG2_MAX_RECTS];
        let mut out = [0u8; 8 + DMG2_MAX_RECTS * 8];
        assert_eq!(encode(0, &damage, &mut out), Ok(out.len()));
        let (_, parsed) = kernel_parse(&out).unwrap();
        assert_eq!(parsed.len(), DMG2_MAX_RECTS);
    }

    #[test]
    fn bad_rects_rejected_without_partial_write() {
        let mut out = [0xAAu8; 32];
        let before = out;
        assert_eq!(
            encode(0, &[rect(-1, 0, 1, 1)], &mut out),
            Err(Dmg2Error::OutOfBounds)
        );
        assert_eq!(out, before);
        assert_eq!(
            encode(0, &[rect(0, -1, 1, 1)], &mut out),
            Err(Dmg2Error::OutOfBounds)
        );
        assert_eq!(out, before);
        assert_eq!(
            encode(0, &[rect(0, 0, 0, 1)], &mut out),
            Err(Dmg2Error::OutOfBounds)
        );
        assert_eq!(out, before);
        assert_eq!(
            encode(0, &[rect(0, 0, 1, 0)], &mut out),
            Err(Dmg2Error::OutOfBounds)
        );
        assert_eq!(out, before);
        // A bad rect after a valid one is still rejected before any write.
        assert_eq!(
            encode(0, &[rect(0, 0, 1, 1), rect(0, 0, 0, 0)], &mut out),
            Err(Dmg2Error::OutOfBounds)
        );
        assert_eq!(out, before);
    }

    #[test]
    fn coord_beyond_u16_rejected() {
        let mut out = [0u8; 16];
        let before = out;
        // x + w == 65537 > u16::MAX.
        assert_eq!(
            encode(0, &[rect(65535, 0, 2, 1)], &mut out),
            Err(Dmg2Error::OutOfBounds)
        );
        assert_eq!(out, before);
        // y + h > u16::MAX.
        assert_eq!(
            encode(0, &[rect(0, 40000, 1, 40000)], &mut out),
            Err(Dmg2Error::OutOfBounds)
        );
        assert_eq!(out, before);
        // Fits exactly at the limit.
        let mut exact = [0u8; 16];
        assert!(encode(0, &[rect(0, 0, 65535, 65535)], &mut exact).is_ok());
    }

    #[test]
    fn short_out_rejected_without_partial_write() {
        let mut out = [0x5Au8; 24];
        let before = out;
        assert_eq!(
            encode(1, &[rect(1, 1, 1, 1), rect(2, 2, 2, 2)], &mut out[..23]),
            Err(Dmg2Error::ShortBuffer)
        );
        assert_eq!(out, before);
        assert_eq!(encode(1, &[], &mut out[..7]), Err(Dmg2Error::ShortBuffer));
        assert_eq!(encode(1, &[], &mut []), Err(Dmg2Error::ShortBuffer));
    }

    #[test]
    fn display_id_encoding() {
        for id in [0u16, 1, 0x00FF, 0xFF00, 0xFFFF] {
            let mut out = [0u8; 8];
            encode(id, &[], &mut out).unwrap();
            assert_eq!(u16::from_le_bytes([out[6], out[7]]), id);
            assert_eq!(u16::from_le_bytes([out[4], out[5]]), 0);
        }
    }
}
