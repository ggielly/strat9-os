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

//! Bounded view over remotely writable shared pixels.
//!
//! A client surface is shared memory the server maps but does not own: its
//! contents may change at any instant. [`SharedPixels`] never hands out that
//! memory: it exposes no accessor for the underlying bytes and only copies a
//! validated, explicitly bounded rectangle into a private destination buffer.
//!
//! The value is created per frame from the client mapping and dropped before
//! the next protocol step; no `&[u8]` over shared memory outlives the call that
//! needed it.

use vasistas_protocol::Rect;

/// Pixel-view or copy failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelError {
    /// Width or height is zero.
    ZeroDimension,
    /// A stride is not a multiple of 4 bytes or is smaller than one row.
    BadStride,
    /// A buffer is smaller than `stride * height`.
    ShortBuffer,
    /// A rectangle is empty, negative or escapes the surface.
    OutOfBounds,
    /// Size arithmetic overflowed.
    Overflow,
}

/// Pixel bytes copied by [`SharedPixels::copy_damage`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct DamageStats {
    /// Number of rectangles copied.
    pub rects: u16,
    /// Total bytes copied into the destination.
    pub bytes: u64,
}

/// Validated, bounded view over a shared `XRGB8888` pixel buffer.
///
/// The byte slice is borrowed for the life of the value and is deliberately
/// not exposed: only [`SharedPixels::copy_rect`] and
/// [`SharedPixels::copy_damage`] read it, into caller-owned memory.
#[derive(Clone, Copy)]
pub struct SharedPixels<'a> {
    bytes: &'a [u8],
    width: u32,
    height: u32,
    stride: u32,
}

impl core::fmt::Debug for SharedPixels<'_> {
    /// Redacted: pixel bytes are never printed.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedPixels")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("stride", &self.stride)
            .finish_non_exhaustive()
    }
}

impl<'a> SharedPixels<'a> {
    /// Build a view after checking the geometry against the actual byte length.
    pub fn new(bytes: &'a [u8], width: u32, height: u32, stride: u32) -> Result<Self, PixelError> {
        if width == 0 || height == 0 {
            return Err(PixelError::ZeroDimension);
        }
        if stride % 4 != 0 || (stride as u64) < (width as u64) * 4 {
            return Err(PixelError::BadStride);
        }
        let needed = (stride as u64)
            .checked_mul(height as u64)
            .ok_or(PixelError::Overflow)?;
        if (bytes.len() as u64) < needed {
            return Err(PixelError::ShortBuffer);
        }
        // Reject sizes that cannot be indexed on this target.
        usize::try_from(needed).map_err(|_| PixelError::Overflow)?;
        Ok(Self {
            bytes,
            width,
            height,
            stride,
        })
    }

    /// Surface width in pixels.
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Surface height in pixels.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Source stride in bytes.
    pub fn stride(&self) -> u32 {
        self.stride
    }

    /// Copy `rect` into `dst` (packed with `dst_stride`) and return the number
    /// of bytes copied.
    ///
    /// The destination is laid out like a frame: the rect lands at its own
    /// coordinates, so it can be written straight into the server's private
    /// backbuffer. `dst` must therefore span at least `(y + h)` rows of
    /// `dst_stride` bytes, and `h` rows at minimum as for `copy_damage`.
    pub fn copy_rect(
        &self,
        rect: Rect,
        dst: &mut [u8],
        dst_stride: u32,
    ) -> Result<u64, PixelError> {
        let (x, y, w, h) = self.check_rect(rect)?;
        check_dst(x, y, w, h, dst_stride, dst.len())?;
        Ok(self.copy_rows(x, y, w, h, dst, dst_stride))
    }

    /// Copy the surface-local `rect` into `dst` at frame position
    /// `(dst_x, dst_y)`.
    ///
    /// Unlike [`SharedPixels::copy_rect`], the destination offset is explicit:
    /// the server places a surface's damage at the surface's screen origin in
    /// its private backbuffer. The source stays surface-local, so a rect is
    /// never read outside the client surface.
    pub fn copy_rect_to(
        &self,
        rect: Rect,
        dst_x: u32,
        dst_y: u32,
        dst: &mut [u8],
        dst_stride: u32,
    ) -> Result<u64, PixelError> {
        let (x, y, w, h) = self.check_rect(rect)?;
        check_dst(dst_x, dst_y, w, h, dst_stride, dst.len())?;
        let row_bytes = w as usize * 4;
        for row in 0..h {
            let src_off = (y + row) as usize * self.stride as usize + x as usize * 4;
            let dst_off = (dst_y + row) as usize * dst_stride as usize + dst_x as usize * 4;
            dst[dst_off..dst_off + row_bytes]
                .copy_from_slice(&self.bytes[src_off..src_off + row_bytes]);
        }
        Ok(row_bytes as u64 * h as u64)
    }

    /// Copy every rect of `damage` into `dst`, or copy nothing.
    ///
    /// Every rectangle and the destination geometry are validated before the
    /// first byte is written: one invalid rect leaves `dst` untouched. An empty
    /// damage list is a no-op returning zeroed [`DamageStats`].
    pub fn copy_damage(
        &self,
        damage: &[Rect],
        dst: &mut [u8],
        dst_stride: u32,
    ) -> Result<DamageStats, PixelError> {
        // A.4 caps one commit at 32 rectangles. Reject larger lists here too:
        // this API is the server's only pixel path and must stay bounded even
        // if a caller bypasses vasistas-core validation.
        if damage.len() > vasistas_protocol::MAX_RECTS {
            return Err(PixelError::Overflow);
        }
        // Validation pass: no destination writes before every rect is valid.
        for rect in damage {
            let (x, y, w, h) = self.check_rect(*rect)?;
            check_dst(x, y, w, h, dst_stride, dst.len())?;
        }

        let mut bytes = 0u64;
        for rect in damage {
            let (x, y, w, h) = self.check_rect(*rect)?;
            bytes += self.copy_rows(x, y, w, h, dst, dst_stride);
        }
        Ok(DamageStats {
            rects: damage.len() as u16,
            bytes,
        })
    }

    /// Validate a rect against this surface.
    fn check_rect(&self, rect: Rect) -> Result<(u32, u32, u32, u32), PixelError> {
        if rect.x < 0 || rect.y < 0 || rect.w == 0 || rect.h == 0 {
            return Err(PixelError::OutOfBounds);
        }
        let x = rect.x as u32;
        let y = rect.y as u32;
        if (x as u64) + (rect.w as u64) > self.width as u64
            || (y as u64) + (rect.h as u64) > self.height as u64
        {
            return Err(PixelError::OutOfBounds);
        }
        Ok((x, y, rect.w, rect.h))
    }

    /// Row-by-row copy of an already validated rect.
    fn copy_rows(&self, x: u32, y: u32, w: u32, h: u32, dst: &mut [u8], dst_stride: u32) -> u64 {
        let row_bytes = w as usize * 4;
        for row in 0..h {
            let src_off = (y + row) as usize * self.stride as usize + x as usize * 4;
            let dst_off = ((y + row) as usize) * dst_stride as usize + x as usize * 4;
            dst[dst_off..dst_off + row_bytes]
                .copy_from_slice(&self.bytes[src_off..src_off + row_bytes]);
        }
        row_bytes as u64 * h as u64
    }
}

/// Validate a destination frame buffer for a rect placed at `(x, y)`.
///
/// Rejects a destination smaller than `dst_stride * h` (the rect's own rows)
/// and one that cannot hold the rect at its coordinates; both are checked in
/// `u64` before any indexing.
fn check_dst(
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    dst_stride: u32,
    dst_len: usize,
) -> Result<(), PixelError> {
    // The destination must be a frame buffer: one row has to hold the rect at
    // its own x, so `dst_stride >= (x + w) * 4` (which implies `>= w * 4`).
    if dst_stride % 4 != 0 || (dst_stride as u64) < (x as u64 + w as u64) * 4 {
        return Err(PixelError::BadStride);
    }
    let rows = (dst_stride as u64)
        .checked_mul(h as u64)
        .ok_or(PixelError::Overflow)?;
    // Last copied byte: (y + h - 1) * stride + (x + w) * 4.
    let end = (dst_stride as u64)
        .checked_mul(y as u64 + h as u64 - 1)
        .ok_or(PixelError::Overflow)?
        .checked_add((x as u64 + w as u64) * 4)
        .ok_or(PixelError::Overflow)?;
    let needed = rows.max(end);
    if (dst_len as u64) < needed {
        return Err(PixelError::ShortBuffer);
    }
    usize::try_from(needed).map_err(|_| PixelError::Overflow)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{vec, vec::Vec};

    /// Deterministic LCG for geometry fuzzing.
    struct Lcg(u64);

    impl Lcg {
        fn next_u32(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }

        fn range(&mut self, max: u32) -> u32 {
            if max == 0 {
                0
            } else {
                self.next_u32() % max
            }
        }
    }

    /// Source buffer whose bytes encode `row * 256 + col` for easy row checks.
    fn source(width: u32, height: u32, stride: u32) -> Vec<u8> {
        let mut v = vec![0u8; (stride * height) as usize];
        for row in 0..height {
            for col in 0..width {
                let off = (row * stride + col * 4) as usize;
                v[off] = (row % 256) as u8;
                v[off + 1] = (col % 256) as u8;
                v[off + 2] = 0xEE;
                v[off + 3] = 0xEE;
            }
        }
        v
    }

    fn rect(x: i32, y: i32, w: u32, h: u32) -> Rect {
        Rect { x, y, w, h }
    }

    #[test]
    fn geometry_accessors() {
        let src = source(4, 3, 16);
        let view = SharedPixels::new(&src, 4, 3, 16).unwrap();
        assert_eq!(view.width(), 4);
        assert_eq!(view.height(), 3);
        assert_eq!(view.stride(), 16);
    }

    #[test]
    fn new_rejects_bad_geometry() {
        let src = vec![0u8; 64];
        assert_eq!(
            SharedPixels::new(&src, 0, 4, 16).unwrap_err(),
            PixelError::ZeroDimension
        );
        assert_eq!(
            SharedPixels::new(&src, 4, 0, 16).unwrap_err(),
            PixelError::ZeroDimension
        );
        // Stride smaller than one row.
        assert_eq!(
            SharedPixels::new(&src, 5, 1, 16).unwrap_err(),
            PixelError::BadStride
        );
        // Stride not a multiple of 4.
        assert_eq!(
            SharedPixels::new(&src, 4, 1, 18).unwrap_err(),
            PixelError::BadStride
        );
        // Shorter than stride * height.
        assert_eq!(
            SharedPixels::new(&src[..47], 4, 3, 16).unwrap_err(),
            PixelError::ShortBuffer
        );
        assert!(SharedPixels::new(&src[..48], 4, 3, 16).is_ok());
    }

    #[test]
    fn new_rejects_huge_geometry_as_short() {
        // `stride * height` fits u64; on a 64-bit target this is a short buffer.
        let src = vec![0u8; 8];
        assert_eq!(
            SharedPixels::new(&src, 1, u32::MAX, 4).unwrap_err(),
            PixelError::ShortBuffer
        );
    }

    #[test]
    fn copy_rect_padded_to_padded() {
        let src = source(8, 4, 40); // 8 px + 8 bytes padding
        let view = SharedPixels::new(&src, 8, 4, 40).unwrap();
        let mut dst = vec![0xFFu8; 32 * 3];
        let n = view.copy_rect(rect(2, 1, 4, 2), &mut dst, 32).unwrap();
        assert_eq!(n, 4 * 4 * 2);
        // Row 0 is entirely untouched: the rect starts at y == 1.
        assert!(dst[..32].iter().all(|b| *b == 0xFF));
        for row in 0..2u32 {
            for col in 0..4u32 {
                let off = ((row + 1) * 32 + (col + 2) * 4) as usize;
                assert_eq!(dst[off], ((row + 1) % 256) as u8, "row marker");
                assert_eq!(dst[off + 1], ((col + 2) % 256) as u8, "col marker");
                assert_eq!(dst[off + 2], 0xEE);
                assert_eq!(dst[off + 3], 0xEE);
            }
            // Padding before and after the copied run is untouched.
            assert_eq!(dst[((row + 1) * 32 + 7) as usize], 0xFF);
            assert_eq!(dst[((row + 1) * 32 + 24) as usize], 0xFF);
        }
    }

    #[test]
    fn copy_rect_tight_dest() {
        let src = source(4, 4, 16);
        let view = SharedPixels::new(&src, 4, 4, 16).unwrap();
        let mut dst = vec![0u8; 64];
        assert_eq!(view.copy_rect(rect(0, 0, 4, 4), &mut dst, 16), Ok(64));
        assert_eq!(dst, src);
    }

    #[test]
    fn copy_rect_to_places_pixels_at_the_destination_offset() {
        let src = source(4, 4, 16);
        let view = SharedPixels::new(&src, 4, 4, 16).unwrap();
        // 8x4 destination frame; copy the 2x2 source block at (2, 1) to (5, 2).
        let mut dst = vec![0u8; 8 * 4 * 4];
        assert_eq!(
            view.copy_rect_to(rect(2, 1, 2, 2), 5, 2, &mut dst, 8 * 4),
            Ok(2 * 2 * 4)
        );
        for row in 0..2u32 {
            for col in 0..2u32 {
                let off = ((2 + row) * 8 * 4 + (5 + col) * 4) as usize;
                assert_eq!(dst[off], ((row + 1) % 256) as u8, "row marker");
                assert_eq!(dst[off + 1], ((col + 2) % 256) as u8, "col marker");
                assert_eq!(dst[off + 2], 0xEE);
                assert_eq!(dst[off + 3], 0xEE);
            }
        }
        // Only the placed block was written.
        assert_eq!(dst.iter().filter(|byte| **byte != 0).count(), 2 * 2 * 4);
    }

    #[test]
    fn copy_rect_to_validates_the_source_and_destination() {
        let src = source(4, 4, 16);
        let view = SharedPixels::new(&src, 4, 4, 16).unwrap();
        let mut dst = vec![0u8; 16 * 4];
        // Source rect outside the surface.
        assert_eq!(
            view.copy_rect_to(rect(3, 0, 2, 1), 0, 0, &mut dst, 16),
            Err(PixelError::OutOfBounds)
        );
        // Destination offsets outside the frame.
        assert_eq!(
            view.copy_rect_to(rect(0, 0, 2, 1), 3, 0, &mut dst, 16),
            Err(PixelError::BadStride)
        );
        assert_eq!(
            view.copy_rect_to(rect(0, 0, 2, 1), 0, 4, &mut dst, 16),
            Err(PixelError::ShortBuffer)
        );
    }

    #[test]
    fn copy_rect_does_not_read_outside_rect() {
        let mut src = vec![0u8; 24 * 3];
        // Fill with a pattern then mark one pixel outside the requested rect.
        for (i, b) in src.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let outside = (1 * 24 + 3 * 4) as usize; // pixel (3,1), outside x<3
        src[outside] = 0xFF;
        let view = SharedPixels::new(&src, 4, 3, 24).unwrap();
        let mut dst = vec![0u8; 24];
        assert_eq!(view.copy_rect(rect(0, 1, 3, 1), &mut dst, 12), Ok(12));
        assert!(dst[..12].iter().all(|b| *b == 0), "row 0 untouched");
        assert!(!dst[12..].contains(&0xFF));
    }

    #[test]
    fn copy_rect_rejects_out_of_bounds() {
        let src = source(4, 4, 16);
        let view = SharedPixels::new(&src, 4, 4, 16).unwrap();
        let mut dst = vec![0u8; 64];
        for bad in [
            rect(-1, 0, 1, 1),
            rect(0, -1, 1, 1),
            rect(0, 0, 0, 1),
            rect(0, 0, 1, 0),
            rect(3, 0, 2, 1),
            rect(0, 3, 1, 2),
            rect(4, 0, 1, 1),
        ] {
            assert_eq!(
                view.copy_rect(bad, &mut dst, 8),
                Err(PixelError::OutOfBounds),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn copy_rect_rejects_bad_dest() {
        let src = source(4, 4, 16);
        let view = SharedPixels::new(&src, 4, 4, 16).unwrap();
        let mut dst = vec![0u8; 64];
        assert_eq!(
            view.copy_rect(rect(0, 0, 4, 1), &mut dst, 12),
            Err(PixelError::BadStride)
        );
        assert_eq!(
            view.copy_rect(rect(0, 0, 4, 1), &mut dst, 18),
            Err(PixelError::BadStride)
        );
        assert_eq!(
            view.copy_rect(rect(0, 0, 4, 2), &mut dst[..31], 16),
            Err(PixelError::ShortBuffer)
        );
    }

    #[test]
    fn copy_rect_rejects_oversized_dest() {
        let src = source(4, 4, 16);
        let view = SharedPixels::new(&src, 4, 4, 16).unwrap();
        let mut dst = vec![0u8; 16];
        assert_eq!(
            view.copy_rect(rect(0, 0, 1, u32::MAX), &mut dst, 4),
            Err(PixelError::OutOfBounds)
        );
    }

    #[test]
    fn copy_damage_stats_and_union() {
        let src = source(8, 8, 32);
        let view = SharedPixels::new(&src, 8, 8, 32).unwrap();
        let mut dst = vec![0u8; 32 * 8];
        let stats = view
            .copy_damage(&[rect(0, 0, 2, 2), rect(4, 4, 2, 2)], &mut dst, 32)
            .unwrap();
        assert_eq!(
            stats,
            DamageStats {
                rects: 2,
                bytes: 2 * 2 * 4 * 2
            }
        );
        // Pixel (0,0): row marker 0, col marker 0. Pixel (1,0): col marker 1.
        assert_eq!(&dst[0..8], &[0, 0, 0xEE, 0xEE, 0, 1, 0xEE, 0xEE]);
        // Pixel (4,4): row marker 4, col marker 4.
        assert_eq!(&dst[144..152], &[4, 4, 0xEE, 0xEE, 4, 5, 0xEE, 0xEE]);
    }

    #[test]
    fn copy_damage_is_atomic_on_invalid_rect() {
        let src = source(8, 8, 32);
        let view = SharedPixels::new(&src, 8, 8, 32).unwrap();
        let mut dst = vec![0x5Au8; 32 * 8];
        let before = dst.clone();
        assert_eq!(
            view.copy_damage(&[rect(0, 0, 3, 3), rect(7, 7, 2, 2)], &mut dst, 32),
            Err(PixelError::OutOfBounds)
        );
        assert_eq!(dst, before);
    }

    #[test]
    fn copy_damage_rejects_bad_dest_atomically() {
        let src = source(8, 8, 32);
        let view = SharedPixels::new(&src, 8, 8, 32).unwrap();
        let mut dst = vec![0x11u8; 32 * 8];
        let before = dst.clone();
        assert_eq!(
            view.copy_damage(&[rect(0, 0, 8, 8)], &mut dst[..32], 32),
            Err(PixelError::ShortBuffer)
        );
        assert_eq!(dst, before);
    }

    #[test]
    fn copy_damage_empty_is_noop() {
        let src = source(4, 4, 16);
        let view = SharedPixels::new(&src, 4, 4, 16).unwrap();
        let mut dst = vec![0x33u8; 16];
        let before = dst.clone();
        assert_eq!(
            view.copy_damage(&[], &mut dst, 16),
            Ok(DamageStats { rects: 0, bytes: 0 })
        );
        assert_eq!(dst, before);
    }

    #[test]
    fn copy_damage_rejects_too_many_rects() {
        let src = source(4, 4, 16);
        let view = SharedPixels::new(&src, 4, 4, 16).unwrap();
        let damage = vec![rect(0, 0, 1, 1); 3];
        let mut dst = vec![0u8; 64];
        assert_eq!(
            view.copy_damage(&damage, &mut dst, 4),
            Ok(DamageStats {
                rects: 3,
                bytes: 12
            })
        );
        assert_eq!(
            view.copy_damage(&vec![rect(0, 0, 1, 1); u16::MAX as usize + 1], &mut dst, 4),
            Err(PixelError::Overflow)
        );
    }

    #[test]
    fn fuzz_geometry_and_rects() {
        let mut rng = Lcg(0x0DDB_1A5E_5BAD_5EED);
        for _ in 0..4000 {
            let width = 1 + rng.range(40);
            let height = 1 + rng.range(40);
            let stride = width * 4 + 4 * rng.range(4);
            let src = vec![0u8; (stride * height) as usize];
            let view = SharedPixels::new(&src, width, height, stride).unwrap();

            let x = rng.range(64) as i32 - 8;
            let y = rng.range(64) as i32 - 8;
            let w = rng.range(48);
            let h = rng.range(48);
            let r = rect(x, y, w, h);

            let dst_w = rng.range(64) + 1;
            let dst_stride = dst_w * 4 + 4 * rng.range(3);
            let dst_h = rng.range(48) + 1;
            let mut dst = vec![0u8; (dst_stride * dst_h) as usize];

            let in_bounds = x >= 0
                && y >= 0
                && w > 0
                && h > 0
                && (x as u64 + w as u64) <= width as u64
                && (y as u64 + h as u64) <= height as u64;
            match view.copy_rect(r, &mut dst, dst_stride) {
                Ok(n) => {
                    assert!(in_bounds, "Ok for out-of-bounds rect {r:?}");
                    assert_eq!(n, w as u64 * 4 * h as u64);
                    assert!((dst_stride as u64) >= w as u64 * 4);
                }
                Err(_) => {}
            }
        }
    }

    #[test]
    fn debug_output_is_redacted() {
        let src = source(4, 2, 16);
        let view = SharedPixels::new(&src, 4, 2, 16).unwrap();
        let text = std::format!("{:?}", view);
        assert!(text.contains("width"));
        assert!(!text.contains("bytes"));
        assert!(!text.contains("["));
    }

    #[test]
    fn copy_damage_rejects_more_than_protocol_rects() {
        let src = source(8, 8, 32);
        let view = SharedPixels::new(&src, 8, 8, 32).unwrap();
        let rects = [rect(0, 0, 1, 1); vasistas_protocol::MAX_RECTS + 1];
        let mut dst = vec![0u8; 8 * 32];
        assert_eq!(
            view.copy_damage(&rects, &mut dst, 32),
            Err(PixelError::Overflow)
        );
        assert!(dst.iter().all(|byte| *byte == 0));
    }
}
