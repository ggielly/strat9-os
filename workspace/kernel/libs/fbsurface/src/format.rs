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

//! Pixel formats and the packed-pixel newtype.
//!
//! [`Format`] is the crate's only source of truth for channel layout. It is
//! a plain value with private fields, so a caller cannot build an
//! inconsistent format (mask without shift, or the reverse) by accident.
//!
//! Colour conversion happens **only** through [`Format::pack`],
//! [`Format::unpack`] and [`Format::convert`]. Bulk blits require identical
//! formats; the conversion path is explicit and therefore visible at the
//! call site, which is exactly what the old `CanvasBuffer::blit_rect`
//! (packed XRGB in, native-format screen out) made impossible to see.

/// An 8-bit-per-channel RGB triple, used at the boundaries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Rgb {
    pub const BLACK: Self = Self::new(0, 0, 0);
    pub const WHITE: Self = Self::new(0xFF, 0xFF, 0xFF);

    #[inline]
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }
}

/// A pixel already encoded in a [`Format`], with no implicit conversion.
///
/// Keeping the raw word in a newtype prevents the classic mix-up where a
/// packed XRGB value is written to a screen whose native layout is BGRX.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Packed(u32);

impl Packed {
    #[inline]
    pub const fn raw(value: u32) -> Self {
        Self(value)
    }

    #[inline]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// Native pixel layout of a contiguous surface.
///
/// Supports the two layouts the kernel actually drives: 32 bpp and 24 bpp.
/// 16 bpp can be represented (for `info` replies and future drivers) but is
/// rejected by [`Canvas`](crate::Canvas) constructors, because the kernel
/// SIMD paths have no 16 bpp implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Format {
    red_mask: u32,
    red_shift: u8,
    green_mask: u32,
    green_shift: u8,
    blue_mask: u32,
    blue_shift: u8,
    bits_per_pixel: u8,
}

impl Format {
    /// Canonical format used by UEFI GOP on x86: `0x00RRGGBB` in a 32-bit
    /// word, i.e. bytes `B, G, R, X` in memory.
    pub const XRGB8888: Self =
        Self::from_masks(32, 0x00FF_0000, 16, 0x0000_FF00, 8, 0x0000_00FF, 0);

    /// Same 8-bit channels, but red in the low byte (`0x00BBGGRR`).
    pub const BGRX8888: Self =
        Self::from_masks(32, 0x0000_00FF, 0, 0x0000_FF00, 8, 0x00FF_0000, 16);

    /// 24 bpp packed, `B, G, R` in memory.
    pub const RGB888: Self = Self::from_masks(24, 0x00FF_0000, 16, 0x0000_FF00, 8, 0x0000_00FF, 0);

    /// 16 bpp 5-6-5 (accepted by [`Format`], rejected by `Canvas` for now).
    pub const RGB565: Self = Self::from_masks(16, 0xF800, 11, 0x07E0, 5, 0x001F, 0);

    /// Build a format from explicit masks. Shifts are kept even when they
    /// could be derived, so a driver that reports them can pass them
    /// through unchanged.
    #[inline]
    pub const fn from_masks(
        bits_per_pixel: u8,
        red_mask: u32,
        red_shift: u8,
        green_mask: u32,
        green_shift: u8,
        blue_mask: u32,
        blue_shift: u8,
    ) -> Self {
        Self {
            red_mask,
            red_shift,
            green_mask,
            green_shift,
            blue_mask,
            blue_shift,
            bits_per_pixel,
        }
    }

    #[inline]
    pub const fn bits_per_pixel(self) -> u8 {
        self.bits_per_pixel
    }

    #[inline]
    pub const fn bytes_per_pixel(self) -> usize {
        (self.bits_per_pixel / 8) as usize
    }

    #[inline]
    pub const fn red_mask(self) -> u32 {
        self.red_mask
    }

    #[inline]
    pub const fn green_mask(self) -> u32 {
        self.green_mask
    }

    #[inline]
    pub const fn blue_mask(self) -> u32 {
        self.blue_mask
    }

    #[inline]
    pub const fn red_shift(self) -> u8 {
        self.red_shift
    }

    #[inline]
    pub const fn green_shift(self) -> u8 {
        self.green_shift
    }

    #[inline]
    pub const fn blue_shift(self) -> u8 {
        self.blue_shift
    }

    /// Whether the drawing paths can drive this layout without conversion.
    ///
    /// 24 and 32 bpp only: those are the two widths implemented by
    /// `PixelOps` and by the scalar fallbacks.
    #[inline]
    pub const fn is_supported(self) -> bool {
        self.bits_per_pixel == 24 || self.bits_per_pixel == 32
    }

    #[inline]
    pub const fn is_xrgb8888(self) -> bool {
        self.bits_per_pixel == 32
            && self.red_shift == 16
            && self.green_shift == 8
            && self.blue_shift == 0
    }

    /// Two formats are compatible when a bulk copy can move raw words
    /// between them without touching the bytes.
    #[inline]
    pub const fn compatible(self, other: Self) -> bool {
        self.bits_per_pixel == other.bits_per_pixel
            && self.red_mask == other.red_mask
            && self.red_shift == other.red_shift
            && self.green_mask == other.green_mask
            && self.green_shift == other.green_shift
            && self.blue_mask == other.blue_mask
            && self.blue_shift == other.blue_shift
    }

    /// Encode an RGB triple into this layout.
    ///
    /// Channels narrower than 8 bits are truncated to their mask, never
    /// shifted into the neighbouring channel. The unused byte of a 32 bpp
    /// word is set opaque, matching the kernel's existing `pack_rgb`.
    #[inline]
    pub const fn pack(self, rgb: Rgb) -> Packed {
        let mut v = ((rgb.r as u32) << self.red_shift) & self.red_mask;
        v |= ((rgb.g as u32) << self.green_shift) & self.green_mask;
        v |= ((rgb.b as u32) << self.blue_shift) & self.blue_mask;
        if self.bits_per_pixel == 32 && self.red_mask & 0xFF00_0000 == 0 {
            v |= 0xFF00_0000;
        }
        Packed(v)
    }

    /// Decode a pixel in this layout back to 8 bits per channel.
    ///
    /// Narrow channels are scaled (5 bits -> 8 bits) rather than shifted, so
    /// a round trip through RGB565 is visually neutral.
    pub const fn unpack(self, px: Packed) -> Rgb {
        Rgb {
            r: channel_to_u8(px.0, self.red_mask, self.red_shift),
            g: channel_to_u8(px.0, self.green_mask, self.green_shift),
            b: channel_to_u8(px.0, self.blue_mask, self.blue_shift),
        }
    }

    /// Convert one pixel to another layout. This is the single conversion
    /// point of the crate; everything else is a raw copy.
    #[inline]
    pub const fn convert(self, dst: Format, px: Packed) -> Packed {
        if self.compatible(dst) {
            return px;
        }
        dst.pack(self.unpack(px))
    }

    /// Convenience: pack an RGB triple without naming the format twice.
    #[inline]
    pub const fn rgb(self, r: u8, g: u8, b: u8) -> Packed {
        self.pack(Rgb::new(r, g, b))
    }

    #[inline]
    pub const fn black(self) -> Packed {
        self.pack(Rgb::BLACK)
    }

    #[inline]
    pub const fn white(self) -> Packed {
        self.pack(Rgb::WHITE)
    }
}

impl Default for Format {
    fn default() -> Self {
        Self::XRGB8888
    }
}

/// Extract one channel and scale it to 8 bits.
const fn channel_to_u8(px: u32, mask: u32, shift: u8) -> u8 {
    if mask == 0 {
        return 0;
    }
    let max = mask >> shift;
    let value = (px & mask) >> shift;
    if max == 0xFF {
        value as u8
    } else {
        // Rounded scaling, overflow-free: value <= max, max <= u32::MAX.
        ((value as u64 * 255 + (max as u64 / 2)) / max as u64) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xrgb_pack_is_opaque_and_ordered() {
        let p = Format::XRGB8888.pack(Rgb::new(0x12, 0x34, 0x56));
        assert_eq!(p.value(), 0xFF12_3456);
        assert_eq!(Format::XRGB8888.unpack(p), Rgb::new(0x12, 0x34, 0x56));
    }

    #[test]
    fn bgrx_swaps_red_and_blue() {
        let p = Format::BGRX8888.pack(Rgb::new(0x12, 0x34, 0x56));
        assert_eq!(p.value(), 0xFF56_3412);
        assert_eq!(Format::BGRX8888.unpack(p), Rgb::new(0x12, 0x34, 0x56));
    }

    #[test]
    fn rgb565_truncates_without_bleeding() {
        // 0xFF must fit in the 5-bit red field, not spill into green.
        let p = Format::RGB565.pack(Rgb::new(0xFF, 0x00, 0x00));
        assert_eq!(p.value(), 0xF800);
        // Round trip is close, not exact.
        let back = Format::RGB565.unpack(p);
        assert_eq!(back.g, 0);
        assert_eq!(back.b, 0);
        assert!(back.r >= 247);
    }

    #[test]
    fn rgb888_pack_does_not_set_alpha() {
        let p = Format::RGB888.pack(Rgb::WHITE);
        assert_eq!(p.value(), 0x00FF_FFFF);
    }

    #[test]
    fn convert_xrgb_to_bgrx_round_trips() {
        let src = Format::XRGB8888.rgb(1, 2, 3);
        let dst = Format::XRGB8888.convert(Format::BGRX8888, src);
        assert_eq!(dst.value(), 0xFF03_0201);
        let back = Format::BGRX8888.convert(Format::XRGB8888, dst);
        assert_eq!(back, src);
    }

    #[test]
    fn identical_formats_are_bitwise_copies() {
        let p = Packed::raw(0xDEAD_BEEF);
        assert_eq!(Format::XRGB8888.convert(Format::XRGB8888, p), p);
        assert!(Format::XRGB8888.compatible(Format::XRGB8888));
        assert!(!Format::XRGB8888.compatible(Format::RGB888));
    }

    #[test]
    fn bytes_per_pixel_matches_width() {
        assert_eq!(Format::XRGB8888.bytes_per_pixel(), 4);
        assert_eq!(Format::RGB888.bytes_per_pixel(), 3);
        assert_eq!(Format::RGB565.bytes_per_pixel(), 2);
        assert!(Format::XRGB8888.is_supported());
        assert!(!Format::RGB565.is_supported());
    }
}
