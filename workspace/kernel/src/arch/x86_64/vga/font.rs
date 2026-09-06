//! PSF (PC Screen Font) font parsing.
//!
//! Supports PSF1 and PSF2 font formats including unicode map decoding.

use alloc::vec::Vec;

pub(crate) const FONT_PSF: &[u8] = include_bytes!("../fonts/zap-ext-light20.psf");

pub(crate) struct FontInfo {
    pub(crate) glyph_count: usize,
    pub(crate) bytes_per_glyph: usize,
    pub(crate) glyph_w: usize,
    pub(crate) glyph_h: usize,
    pub(crate) data_offset: usize,
    pub(crate) unicode_table_offset: Option<usize>,
}

pub(crate) fn parse_psf(font: &[u8]) -> Option<FontInfo> {
    // PSF1
    if font.len() >= 4 && font[0] == 0x36 && font[1] == 0x04 {
        let mode = font[2];
        let glyph_count = if (mode & 0x01) != 0 { 512 } else { 256 };
        let glyph_h = font[3] as usize;
        let bytes_per_glyph = glyph_h;
        return Some(FontInfo {
            glyph_count,
            bytes_per_glyph,
            glyph_w: 8,
            glyph_h,
            data_offset: 4,
            unicode_table_offset: None,
        });
    }

    // PSF2
    if font.len() >= 32 && font[0] == 0x72 && font[1] == 0xB5 && font[2] == 0x4A && font[3] == 0x86
    {
        let rd_u32 = |off: usize| -> u32 {
            u32::from_le_bytes([font[off], font[off + 1], font[off + 2], font[off + 3]])
        };
        let headersize = rd_u32(8) as usize;
        let flags = rd_u32(12);
        let glyph_count = rd_u32(16) as usize;
        let bytes_per_glyph = rd_u32(20) as usize;
        let glyph_h = rd_u32(24) as usize;
        let glyph_w = rd_u32(28) as usize;
        let glyph_bytes = glyph_count.saturating_mul(bytes_per_glyph);
        let unicode_table_offset = if (flags & 1) != 0 {
            Some(headersize.saturating_add(glyph_bytes))
        } else {
            None
        };
        return Some(FontInfo {
            glyph_count,
            bytes_per_glyph,
            glyph_w,
            glyph_h,
            data_offset: headersize,
            unicode_table_offset,
        });
    }

    None
}

/// Performs the decode utf8 at operation.
fn decode_utf8_at(bytes: &[u8], pos: usize) -> Option<(u32, usize)> {
    let b0 = *bytes.get(pos)?;
    if b0 < 0x80 {
        return Some((b0 as u32, 1));
    }
    if (b0 & 0xE0) == 0xC0 {
        let b1 = *bytes.get(pos + 1)?;
        if (b1 & 0xC0) != 0x80 {
            return None;
        }
        let cp = (((b0 & 0x1F) as u32) << 6) | ((b1 & 0x3F) as u32);
        return Some((cp, 2));
    }
    if (b0 & 0xF0) == 0xE0 {
        let b1 = *bytes.get(pos + 1)?;
        let b2 = *bytes.get(pos + 2)?;
        if (b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 {
            return None;
        }
        let cp = (((b0 & 0x0F) as u32) << 12) | (((b1 & 0x3F) as u32) << 6) | ((b2 & 0x3F) as u32);
        return Some((cp, 3));
    }
    if (b0 & 0xF8) == 0xF0 {
        let b1 = *bytes.get(pos + 1)?;
        let b2 = *bytes.get(pos + 2)?;
        let b3 = *bytes.get(pos + 3)?;
        if (b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80 {
            return None;
        }
        let cp = (((b0 & 0x07) as u32) << 18)
            | (((b1 & 0x3F) as u32) << 12)
            | (((b2 & 0x3F) as u32) << 6)
            | ((b3 & 0x3F) as u32);
        return Some((cp, 4));
    }
    None
}

/// Parses psf2 unicode map.
pub(crate) fn parse_psf2_unicode_map(font: &[u8], info: &FontInfo) -> Vec<(u32, usize)> {
    let Some(mut i) = info.unicode_table_offset else {
        return Vec::new();
    };
    if i >= font.len() {
        return Vec::new();
    }

    let mut map = Vec::new();
    for glyph in 0..info.glyph_count {
        while i < font.len() {
            let b = font[i];
            if b == 0xFF {
                i += 1;
                break;
            }
            if b == 0xFE {
                // PSF2 sequence marker; skip marker and continue parsing bytes until glyph separator.
                i += 1;
                continue;
            }
            if let Some((cp, adv)) = decode_utf8_at(font, i) {
                if !map.iter().any(|(u, _)| *u == cp) {
                    map.push((cp, glyph));
                }
                i += adv;
            } else {
                i += 1;
            }
        }
    }

    map
}
