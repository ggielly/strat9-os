//! Geometry and byte layout of directly addressable GOP framebuffers.
use crate::memory_map::{page_allocation_size, PhysicalRange, PAGE_SIZE};

pub const MAX_FRAMEBUFFER_SPAN: u64 = 1 << 30;

#[derive(Clone, Copy, Debug, Default)]
pub struct Framebuffer {
    pub physical: u64,
    pub aperture_size: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub red_shift: u8,
    pub blue_shift: u8,
}

impl Framebuffer {
    /// Prefer 1600x1200, then the largest mode within that console size.
    /// If firmware only offers larger modes, try the smallest one first.
    pub fn console_mode_rank(self) -> (bool, u64) {
        let area = u64::from(self.width) * u64::from(self.height);
        let oversized = self.width > 1600 || self.height > 1200;
        (oversized, if oversized { area } else { u64::MAX - area })
    }

    pub fn geometry(width: usize, height: usize, stride: usize, rgb: bool) -> Option<Self> {
        if width == 0 || height == 0 || stride < width {
            return None;
        }
        let result = Self {
            width: u32::try_from(width).ok()?,
            height: u32::try_from(height).ok()?,
            stride: u32::try_from(stride.checked_mul(4)?).ok()?,
            // GOP specifies byte order; x86-64 pixels are little-endian u32s.
            red_shift: if rgb { 0 } else { 16 },
            blue_shift: if rgb { 16 } else { 0 },
            ..Self::default()
        };
        (result.visible_size() <= MAX_FRAMEBUFFER_SPAN).then_some(result)
    }

    pub fn visible_size(self) -> u64 {
        u64::from(self.stride) * u64::from(self.height)
    }

    pub fn with_aperture(mut self, base: u64, size: u64) -> Option<Self> {
        // The kernel writes pixels as aligned u32 values. Page alignment is
        // unnecessary, but an unaligned pixel base violates that contract.
        if base == 0 || base % 4 != 0 || self.visible_size() == 0 || self.visible_size() > size {
            return None;
        }
        self.physical = base;
        self.aperture_size = size;
        self.aperture().ok()?;
        Some(self)
    }

    /// Reserve/cache the entire advertised aperture, including partial pages.
    pub fn aperture(self) -> Result<PhysicalRange, &'static str> {
        if self.aperture_size == 0 {
            return Ok(PhysicalRange { base: 0, size: 0 });
        }
        self.physical
            .checked_add(self.aperture_size)
            .ok_or("framebuffer overflow")?;
        let base = self.physical & !(PAGE_SIZE - 1);
        let size = page_allocation_size(
            self.aperture_size
                .checked_add(self.physical - base)
                .ok_or("framebuffer overflow")?,
        )?;
        base.checked_add(size)
            .ok_or("framebuffer page range overflow")?;
        if size > MAX_FRAMEBUFFER_SPAN {
            return Err("framebuffer exceeds its 1 GiB virtual window");
        }
        Ok(PhysicalRange { base, size })
    }
}
