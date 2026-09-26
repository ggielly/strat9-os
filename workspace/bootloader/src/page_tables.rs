//! Bounded page-table construction, also usable with ordinary host memory.
use crate::{
    boot_plan::{DirectMapPlan, GIB, INITIAL_ALLOCATION_LIMIT},
    elf::{Elf64Info, KERNEL_VIRT_BASE, MAX_KERNEL_IMAGE_SIZE},
    memory_map::{page_allocation_size, PhysicalRange, PAGE_SIZE},
};

pub const FRAMEBUFFER_BASE: u64 = 0xFFFF_DEAD_0000_0000;
pub const ENVIRONMENT_BASE: u64 = 0xFFFF_BEEF_0000_0000;
pub const HHDM_OFFSET: u64 = 0xFFFF_FF00_0000_0000;
const HUGE_PAGE: u64 = 0x20_0000;
const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const HUGE: u64 = 1 << 7;
const NX: u64 = 1 << 63;
const UC: u64 = (1 << 3) | (1 << 4); // PAT[3], verified as UC; no PAT rewrite.
const ADDRESS: u64 = 0x000F_FFFF_FFFF_F000;

pub fn page_range(range: PhysicalRange) -> Result<PhysicalRange, &'static str> {
    if range.size == 0 {
        return Ok(PhysicalRange { base: 0, size: 0 });
    }
    range.end()?;
    let base = range.base & !(PAGE_SIZE - 1);
    let size = page_allocation_size(
        range
            .size
            .checked_add(range.base - base)
            .ok_or("page span overflow")?,
    )?;
    let result = PhysicalRange { base, size };
    result.end()?;
    Ok(result)
}

pub fn overlaps(a: PhysicalRange, b: PhysicalRange) -> bool {
    a.size != 0
        && b.size != 0
        && a.base < b.base.saturating_add(b.size)
        && b.base < a.base.saturating_add(a.size)
}

fn contains(outer: PhysicalRange, inner: PhysicalRange) -> bool {
    inner.base >= outer.base
        && inner
            .end()
            .ok()
            .zip(outer.end().ok())
            .is_some_and(|(i, o)| i <= o)
}

pub struct MappingPlan<'a> {
    pub direct_map: DirectMapPlan,
    pub kernel: &'a Elf64Info,
    pub loader_image: PhysicalRange,
    /// Sorted, merged, page-aligned firmware RAM ranges supporting WB.
    pub write_back: &'a [PhysicalRange],
    /// The complete GOP aperture, not just visible pixels.
    pub framebuffer: PhysicalRange,
    pub environment: PhysicalRange,
}

impl MappingPlan<'_> {
    fn kernel_range(&self) -> Result<PhysicalRange, &'static str> {
        if self.kernel.phys_base == 0
            || self.kernel.phys_base % PAGE_SIZE != 0
            || self.kernel.phys_end <= self.kernel.phys_base
        {
            return Err("invalid kernel physical extent");
        }
        let range = page_range(PhysicalRange {
            base: self.kernel.phys_base,
            size: self.kernel.image_size(),
        })?;
        if range.size > MAX_KERNEL_IMAGE_SIZE {
            return Err("kernel exceeds its 1 GiB virtual window");
        }
        Ok(range)
    }

    /// None means a boundary needs 4 KiB leaves. RAM is WB, gaps/MMIO and
    /// every alias of the framebuffer are UC. All input boundaries are pages.
    fn cache_flags(&self, range: PhysicalRange) -> Option<u64> {
        let framebuffer = page_range(self.framebuffer).ok()?;
        if overlaps(framebuffer, range) {
            return contains(framebuffer, range).then_some(UC);
        }
        let index = self
            .write_back
            .partition_point(|wb| wb.base.saturating_add(wb.size) <= range.base);
        match self.write_back.get(index).copied() {
            Some(wb) if contains(wb, range) => Some(0),
            Some(wb) if overlaps(wb, range) => None,
            _ => Some(UC),
        }
    }

    /// Compare a final firmware descriptor with the prepared WB ranges. This
    /// ignores the explicit framebuffer override, which always remains UC.
    pub fn agrees_with_firmware(&self, range: PhysicalRange, write_back: bool) -> bool {
        if range.size == 0 {
            return true;
        }
        let index = self
            .write_back
            .partition_point(|wb| wb.base.saturating_add(wb.size) <= range.base);
        match self.write_back.get(index).copied() {
            Some(wb) if write_back => contains(wb, range),
            Some(wb) => !overlaps(wb, range),
            None => !write_back,
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        let kernel = self.kernel_range()?;
        let loader = page_range(self.loader_image)?;
        let fb = page_range(self.framebuffer)?;
        let env = page_range(self.environment)?;
        if self.kernel.segment_count == 0 || self.kernel.segment_count > self.kernel.segments.len()
        {
            return Err("invalid kernel segment count");
        }
        let mut previous_end = kernel.base;
        let mut previous_flags = 0;
        for segment in &self.kernel.segments[..self.kernel.segment_count] {
            let range = PhysicalRange {
                base: segment.phys_addr,
                size: segment.mem_size,
            };
            if range.size == 0
                || !contains(kernel, range)
                || range.base < previous_end
                || segment.flags & !7 != 0
                || segment.flags & 3 == 3
                || segment.virt_addr != KERNEL_VIRT_BASE + (range.base - kernel.base)
                || (range.base / PAGE_SIZE == (previous_end - 1) / PAGE_SIZE
                    && segment.flags != previous_flags)
            {
                return Err("invalid kernel segment mapping permissions");
            }
            previous_end = range.end()?;
            previous_flags = segment.flags;
        }
        let mut previous_end = 0;
        for range in self.write_back {
            if range.size == 0
                || range.base % PAGE_SIZE != 0
                || range.size % PAGE_SIZE != 0
                || range.base < previous_end
            {
                return Err("invalid WB memory ranges");
            }
            previous_end = range.end()?;
        }
        for range in [kernel, loader, fb, env] {
            if range.size != 0 && !self.direct_map.covers(range) {
                return Err("mapping lies outside the prepared direct map");
            }
        }
        if loader.size == 0
            || overlaps(kernel, loader)
            || overlaps(kernel, fb)
            || overlaps(loader, fb)
            || overlaps(env, fb)
            || overlaps(kernel, env)
            || overlaps(loader, env)
            || fb.size > GIB
            || env.size > GIB
        {
            return Err("overlapping images or oversized mapping window");
        }
        if self.cache_flags(kernel) != Some(0) || self.cache_flags(loader) != Some(0) {
            return Err("kernel and EFI image must reside in WB RAM");
        }
        Ok(())
    }

    fn split_direct_leaf(&self, physical: u64, identity: bool) -> bool {
        let chunk = PhysicalRange {
            base: physical,
            size: HUGE_PAGE,
        };
        // Keep low memory granular for fixed MTRRs and the later AP trampoline.
        physical == 0
            || self.cache_flags(chunk).is_none()
            || overlaps(chunk, self.kernel_range().expect("validated kernel"))
            || (identity
                && overlaps(
                    chunk,
                    page_range(self.loader_image).expect("validated image"),
                ))
    }

    fn kernel_flags(&self, physical: u64) -> u64 {
        let page = PhysicalRange {
            base: physical,
            size: PAGE_SIZE,
        };
        for segment in &self.kernel.segments[..self.kernel.segment_count] {
            if overlaps(
                page,
                PhysicalRange {
                    base: segment.phys_addr,
                    size: segment.mem_size,
                },
            ) {
                return PRESENT
                    | if segment.flags & 2 != 0 { WRITABLE } else { 0 }
                    | if segment.flags & 1 == 0 { NX } else { 0 };
            }
        }
        PRESENT | NX // Image gaps and padding are read-only, non-executable.
    }

    fn direct_flags(&self, physical: u64, identity: bool) -> Result<u64, &'static str> {
        let page = PhysicalRange {
            base: physical,
            size: PAGE_SIZE,
        };
        let permissions = if overlaps(page, self.kernel_range()?) {
            self.kernel_flags(physical) | NX // No writable or executable code alias.
        } else if identity && overlaps(page, page_range(self.loader_image)?) {
            PRESENT // EFI transition RX until the kernel retires this mapping.
        } else {
            PRESENT | WRITABLE | NX
        };
        Ok(permissions | self.cache_flags(page).ok_or("unaligned cache boundary")?)
    }

    pub fn table_pages(&self) -> Result<u64, &'static str> {
        self.validate()?;
        // Root, identity/HHDM PDPTs, kernel PDPT+PD, direct-map PDs, kernel PTs.
        let mut pages =
            5 + 2 * (self.direct_map.end() / GIB) + self.kernel_range()?.size.div_ceil(HUGE_PAGE);
        for identity in [true, false] {
            for physical in (0..self.direct_map.end()).step_by(HUGE_PAGE as usize) {
                pages += u64::from(self.split_direct_leaf(physical, identity));
            }
        }
        for range in [self.framebuffer, self.environment] {
            let size = page_range(range)?.size;
            if size != 0 {
                pages += 2 + size.div_ceil(HUGE_PAGE);
            }
        }
        Ok(pages)
    }
}

struct Tables<'a> {
    words: &'a mut [u64],
    base: u64,
    used: usize,
}

impl Tables<'_> {
    fn allocate(&mut self) -> Result<usize, &'static str> {
        let index = self.used;
        if self.words.len().saturating_sub(index) < 512 {
            return Err("page-table arena exhausted");
        }
        self.words[index..index + 512].fill(0);
        self.used += 512;
        Ok(index)
    }

    fn child(&mut self, table: usize, slot: usize) -> Result<usize, &'static str> {
        let entry = self.words[table + slot];
        if entry == 0 {
            let child = self.allocate()?;
            self.words[table + slot] = self.base + child as u64 * 8 | PRESENT | WRITABLE;
            Ok(child)
        } else if entry & HUGE != 0 {
            Err("page-table collision with huge leaf")
        } else {
            Ok(((entry & ADDRESS)
                .checked_sub(self.base)
                .ok_or("foreign page-table pointer")?
                / 8) as usize)
        }
    }

    fn map(
        &mut self,
        virtual_addr: u64,
        physical: u64,
        flags: u64,
        huge: bool,
    ) -> Result<(), &'static str> {
        let mut table = 0;
        for shift in [39, 30] {
            table = self.child(table, ((virtual_addr >> shift) & 511) as usize)?;
        }
        let leaf_shift = if huge {
            21
        } else {
            table = self.child(table, ((virtual_addr >> 21) & 511) as usize)?;
            12
        };
        let slot = table + ((virtual_addr >> leaf_shift) & 511) as usize;
        if self.words[slot] != 0 {
            return Err("duplicate page mapping");
        }
        self.words[slot] = physical | flags | if huge { HUGE } else { 0 };
        Ok(())
    }
}

/// Build the actual entries in a caller-supplied slice. `base` is their physical
/// address (a synthetic address in host tests); this routine dereferences no PTE.
pub fn build_page_tables(
    words: &mut [u64],
    base: u64,
    plan: &MappingPlan<'_>,
) -> Result<u64, &'static str> {
    let pages = plan.table_pages()?;
    let size = pages * PAGE_SIZE;
    let area = PhysicalRange { base, size };
    if base == 0
        || base % PAGE_SIZE != 0
        || area.end()? > INITIAL_ALLOCATION_LIMIT
        || words.len() < (size / 8) as usize
        || !plan.direct_map.covers(area)
        || plan.cache_flags(area) != Some(0)
        || [
            plan.kernel_range()?,
            page_range(plan.loader_image)?,
            page_range(plan.environment)?,
        ]
        .into_iter()
        .any(|range| overlaps(area, range))
    {
        return Err("invalid page-table allocation");
    }
    let mut tables = Tables {
        words: &mut words[..(size / 8) as usize],
        base,
        used: 0,
    };
    tables.allocate()?;
    for (offset, identity) in [(0, true), (HHDM_OFFSET, false)] {
        for physical in (0..plan.direct_map.end()).step_by(HUGE_PAGE as usize) {
            if plan.split_direct_leaf(physical, identity) {
                for page in (physical..physical + HUGE_PAGE).step_by(PAGE_SIZE as usize) {
                    tables.map(
                        offset + page,
                        page,
                        plan.direct_flags(page, identity)?,
                        false,
                    )?;
                }
            } else {
                let cache = plan
                    .cache_flags(PhysicalRange {
                        base: physical,
                        size: HUGE_PAGE,
                    })
                    .ok_or("mixed huge-page cache attributes")?;
                tables.map(
                    offset + physical,
                    physical,
                    PRESENT | WRITABLE | NX | cache,
                    true,
                )?;
            }
        }
    }
    let kernel = plan.kernel_range()?;
    for displacement in (0..kernel.size).step_by(PAGE_SIZE as usize) {
        let physical = kernel.base + displacement;
        tables.map(
            KERNEL_VIRT_BASE + displacement,
            physical,
            plan.kernel_flags(physical),
            false,
        )?;
    }
    for (window, range, flags) in [
        (
            FRAMEBUFFER_BASE,
            plan.framebuffer,
            PRESENT | WRITABLE | NX | UC,
        ),
        (ENVIRONMENT_BASE, plan.environment, PRESENT | NX),
    ] {
        let range = page_range(range)?;
        for displacement in (0..range.size).step_by(PAGE_SIZE as usize) {
            let physical = range.base + displacement;
            let cache = plan
                .cache_flags(PhysicalRange {
                    base: physical,
                    size: PAGE_SIZE,
                })
                .ok_or("mixed window cache attributes")?;
            tables.map(window + displacement, physical, flags | cache, false)?;
        }
    }
    if tables.used as u64 != size / 8 {
        return Err("page-table budget does not match construction");
    }
    Ok(base)
}

/// # Safety
/// The caller exclusively owns and reserves the page-aligned physical arena;
/// it must remain accessible under the firmware's current identity map.
pub unsafe fn create_page_tables(
    table_area: PhysicalRange,
    plan: &MappingPlan<'_>,
) -> Result<u64, &'static str> {
    let size = plan.table_pages()? * PAGE_SIZE;
    if table_area.base == 0
        || table_area.base % PAGE_SIZE != 0
        || table_area.size < size
        || table_area.end()? > INITIAL_ALLOCATION_LIMIT
    {
        return Err("invalid page-table arena");
    }
    let words = unsafe {
        core::slice::from_raw_parts_mut(table_area.base as *mut u64, (size / 8) as usize)
    };
    build_page_tables(words, table_area.base, plan)
}
