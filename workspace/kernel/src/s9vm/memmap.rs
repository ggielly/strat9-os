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

//! s9vm : guest memory map (GPA).
//!
//! **Pure** module: it holds the set of guest physical address ranges
//! reserved for a world (overlaps, alignment, quotas, page accounting)
//! without touching frames or translation tables. The kernel layer
//! (`s9vm::vm`) binds these ranges to pinned frames and second-level
//! tables.
//!
//! It also owns the granularity plan used by that binding: a reservation
//! whose base is 2 MiB aligned and whose length is a multiple of 2 MiB is
//! split into 2 MiB leaves, while a partial head or tail stays on 4 KiB
//! pages. [`plan_map`] performs the split; the caller installs the segments
//! (2 MiB needs a 2 MiB-aligned, physically contiguous frame block).
//!
//! Testable on the host (L2 tests).

use alloc::{collections::BTreeMap, vec::Vec};

/// Size of a base page (4 KiB).
pub const PAGE_SIZE: u64 = 4096;
/// Size of a large second-level page (2 MiB).
pub const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;
/// Number of 4 KiB frames covered by one 2 MiB leaf.
pub const LARGE_PAGE_FRAMES: usize = (LARGE_PAGE_SIZE / PAGE_SIZE) as usize;
/// Maximum guest physical address width covered (48 bits).
pub const MAX_GPA: u64 = 1 << 48;

/// Maximum number of distinct ranges per world (safety bound).
pub const MAX_REGIONS: usize = 256;

/// Reservation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// Zero, unaligned, or out-of-GPA-space address or length.
    InvalidRange,
    /// The range overlaps an already reserved range.
    Overlap,
    /// World page quota exceeded.
    QuotaExceeded,
    /// Too many distinct ranges.
    TooManyRegions,
    /// The range does not exist.
    NotMapped,
}

/// Reserved range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    /// Starting guest physical address (4 KiB aligned).
    pub gpa: u64,
    /// Length in bytes (multiple of 4 KiB).
    pub len: u64,
    /// Requested permissions (`Perms` bits: 1 = read, 2 = write,
    /// 4 = execute).
    pub perms: u32,
    /// Memory type (0 = WB by default).
    pub memtype: u8,
}

impl Region {
    /// End address (exclusive).
    pub const fn end(&self) -> u64 {
        self.gpa + self.len
    }

    /// True if the range contains the address.
    pub const fn contains(&self, gpa: u64) -> bool {
        gpa >= self.gpa && gpa < self.end()
    }
}

/// Guest memory map of a world.
#[derive(Debug)]
pub struct GuestMap {
    regions: BTreeMap<u64, Region>,
    pages: u64,
    quota_pages: u64,
}

impl GuestMap {
    /// Creates an empty map with a page quota.
    pub fn new(quota_pages: u64) -> Self {
        Self {
            regions: BTreeMap::new(),
            pages: 0,
            quota_pages,
        }
    }

    /// Number of reserved pages.
    pub const fn pages(&self) -> u64 {
        self.pages
    }

    /// Page quota.
    pub const fn quota_pages(&self) -> u64 {
        self.quota_pages
    }

    /// Number of ranges.
    pub fn region_count(&self) -> usize {
        self.regions.len()
    }

    /// Reserves a range. Idempotence is forbidden: an exact overlap is
    /// an error, which makes double mappings visible.
    pub fn reserve(
        &mut self,
        gpa: u64,
        len: u64,
        perms: u32,
        memtype: u8,
    ) -> Result<Region, MapError> {
        if len == 0 || gpa % PAGE_SIZE != 0 || len % PAGE_SIZE != 0 {
            return Err(MapError::InvalidRange);
        }
        let end = gpa.checked_add(len).ok_or(MapError::InvalidRange)?;
        if end > MAX_GPA {
            return Err(MapError::InvalidRange);
        }
        if self.overlaps(gpa, end) {
            return Err(MapError::Overlap);
        }
        if self.regions.len() >= MAX_REGIONS {
            return Err(MapError::TooManyRegions);
        }
        let pages = len / PAGE_SIZE;
        let new_total = self
            .pages
            .checked_add(pages)
            .ok_or(MapError::QuotaExceeded)?;
        if new_total > self.quota_pages {
            return Err(MapError::QuotaExceeded);
        }
        let region = Region {
            gpa,
            len,
            perms,
            memtype,
        };
        self.regions.insert(gpa, region);
        self.pages = new_total;
        Ok(region)
    }

    /// True if `[gpa, end)` overlaps an existing range.
    fn overlaps(&self, gpa: u64, end: u64) -> bool {
        if let Some((_, previous)) = self.regions.range(..=gpa).next_back() {
            if previous.end() > gpa {
                return true;
            }
        }
        if let Some((start, _)) = self.regions.range(gpa..).next() {
            if *start < end {
                return true;
            }
        }
        false
    }

    /// Removes the range starting exactly at `gpa`.
    pub fn remove(&mut self, gpa: u64) -> Option<Region> {
        let region = self.regions.remove(&gpa)?;
        self.pages = self.pages.saturating_sub(region.len / PAGE_SIZE);
        Some(region)
    }

    /// Returns the range containing `gpa`.
    pub fn region_containing(&self, gpa: u64) -> Option<Region> {
        let (_, region) = self.regions.range(..=gpa).next_back()?;
        if region.contains(gpa) {
            Some(*region)
        } else {
            None
        }
    }

    /// Iterates over the ranges (ascending order).
    pub fn regions(&self) -> impl Iterator<Item = &Region> {
        self.regions.values()
    }

    /// Clears the whole map (frames remain the caller's responsibility).
    pub fn clear(&mut self) {
        self.regions.clear();
        self.pages = 0;
    }

    /// Resets the quota (used when a world is reconfigured).
    pub fn set_quota(&mut self, quota_pages: u64) {
        self.quota_pages = quota_pages;
    }

    /// Reserves a range and returns its 2 MiB/4 KiB mapping plan.
    ///
    /// The reservation rules (alignment, overlap, quota) are exactly those of
    /// [`Self::reserve`]: the quota counts the same number of 4 KiB pages
    /// whatever the granularity, so a 2 MiB leaf accounts for 512 pages.
    pub fn reserve_with_plan(
        &mut self,
        gpa: u64,
        len: u64,
        perms: u32,
        memtype: u8,
    ) -> Result<(Region, Vec<MapSegment>), MapError> {
        let region = self.reserve(gpa, len, perms, memtype)?;
        let plan = plan_map(gpa, len)?;
        Ok((region, plan))
    }
}

/// Granularity of one mapping-plan segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageSize {
    /// One 4 KiB second-level page.
    Page4K,
    /// One 2 MiB second-level page.
    Page2M,
}

/// One contiguous piece of a guest mapping plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapSegment {
    /// Starting guest physical address (aligned to `page_size`).
    pub gpa: u64,
    /// Length in bytes (multiple of `page_size`).
    pub len: u64,
    /// Granularity used for this segment.
    pub page_size: PageSize,
}

impl MapSegment {
    /// End address (exclusive).
    pub const fn end(&self) -> u64 {
        self.gpa + self.len
    }

    /// Number of 4 KiB pages covered by this segment.
    ///
    /// This is the quota cost: a 2 MiB leaf accounts for 512 pages.
    pub const fn pages(&self) -> u64 {
        self.len / PAGE_SIZE
    }

    /// True when the segment must be installed with a 2 MiB leaf.
    pub const fn is_large(&self) -> bool {
        matches!(self.page_size, PageSize::Page2M)
    }
}

/// Plans the 2 MiB/4 KiB split of `[gpa, gpa + len)`.
///
/// Rules:
/// - the range must be 4 KiB aligned and inside the guest physical space,
///   like [`GuestMap::reserve`];
/// - a 2 MiB-aligned, 2 MiB-multiple middle is emitted as 2 MiB segments;
/// - a partial head (base not 2 MiB aligned) and a partial tail stay 4 KiB;
/// - a granularity never straddles a 2 MiB boundary, so one 2 MiB region is
///   always mapped with a single granularity.
///
/// The plan only splits the **GPA** range. Installing a 2 MiB segment also
/// requires a 2 MiB-aligned, physically contiguous host block; a caller that
/// cannot provide one must fall back to 4 KiB pages for that region.
pub fn plan_map(gpa: u64, len: u64) -> Result<Vec<MapSegment>, MapError> {
    if len == 0 || gpa % PAGE_SIZE != 0 || len % PAGE_SIZE != 0 {
        return Err(MapError::InvalidRange);
    }
    let end = gpa.checked_add(len).ok_or(MapError::InvalidRange)?;
    if end > MAX_GPA {
        return Err(MapError::InvalidRange);
    }

    let mut segments = Vec::new();
    let mut cursor = gpa;
    let mut remaining = len;

    // Partial head: 4 KiB pages up to the next 2 MiB boundary.
    let head = (LARGE_PAGE_SIZE - (cursor % LARGE_PAGE_SIZE)) % LARGE_PAGE_SIZE;
    if head != 0 {
        let take = core::cmp::min(head, remaining);
        segments.push(MapSegment {
            gpa: cursor,
            len: take,
            page_size: PageSize::Page4K,
        });
        cursor += take;
        remaining -= take;
    }

    // 2 MiB-aligned middle.
    while remaining >= LARGE_PAGE_SIZE {
        segments.push(MapSegment {
            gpa: cursor,
            len: LARGE_PAGE_SIZE,
            page_size: PageSize::Page2M,
        });
        cursor += LARGE_PAGE_SIZE;
        remaining -= LARGE_PAGE_SIZE;
    }

    // Partial tail.
    if remaining != 0 {
        segments.push(MapSegment {
            gpa: cursor,
            len: remaining,
            page_size: PageSize::Page4K,
        });
    }

    Ok(segments)
}

/// Checks that `hp_as` is exactly the set of frames of one 2 MiB-aligned block.
///
/// This is the host-contiguity test used before installing a 2 MiB leaf: a
/// large leaf maps 512 consecutive 4 KiB frames starting at a 2 MiB-aligned
/// host physical address. `base` is the lowest HPA of the set (the caller
/// derives it from the allocated frames) and `hp_as` is a slice of
/// [`LARGE_PAGE_FRAMES`] host physical addresses, in any order.
///
/// Returns `false` when the count is wrong, the base is not 2 MiB aligned, a
/// frame is misaligned, out of the block, or duplicated. A fragmented
/// allocator (holes, an unaligned base, or fewer than 512 frames) therefore
/// always returns `false`, and the caller falls back to 4 KiB pages.
pub fn contiguous_2m_aligned(base: u64, hp_as: &[u64]) -> bool {
    if hp_as.len() != LARGE_PAGE_FRAMES || base % LARGE_PAGE_SIZE != 0 {
        return false;
    }
    let Some(end) = base.checked_add(LARGE_PAGE_SIZE) else {
        return false;
    };

    // One bit per 4 KiB frame of the block: 512 bits.
    let mut seen = [0u64; LARGE_PAGE_FRAMES / 64];
    for &hpa in hp_as {
        if hpa % PAGE_SIZE != 0 || hpa < base || hpa >= end {
            return false;
        }
        let index = ((hpa - base) / PAGE_SIZE) as usize;
        let word = &mut seen[index / 64];
        let mask = 1u64 << (index % 64);
        if *word & mask != 0 {
            return false; // duplicate frame
        }
        *word |= mask;
    }

    // All 512 bits must be set: the set must cover the whole block.
    seen.iter().all(|word| *word == u64::MAX)
}

/// Permissions decoded from the ABI (1 = read, 2 = write, 4 = execute).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapPerms {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

/// Converts ABI permissions (1 = R, 2 = W, 4 = X; 0 = read) into
/// [`MapPerms`].
pub const fn perms_from_abi(bits: u32) -> MapPerms {
    MapPerms {
        read: bits & 1 != 0 || bits == 0,
        write: bits & 2 != 0,
        execute: bits & 4 != 0,
    }
}
