//! s9vm — guest memory map (GPA).
//!
//! **Pure** module: it holds the set of guest physical address ranges
//! reserved for a world (overlaps, alignment, quotas, page accounting)
//! without touching frames or translation tables. The kernel layer
//! (`s9vm::vm`) binds these ranges to pinned frames and second-level
//! tables.
//!
//! Testable on the host (L2 tests).

use alloc::collections::BTreeMap;

/// Size of a base page (4 KiB).
pub const PAGE_SIZE: u64 = 4096;
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
