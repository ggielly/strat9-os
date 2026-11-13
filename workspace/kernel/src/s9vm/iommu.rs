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

//! s9vm : device address translation (IOMMU model).
//!
//! **Pure** module: a software model of the translation unit that a
//! device-assignment backend will program. It is deliberately independent of
//! the hardware VT-d driver (`hardware::iommu`) and of the world registry: it
//! only answers the question *"may this device, in this domain, reach this
//! host page, and at which address?"*.
//!
//! # Model
//!
//! - A [`DomainId`] identifies an address space (one per world, or per set of
//!   devices assigned to that world).
//! - A [`DeviceId`] (a bus/device/function identifier) is bound to at most one
//!   domain through the context table ([`IommuModel::bind_device`]).
//! - Inside a domain, [`IommuModel::map`] installs 4 KiB leaves and
//!   [`IommuModel::map_2m`] installs 2 MiB leaves. A leaf records the host
//!   physical address (HPA), the leaf size and the device-visible permissions
//!   ([`Perms`], re-used from the second-level table module so a mapping has
//!   the same meaning on both paths).
//! - [`IommuModel::translate`] walks the domain and returns the HPA, or
//!   `None` when the address is not mapped.
//!
//! # Security invariant
//!
//! 1. **No implicit reachability.** The model has no identity fallback: a
//!    device address that was not explicitly mapped translates to `None`.
//!    The caller must treat `None` as a device fault (never as "use the
//!    address as a host physical address").
//! 2. **Domain isolation.** Each domain owns its leaves. Two domains may map
//!    the *same* device-visible address to *different* host pages (the
//!    normal case for two worlds); a translation is always resolved inside
//!    exactly one domain and never consults another.
//! 3. **No aliasing by overlap.** Two leaves of one domain never overlap: a
//!    second mapping of an already mapped range is refused with
//!    [`IommuError::Overlap`] instead of silently replacing the first one.
//! 4. **Bounded memory.** The number of domains, the number of leaves per
//!    domain and the number of bound devices are capped; the counters are
//!    saturating so adversarial traffic cannot wrap them.
//!
//! The guest-visible address is called `gpa` here because for the common
//! case "emulated device, guest RAM" the device address *is* the guest
//! physical address; for a passthrough device it is the IOVA that the real
//! IOMMU translates. Both are 48-bit addresses in the current model.
//!
//! Testable on the host (L2 tests): no allocation beyond `alloc`, no
//! `unsafe`, no kernel service.

use alloc::{collections::BTreeMap, vec::Vec};

use super::mmu::Perms;

/// Size of a base page (4 KiB), the granularity of [`IommuModel::map`].
pub const PAGE_SIZE: u64 = 4096;
/// Size of a large leaf installed by [`IommuModel::map_2m`].
pub const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;
/// Number of 4 KiB pages covered by one 2 MiB leaf.
pub const LARGE_PAGE_FRAMES: u64 = LARGE_PAGE_SIZE / PAGE_SIZE;
/// Maximum device-visible address width covered (48 bits).
pub const MAX_ADDRESS: u64 = 1 << 48;
/// Maximum host physical address width covered (48 bits).
pub const MAX_HPA: u64 = 1 << 48;
/// Maximum number of domains (one per world/device set).
pub const MAX_DOMAINS: usize = 64;
/// Maximum number of leaves per domain (4 KiB leaves and 2 MiB leaves count
/// as one entry each).
pub const MAX_ENTRIES_PER_DOMAIN: usize = 1024;
/// Maximum number of devices in the context table.
pub const MAX_DEVICES: usize = 128;

/// Errors of the translation model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IommuError {
    /// Zero length, unaligned address/length, out-of-range address, or a
    /// misaligned 2 MiB mapping.
    InvalidRange,
    /// The requested range overlaps an existing leaf of the domain.
    Overlap,
    /// The requested range is not entirely mapped (or is covered by a larger
    /// leaf that cannot be partially unmapped).
    NotMapped,
    /// The per-domain leaf quota would be exceeded.
    QuotaExceeded,
    /// [`MAX_DOMAINS`] domains already exist.
    TooManyDomains,
    /// The domain identifier does not exist.
    UnknownDomain,
    /// The device is already bound to a domain.
    AlreadyBound,
}

/// Identifier of an address space, allocated by [`IommuModel::create_domain`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainId(pub u32);

impl DomainId {
    /// Raw identifier (for the syscall/ABI layer).
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Builds an identifier from its raw value.
    pub const fn from_u32(raw: u32) -> Self {
        Self(raw)
    }
}

/// Identifier of a device in the context table.
///
/// The kernel uses the PCI segment/bus/device/function encoding; the model
/// only requires that the value is stable and unique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(pub u32);

impl DeviceId {
    /// Raw identifier.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Builds an identifier from its raw value.
    pub const fn from_u32(raw: u32) -> Self {
        Self(raw)
    }
}

/// Size of one leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafSize {
    /// 4 KiB leaf.
    Page4K,
    /// 2 MiB leaf.
    Page2M,
}

impl LeafSize {
    /// Size in bytes.
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Page4K => PAGE_SIZE,
            Self::Page2M => LARGE_PAGE_SIZE,
        }
    }

    /// Number of 4 KiB pages covered.
    pub const fn pages(self) -> u64 {
        match self {
            Self::Page4K => 1,
            Self::Page2M => LARGE_PAGE_FRAMES,
        }
    }
}

/// One leaf as reported by [`IommuModel::entries`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IommuEntry {
    /// Device-visible base address (4 KiB or 2 MiB aligned).
    pub gpa: u64,
    /// Host physical base address, aligned like the leaf.
    pub hpa: u64,
    /// Leaf size.
    pub size: LeafSize,
    /// Device-visible permissions.
    pub perms: Perms,
}

impl IommuEntry {
    /// End address (exclusive) of the leaf.
    pub const fn end(&self) -> u64 {
        self.gpa + self.size.bytes()
    }
}

/// Result of a successful translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IommuTranslation {
    /// Translated host physical address (including the offset inside the
    /// leaf).
    pub hpa: u64,
    /// Size of the leaf that resolved the translation.
    pub size: LeafSize,
    /// Permissions of that leaf.
    pub perms: Perms,
}

/// Cumulative diagnostics of the model.
///
/// All counters are **saturating**: they are informational only and can never
/// wrap or panic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IommuStats {
    /// 4 KiB pages mapped (2 MiB leaves count as 512 pages).
    pub mapped_pages: u64,
    /// 4 KiB pages unmapped.
    pub unmapped_pages: u64,
    /// Successful translations.
    pub translations: u64,
    /// Failed translations (unmapped, unknown domain/device).
    pub faults: u64,
}

impl IommuStats {
    fn note_mapped(&mut self, pages: u64) {
        self.mapped_pages = self.mapped_pages.saturating_add(pages);
    }

    fn note_unmapped(&mut self, pages: u64) {
        self.unmapped_pages = self.unmapped_pages.saturating_add(pages);
    }

    fn note_translation(&mut self) {
        self.translations = self.translations.saturating_add(1);
    }

    fn note_fault(&mut self) {
        self.faults = self.faults.saturating_add(1);
    }
}

/// One installed leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Leaf {
    hpa: u64,
    size: LeafSize,
    perms: Perms,
}

impl Leaf {
    const fn end(&self, gpa: u64) -> u64 {
        gpa + self.size.bytes()
    }
}

/// One address space of the model.
#[derive(Debug, Default)]
struct Domain {
    /// Leaves sorted by device-visible base address; the invariant is that
    /// they never overlap.
    leaves: BTreeMap<u64, Leaf>,
}

impl Domain {
    fn entries(&self) -> usize {
        self.leaves.len()
    }

    fn pages(&self) -> u64 {
        self.leaves.values().map(|leaf| leaf.size.pages()).sum()
    }

    /// True when `[start, end)` intersects a leaf already installed.
    fn conflicts(&self, start: u64, end: u64) -> bool {
        if let Some((gpa, leaf)) = self.leaves.range(..start).next_back() {
            if leaf.end(*gpa) > start {
                return true;
            }
        }
        self.leaves
            .range(start..)
            .next()
            .is_some_and(|(gpa, _)| *gpa < end)
    }

    /// Leaf containing `gpa`, if any.
    fn find(&self, gpa: u64) -> Option<(u64, &Leaf)> {
        let (base, leaf) = self.leaves.range(..=gpa).next_back()?;
        if gpa < leaf.end(*base) {
            Some((*base, leaf))
        } else {
            None
        }
    }
}

/// Software model of the device translation unit.
#[derive(Debug, Default)]
pub struct IommuModel {
    domains: BTreeMap<DomainId, Domain>,
    /// Context table: device -> domain. A device is bound to at most one
    /// domain at a time.
    devices: BTreeMap<DeviceId, DomainId>,
    next_domain_id: u32,
    stats: IommuStats,
}

impl IommuModel {
    /// Creates an empty model (no domain, no device binding).
    pub fn new() -> Self {
        Self::default()
    }

    // ------------------------------------------------------------------
    // Domains and context table
    // ------------------------------------------------------------------

    /// Creates a new address space.
    pub fn create_domain(&mut self) -> Result<DomainId, IommuError> {
        if self.domains.len() >= MAX_DOMAINS {
            return Err(IommuError::TooManyDomains);
        }
        // Identifiers are never reused during the lifetime of the model, so a
        // stale identifier can never alias a live domain.
        let id = loop {
            let candidate = self.next_domain_id;
            self.next_domain_id = self.next_domain_id.wrapping_add(1);
            if !self.domains.contains_key(&DomainId(candidate)) {
                break DomainId(candidate);
            }
        };
        self.domains.insert(id, Domain::default());
        Ok(id)
    }

    /// Number of live domains.
    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }

    /// True when the domain exists.
    pub fn domain_exists(&self, domain: DomainId) -> bool {
        self.domains.contains_key(&domain)
    }

    /// Binds a device to a domain (context-table entry).
    ///
    /// A device can be bound to one domain only; unbind it first to move it.
    /// The domain must exist.
    pub fn bind_device(&mut self, domain: DomainId, device: DeviceId) -> Result<(), IommuError> {
        if !self.domains.contains_key(&domain) {
            return Err(IommuError::UnknownDomain);
        }
        if self.devices.contains_key(&device) {
            return Err(IommuError::AlreadyBound);
        }
        if self.devices.len() >= MAX_DEVICES {
            return Err(IommuError::QuotaExceeded);
        }
        self.devices.insert(device, domain);
        Ok(())
    }

    /// Removes a context-table entry. Returns `true` when the device was
    /// bound.
    pub fn unbind_device(&mut self, device: DeviceId) -> bool {
        self.devices.remove(&device).is_some()
    }

    /// Domain a device is bound to, if any.
    pub fn domain_for_device(&self, device: DeviceId) -> Option<DomainId> {
        self.devices.get(&device).copied()
    }

    /// Number of bound devices.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Destroys a domain and every device binding that points to it.
    ///
    /// Returns `true` when the domain existed.
    pub fn destroy_domain(&mut self, domain: DomainId) -> bool {
        if self.domains.remove(&domain).is_none() {
            return false;
        }
        self.devices.retain(|_, bound| *bound != domain);
        true
    }

    /// Removes every mapping of every domain, keeping domains and device
    /// bindings. Diagnostics counters are cumulative and are not reset.
    pub fn clear(&mut self) {
        for domain in self.domains.values_mut() {
            domain.leaves.clear();
        }
    }

    /// Destroys the whole model: domains, device bindings, counters and
    /// identifier allocation state. The model can be reused afterwards.
    pub fn destroy(&mut self) {
        self.domains.clear();
        self.devices.clear();
        self.next_domain_id = 0;
        self.stats = IommuStats::default();
    }

    // ------------------------------------------------------------------
    // Mapping
    // ------------------------------------------------------------------

    /// Maps `len` device-visible bytes (4 KiB granularity) to host memory.
    ///
    /// Identity maps are allowed (`gpa == hpa`). The whole range must be
    /// aligned, unallocated and within the reserved page quota; the operation
    /// is all-or-nothing. Returns the number of 4 KiB pages mapped.
    pub fn map(
        &mut self,
        domain: DomainId,
        gpa: u64,
        hpa: u64,
        len: u64,
        perms: Perms,
    ) -> Result<u64, IommuError> {
        validate_range(gpa, hpa, len)?;
        let pages = len / PAGE_SIZE;
        let domain_state = self
            .domains
            .get_mut(&domain)
            .ok_or(IommuError::UnknownDomain)?;

        let entries = usize::try_from(pages).map_err(|_| IommuError::QuotaExceeded)?;
        if domain_state.entries() + entries > MAX_ENTRIES_PER_DOMAIN {
            return Err(IommuError::QuotaExceeded);
        }
        let end = gpa + len;
        if domain_state.conflicts(gpa, end) {
            return Err(IommuError::Overlap);
        }
        for page in 0..pages {
            let gpa_page = gpa + page * PAGE_SIZE;
            domain_state.leaves.insert(
                gpa_page,
                Leaf {
                    hpa: hpa + page * PAGE_SIZE,
                    size: LeafSize::Page4K,
                    perms,
                },
            );
        }
        self.stats.note_mapped(pages);
        Ok(pages)
    }

    /// Maps `len` device-visible bytes with 2 MiB leaves.
    ///
    /// Both addresses and the length must be 2 MiB aligned/multiples, and the
    /// range must not overlap an existing leaf (including 4 KiB leaves).
    /// Returns the number of 4 KiB pages covered.
    pub fn map_2m(
        &mut self,
        domain: DomainId,
        gpa: u64,
        hpa: u64,
        len: u64,
        perms: Perms,
    ) -> Result<u64, IommuError> {
        validate_range(gpa, hpa, len)?;
        if gpa % LARGE_PAGE_SIZE != 0 || hpa % LARGE_PAGE_SIZE != 0 || len % LARGE_PAGE_SIZE != 0 {
            return Err(IommuError::InvalidRange);
        }
        let frames = len / LARGE_PAGE_SIZE;
        let domain_state = self
            .domains
            .get_mut(&domain)
            .ok_or(IommuError::UnknownDomain)?;
        let entries = usize::try_from(frames).map_err(|_| IommuError::QuotaExceeded)?;
        if domain_state.entries() + entries > MAX_ENTRIES_PER_DOMAIN {
            return Err(IommuError::QuotaExceeded);
        }
        let end = gpa + len;
        if domain_state.conflicts(gpa, end) {
            return Err(IommuError::Overlap);
        }
        for frame in 0..frames {
            let gpa_leaf = gpa + frame * LARGE_PAGE_SIZE;
            domain_state.leaves.insert(
                gpa_leaf,
                Leaf {
                    hpa: hpa + frame * LARGE_PAGE_SIZE,
                    size: LeafSize::Page2M,
                    perms,
                },
            );
        }
        let pages = len / PAGE_SIZE;
        self.stats.note_mapped(pages);
        Ok(pages)
    }

    /// Removes `len` bytes previously mapped by 4 KiB leaves.
    ///
    /// The range must be entirely covered by 4 KiB leaves of this domain; a
    /// range covered by a 2 MiB leaf is refused with
    /// [`IommuError::NotMapped`] (use [`Self::unmap_2m`]). All-or-nothing:
    /// on error nothing is removed. Returns the number of pages unmapped.
    pub fn unmap(&mut self, domain: DomainId, gpa: u64, len: u64) -> Result<u64, IommuError> {
        validate_range(gpa, gpa, len)?;
        let pages = len / PAGE_SIZE;
        let domain_state = self
            .domains
            .get_mut(&domain)
            .ok_or(IommuError::UnknownDomain)?;
        for page in 0..pages {
            let gpa_page = gpa + page * PAGE_SIZE;
            match domain_state.leaves.get(&gpa_page) {
                Some(leaf) if leaf.size == LeafSize::Page4K => {}
                _ => return Err(IommuError::NotMapped),
            }
        }
        for page in 0..pages {
            let gpa_page = gpa + page * PAGE_SIZE;
            domain_state.leaves.remove(&gpa_page);
        }
        self.stats.note_unmapped(pages);
        Ok(pages)
    }

    /// Removes `len` bytes previously mapped by 2 MiB leaves.
    ///
    /// Alignment and all-or-nothing semantics are the same as [`Self::unmap`].
    pub fn unmap_2m(&mut self, domain: DomainId, gpa: u64, len: u64) -> Result<u64, IommuError> {
        validate_range(gpa, gpa, len)?;
        if gpa % LARGE_PAGE_SIZE != 0 || len % LARGE_PAGE_SIZE != 0 {
            return Err(IommuError::InvalidRange);
        }
        let frames = len / LARGE_PAGE_SIZE;
        let domain_state = self
            .domains
            .get_mut(&domain)
            .ok_or(IommuError::UnknownDomain)?;
        for frame in 0..frames {
            let gpa_leaf = gpa + frame * LARGE_PAGE_SIZE;
            match domain_state.leaves.get(&gpa_leaf) {
                Some(leaf) if leaf.size == LeafSize::Page2M => {}
                _ => return Err(IommuError::NotMapped),
            }
        }
        for frame in 0..frames {
            let gpa_leaf = gpa + frame * LARGE_PAGE_SIZE;
            domain_state.leaves.remove(&gpa_leaf);
        }
        let pages = len / PAGE_SIZE;
        self.stats.note_unmapped(pages);
        Ok(pages)
    }

    // ------------------------------------------------------------------
    // Translation
    // ------------------------------------------------------------------

    /// Translates one device-visible address inside a domain.
    ///
    /// Returns `None` when the address is not mapped in that domain. A device
    /// bound to another domain can never observe this mapping: the domain is
    /// an explicit parameter and no fallback exists.
    pub fn translate(&mut self, domain: DomainId, gpa: u64) -> Option<u64> {
        translate_in(&self.domains, domain, gpa, &mut self.stats)
    }

    /// Translates one device-visible address through the context table.
    ///
    /// The device must be bound to a live domain and the address mapped in
    /// it. An unbound device, a destroyed domain or an unmapped address all
    /// return `None` (counted as a fault).
    pub fn translate_device(&mut self, device: DeviceId, gpa: u64) -> Option<u64> {
        let domain = match self.devices.get(&device).copied() {
            Some(domain) if self.domains.contains_key(&domain) => domain,
            _ => {
                self.stats.note_fault();
                return None;
            }
        };
        translate_in(&self.domains, domain, gpa, &mut self.stats)
    }

    /// Detailed translation: host address, leaf size and permissions.
    pub fn translate_entry(&mut self, domain: DomainId, gpa: u64) -> Option<IommuTranslation> {
        let (base, leaf) = match self.domains.get(&domain) {
            Some(state) => match state.find(gpa) {
                Some(found) => found,
                None => {
                    self.stats.note_fault();
                    return None;
                }
            },
            None => {
                self.stats.note_fault();
                return None;
            }
        };
        self.stats.note_translation();
        Some(IommuTranslation {
            hpa: leaf.hpa + (gpa - base),
            size: leaf.size,
            perms: leaf.perms,
        })
    }

    // ------------------------------------------------------------------
    // Inspection
    // ------------------------------------------------------------------

    /// Number of leaves installed in a domain.
    pub fn mapped_entries(&self, domain: DomainId) -> Option<usize> {
        self.domains.get(&domain).map(Domain::entries)
    }

    /// Number of 4 KiB pages covered by the leaves of a domain.
    pub fn mapped_pages(&self, domain: DomainId) -> Option<u64> {
        self.domains.get(&domain).map(Domain::pages)
    }

    /// Deterministic snapshot of the leaves of a domain, sorted by address.
    ///
    /// The order is the `BTreeMap` order (ascending device-visible address),
    /// so two models fed the same operations produce byte-identical
    /// snapshots. Returns `None` for an unknown domain.
    pub fn entries(&self, domain: DomainId) -> Option<Vec<IommuEntry>> {
        let state = self.domains.get(&domain)?;
        Some(
            state
                .leaves
                .iter()
                .map(|(gpa, leaf)| IommuEntry {
                    gpa: *gpa,
                    hpa: leaf.hpa,
                    size: leaf.size,
                    perms: leaf.perms,
                })
                .collect(),
        )
    }

    /// Cumulative diagnostics.
    pub const fn stats(&self) -> IommuStats {
        self.stats
    }
}

fn translate_in(
    domains: &BTreeMap<DomainId, Domain>,
    domain: DomainId,
    gpa: u64,
    stats: &mut IommuStats,
) -> Option<u64> {
    let state = match domains.get(&domain) {
        Some(state) => state,
        None => {
            stats.note_fault();
            return None;
        }
    };
    match state.find(gpa) {
        Some((base, leaf)) => {
            stats.note_translation();
            Some(leaf.hpa + (gpa - base))
        }
        None => {
            stats.note_fault();
            None
        }
    }
}

/// Validates an aligned 4 KiB-granularity range.
fn validate_range(gpa: u64, hpa: u64, len: u64) -> Result<(), IommuError> {
    if len == 0 || len % PAGE_SIZE != 0 {
        return Err(IommuError::InvalidRange);
    }
    if gpa % PAGE_SIZE != 0 || hpa % PAGE_SIZE != 0 {
        return Err(IommuError::InvalidRange);
    }
    let gpa_end = gpa.checked_add(len).ok_or(IommuError::InvalidRange)?;
    let hpa_end = hpa.checked_add(len).ok_or(IommuError::InvalidRange)?;
    if gpa_end > MAX_ADDRESS || hpa_end > MAX_HPA {
        return Err(IommuError::InvalidRange);
    }
    Ok(())
}
