//! IOMMU domain and IOVA management.
//!
//! This module is the architecture-neutral bookkeeping layer between a PCI
//! function and the DMA allocator:
//!
//! * a [`Domain`] is bound to one [`Sbdf`] and owns a sparse IOVA space;
//! * mappings are kept in a `BTreeMap` keyed by IOVA start, so `map`, `unmap`
//!   and `translate` are O(log n) and overlap checks never scan the whole
//!   table;
//! * domains are allocated from a 16-bit bitmap (the VT-d domain-id width) and
//!   handed out as `Arc<Domain>` with an explicit logical reference count so
//!   hot-unplug can revoke DMA in one place;
//! * hardware programming lives in `crate::arch::iommu` behind a [`Backend`].
//!
//! Ordering invariant: the global `DOMAINS` registry lock is always taken
//! before the `DOMAIN_BITMAP` lock.  A [`Domain`] state lock is never taken
//! while holding the registry lock.

use alloc::{
    collections::BTreeMap,
    sync::Arc,
    vec::Vec,
};
use core::{
    fmt,
    ops::{BitAnd, BitOr},
    sync::atomic::{AtomicBool, Ordering},
};

use crate::sync::SpinLock;

/// First address handed out to drivers in a domain IOVA space.
///
/// The low 4 GiB are left alone so that a 32-bit-only device can still be
/// given a valid address without extra bounce buffering.
pub const IOVA_BASE: u64 = 0x1_0000_0000;

/// Page granularity of every IOMMU mapping.
pub const IOMMU_PAGE_SIZE: u64 = 4096;

/// Highest domain id the VT-d context entry can encode.
pub const MAX_DOMAIN_ID: u16 = u16::MAX;

const BITMAP_WORDS: usize = (MAX_DOMAIN_ID as usize + 1) / 64;

// =============================================================================
// Sbdf : segment / bus / device / function
// =============================================================================

/// A PCI function identity, including its PCI segment group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sbdf {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl Sbdf {
    /// Build a new segment-qualified PCI identity.
    pub const fn new(segment: u16, bus: u8, device: u8, function: u8) -> Self {
        Self {
            segment,
            bus,
            device,
            function,
        }
    }

    /// Identity of a device seen on segment 0 (the common case).
    pub const fn from_pci(bus: u8, device: u8, function: u8) -> Self {
        Self::new(0, bus, device, function)
    }

    /// Packed 32-bit representation: `segment:16 | bus:8 | dev:5 | fn:3`.
    pub const fn to_u32(self) -> u32 {
        ((self.segment as u32) << 16)
            | ((self.bus as u32) << 8)
            | ((self.device as u32 & 0x1f) << 3)
            | (self.function as u32 & 0x7)
    }

    /// Unpack a value previously produced by [`Sbdf::to_u32`].
    pub const fn from_u32(raw: u32) -> Self {
        Self {
            segment: (raw >> 16) as u16,
            bus: (raw >> 8) as u8,
            device: ((raw >> 3) & 0x1f) as u8,
            function: (raw & 0x7) as u8,
        }
    }
}

impl fmt::Display for Sbdf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04x}:{:02x}:{:02x}.{:x}",
            self.segment, self.bus, self.device, self.function
        )
    }
}

// =============================================================================
// DmaProt : access rights of a mapping
// =============================================================================

/// DMA access rights for a mapping.
///
/// For a device:
/// * `READ` means the device may read memory (the DMA buffer is a write for
///   the CPU);
/// * `WRITE` means the device may write memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DmaProt(u8);

impl DmaProt {
    /// No access.
    pub const NONE: Self = Self(0);
    /// Device may read memory.
    pub const READ: Self = Self(0b01);
    /// Device may write memory.
    pub const WRITE: Self = Self(0b10);
    /// Device may read and write memory.
    pub const READ_WRITE: Self = Self(0b11);

    /// Raw bits, as used by the syscall ABI.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Rebuild rights from raw ABI bits, rejecting unknown bits.
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !0b11 != 0 {
            None
        } else {
            Some(Self(bits))
        }
    }

    /// True when every right in `other` is present.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// True when no access is granted.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Device-readable mapping.
    pub const fn readable(self) -> bool {
        self.0 & Self::READ.0 != 0
    }

    /// Device-writable mapping.
    pub const fn writable(self) -> bool {
        self.0 & Self::WRITE.0 != 0
    }
}

impl BitOr for DmaProt {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitAnd for DmaProt {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

// =============================================================================
// Errors
// =============================================================================

/// Errors returned by the IOMMU bookkeeping layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IommuError {
    /// No IOMMU is described by the firmware.
    NotPresent,
    /// A backend exists but has not been validated for activation.
    BackendNotReady,
    /// All 16-bit domain ids are in use.
    NoDomainSpace,
    /// The domain id does not belong to a live delegation.
    UnknownDomain,
    /// Zero-length, unaligned or overflowing range.
    InvalidRange,
    /// The range overlaps an existing mapping.
    Overlap,
    /// The IOVA range is not fully mapped.
    NotMapped,
    /// The buffer already belongs to a domain.
    AlreadyMapped,
}

impl IommuError {
    /// Stable short description, used in logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            IommuError::NotPresent => "no IOMMU firmware present",
            IommuError::BackendNotReady => "IOMMU backend not ready",
            IommuError::NoDomainSpace => "no free IOMMU domain id",
            IommuError::UnknownDomain => "unknown IOMMU domain",
            IommuError::InvalidRange => "invalid IOVA range",
            IommuError::Overlap => "overlapping IOVA range",
            IommuError::NotMapped => "IOVA range not mapped",
            IommuError::AlreadyMapped => "buffer already mapped to a domain",
        }
    }
}

/// Opaque domain identifier (VT-d uses 16 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainId(pub u16);

impl DomainId {
    /// Raw numeric identifier.
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// Rebuild an id from the raw ABI value.
    pub const fn from_raw(raw: u16) -> Self {
        Self(raw)
    }
}

// =============================================================================
// Mappings
// =============================================================================

/// One IOVA -> physical mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    pub iova: u64,
    pub phys: u64,
    pub len: u64,
    pub prot: DmaProt,
}

impl Mapping {
    /// Exclusive end of the IOVA range.
    pub const fn end(&self) -> u64 {
        self.iova.saturating_add(self.len)
    }

    /// True when `iova` falls inside this mapping.
    pub const fn contains(&self, iova: u64) -> bool {
        iova >= self.iova && iova < self.end()
    }
}

/// Result of a software translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Translation {
    pub phys: u64,
    pub prot: DmaProt,
    /// Bytes between `iova` and the end of the mapping.
    pub remaining: u64,
}

#[derive(Debug)]
struct DomainState {
    refs: usize,
    generation: u64,
    mappings: BTreeMap<u64, Mapping>,
}

impl DomainState {
    fn new() -> Self {
        Self {
            refs: 1,
            generation: 0,
            mappings: BTreeMap::new(),
        }
    }

    /// Find the first hole at or after [`IOVA_BASE`] that fits `len`.
    fn alloc_iova(&self, len: u64) -> Result<u64, IommuError> {
        let mut candidate = IOVA_BASE;
        for mapping in self.mappings.values() {
            if mapping.end() <= candidate {
                continue;
            }
            let fits = candidate
                .checked_add(len)
                .map(|end| end <= mapping.iova)
                .unwrap_or(false);
            if fits {
                return Ok(candidate);
            }
            candidate = candidate.max(mapping.end());
        }
        candidate.checked_add(len).ok_or(IommuError::InvalidRange)?;
        Ok(candidate)
    }
}

// =============================================================================
// Domain
// =============================================================================

/// A DMA domain attached to one PCI function.
pub struct Domain {
    id: DomainId,
    sbdf: Sbdf,
    state: SpinLock<DomainState>,
}

impl fmt::Debug for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock();
        f.debug_struct("Domain")
            .field("id", &self.id)
            .field("sbdf", &self.sbdf)
            .field("refs", &state.refs)
            .field("generation", &state.generation)
            .field("mappings", &state.mappings.len())
            .finish()
    }
}

impl Domain {
    fn new(id: DomainId, sbdf: Sbdf) -> Self {
        Self {
            id,
            sbdf,
            state: SpinLock::new(DomainState::new()),
        }
    }

    /// Domain identifier.
    pub const fn id(&self) -> DomainId {
        self.id
    }

    /// PCI function this domain is bound to.
    pub const fn sbdf(&self) -> Sbdf {
        self.sbdf
    }

    /// Logical reference count (one per outstanding delegation).
    pub fn refs(&self) -> usize {
        self.state.lock().refs
    }

    /// Take one more logical reference.
    pub fn acquire(&self) -> usize {
        let mut state = self.state.lock();
        state.refs = state.refs.saturating_add(1);
        state.refs
    }

    /// Drop one logical reference, returning the new count.
    pub fn release(&self) -> usize {
        let mut state = self.state.lock();
        state.refs = state.refs.saturating_sub(1);
        state.refs
    }

    /// Monotonic generation, bumped on every map/unmap.
    pub fn generation(&self) -> u64 {
        self.state.lock().generation
    }

    /// Number of live mappings.
    pub fn mapping_count(&self) -> usize {
        self.state.lock().mappings.len()
    }

    /// Snapshot of the mappings, sorted by IOVA.
    pub fn mappings(&self) -> Vec<Mapping> {
        self.state.lock().mappings.values().copied().collect()
    }

    /// True when the domain has at least one mapping.
    pub fn is_active(&self) -> bool {
        !self.state.lock().mappings.is_empty()
    }

    /// Map `len` bytes of physical memory at `iova`.
    ///
    /// The range must be page-aligned, non-empty and must not overlap an
    /// existing mapping.  The overlap check is O(log n).
    pub fn map(
        &self,
        iova: u64,
        phys: u64,
        len: u64,
        prot: DmaProt,
    ) -> Result<(), IommuError> {
        validate_range(iova, len)?;
        if phys & (IOMMU_PAGE_SIZE - 1) != 0 {
            return Err(IommuError::InvalidRange);
        }
        phys.checked_add(len).ok_or(IommuError::InvalidRange)?;

        let mut state = self.state.lock();

        // Previous mapping (largest start <= iova) may straddle `iova`.
        if let Some((_, prev)) = state.mappings.range(..=iova).next_back() {
            if prev.end() > iova {
                return Err(IommuError::Overlap);
            }
        }
        // Next mapping starting inside [iova, iova + len).
        if let Some((&next_start, _)) = state.mappings.range(iova..iova + len).next() {
            debug_assert!(next_start >= iova);
            return Err(IommuError::Overlap);
        }

        state.mappings.insert(
            iova,
            Mapping {
                iova,
                phys,
                len,
                prot,
            },
        );
        state.generation = state.generation.wrapping_add(1);
        Ok(())
    }

    /// Allocate a free IOVA range and map `phys` into it.
    pub fn map_auto(
        &self,
        phys: u64,
        len: u64,
        prot: DmaProt,
    ) -> Result<u64, IommuError> {
        validate_range(0, len)?;
        let iova = {
            let state = self.state.lock();
            state.alloc_iova(len)?
        };
        self.map(iova, phys, len, prot)?;
        Ok(iova)
    }

    /// Remove every mapping fully contained in `[iova, iova + len)`.
    ///
    /// Returns how many mappings were removed.  A partial overlap is an error:
    /// callers must unmap on the granularity they mapped.
    pub fn unmap(&self, iova: u64, len: u64) -> Result<usize, IommuError> {
        validate_range(iova, len)?;
        let end = iova + len;
        let mut state = self.state.lock();

        let mut keys: Vec<u64> = Vec::new();
        if let Some((&start, prev)) = state.mappings.range(..end).next_back() {
            if prev.end() > iova {
                keys.push(start);
            }
        }
        for &start in state.mappings.range(iova..end).map(|(k, _)| k) {
            if !keys.contains(&start) {
                keys.push(start);
            }
        }
        if keys.is_empty() {
            return Err(IommuError::NotMapped);
        }
        for key in &keys {
            let Some(mapping) = state.mappings.get(key) else {
                continue;
            };
            if mapping.iova < iova || mapping.end() > end {
                return Err(IommuError::InvalidRange);
            }
        }
        for key in &keys {
            state.mappings.remove(key);
        }
        state.generation = state.generation.wrapping_add(1);
        Ok(keys.len())
    }

    /// Remove exactly one mapping that starts at `iova`.
    pub fn unmap_exact(&self, iova: u64) -> Result<Mapping, IommuError> {
        let mut state = self.state.lock();
        let mapping = state.mappings.remove(&iova).ok_or(IommuError::NotMapped)?;
        state.generation = state.generation.wrapping_add(1);
        Ok(mapping)
    }

    /// Translate an IOVA with the software table.
    ///
    /// This is the source of truth while hardware translation is disabled, and
    /// a verification aid afterwards.
    pub fn translate(&self, iova: u64) -> Option<Translation> {
        let state = self.state.lock();
        let (_, mapping) = state.mappings.range(..=iova).next_back()?;
        if !mapping.contains(iova) {
            return None;
        }
        Some(Translation {
            phys: mapping.phys + (iova - mapping.iova),
            prot: mapping.prot,
            remaining: mapping.end() - iova,
        })
    }

    /// Remove every mapping, keeping the domain alive.
    pub fn reset(&self) {
        let mut state = self.state.lock();
        if !state.mappings.is_empty() {
            state.mappings.clear();
            state.generation = state.generation.wrapping_add(1);
        }
    }
}

fn validate_range(iova: u64, len: u64) -> Result<(), IommuError> {
    if len == 0 || iova & (IOMMU_PAGE_SIZE - 1) != 0 || len & (IOMMU_PAGE_SIZE - 1) != 0 {
        return Err(IommuError::InvalidRange);
    }
    iova.checked_add(len).ok_or(IommuError::InvalidRange)?;
    Ok(())
}

// =============================================================================
// Global registry
// =============================================================================

static DOMAINS: SpinLock<BTreeMap<DomainId, Arc<Domain>>> = SpinLock::new(BTreeMap::new());
static DOMAIN_BITMAP: SpinLock<[u64; BITMAP_WORDS]> = SpinLock::new([0u64; BITMAP_WORDS]);
static HARDWARE_ENABLED: AtomicBool = AtomicBool::new(false);

fn allocate_domain_id() -> Result<DomainId, IommuError> {
    let mut bitmap = DOMAIN_BITMAP.lock();
    // Id 0 is reserved: VTD uses it for the "no translation" context.
    for word in 0..BITMAP_WORDS {
        let mut free = !bitmap[word];
        if word == 0 {
            free &= !1u64; // keep bit 0 clear
        }
        if free == 0 {
            continue;
        }
        let bit = free.trailing_zeros() as usize;
        bitmap[word] |= 1u64 << bit;
        return Ok(DomainId((word * 64 + bit) as u16));
    }
    Err(IommuError::NoDomainSpace)
}

fn free_domain_id(id: DomainId) {
    let index = id.0 as usize;
    if index == 0 || index > MAX_DOMAIN_ID as usize {
        return;
    }
    let mut bitmap = DOMAIN_BITMAP.lock();
    bitmap[index / 64] &= !(1u64 << (index % 64));
}

/// True when the firmware advertised an IOMMU (DMAR or IVRS).
pub fn firmware_present() -> bool {
    crate::acpi::get_dmar().is_some() || crate::acpi::get_ivrs().is_some()
}

/// True when translation is actually programmed.
pub fn enabled() -> bool {
    HARDWARE_ENABLED.load(Ordering::Acquire)
}

/// Return the domain bound to `sbdf`, creating it on first use.
///
/// Each successful call takes one logical reference; release it with
/// [`release_domain`] once the caller no longer needs the domain.
pub fn domain_for(sbdf: Sbdf) -> Result<Arc<Domain>, IommuError> {
    let mut domains = DOMAINS.lock();
    if let Some(existing) = domains.values().find(|domain| domain.sbdf() == sbdf) {
        existing.acquire();
        return Ok(existing.clone());
    }
    let id = allocate_domain_id()?;
    let domain = Arc::new(Domain::new(id, sbdf));
    domains.insert(id, domain.clone());
    Ok(domain)
}

/// Convenience wrapper for segment 0.
pub fn create_domain(bus: u8, device: u8, function: u8) -> Result<Arc<Domain>, IommuError> {
    domain_for(Sbdf::from_pci(bus, device, function))
}

/// Look up a live domain by id.
///
/// The returned `Arc` keeps the object alive but does **not** take a logical
/// reference: logical references model delegations, not transient lookups.
pub fn get_domain(id: DomainId) -> Option<Arc<Domain>> {
    DOMAINS.lock().get(&id).cloned()
}

/// Drop one logical reference, tearing down the domain when it reaches zero.
pub fn release_domain(domain: &Arc<Domain>) -> bool {
    if domain.release() > 0 {
        return false;
    }
    let id = domain.id();
    domain.reset();
    let mut domains = DOMAINS.lock();
    // Only remove the registry entry if it is still the same object.
    let same = domains
        .get(&id)
        .map(|entry| Arc::ptr_eq(entry, domain))
        .unwrap_or(false);
    if same {
        domains.remove(&id);
        free_domain_id(id);
        true
    } else {
        false
    }
}

/// Destroy a domain unconditionally (hot-unplug, forced teardown).
pub fn teardown(id: DomainId) -> bool {
    let mut domains = DOMAINS.lock();
    let Some(domain) = domains.remove(&id) else {
        return false;
    };
    domain.reset();
    free_domain_id(id);
    true
}

/// Map an IOVA range into an existing domain, by id.
pub fn map(
    domain: DomainId,
    iova: u64,
    phys: u64,
    len: u64,
    prot: DmaProt,
) -> Result<(), IommuError> {
    let domain = lookup(domain)?;
    domain.map(iova, phys, len, prot)
}

/// Remove mappings from an existing domain, by id.
pub fn unmap(domain: DomainId, iova: u64, len: u64) -> Result<usize, IommuError> {
    let domain = lookup(domain)?;
    domain.unmap(iova, len)
}

/// Translate an IOVA through an existing domain, by id.
pub fn translate(domain: DomainId, iova: u64) -> Option<Translation> {
    lookup(domain).ok()?.translate(iova)
}

fn lookup(id: DomainId) -> Result<Arc<Domain>, IommuError> {
    DOMAINS
        .lock()
        .get(&id)
        .cloned()
        .ok_or(IommuError::UnknownDomain)
}

/// Number of live domains, for diagnostics.
pub fn domain_count() -> usize {
    DOMAINS.lock().len()
}

/// Parse the firmware tables and log a short IOMMU summary.
///
/// This never touches hardware: activation is a separate, explicit step.
pub fn init() {
    let discovery = crate::arch::iommu::init();
    if discovery.present {
        log::info!(
            "[IOMMU] {} backend, {} DRHD unit(s), {} RMRR, {} ATSR, {} bit host width, \
             intr-remap={}, x2apic-opt-out={}, ready={}",
            discovery.backend,
            discovery.units,
            discovery.rmrrs,
            discovery.atsrs,
            discovery.host_address_width,
            discovery.intr_remap,
            discovery.x2apic_opt_out,
            discovery.ready
        );
    } else {
        log::info!("[IOMMU] no IOMMU firmware table found (DMA is untranslated)");
    }
}

/// Enable hardware translation.
///
/// Returns `false` unless a backend reports itself ready and successfully
/// programs the root/context tables.  P0 deliberately keeps this false until
/// the VT-d backend has been validated on real hardware.
pub fn activate() -> bool {
    if HARDWARE_ENABLED.load(Ordering::Acquire) {
        return true;
    }
    let backend = crate::arch::iommu::backend();
    if !backend.is_ready() {
        return false;
    }
    if backend.activate().is_err() {
        return false;
    }
    HARDWARE_ENABLED.store(true, Ordering::Release);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sbdf_roundtrip() {
        let sbdf = Sbdf::new(2, 0x1f, 3, 5);
        assert_eq!(Sbdf::from_u32(sbdf.to_u32()), sbdf);
    }

    #[test]
    fn map_translate_unmap() {
        let domain = Domain::new(DomainId(7), Sbdf::from_pci(0, 2, 0));
        domain.map(IOVA_BASE, 0x1000, 0x2000, DmaProt::READ_WRITE).unwrap();
        let t = domain.translate(IOVA_BASE + 0x1800).unwrap();
        assert_eq!(t.phys, 0x2800);
        assert_eq!(t.remaining, 0x800);
        assert_eq!(domain.generation(), 1);

        assert!(domain.map(IOVA_BASE, 0x9000, 0x1000, DmaProt::READ).is_err());
        assert!(domain.map(IOVA_BASE - 0x1000, 0x9000, 0x3000, DmaProt::READ).is_err());

        assert_eq!(domain.unmap(IOVA_BASE, 0x2000).unwrap(), 1);
        assert!(domain.translate(IOVA_BASE).is_none());
        assert_eq!(domain.unmap(IOVA_BASE, 0x2000), Err(IommuError::NotMapped));
    }

    #[test]
    fn auto_iova_skips_holes() {
        let domain = Domain::new(DomainId(9), Sbdf::from_pci(0, 3, 0));
        let a = domain.map_auto(0x10_0000, 0x1000, DmaProt::READ).unwrap();
        let b = domain.map_auto(0x20_0000, 0x1000, DmaProt::READ).unwrap();
        assert_eq!(a, IOVA_BASE);
        assert_eq!(b, IOVA_BASE + 0x1000);
        domain.unmap_exact(a).unwrap();
        let c = domain.map_auto(0x30_0000, 0x1000, DmaProt::READ).unwrap();
        assert_eq!(c, IOVA_BASE);
    }

    #[test]
    fn dma_prot_bits() {
        assert!(DmaProt::READ_WRITE.contains(DmaProt::READ));
        assert!(DmaProt::READ_WRITE.contains(DmaProt::WRITE));
        assert!(!DmaProt::READ.contains(DmaProt::WRITE));
        assert!(DmaProt::READ.readable() && !DmaProt::READ.writable());
        assert_eq!(DmaProt::from_bits(0b100), None);
        assert_eq!(DmaProt::from_bits(0b11), Some(DmaProt::READ_WRITE));
    }

    #[test]
    fn rejects_unaligned_and_empty() {
        let domain = Domain::new(DomainId(11), Sbdf::from_pci(0, 4, 0));
        assert_eq!(
            domain.map(IOVA_BASE + 1, 0x1000, 0x1000, DmaProt::READ),
            Err(IommuError::InvalidRange)
        );
        assert_eq!(
            domain.map(IOVA_BASE, 0x1000, 0, DmaProt::READ),
            Err(IommuError::InvalidRange)
        );
    }
}
