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
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use crate::sync::{FixedQueue, SpinLock};

/// First address handed out to drivers in a domain IOVA space.
///
/// The low 4 GiB are left alone so that a 32-bit-only device can still be
/// given a valid address without extra bounce buffering.
pub const IOVA_BASE: u64 = 0x1_0000_0000;

/// Page granularity of every IOMMU mapping.
pub const IOMMU_PAGE_SIZE: u64 = 4096;

/// Large-page granularities supported by the second-level page tables.
pub const IOMMU_SUPERPAGE_2M: u64 = 2 * 1024 * 1024;
/// 1 GiB leaf entries.
pub const IOMMU_SUPERPAGE_1G: u64 = 1024 * 1024 * 1024;

/// Granularity of one mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingKind {
    /// 4 KiB leaf.
    Page4K,
    /// 2 MiB leaf (second-level PS bit at level 2).
    Page2M,
    /// 1 GiB leaf (second-level PS bit at level 3).
    Page1G,
}

impl MappingKind {
    /// Size represented by one leaf entry.
    pub const fn size(self) -> u64 {
        match self {
            MappingKind::Page4K => IOMMU_PAGE_SIZE,
            MappingKind::Page2M => IOMMU_SUPERPAGE_2M,
            MappingKind::Page1G => IOMMU_SUPERPAGE_1G,
        }
    }

    /// Smallest kind that can cover `len` with the given base alignment.
    ///
    /// Returns `None` when `len` is zero or not a multiple of 4 KiB.
    pub fn best_for(iova: u64, len: u64) -> Option<Self> {
        if len == 0 || len & (IOMMU_PAGE_SIZE - 1) != 0 {
            return None;
        }
        if len >= IOMMU_SUPERPAGE_1G
            && iova & (IOMMU_SUPERPAGE_1G - 1) == 0
            && len & (IOMMU_SUPERPAGE_1G - 1) == 0
        {
            Some(MappingKind::Page1G)
        } else if len >= IOMMU_SUPERPAGE_2M
            && iova & (IOMMU_SUPERPAGE_2M - 1) == 0
            && len & (IOMMU_SUPERPAGE_2M - 1) == 0
        {
            Some(MappingKind::Page2M)
        } else {
            Some(MappingKind::Page4K)
        }
    }
}

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
    /// The physical range is reserved by the firmware (RMRR/IVMD).
    Reserved,
    /// The domain is quiesced and refuses new mappings.
    Quiesced,
    /// The backend does not implement the requested feature.
    Unsupported,
    /// The hardware backend refused the operation.
    Hardware,
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
            IommuError::Reserved => "physical range is firmware-reserved",
            IommuError::Quiesced => "IOMMU domain is quiesced",
            IommuError::Unsupported => "operation not supported by the IOMMU backend",
            IommuError::Hardware => "IOMMU hardware refused the operation",
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
    pub kind: MappingKind,
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

// =============================================================================
// Faults
// =============================================================================

/// What the kernel should do when a device faults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultPolicy {
    /// Queue the record and keep going.
    Log,
    /// Queue the record and signal the owning strate.
    Notify,
    /// Destroy every domain owned by the faulting silo.
    KillOwner,
    /// Stop the kernel (critical devices only).
    Panic,
}

impl FaultPolicy {
    /// Decode the ABI representation (0=log, 1=notify, 2=kill, 3=panic).
    pub const fn from_raw(raw: u8) -> Self {
        match raw {
            1 => FaultPolicy::Notify,
            2 => FaultPolicy::KillOwner,
            3 => FaultPolicy::Panic,
            _ => FaultPolicy::Log,
        }
    }

    /// Stable numeric representation.
    pub const fn as_raw(self) -> u8 {
        match self {
            FaultPolicy::Log => 0,
            FaultPolicy::Notify => 1,
            FaultPolicy::KillOwner => 2,
            FaultPolicy::Panic => 3,
        }
    }

    /// Action actually taken for this policy.
    pub const fn action(self) -> FaultAction {
        match self {
            FaultPolicy::Log => FaultAction::Logged,
            FaultPolicy::Notify => FaultAction::Notified,
            FaultPolicy::KillOwner => FaultAction::OwnerRevoked,
            FaultPolicy::Panic => FaultAction::Panicked,
        }
    }
}

/// Outcome attached to a queued fault record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultAction {
    Logged,
    Notified,
    OwnerRevoked,
    Panicked,
}

impl FaultAction {
    /// Stable numeric representation for the ABI.
    pub const fn as_raw(self) -> u8 {
        match self {
            FaultAction::Logged => 0,
            FaultAction::Notified => 1,
            FaultAction::OwnerRevoked => 2,
            FaultAction::Panicked => 3,
        }
    }
}

/// Reason reported by the hardware (or by a debug injection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultReason {
    /// The device attempted a read with no valid translation.
    Read,
    /// The device attempted a write with no valid translation.
    Write,
    /// The translation existed but the access rights denied it.
    Permission,
    /// The IOVA was outside the domain's declared range.
    OutOfRange,
}

impl FaultReason {
    /// Stable numeric representation for the ABI.
    pub const fn as_raw(self) -> u8 {
        match self {
            FaultReason::Read => 0,
            FaultReason::Write => 1,
            FaultReason::Permission => 2,
            FaultReason::OutOfRange => 3,
        }
    }
}

/// One bounded fault record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultRecord {
    pub seq: u64,
    pub timestamp_ns: u64,
    pub domain: DomainId,
    pub sbdf: Sbdf,
    pub iova: u64,
    pub reason: FaultReason,
    pub access: DmaProt,
    pub owner: Option<u32>,
    pub action: FaultAction,
}

/// Maximum number of fault records kept globally.
pub const FAULT_QUEUE_CAPACITY: usize = 256;
/// Per-domain burst before records are dropped (rate limit).
pub const FAULT_BURST: u32 = 32;

static FAULTS: SpinLock<FixedQueue<FaultRecord, FAULT_QUEUE_CAPACITY>> =
    SpinLock::new(FixedQueue::new());
static FAULT_SEQ: AtomicU64 = AtomicU64::new(1);
static FAULT_DROPPED: AtomicU64 = AtomicU64::new(0);

// =============================================================================
// Reserved regions (RMRR / IVMD)
// =============================================================================

/// A physical range reserved for a device by the firmware.
///
/// The IOMMU must identity-map it for the listed devices, and the DMA
/// allocator must never hand those pages to another domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedRegion {
    pub segment: u16,
    /// Inclusive start.
    pub base: u64,
    /// Inclusive end.
    pub limit: u64,
    /// Explicit endpoint list; empty means `all_bus_from` applies.
    pub devices: Vec<Sbdf>,
    /// When set, every bus `>=` this value in `segment` is covered.
    pub all_bus_from: Option<u8>,
    /// True when the region was identity-mapped during discovery.
    pub identity_mapped: bool,
}

impl ReservedRegion {
    /// True when `phys` falls inside the reserved range.
    pub const fn contains(&self, phys: u64) -> bool {
        phys >= self.base && phys <= self.limit
    }

    /// True when the region overlaps `[start, start + len)`.
    pub const fn overlaps(&self, start: u64, len: u64) -> bool {
        match start.checked_add(len) {
            Some(end) => start <= self.limit && end > self.base,
            None => true,
        }
    }

    /// True when this region applies to `sbdf`.
    pub fn covers(&self, sbdf: Sbdf) -> bool {
        if self.segment != sbdf.segment {
            return false;
        }
        if self.devices.iter().any(|d| *d == sbdf) {
            return true;
        }
        self.all_bus_from
            .map(|bus| sbdf.bus >= bus)
            .unwrap_or(false)
    }
}

static RESERVED: SpinLock<Vec<ReservedRegion>> = SpinLock::new(Vec::new());
static PANIC_ON_INVALID_RMRR: AtomicBool = AtomicBool::new(false);

/// Replace the reserved-region set with the firmware description.
pub fn set_reserved_regions(regions: Vec<ReservedRegion>, panic_on_invalid: bool) {
    PANIC_ON_INVALID_RMRR.store(panic_on_invalid, Ordering::Release);
    for region in &regions {
        if region.base > region.limit {
            if panic_on_invalid {
                panic!(
                    "IOMMU: invalid RMRR {}..{} for segment {}",
                    region.base, region.limit, region.segment
                );
            }
            log::warn!(
                "[IOMMU] ignoring inverted RMRR {:#x}..{:#x} seg={}",
                region.base,
                region.limit,
                region.segment
            );
        }
    }
    *RESERVED.lock() = regions;
}

/// Snapshot of the reserved regions, for diagnostics and `/srv/iommu`.
pub fn reserved_regions() -> Vec<ReservedRegion> {
    RESERVED.lock().clone()
}

/// Find the reserved region, if any, covering `[start, start + len)` for `sbdf`.
pub fn reserved_conflict(sbdf: Sbdf, start: u64, len: u64) -> Option<ReservedRegion> {
    RESERVED
        .lock()
        .iter()
        .find(|r| r.covers(sbdf) && r.overlaps(start, len))
        .cloned()
}

// =============================================================================
// Statistics
// =============================================================================

/// Per-domain counters exported through `/srv/iommu`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DomainStats {
    pub maps: u64,
    pub unmaps: u64,
    pub bytes_mapped: u64,
    pub faults: u64,
    pub dropped_faults: u64,
}

/// Global counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IommuStats {
    pub domains_created: u64,
    pub domains_destroyed: u64,
    pub maps: u64,
    pub unmaps: u64,
    pub faults: u64,
    pub dropped_faults: u64,
    pub activations: u64,
}

static STATS: SpinLock<IommuStats> = SpinLock::new(IommuStats {
    domains_created: 0,
    domains_destroyed: 0,
    maps: 0,
    unmaps: 0,
    faults: 0,
    dropped_faults: 0,
    activations: 0,
});

/// Snapshot of the global counters.
pub fn stats() -> IommuStats {
    *STATS.lock()
}

#[derive(Debug)]
struct DomainState {
    refs: usize,
    generation: u64,
    quiesced: bool,
    owner: Option<u32>,
    policy: FaultPolicy,
    fault_budget: u32,
    stats: DomainStats,
    mappings: BTreeMap<u64, Mapping>,
}

impl DomainState {
    fn new(owner: Option<u32>, policy: FaultPolicy) -> Self {
        Self {
            refs: 1,
            generation: 0,
            quiesced: false,
            owner,
            policy,
            fault_budget: FAULT_BURST,
            stats: DomainStats::default(),
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
    /// Constructor for tests and kernel-internal domains without an owner.
    #[allow(dead_code)]
    fn new(id: DomainId, sbdf: Sbdf) -> Self {
        Self::new_owned(id, sbdf, None, FaultPolicy::Log)
    }

    fn new_owned(
        id: DomainId,
        sbdf: Sbdf,
        owner: Option<u32>,
        policy: FaultPolicy,
    ) -> Self {
        Self {
            id,
            sbdf,
            state: SpinLock::new(DomainState::new(owner, policy)),
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

    /// Owning silo SID, when the domain was created for a userspace driver.
    pub fn owner(&self) -> Option<u32> {
        self.state.lock().owner
    }

    /// Fault policy attached to this domain.
    pub fn fault_policy(&self) -> FaultPolicy {
        self.state.lock().policy
    }

    /// Change the fault policy.
    pub fn set_fault_policy(&self, policy: FaultPolicy) {
        self.state.lock().policy = policy;
    }

    /// True when new mappings are refused.
    pub fn is_quiesced(&self) -> bool {
        self.state.lock().quiesced
    }

    /// Stop accepting new mappings (hot-unplug prep).
    pub fn quiesce(&self) {
        let mut state = self.state.lock();
        state.quiesced = true;
        state.generation = state.generation.wrapping_add(1);
    }

    /// Accept new mappings again.
    pub fn resume(&self) {
        let mut state = self.state.lock();
        state.quiesced = false;
        state.generation = state.generation.wrapping_add(1);
    }

    /// Per-domain statistics.
    pub fn stats(&self) -> DomainStats {
        self.state.lock().stats
    }

    /// Number of bytes currently mapped.
    pub fn mapped_bytes(&self) -> u64 {
        self.state
            .lock()
            .mappings
            .values()
            .map(|mapping| mapping.len)
            .sum()
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
        let kind = MappingKind::best_for(iova, len)
            .filter(|kind| phys & (kind.size() - 1) == 0)
            .unwrap_or(MappingKind::Page4K);
        self.map_kind(iova, phys, len, prot, kind)
    }

    /// Map `len` bytes using an explicit page granularity.
    pub fn map_kind(
        &self,
        iova: u64,
        phys: u64,
        len: u64,
        prot: DmaProt,
        kind: MappingKind,
    ) -> Result<(), IommuError> {
        self.map_impl(iova, phys, len, prot, kind, false)
    }

    /// Identity-map a firmware-reserved range (RMRR/IVMD) into this domain.
    ///
    /// This bypasses the reserved-region conflict check: it is the one path
    /// allowed to touch those pages, and only for their owning device.
    pub fn map_reserved(
        &self,
        iova: u64,
        phys: u64,
        len: u64,
        prot: DmaProt,
    ) -> Result<(), IommuError> {
        let kind = MappingKind::best_for(iova, len)
            .filter(|kind| phys & (kind.size() - 1) == 0)
            .unwrap_or(MappingKind::Page4K);
        self.map_impl(iova, phys, len, prot, kind, true)
    }

    fn map_impl(
        &self,
        iova: u64,
        phys: u64,
        len: u64,
        prot: DmaProt,
        kind: MappingKind,
        allow_reserved: bool,
    ) -> Result<(), IommuError> {
        validate_range(iova, len)?;
        let leaf = kind.size();
        if iova & (leaf - 1) != 0 || len & (leaf - 1) != 0 {
            return Err(IommuError::InvalidRange);
        }
        if phys & (IOMMU_PAGE_SIZE - 1) != 0 {
            return Err(IommuError::InvalidRange);
        }
        phys.checked_add(len).ok_or(IommuError::InvalidRange)?;

        // Firmware-reserved regions (RMRR/IVMD) must not be handed to a
        // domain unless the device is their intended owner.
        if !allow_reserved && reserved_conflict(self.sbdf, phys, len).is_some() {
            return Err(IommuError::Reserved);
        }

        let mut state = self.state.lock();
        if state.quiesced {
            return Err(IommuError::Quiesced);
        }

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

        // Program the backend first: a hardware refusal must leave the
        // software table unchanged.
        crate::arch::iommu::map_domain(self.id, self.sbdf, iova, phys, len, prot, kind)
            .map_err(backend_error)?;

        state.mappings.insert(
            iova,
            Mapping {
                iova,
                phys,
                len,
                prot,
                kind,
            },
        );
        state.generation = state.generation.wrapping_add(1);
        state.stats.maps = state.stats.maps.wrapping_add(1);
        state.stats.bytes_mapped = state.stats.bytes_mapped.wrapping_add(len);
        drop(state);
        let mut global = STATS.lock();
        global.maps = global.maps.wrapping_add(1);
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

        // Tear down hardware shadows before forgetting the mappings.
        for key in &keys {
            if let Some(mapping) = state.mappings.get(key).copied() {
                crate::arch::iommu::unmap_domain(
                    self.id,
                    self.sbdf,
                    mapping.iova,
                    mapping.len,
                    mapping.kind,
                )
                .map_err(backend_error)?;
            }
        }

        let mut removed_bytes = 0u64;
        for key in &keys {
            if let Some(mapping) = state.mappings.remove(key) {
                removed_bytes = removed_bytes.wrapping_add(mapping.len);
            }
        }
        state.generation = state.generation.wrapping_add(1);
        state.stats.unmaps = state.stats.unmaps.wrapping_add(keys.len() as u64);
        state.stats.bytes_mapped = state.stats.bytes_mapped.saturating_sub(removed_bytes);
        let removed = keys.len();
        drop(state);
        let mut global = STATS.lock();
        global.unmaps = global.unmaps.wrapping_add(removed as u64);
        Ok(removed)
    }

    /// Remove exactly one mapping that starts at `iova`.
    pub fn unmap_exact(&self, iova: u64) -> Result<Mapping, IommuError> {
        let mut state = self.state.lock();
        let mapping = *state.mappings.get(&iova).ok_or(IommuError::NotMapped)?;
        crate::arch::iommu::unmap_domain(
            self.id,
            self.sbdf,
            mapping.iova,
            mapping.len,
            mapping.kind,
        )
        .map_err(backend_error)?;
        state.mappings.remove(&iova);
        state.generation = state.generation.wrapping_add(1);
        state.stats.unmaps = state.stats.unmaps.wrapping_add(1);
        state.stats.bytes_mapped = state.stats.bytes_mapped.saturating_sub(mapping.len);
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
        let mappings: Vec<Mapping> = self.state.lock().mappings.values().copied().collect();
        for mapping in mappings {
            let _ = crate::arch::iommu::unmap_domain(
                self.id,
                self.sbdf,
                mapping.iova,
                mapping.len,
                mapping.kind,
            );
        }
        let mut state = self.state.lock();
        if !state.mappings.is_empty() {
            state.mappings.clear();
            state.stats.bytes_mapped = 0;
            state.generation = state.generation.wrapping_add(1);
        }
    }

    /// Record a fault for this domain and apply its policy.
    ///
    /// Returns the queued record (with the action that was taken).  The
    /// per-domain burst budget bounds the work done by a misbehaving device;
    /// excess records are counted and dropped.
    pub fn report_fault(
        &self,
        iova: u64,
        reason: FaultReason,
        access: DmaProt,
    ) -> Option<FaultRecord> {
        let (owner, action, seq) = {
            let mut state = self.state.lock();
            state.stats.faults = state.stats.faults.wrapping_add(1);
            let policy = state.policy;
            let action = policy.action();
            let seq = FAULT_SEQ.fetch_add(1, Ordering::Relaxed);
            if state.fault_budget == 0 {
                state.stats.dropped_faults = state.stats.dropped_faults.wrapping_add(1);
                drop(state);
                FAULT_DROPPED.fetch_add(1, Ordering::Relaxed);
                let mut global = STATS.lock();
                global.dropped_faults = global.dropped_faults.wrapping_add(1);
                drop(global);
                if policy == FaultPolicy::Panic {
                    panic!("IOMMU fault (rate-limited) domain={:?}", self.id);
                }
                return None;
            }
            state.fault_budget -= 1;
            (state.owner, action, seq)
        };

        let record = FaultRecord {
            seq,
            timestamp_ns: crate::syscall::time::current_time_ns(),
            domain: self.id,
            sbdf: self.sbdf,
            iova,
            reason,
            access,
            owner,
            action,
        };

        {
            let mut global = STATS.lock();
            global.faults = global.faults.wrapping_add(1);
        }
        if FAULTS.lock().push_back(record).is_err() {
            FAULT_DROPPED.fetch_add(1, Ordering::Relaxed);
            let mut global = STATS.lock();
            global.dropped_faults = global.dropped_faults.wrapping_add(1);
        }

        match action {
            FaultAction::OwnerRevoked => {
                if let Some(sid) = owner {
                    revoke_owner(sid);
                }
            }
            FaultAction::Panicked => {
                panic!(
                    "IOMMU fault: sbdf={} iova={:#x} domain={:?}",
                    self.sbdf, iova, self.id
                );
            }
            _ => {}
        }
        Some(record)
    }
}

fn validate_range(iova: u64, len: u64) -> Result<(), IommuError> {
    if len == 0 || iova & (IOMMU_PAGE_SIZE - 1) != 0 || len & (IOMMU_PAGE_SIZE - 1) != 0 {
        return Err(IommuError::InvalidRange);
    }
    iova.checked_add(len).ok_or(IommuError::InvalidRange)?;
    Ok(())
}

fn backend_error(error: crate::arch::iommu::IommuError) -> IommuError {
    use crate::arch::iommu::IommuError as Backend;
    match error {
        Backend::NotPresent => IommuError::NotPresent,
        Backend::NotReady => IommuError::BackendNotReady,
        Backend::Unsupported => IommuError::Unsupported,
        Backend::Hardware => IommuError::Hardware,
        Backend::InvalidDomain => IommuError::UnknownDomain,
    }
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
    domain_for_owned(sbdf, None, FaultPolicy::Log)
}

/// Same as [`domain_for`], but records the owning silo and its fault policy.
///
/// When the domain is created, firmware-reserved ranges (RMRR/IVMD) that
/// apply to `sbdf` are identity-mapped so the device keeps working on its
/// reserved buffers.
pub fn domain_for_owned(
    sbdf: Sbdf,
    owner: Option<u32>,
    policy: FaultPolicy,
) -> Result<Arc<Domain>, IommuError> {
    let mut domains = DOMAINS.lock();
    if let Some(existing) = domains.values().find(|domain| domain.sbdf() == sbdf) {
        existing.acquire();
        return Ok(existing.clone());
    }
    let id = allocate_domain_id()?;
    let domain = Arc::new(Domain::new_owned(id, sbdf, owner, policy));
    domains.insert(id, domain.clone());
    {
        let mut global = STATS.lock();
        global.domains_created = global.domains_created.wrapping_add(1);
    }

    // Identity-map the firmware-reserved regions this device owns.
    for region in RESERVED.lock().iter().filter(|r| r.covers(sbdf)) {
        let start = region.base & !(IOMMU_PAGE_SIZE - 1);
        let Some(end) = region
            .limit
            .checked_add(IOMMU_PAGE_SIZE)
            .map(|limit| limit & !(IOMMU_PAGE_SIZE - 1))
        else {
            continue;
        };
        if end <= start {
            continue;
        }
        if let Err(err) =
            domain.map_reserved(start, start, end - start, DmaProt::READ_WRITE)
        {
            log::warn!(
                "[IOMMU] cannot identity-map RMRR {:#x}..{:#x} for {}: {:?}",
                start,
                end - 1,
                sbdf,
                err
            );
        }
    }

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
        let mut global = STATS.lock();
        global.domains_destroyed = global.domains_destroyed.wrapping_add(1);
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
    let mut global = STATS.lock();
    global.domains_destroyed = global.domains_destroyed.wrapping_add(1);
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

/// Number of live domains and mapped bytes owned by a silo.
pub fn owner_usage(sid: u32) -> (usize, u64) {
    let domains = DOMAINS.lock();
    let owned: Vec<Arc<Domain>> = domains
        .values()
        .filter(|domain| domain.owner() == Some(sid))
        .cloned()
        .collect();
    drop(domains);
    let mut bytes = 0u64;
    for domain in &owned {
        bytes = bytes.saturating_add(domain.mapped_bytes());
    }
    (owned.len(), bytes)
}

/// Destroy every domain owned by `sid` (silo death, hot-unplug, fault).
pub fn revoke_owner(sid: u32) -> usize {
    let ids: Vec<DomainId> = {
        let domains = DOMAINS.lock();
        domains
            .values()
            .filter(|domain| domain.owner() == Some(sid))
            .map(|domain| domain.id())
            .collect()
    };
    let mut revoked = 0;
    for id in ids {
        if teardown(id) {
            revoked += 1;
        }
    }
    if revoked > 0 {
        log::warn!("[IOMMU] revoked {} domain(s) for silo {}", revoked, sid);
    }
    revoked
}

/// Stop accepting new mappings for a domain (hot-unplug preparation).
pub fn quiesce(id: DomainId) -> Result<(), IommuError> {
    lookup(id)?.quiesce();
    Ok(())
}

/// Allow new mappings again.
pub fn resume(id: DomainId) -> Result<(), IommuError> {
    lookup(id)?.resume();
    Ok(())
}

/// Detach a domain from its device: quiesce, then tear it down.
pub fn detach(id: DomainId) -> bool {
    if let Ok(domain) = lookup(id) {
        domain.quiesce();
    }
    teardown(id)
}

/// Detach every domain bound to `sbdf` (device hot-removal).
pub fn detach_device(sbdf: Sbdf) -> usize {
    let ids: Vec<DomainId> = DOMAINS
        .lock()
        .values()
        .filter(|domain| domain.sbdf() == sbdf)
        .map(|domain| domain.id())
        .collect();
    let mut detached = 0;
    for id in ids {
        if detach(id) {
            detached += 1;
        }
    }
    if detached > 0 {
        log::info!("[IOMMU] detached {} domain(s) from {}", detached, sbdf);
    }
    detached
}

/// Map a range with automatic 2 MiB/1 GiB superpage selection.
pub fn map_super(
    domain: DomainId,
    iova: u64,
    phys: u64,
    len: u64,
    prot: DmaProt,
) -> Result<MappingKind, IommuError> {
    let domain = lookup(domain)?;
    let kind = MappingKind::best_for(iova, len)
        .filter(|kind| phys & (kind.size() - 1) == 0)
        .ok_or(IommuError::InvalidRange)?;
    domain.map_kind(iova, phys, len, prot, kind)?;
    Ok(kind)
}

// =============================================================================
// Fault queue API
// =============================================================================

/// Pop the oldest fault record.
pub fn next_fault() -> Option<FaultRecord> {
    FAULTS.lock().pop_front()
}

/// Number of fault records dropped by the rate limiter or a full queue.
pub fn faults_dropped() -> u64 {
    FAULT_DROPPED.load(Ordering::Relaxed)
}

/// Refill the per-domain fault burst budget.
pub fn refill_fault_budget(domain: DomainId, burst: u32) {
    if let Ok(domain) = lookup(domain) {
        domain.state.lock().fault_budget = burst;
    }
}

/// Inject a synthetic fault (debug builds and fault-policy tests).
pub fn inject_fault(
    domain: DomainId,
    iova: u64,
    reason: FaultReason,
    access: DmaProt,
) -> Option<FaultRecord> {
    lookup(domain).ok()?.report_fault(iova, reason, access)
}

/// Coarse IOMMU groups derived from the DMAR DRHD scopes.
///
/// This is not a full PCIe ACS analysis: devices sharing a DRHD and a bus are
/// reported together, which is enough to warn a caller that two functions
/// cannot be isolated from each other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IommuGroup {
    pub id: u32,
    pub segment: u16,
    pub bus: u8,
    pub devices: Vec<Sbdf>,
}

/// Return the coarse IOMMU groups advertised by the firmware.
pub fn groups() -> Vec<IommuGroup> {
    let Some(dmar) = crate::acpi::get_dmar() else {
        return Vec::new();
    };
    let Ok(units) = dmar.drhds() else {
        return Vec::new();
    };
    let mut groups: Vec<IommuGroup> = Vec::new();
    for unit in units {
        for scope in unit.scopes {
            let e = match scope.endpoint() {
                Some(endpoint) => endpoint,
                None => continue,
            };
            let sbdf = Sbdf::new(unit.segment, e.0, e.1, e.2);
            if let Some(group) = groups
                .iter_mut()
                .find(|g| g.segment == sbdf.segment && g.bus == sbdf.bus)
            {
                if !group.devices.contains(&sbdf) {
                    group.devices.push(sbdf);
                }
            } else {
                groups.push(IommuGroup {
                    id: groups.len() as u32,
                    segment: sbdf.segment,
                    bus: sbdf.bus,
                    devices: alloc::vec![sbdf],
                });
            }
        }
    }
    groups
}

/// Parse the firmware tables and log a short IOMMU summary.
///
/// This never touches hardware: activation is a separate, explicit step.
pub fn init() {
    let discovery = crate::arch::iommu::init();
    load_reserved_regions();
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
    let mut global = STATS.lock();
    global.activations = global.activations.wrapping_add(1);
    true
}

/// Translate the DMAR RMRR structures into [`ReservedRegion`]s.
fn load_reserved_regions() {
    use crate::acpi::dmar::ScopeKind;

    let Some(dmar) = crate::acpi::get_dmar() else {
        return;
    };
    let Ok(rmrrs) = dmar.rmrrs() else {
        return;
    };

    let mut regions = Vec::new();
    for rmrr in rmrrs {
        let mut devices = Vec::new();
        let mut all_bus_from: Option<u8> = None;
        for scope in &rmrr.scopes {
            match scope.kind {
                ScopeKind::PciEndpoint => {
                    if let Some((bus, device, function)) = scope.endpoint() {
                        devices.push(Sbdf::new(rmrr.segment, bus, device, function));
                    }
                }
                ScopeKind::PciSubHierarchy => {
                    if scope.path.is_empty() {
                        all_bus_from = Some(
                            all_bus_from
                                .map(|bus| bus.min(scope.start_bus))
                                .unwrap_or(scope.start_bus),
                        );
                    } else if let Some(path) = scope.path.last() {
                        devices.push(Sbdf::new(
                            rmrr.segment,
                            scope.start_bus,
                            path.device,
                            path.function,
                        ));
                    }
                }
                _ => {}
            }
        }
        if devices.is_empty() && all_bus_from.is_none() {
            let panic_on_invalid = PANIC_ON_INVALID_RMRR.load(Ordering::Acquire);
            if panic_on_invalid {
                panic!(
                    "IOMMU: RMRR {:#x}..{:#x} has no device scope",
                    rmrr.base, rmrr.limit
                );
            }
            log::warn!(
                "[IOMMU] ignoring RMRR {:#x}..{:#x} without a usable device scope",
                rmrr.base,
                rmrr.limit
            );
            continue;
        }
        regions.push(ReservedRegion {
            segment: rmrr.segment,
            base: rmrr.base,
            limit: rmrr.limit,
            devices,
            all_bus_from,
            identity_mapped: false,
        });
    }

    if !regions.is_empty() {
        log::info!("[IOMMU] {} reserved region(s) from RMRR", regions.len());
    }
    set_reserved_regions(regions, false);
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
    fn superpage_selection() {
        assert_eq!(
            MappingKind::best_for(IOVA_BASE, IOMMU_SUPERPAGE_2M),
            Some(MappingKind::Page2M)
        );
        assert_eq!(
            MappingKind::best_for(IOVA_BASE, IOMMU_SUPERPAGE_1G),
            Some(MappingKind::Page1G)
        );
        // Misaligned base must fall back to 4 KiB leaves.
        assert_eq!(
            MappingKind::best_for(IOVA_BASE + IOMMU_PAGE_SIZE, IOMMU_SUPERPAGE_2M),
            Some(MappingKind::Page4K)
        );
        assert_eq!(MappingKind::best_for(IOVA_BASE, 0), None);
    }

    #[test]
    fn quiesce_refuses_new_mappings() {
        let domain = Domain::new(DomainId(21), Sbdf::from_pci(0, 5, 0));
        domain.quiesce();
        assert_eq!(
            domain.map(IOVA_BASE, 0x1000, 0x1000, DmaProt::READ),
            Err(IommuError::Quiesced)
        );
        domain.resume();
        assert!(domain
            .map(IOVA_BASE, 0x1000, 0x1000, DmaProt::READ)
            .is_ok());
    }

    #[test]
    fn reserved_regions_are_rejected() {
        let sbdf = Sbdf::from_pci(0, 6, 0);
        set_reserved_regions(
            alloc::vec![ReservedRegion {
                segment: 0,
                base: 0x8000,
                limit: 0x8fff,
                devices: alloc::vec![sbdf],
                all_bus_from: None,
                identity_mapped: false,
            }],
            false,
        );
        let domain = Domain::new(DomainId(22), sbdf);
        assert_eq!(
            domain.map(IOVA_BASE, 0x8000, 0x1000, DmaProt::READ),
            Err(IommuError::Reserved)
        );
        // The reserved identity mapping path is the only way in.
        assert!(domain
            .map_reserved(0x8000, 0x8000, 0x1000, DmaProt::READ_WRITE)
            .is_ok());
        set_reserved_regions(alloc::vec![], false);
    }

    #[test]
    fn fault_policy_kill_owner_records_the_action() {
        let domain = Domain::new_owned(
            DomainId(23),
            Sbdf::from_pci(0, 7, 0),
            Some(42),
            FaultPolicy::KillOwner,
        );
        let record = domain
            .report_fault(IOVA_BASE, FaultReason::Write, DmaProt::WRITE)
            .expect("fault queued");
        assert_eq!(record.owner, Some(42));
        assert_eq!(record.action, FaultAction::OwnerRevoked);
        assert_eq!(domain.stats().faults, 1);
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
