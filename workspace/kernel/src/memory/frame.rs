// Physical frame allocator abstraction

use crate::{memory::boot_alloc::BootAllocator, sync::IrqDisabledToken};
use core::{
    mem, ptr,
    sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering},
};
use x86_64::PhysAddr;

// ──────────────────────────────────────────────────────────────────────────────
// FrameAllocOptions  (Asterinas OSTD pattern)
// ──────────────────────────────────────────────────────────────────────────────
//
// DESIGN NOTES — why this wrapper exists:
//
//  * In Asterinas OSTD, `FrameAllocOptions::new()` defaults to `zeroed: true`.
//    This means callers can never accidentally hand out a frame that still holds
//    data from a previous lifetime.  The only way to skip zeroing is an
//    explicit `.zeroed(false)` call at the site that *knows* it is safe to do
//    so (e.g. a frame that will be fully overwritten before any read).
//
//  * The critical failure mode we are fixing:
//    `BuddyFrameAllocator::allocate_frame` (used by `OffsetPageTable` when it
//    needs a new intermediate page-table node) was returning raw, unzeroed
//    frames.  A freshly-split buddy block can contain bytes left behind by the
//    slab allocator (POISON_BYTE = 0xDE) or by whatever previously lived in
//    that memory.  The CPU page-table walker reads all 512 entries of every
//    intermediate node it traverses.  A random non-zero entry is decoded as a
//    valid PTE pointing to an arbitrary physical address — which explains why
//    RIP (the first fetch address the CPU tries after entering Ring 3) changes
//    on every boot.
//
//  * The `flags` field mirrors OSTD's per-frame metadata: we stamp the purpose
//    (kernel / user / page-table) into `FrameMeta::flags` atomically using
//    `Ordering::Release` so that any CPU that later reads the frame through
//    `get_meta` observes the correct flags.
//
//  * Refcount state machine (OSTD-style, fully enforced):
//
//    `buddy.rs` maintains the invariant: free-list frame ⟹ refcount == REFCOUNT_UNUSED.
//    `mark_block_free()` stamps REFCOUNT_UNUSED; `mark_block_allocated()` leaves it
//    untouched.  `FrameAllocOptions::allocate()` performs CAS(REFCOUNT_UNUSED → 1)
//    as a fail-fast corruption check before publishing the frame as live:
//
//       buddy alloc ──▶ optional zero ──▶ set flags ──▶ CAS(UNUSED → 1) ──▶ live

/// Sentinel refcount for a frame that is in the buddy free list.
///
/// Mirrors `REF_COUNT_UNUSED` in Asterinas OSTD `meta.rs`.
///
/// `buddy.rs` stamps this value in `mark_block_free()` and leaves it intact in
/// `mark_block_allocated()`.  `FrameAllocOptions::allocate()` performs
/// `CAS(REFCOUNT_UNUSED → 1)` to atomically claim the frame and detect any
/// double-free / free-list corruption.
pub const REFCOUNT_UNUSED: u32 = u32::MAX;

/// Options controlling how a physical frame is allocated.
///
/// The default configuration (`FrameAllocOptions::new()`) produces a
/// **zeroed** frame.  Callers that need a non-zeroed frame (e.g. DMA buffers
/// that are immediately filled by hardware, or frames that will be fully
/// overwritten before any read) must explicitly call `.zeroed(false)`.
///
/// # Example
///
/// ```ignore
/// // Allocate a zeroed page-table frame (the safe default).
/// let frame = FrameAllocOptions::new()
///     .purpose(FramePurpose::PageTable)
///     .allocate(token)?;
///
/// // Allocate a user-data frame without zeroing (caller guarantees it will
/// // be fully overwritten, e.g. by an ELF segment load).
/// let frame = FrameAllocOptions::new()
///     .zeroed(false)
///     .purpose(FramePurpose::UserData)
///     .allocate(token)?;
/// ```
pub struct FrameAllocOptions {
    /// Whether the frame content should be zeroed before being returned.
    ///
    /// Defaults to `true`.  Setting this to `false` is only safe when the
    /// caller guarantees the frame will be fully written before any read.
    zeroed: bool,
    /// The logical purpose of the frame, encoded as `frame_flags` bits.
    purpose_flags: u32,
}

/// Describes the intended purpose of an allocated frame.
///
/// Purpose is written into `FrameMeta::flags` with `Ordering::Release` so
/// that any concurrent reader of the metadata (e.g. a TLB-shootdown handler
/// deciding whether a frame holds a page-table node) sees a consistent view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramePurpose {
    /// Frame will hold a kernel page-table node (PML4/PDPT/PD/PT).
    ///
    /// These frames MUST be zeroed — unzeroed page-table nodes are the primary
    /// source of non-deterministic RIP at Ring 3 transition.
    PageTable,
    /// Frame belongs to kernel address-space (e.g. heap, stack, metadata).
    KernelData,
    /// Frame belongs to a user-space address-space (anonymous or file-backed).
    UserData,
    /// Caller-managed; raw flags are passed through unchanged.
    Custom(u32),
}

impl FramePurpose {
    fn to_flags(self) -> u32 {
        match self {
            // Page-table frames are always kernel-owned.
            Self::PageTable => frame_flags::KERNEL | frame_flags::ALLOCATED,
            Self::KernelData => frame_flags::KERNEL | frame_flags::ALLOCATED,
            Self::UserData => frame_flags::USER | frame_flags::ALLOCATED,
            Self::Custom(f) => f | frame_flags::ALLOCATED,
        }
    }

    /// Returns `true` if this purpose requires zeroing regardless of the
    /// `zeroed` option.  Page-table nodes must always be zeroed.
    pub fn requires_zero(self) -> bool {
        matches!(self, Self::PageTable)
    }
}

impl Default for FrameAllocOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameAllocOptions {
    /// Creates allocation options with safe defaults:
    ///  - `zeroed = true`
    ///  - purpose = `KernelData`
    pub fn new() -> Self {
        Self {
            zeroed: true,
            purpose_flags: FramePurpose::KernelData.to_flags(),
        }
    }

    /// Override the zero-initialisation policy.
    ///
    /// # Safety contract (enforced by convention, not the type system)
    ///
    /// If `zeroed` is set to `false`, the caller MUST fully overwrite every
    /// byte of the frame before allowing any other CPU or subsystem to read it.
    /// Violating this rule is a memory-safety hazard: stale bytes in an
    /// intermediate page-table node cause the CPU to follow arbitrary PTEs.
    pub fn zeroed(mut self, zeroed: bool) -> Self {
        self.zeroed = zeroed;
        self
    }

    /// Set the intended purpose of the frame.
    ///
    /// `PageTable` purpose forces zeroing even if `.zeroed(false)` was called.
    pub fn purpose(mut self, p: FramePurpose) -> Self {
        self.purpose_flags = p.to_flags();
        // Page-table nodes must always be zeroed — override any caller setting.
        if p.requires_zero() {
            self.zeroed = true;
        }
        self
    }

    /// Allocate a single 4 KiB frame according to the configured options.
    ///
    /// The allocation path is:
    ///
    /// 1. Ask the buddy allocator for an order-0 frame (exclusive ownership is
    ///    guaranteed by the buddy's own bitmap + free-list discipline).
    /// 2. Optionally zero the 4 KiB frame contents via the HHDM.
    /// 3. Stamp `FrameMeta::flags` with the purpose flags using `Release`
    ///    ordering.
    /// 4. Store `refcount = 1` with `Release` ordering so any later `Acquire`
    ///    load of the refcount observes the fully-initialised metadata and
    ///    (if zeroed) zeroed content.
    ///
    /// # Sentinel handoff: `CAS(REFCOUNT_UNUSED → 1)`
    ///
    /// `buddy.rs` maintains the invariant that every frame on the free list has
    /// `refcount == REFCOUNT_UNUSED`.  `mark_block_allocated()` leaves this
    /// sentinel intact, so the frame arriving here still carries `REFCOUNT_UNUSED`.
    ///
    /// The CAS atomically claims the frame and acts as a fail-fast corruption
    /// check: if the same frame appears twice in the buddy free list (double-free
    /// or metadata corruption), the second allocation attempt will observe a
    /// refcount of `1` (set by the first allocation) and panic immediately rather
    /// than silently aliasing memory.
    pub fn allocate(self, token: &IrqDisabledToken) -> Result<PhysFrame, AllocError> {
        // Step 1 — exclusive frame from the buddy allocator.
        let frame = crate::memory::buddy::alloc(token, 0)?;
        let phys = frame.start_address.as_u64();

        // SAFETY: `get_meta` panics only if `phys` is out-of-bounds, which
        // would be a buddy-level invariant violation (it returned an address
        // beyond the metadata array).  That is a kernel bug, not UB here.
        let meta = get_meta(frame.start_address);

        // Step 2 — zero the frame content if required.
        //
        // The zeroing MUST happen before the `Release` store of `refcount = 1`
        // (step 4) so that any thread performing an `Acquire` load of the
        // refcount and then reading frame bytes observes zeros.
        //
        // For `FramePurpose::PageTable` this is unconditional: the CPU's
        // page-table walker reads all 512 entries of every intermediate node it
        // visits.  Stale non-zero bytes would be decoded as valid PTEs pointing
        // to arbitrary physical addresses, producing a non-deterministic RIP on
        // Ring 3 entry (the root cause of the original bug).
        //
        // SAFETY: `phys_to_virt(phys)` is a valid HHDM address covering exactly
        // `PAGE_SIZE` bytes.  The buddy allocator guarantees we have exclusive
        // ownership of these bytes for the duration of this function.
        if self.zeroed {
            unsafe {
                ptr::write_bytes(
                    crate::memory::phys_to_virt(phys) as *mut u8,
                    0,
                    PAGE_SIZE as usize,
                );
            }
        }

        // Step 3 — stamp purpose flags with `Release` ordering.
        //
        // Any reader that subsequently loads `refcount` with `Acquire` (step 4)
        // is guaranteed to observe these flags as well.
        meta.flags.store(self.purpose_flags, Ordering::Release);
        meta.set_order(0);

        // Step 4 — claim the frame and publish it as live.
        //
        // CAS(REFCOUNT_UNUSED → 1): atomically transitions the frame from the
        // buddy free-list sentinel to a live, exclusively-owned frame.  The
        // `AcqRel` success ordering ensures steps 2 and 3 happen-before any
        // `Acquire` load of this refcount by another CPU, and also observes
        // the buddy's `Release` store of REFCOUNT_UNUSED.
        //
        // Failure means the frame's refcount was not REFCOUNT_UNUSED — either
        // the frame is still live (double-alloc) or the buddy free list is
        // corrupt (double-free).  Both are kernel bugs; panic immediately.
        meta.cas_refcount(REFCOUNT_UNUSED, 1)
            .unwrap_or_else(|actual| {
                panic!(
                    "buddy corruption: frame {:#x} refcount is {:#x} (expected REFCOUNT_UNUSED); \
                 double-free or free-list corruption",
                    phys, actual,
                )
            });

        Ok(frame)
    }
}

pub const PAGE_SIZE: u64 = 4096;
pub const FRAME_META_ALIGN: usize = 64;
pub const FRAME_META_SIZE: usize = 64;
pub const FRAME_META_LINK_NONE: u64 = u64::MAX;

/// Persistent flags stored in [`FrameMeta`].
pub mod frame_flags {
    /// La frame est allouée.
    pub const ALLOCATED: u32 = 1 << 8;
    /// La frame est libre.
    pub const FREE: u32 = 1 << 9;
    /// La frame est réservée au noyau.
    pub const KERNEL: u32 = 1 << 10;
    /// La frame appartient à l'espace utilisateur.
    pub const USER: u32 = 1 << 11;
    /// La frame est empoisonnée et ne doit plus être recyclée telle quelle.
    pub const POISONED: u32 = 1 << 12;
    /// Frame éligible au copy-on-write.
    pub const COW: u32 = 1 << 0;
    /// Frame partagée de type DLL, jamais COW.
    pub const DLL: u32 = 1 << 1;
    /// Frame anonyme.
    pub const ANONYMOUS: u32 = 1 << 2;
}

/// Bytes used by the named fields of [`FrameMeta`] before the padding.
const FRAME_META_FIELDS_SIZE: usize = 8 + 8 + 4 + 1 + 3 + 4; // next+prev+flags+order+_reserved0+refcount

/// Intriside metadata for a physical frame.
/// - 64 bytes (one cache line) for efficient atomic access and to avoid false sharing.

#[repr(C, align(64))]
pub struct FrameMeta {
    pub(crate) next: AtomicU64,
    pub(crate) prev: AtomicU64,
    pub(crate) flags: AtomicU32,
    pub(crate) order: AtomicU8,
    _reserved0: [u8; 3],
    pub(crate) refcount: AtomicU32,
    _cacheline_pad: [u8; FRAME_META_SIZE - FRAME_META_FIELDS_SIZE],
}

impl FrameMeta {
    /// Create emplty metadata ready to be initialized by the boot allocator.
    pub const fn new() -> Self {
        Self {
            next: AtomicU64::new(FRAME_META_LINK_NONE),
            prev: AtomicU64::new(FRAME_META_LINK_NONE),
            flags: AtomicU32::new(0),
            order: AtomicU8::new(0),
            ///
            _reserved0: [0; 3],
            refcount: AtomicU32::new(0),
            _cacheline_pad: [0; FRAME_META_SIZE - FRAME_META_FIELDS_SIZE],
        }
    }

    #[inline]
    pub fn next(&self) -> u64 {
        self.next.load(Ordering::Acquire)
    }

    #[inline]
    pub fn set_next(&self, next: u64) {
        self.next.store(next, Ordering::Release);
    }

    #[inline]
    pub fn prev(&self) -> u64 {
        self.prev.load(Ordering::Acquire)
    }

    #[inline]
    pub fn set_prev(&self, prev: u64) {
        self.prev.store(prev, Ordering::Release);
    }

    #[inline]
    pub fn inc_ref(&self) {
        self.refcount.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn dec_ref(&self) -> u32 {
        self.refcount.fetch_sub(1, Ordering::Release)
    }

    #[inline]
    pub fn get_refcount(&self) -> u32 {
        self.refcount.load(Ordering::Acquire)
    }

    #[inline]
    pub fn set_flags(&self, flags: u32) {
        self.flags.store(flags, Ordering::Release);
    }

    #[inline]
    pub fn get_flags(&self) -> u32 {
        self.flags.load(Ordering::Acquire)
    }

    #[inline]
    pub fn get_order(&self) -> u8 {
        self.order.load(Ordering::Acquire)
    }

    #[inline]
    pub fn set_order(&self, order: u8) {
        self.order.store(order, Ordering::Release);
    }

    #[inline]
    pub fn set_refcount(&self, count: u32) {
        self.refcount.store(count, Ordering::Release);
    }

    #[inline]
    pub fn cas_refcount(&self, expect: u32, new: u32) -> Result<u32, u32> {
        self.refcount
            .compare_exchange(expect, new, Ordering::AcqRel, Ordering::Acquire)
    }

    #[inline]
    pub fn reset_refcount(&self) {
        self.set_refcount(0);
    }

    #[inline]
    pub fn is_cow(&self) -> bool {
        self.get_flags() & frame_flags::COW != 0
    }

    #[inline]
    pub fn is_dll(&self) -> bool {
        self.get_flags() & frame_flags::DLL != 0
    }
}

const _: () = {
    assert!(mem::align_of::<FrameMeta>() == FRAME_META_ALIGN);
    assert!(mem::size_of::<FrameMeta>() == FRAME_META_SIZE);
};

/// The metadata array size for `ram_size` bytes, rounded up to the nearest page since each frame
/// has a dedicated metadata entry.

/// @param ram_size Total RAM size to be covered by the metadata (in bytes).
///
pub const fn metadata_size_for(ram_size: u64) -> u64 {
    let frames = (ram_size / PAGE_SIZE) + if ram_size % PAGE_SIZE == 0 { 0 } else { 1 };
    frames * FRAME_META_SIZE as u64
}

static METADATA_BASE_VIRT: AtomicU64 = AtomicU64::new(0);
static METADATA_FRAME_COUNT: AtomicU64 = AtomicU64::new(0);

/// Initialize the global metadata array for all physical frames.
pub fn init_metadata_array(total_ram: u64, boot_alloc: &mut BootAllocator) {
    let frame_count = (total_ram / PAGE_SIZE) + if total_ram % PAGE_SIZE == 0 { 0 } else { 1 };
    if frame_count == 0 {
        METADATA_BASE_VIRT.store(0, Ordering::Release);
        METADATA_FRAME_COUNT.store(0, Ordering::Release);
        return;
    }

    let bytes = metadata_size_for(total_ram) as usize;
    let phys = boot_alloc.alloc(bytes, FRAME_META_ALIGN);
    let virt = crate::memory::phys_to_virt(phys.as_u64()) as *mut FrameMeta;

    for idx in 0..frame_count as usize {
        // SAFETY: le bloc a été réservé par le boot allocator avec un alignement
        // compatible `FrameMeta` et une taille suffisante pour tout le tableau.
        unsafe {
            ptr::write(virt.add(idx), FrameMeta::new());
        }
    }

    METADATA_FRAME_COUNT.store(frame_count, Ordering::Release);
    METADATA_BASE_VIRT.store(virt as u64, Ordering::Release);
}

/// Get the metadata for a given physical frame.
pub fn get_meta(phys: PhysAddr) -> &'static FrameMeta {
    let base = METADATA_BASE_VIRT.load(Ordering::Acquire);
    let frame_count = METADATA_FRAME_COUNT.load(Ordering::Acquire);
    assert!(base != 0, "frame metadata array is not initialized");

    let pfn = phys.as_u64() / PAGE_SIZE;
    assert!(pfn < frame_count, "frame metadata access out of bounds");

    let byte_offset = pfn as usize * FRAME_META_SIZE;
    // SAFETY: le tableau global couvre au moins `frame_count` entrées et reste
    // vivant pendant toute la durée du noyau.
    unsafe { &*((base as usize + byte_offset) as *const FrameMeta) }
}

/// Physical frame (4KB aligned physical memory)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysFrame {
    pub start_address: PhysAddr,
}

/// Performs the phys frame containing address operation.
impl PhysFrame {
    /// Create a PhysFrame containing the given physical address
    pub fn containing_address(addr: PhysAddr) -> Self {
        PhysFrame {
            start_address: PhysAddr::new(addr.as_u64() & !0xFFF),
        }
    }

    /// Create a PhysFrame from a 4KB-aligned address
    pub fn from_start_address(addr: PhysAddr) -> Result<Self, ()> {
        if addr.is_aligned(4096u64) {
            Ok(PhysFrame {
                start_address: addr,
            })
        } else {
            Err(())
        }
    }

    /// Create an inclusive range of frames
    pub fn range_inclusive(start: PhysFrame, end: PhysFrame) -> FrameRangeInclusive {
        FrameRangeInclusive { start, end }
    }
}

/// Iterator over an inclusive range of physical frames
pub struct FrameRangeInclusive {
    pub start: PhysFrame,
    pub end: PhysFrame,
}

/// Performs the iterator operation for FrameRangeInclusive.
impl Iterator for FrameRangeInclusive {
    type Item = PhysFrame;

    /// Performs the next operation.
    fn next(&mut self) -> Option<Self::Item> {
        if self.start <= self.end {
            let frame = self.start;
            self.start.start_address += 4096u64;
            Some(frame)
        } else {
            None
        }
    }
}

/// Frame allocation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocError {
    /// No memory available
    OutOfMemory,
    /// Invalid order (> MAX_ORDER)
    InvalidOrder,
    /// Invalid address alignment
    InvalidAddress,
}

/// Frame allocator trait
pub trait FrameAllocator {
    /// Allocate `2^order` contiguous frames.
    ///
    /// Le token interdit les appels depuis un contexte où le verrou global de
    /// l'allocateur pourrait être ré-entré par interruption.
    fn alloc(&mut self, order: u8, token: &IrqDisabledToken) -> Result<PhysFrame, AllocError>;

    /// Free `2^order` contiguous frames starting at frame.
    fn free(&mut self, frame: PhysFrame, order: u8, token: &IrqDisabledToken);

    /// Allocate a single frame (convenience method)
    fn alloc_frame(&mut self, token: &IrqDisabledToken) -> Result<PhysFrame, AllocError> {
        self.alloc(0, token)
    }
}
