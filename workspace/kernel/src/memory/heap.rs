// Heap allocator: slab sub-allocator + VM-backed large-allocation path.
//
// Small allocations (effective size =< 2048 B) come from per-size-class slab
// free lists.  Each slab class draws whole pages from the buddy allocator and
// carves them into fixed-size blocks.  Freed blocks return to the slab free
// list, so the buddy's page counter stabilises after warm-up instead of
// growing on every tiny allocation.
//
// Large allocations (> 2048 B) go through the kernel vmalloc backend:
// virtually contiguous, physically fragmented, and independent from
// high-order physically contiguous buddy blocks.
//
// Lock ordering : SLAB_ALLOC (outer) may call the frame-allocation helpers.
// Those helpers can hit a CPU-local cache (no global buddy lock) or fall back
// to the global buddy lock as needed.

use crate::{memory, sync::SpinLock};
use core::{
    alloc::{GlobalAlloc, Layout},
    ptr,
    sync::atomic::{AtomicUsize, Ordering as AtomicOrdering},
};
use x86_64::PhysAddr;

// ---------------------------------------------------------------------------
// Slab size classes
// ---------------------------------------------------------------------------

/// Slab block sizes chosen to bound internal fragmentation to ~25% worst-case
/// (average ~12%) instead of 50% with pure power-of-two classes.
///
/// The progression follows a roughly 1.25× step above 64 bytes.  Below 64
/// bytes the absolute waste of a 2× jump is small enough (max 32 bytes) to
/// keep power-of-two boundaries, avoiding an explosion of size classes.
///
/// | Class range | Step      | Max waste |
/// |-------------|-----------|-----------|
/// | 8 to  64 B  | x2 / 1,5× | ≤ 32 B    |
/// |64 to 256 B  | ~ x1,25×  | ≤ 64 B    |
/// |256 to 2048 B| x1,25     | ≤ 512 B   |

const SLAB_SIZES: [usize; 26] = [
    8, 16, 24, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 640, 768, 896,
    1024, 1280, 1536, 1792, 2048,
];
const NUM_SLABS: usize = SLAB_SIZES.len();
/// Allocations with effective size above this threshold bypass the slab.
const MAX_SLAB_SIZE: usize = 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelHeapBackend {
    Slab,
    Vmalloc,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelHeapAllocError {
    InvalidLayout,
    SlabRefillFailed { effective: usize, class_size: usize },
    Vmalloc(memory::vmalloc::VmallocError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelHeapFailureSnapshot {
    pub backend: KernelHeapBackend,
    pub requested_size: usize,
    pub align: usize,
    pub effective_size: usize,
    pub error: KernelHeapAllocError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlabDiagSnapshot {
    pub pages_allocated: usize,
    pub pages_reclaimed: usize,
    pub pages_live: usize,
}

#[inline]
pub(crate) fn classify_kernel_heap_backend(layout: Layout) -> KernelHeapBackend {
    let effective = layout.size().max(layout.align());
    if effective <= MAX_SLAB_SIZE {
        KernelHeapBackend::Slab
    } else {
        KernelHeapBackend::Vmalloc
    }
}

// =============================================================================
// CRITICAL: slab corruption detection
//
// Set HEAP_POISON_ENABLED to true during debugging of heap-corruption crashes.
// When enabled:
//   - Every block carved by refill() is filled with POISON_BYTE in bytes [8..N-4]
//     and stamped with SLAB_CANARY in the last 4 bytes.
//   - dealloc_block() restores the canary and re-poisons before linking.
//   - alloc_block() verifies poison and canary before handing the block out;
//     a mismatch is logged immediately via serial_println! (non-allocating).
//
// This detects:
//   - Use-after-free: a write to a freed slab block overwrites poison bytes.
//   - Buffer overflow: a write past the end overwrites the canary or the next
//     block's free-list pointer.
//
// Cost: one memset + canary write per alloc/dealloc for slab classes.
// =============================================================================
const HEAP_POISON_ENABLED: bool = true;
/// Byte pattern written to the body of freed slab blocks.
const POISON_BYTE: u8 = 0xDE;
/// Canary word placed at the last 4 bytes of each slab block.
const SLAB_CANARY: u32 = 0xDEAD_BEEF;

// ---------------------------------------------------------------------------
// Slab page header : embedded at byte 0 of every buddy page used by a class.
// Blocks start at offset SLAB_HEADER_SIZE within the page.
// ---------------------------------------------------------------------------

/// Header at the base of each 4 KiB page dedicated to a slab class.
///
/// Page layout:
/// ```text
/// [0 .. SLAB_HEADER_SIZE)   SlabPageHeader  (24 bytes)
/// [SLAB_HEADER_SIZE .. 4096) slab blocks, each SLAB_SIZES[ci] bytes
/// ```
///
/// A page lives in `partial_pages[ci]` while `0 < free_count < total_blocks`.
/// It is removed when all blocks are allocated (`free_count == 0`), and is
/// reclaimed to the buddy allocator when it becomes fully empty again
/// (`free_count == total_blocks`).
#[repr(C)]
struct SlabPageHeader {
    /// Next page in the partial list for this class (null = end of list).
    next_partial: *mut SlabPageHeader,
    /// Head of the intra-page free-block chain (null = page is full).
    free_head: *mut u8,
    /// Free blocks currently in this page.
    free_count: u32,
    /// Total blocks this page can hold (constant per class after refill).
    total_blocks: u32,
}

// SAFETY: only accessed under SLAB_ALLOC spinlock.
unsafe impl Send for SlabPageHeader {}
unsafe impl Sync for SlabPageHeader {}

/// Byte offset at which slab blocks begin within each slab page.
const SLAB_HEADER_SIZE: usize = core::mem::size_of::<SlabPageHeader>();

// Compile-time invariants.
const _: () = assert!(
    SLAB_HEADER_SIZE == 24,
    "SlabPageHeader size changed : update docs"
);
const _: () = assert!(
    (4096 - SLAB_HEADER_SIZE) / SLAB_SIZES[NUM_SLABS - 1] >= 1,
    "SlabPageHeader too large: largest slab class gets 0 blocks per page"
);

// ---------------------------------------------------------------------------
// SlabState
// ---------------------------------------------------------------------------

/// Per-size-class partial-page lists.
///
/// `partial_pages[ci]` is the head of a singly-linked list of `SlabPageHeader`
/// nodes for class `ci`.  A page enters the list on `refill` and on the first
/// `dealloc` after going full.  It leaves the list when all its blocks are
/// allocated (it silently becomes "full") or when it becomes completely empty
/// (it is then returned to the buddy allocator).
struct SlabState {
    partial_pages: [*mut SlabPageHeader; NUM_SLABS],
}

// SAFETY: protected exclusively through `SLAB_ALLOC: SpinLock<SlabState>`.
unsafe impl Send for SlabState {}
unsafe impl Sync for SlabState {}

impl SlabState {
    const fn new() -> Self {
        SlabState {
            partial_pages: [ptr::null_mut(); NUM_SLABS],
        }
    }

    /// Return the slab class index for `effective` bytes.
    #[inline]
    fn class_index(effective: usize) -> usize {
        for (i, &s) in SLAB_SIZES.iter().enumerate() {
            if effective <= s {
                return i;
            }
        }
        unreachable!("class_index called with effective > MAX_SLAB_SIZE")
    }

    /// Allocate one buddy page, write a `SlabPageHeader` at its base, carve
    /// the remaining space into blocks, and prepend the page to `partial_pages[ci]`.
    unsafe fn refill(&mut self, ci: usize, token: &crate::sync::IrqDisabledToken) {
        let slab_size = SLAB_SIZES[ci];
        let num_blocks = (4096 - SLAB_HEADER_SIZE) / slab_size;
        debug_assert!(
            num_blocks >= 1,
            "refill: slab_size {} yields 0 blocks",
            slab_size
        );

        let frame = match memory::allocate_frame(token) {
            Ok(f) => f,
            Err(_) => return, // OOM : alloc_block will see null partial and return null
        };
        SLAB_PAGES_ALLOCATED.fetch_add(1, AtomicOrdering::Relaxed);

        let page_virt = super::phys_to_virt(frame.start_address.as_u64()) as *mut u8;

        // Initialise page header at byte 0.
        let header = page_virt as *mut SlabPageHeader;
        (*header).next_partial = ptr::null_mut();
        (*header).free_head = ptr::null_mut();
        (*header).free_count = 0;
        (*header).total_blocks = num_blocks as u32;

        // Carve blocks starting at SLAB_HEADER_SIZE, highest index first so
        // the lowest-address block ends up at the head (cosmetic only).
        let blocks_start = page_virt.add(SLAB_HEADER_SIZE);
        for i in (0..num_blocks).rev() {
            let block = blocks_start.add(i * slab_size);
            *(block as *mut *mut u8) = (*header).free_head;
            if HEAP_POISON_ENABLED {
                let end = slab_size.saturating_sub(4);
                for off in 8..end {
                    *block.add(off) = POISON_BYTE;
                }
                if slab_size >= 12 {
                    let cp = block.add(slab_size - 4) as *mut u32;
                    *cp = SLAB_CANARY;
                }
            }
            (*header).free_head = block;
            (*header).free_count += 1;
        }

        // Prepend to partial list.
        (*header).next_partial = self.partial_pages[ci];
        self.partial_pages[ci] = header;
    }

    /// Pop one block from the first partial page for class `ci`.
    /// Calls `refill` when the partial list is empty.  Returns null on OOM.
    unsafe fn alloc_block(&mut self, ci: usize, token: &crate::sync::IrqDisabledToken) -> *mut u8 {
        if self.partial_pages[ci].is_null() {
            self.refill(ci, token);
        }
        let header = self.partial_pages[ci];
        if header.is_null() {
            return ptr::null_mut();
        }

        let block = (*header).free_head;
        debug_assert!(
            !block.is_null(),
            "alloc_block: partial page has null free_head"
        );

        (*header).free_head = *(block as *const *mut u8);
        (*header).free_count -= 1;

        // Remove page from partial list when it is now full (free_count == 0).
        if (*header).free_count == 0 {
            self.partial_pages[ci] = (*header).next_partial;
            (*header).next_partial = ptr::null_mut();
        }

        if HEAP_POISON_ENABLED {
            let slab_size = SLAB_SIZES[ci];
            let end = slab_size.saturating_sub(4);
            let mut bad_off: Option<usize> = None;
            for off in 8..end {
                if *block.add(off) != POISON_BYTE {
                    bad_off = Some(off);
                    break;
                }
            }
            if let Some(off) = bad_off {
                let b0 = *block.add(off);
                let b1 = if off + 1 < slab_size {
                    *block.add(off + 1)
                } else {
                    0
                };
                let b2 = if off + 2 < slab_size {
                    *block.add(off + 2)
                } else {
                    0
                };
                let b3 = if off + 3 < slab_size {
                    *block.add(off + 3)
                } else {
                    0
                };
                crate::serial_println!(
                    "\x1b[1;31m[HEAP] USE-AFTER-FREE: slab[{}] block={:#x} off={} bytes=[{:02x} {:02x} {:02x} {:02x}]\x1b[0m",
                    slab_size,
                    block as u64,
                    off,
                    b0,
                    b1,
                    b2,
                    b3
                );
            }
            if slab_size >= 12 {
                let canary = *(block.add(slab_size - 4) as *const u32);
                if canary != SLAB_CANARY {
                    crate::serial_println!(
                        "\x1b[1;31m[HEAP] CANARY OVERFLOW: slab[{}] block={:#x} expected={:#x} got={:#x}\x1b[0m",
                        slab_size,
                        block as u64,
                        SLAB_CANARY,
                        canary
                    );
                }
            }
        }

        block
    }

    /// Return `ptr` to its slab page and reclaim the page to the buddy
    /// allocator if it becomes fully empty.
    unsafe fn dealloc_block(
        &mut self,
        ptr: *mut u8,
        ci: usize,
        token: &crate::sync::IrqDisabledToken,
    ) {
        let slab_size = SLAB_SIZES[ci];

        if HEAP_POISON_ENABLED {
            if slab_size >= 12 {
                let cp = ptr.add(slab_size - 4) as *mut u32;
                *cp = SLAB_CANARY;
            }
            let end = slab_size.saturating_sub(4);
            for off in 8..end {
                *ptr.add(off) = POISON_BYTE;
            }
        }

        // Locate the page header: round ptr down to 4 KiB boundary.
        let page_base = (ptr as usize) & !0xFFF;
        let header = page_base as *mut SlabPageHeader;

        let was_full = (*header).free_count == 0;

        // Push block onto the page's intra-page free list.
        *(ptr as *mut *mut u8) = (*header).free_head;
        (*header).free_head = ptr;
        (*header).free_count += 1;

        if was_full {
            // Page went full -> partial: re-insert at list head.
            (*header).next_partial = self.partial_pages[ci];
            self.partial_pages[ci] = header;
        }

        // Reclaim fully-empty pages to the buddy allocator.
        if (*header).free_count == (*header).total_blocks {
            self.remove_from_partial(header, ci);
            let phys = super::virt_to_phys(page_base as u64);
            // Zero the header before freeing to catch accidental reuse.
            core::ptr::write_bytes(header as *mut u8, 0, SLAB_HEADER_SIZE);
            let frame = memory::frame::PhysFrame {
                start_address: PhysAddr::new(phys),
            };
            memory::free_frame(token, frame);
            SLAB_PAGES_RECLAIMED.fetch_add(1, AtomicOrdering::Relaxed);
        }
    }

    /// Unlink `page` from `partial_pages[ci]`.  O(n) in partial-list length.
    unsafe fn remove_from_partial(&mut self, page: *mut SlabPageHeader, ci: usize) {
        if self.partial_pages[ci] == page {
            self.partial_pages[ci] = (*page).next_partial;
            (*page).next_partial = ptr::null_mut();
            return;
        }
        let mut cur = self.partial_pages[ci];
        while !cur.is_null() {
            let next = (*cur).next_partial;
            if next == page {
                (*cur).next_partial = (*page).next_partial;
                (*page).next_partial = ptr::null_mut();
                return;
            }
            cur = next;
        }
        debug_assert!(
            false,
            "remove_from_partial: page {:p} not found in class {} list",
            page, ci
        );
    }
}

static SLAB_ALLOC: SpinLock<SlabState> = SpinLock::new(SlabState::new());
static LAST_HEAP_FAILURE: SpinLock<Option<KernelHeapFailureSnapshot>> = SpinLock::new(None);

/// Total buddy pages ever handed to the slab allocator.
static SLAB_PAGES_ALLOCATED: AtomicUsize = AtomicUsize::new(0);
/// Total buddy pages ever returned from the slab allocator (fully-empty reclaim).
static SLAB_PAGES_RECLAIMED: AtomicUsize = AtomicUsize::new(0);

/// Returns the slab lock address for deadlock tracing.
pub fn debug_slab_lock_addr() -> usize {
    &SLAB_ALLOC as *const _ as usize
}

/// Register slab lock for E9 trace (call from init).
pub fn debug_register_slab_trace() {
    crate::sync::debug_set_trace_slab_addr(debug_slab_lock_addr());
}

// ---------------------------------------------------------------------------
// GlobalAlloc implementation
// ---------------------------------------------------------------------------

pub struct LockedHeap;

unsafe impl GlobalAlloc for LockedHeap {
    /// Performs the alloc operation.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        try_alloc_kernel_heap(layout).unwrap_or(ptr::null_mut())
    }

    /// Performs the dealloc operation.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let effective = layout.size().max(layout.align());

        match classify_kernel_heap_backend(layout) {
            KernelHeapBackend::Slab => {
                // --- slab path: return block to free list ---
                let ci = SlabState::class_index(effective);
                let cpu = crate::arch::x86_64::percpu::current_cpu_index();
                let irq_enabled = crate::arch::x86_64::interrupts_enabled();
                if !irq_enabled {
                    use core::sync::atomic::{AtomicUsize, Ordering};
                    static HEAP_D_COUNT: AtomicUsize = AtomicUsize::new(0);
                    let n = HEAP_D_COUNT.fetch_add(1, Ordering::Relaxed);
                    if n % 100 == 0 {
                        crate::e9_println!(
                            "HEAP-D cpu={} irq=0 size={} ci={} n={}",
                            cpu,
                            effective,
                            ci,
                            n
                        );
                    }
                }
                // Catch layout mismatches where a vmalloc pointer is freed with
                // a small layout (classify_kernel_heap_backend routes to Slab).
                // This means the caller passed a different layout to dealloc than
                // was used for alloc : a GlobalAlloc contract violation.
                #[cfg(debug_assertions)]
                {
                    let addr = ptr as u64;
                    if addr >= crate::memory::vmalloc::VMALLOC_VIRT_START
                        && addr < crate::memory::vmalloc::VMALLOC_VIRT_END
                    {
                        crate::serial_println!(
                            "[heap][bug] slab dealloc: ptr {:#x} is in vmalloc range : layout mismatch",
                            addr
                        );
                        debug_assert!(
                            false,
                            "slab dealloc with vmalloc pointer : alloc/dealloc layout mismatch"
                        );
                    }
                }
                let mut slab = SLAB_ALLOC.lock();
                slab.with_mut_and_token(|s, token| s.dealloc_block(ptr, ci, token));
            }
            KernelHeapBackend::Vmalloc => {
                // vmalloc path: free via the vmalloc arena
                let addr = ptr as u64;
                if addr >= crate::memory::vmalloc::VMALLOC_VIRT_START
                    && addr < crate::memory::vmalloc::VMALLOC_VIRT_END
                {
                    crate::sync::with_irqs_disabled(|token| {
                        crate::memory::free_kernel_virtual(ptr, token);
                    });
                } else {
                    // Pointer is outside the vmalloc arena with a large-allocation
                    // layout. This is a leak : warn loudly in debug builds.
                    #[cfg(debug_assertions)]
                    {
                        crate::serial_println!(
                            "[heap][bug] vmalloc dealloc: ptr {:#x} outside vmalloc arena \
                             [{:#x}..{:#x}] : memory leaked",
                            addr,
                            crate::memory::vmalloc::VMALLOC_VIRT_START,
                            crate::memory::vmalloc::VMALLOC_VIRT_END,
                        );
                        debug_assert!(
                            false,
                            "vmalloc dealloc with out-of-range pointer : memory leaked"
                        );
                    }
                }
            }
        }
    }
}

fn record_heap_failure(
    layout: Layout,
    effective: usize,
    backend: KernelHeapBackend,
    error: KernelHeapAllocError,
) -> KernelHeapAllocError {
    *LAST_HEAP_FAILURE.lock() = Some(KernelHeapFailureSnapshot {
        backend,
        requested_size: layout.size(),
        align: layout.align(),
        effective_size: effective,
        error,
    });
    error
}

pub fn last_heap_failure_snapshot() -> Option<KernelHeapFailureSnapshot> {
    *LAST_HEAP_FAILURE.lock()
}

pub fn slab_diag_snapshot() -> SlabDiagSnapshot {
    let allocated = SLAB_PAGES_ALLOCATED.load(AtomicOrdering::Relaxed);
    let reclaimed = SLAB_PAGES_RECLAIMED.load(AtomicOrdering::Relaxed);
    SlabDiagSnapshot {
        pages_allocated: allocated,
        pages_reclaimed: reclaimed,
        pages_live: allocated.saturating_sub(reclaimed),
    }
}

/// Fallible heap entry point with explicit backend-aware errors.
///
/// Kernel code that can recover from allocation failure should prefer this API
/// over `Box`/`Vec`/`GlobalAlloc`, which eventually route to
/// [`alloc_error_handler`] and remain fatal by language contract.
#[inline]
pub unsafe fn try_alloc_kernel_heap(layout: Layout) -> Result<*mut u8, KernelHeapAllocError> {
    // Effective size must satisfy both the size and alignment requirements.
    let effective = layout.size().max(layout.align());
    // `Layout` constructors guarantee a non-zero alignment; keep the power-of-two
    // check as a defensive guard for any malformed caller input.
    if !layout.align().is_power_of_two() {
        return Err(record_heap_failure(
            layout,
            effective,
            classify_kernel_heap_backend(layout),
            KernelHeapAllocError::InvalidLayout,
        ));
    }
    let boot_reg = crate::silo::debug_boot_reg_active();
    if boot_reg {
        crate::serial_println!(
            "[trace][heap] alloc enter effective={} size={} align={}",
            effective,
            layout.size(),
            layout.align()
        );
    }

    let result = match classify_kernel_heap_backend(layout) {
        KernelHeapBackend::Slab => {
            // --- slab path ---
            let ci = SlabState::class_index(effective);
            // Race/corruption diagnostic: log alloc when IRQs disabled (rate-limited).
            let cpu = crate::arch::x86_64::percpu::current_cpu_index();
            let irq_enabled = crate::arch::x86_64::interrupts_enabled();
            if !irq_enabled {
                use core::sync::atomic::{AtomicUsize, Ordering};
                static HEAP_A_COUNT: AtomicUsize = AtomicUsize::new(0);
                let n = HEAP_A_COUNT.fetch_add(1, Ordering::Relaxed);
                if n % 100 == 0 {
                    crate::e9_println!(
                        "HEAP-A cpu={} irq=0 size={} ci={} n={}",
                        cpu,
                        effective,
                        ci,
                        n
                    );
                }
            }
            if boot_reg {
                crate::serial_println!(
                    "[trace][heap] alloc slab ci={} slab_size={} lock={:#x}",
                    ci,
                    SLAB_SIZES[ci],
                    &SLAB_ALLOC as *const _ as usize
                );
            }
            let mut slab = SLAB_ALLOC.lock();
            if boot_reg {
                crate::serial_println!("[trace][heap] alloc slab lock acquired");
            }
            let ptr = slab.with_mut_and_token(|s, token| s.alloc_block(ci, token));
            if ptr.is_null() {
                return Err(record_heap_failure(
                    layout,
                    effective,
                    KernelHeapBackend::Slab,
                    KernelHeapAllocError::SlabRefillFailed {
                        effective,
                        class_size: SLAB_SIZES[ci],
                    },
                ));
            }
            ptr
        }
        KernelHeapBackend::Vmalloc => {
            // --- vmalloc path (large allocation) ---
            if boot_reg {
                crate::serial_println!("[trace][heap] alloc vmalloc size={}", effective);
            }

            crate::sync::with_irqs_disabled(|token| {
                crate::memory::allocate_kernel_virtual(effective, token).map_err(|error| {
                    record_heap_failure(
                        layout,
                        effective,
                        KernelHeapBackend::Vmalloc,
                        KernelHeapAllocError::Vmalloc(error),
                    )
                })
            })?
        }
    };

    Ok(result)
}

#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap = LockedHeap;

/// Compatibility facade over the current global kernel heap policy.
///
/// Callers that need an explicit heap allocation entry point, rather than
/// relying on `Box`/`Vec`/`GlobalAlloc`, should use this helper. The selected
/// backend remains the current heap policy:
/// - small allocations -> slab
/// - large allocations -> vmalloc
#[inline]
pub unsafe fn alloc_kernel_heap(layout: Layout) -> *mut u8 {
    try_alloc_kernel_heap(layout).unwrap_or(ptr::null_mut())
}

/// Free memory previously returned by [`alloc_kernel_heap`].
#[inline]
pub unsafe fn dealloc_kernel_heap(ptr: *mut u8, layout: Layout) {
    HEAP_ALLOCATOR.dealloc(ptr, layout);
}

fn log_common_oom_header(layout: Layout, effective: usize) {
    let cpu = crate::arch::x86_64::percpu::current_cpu_index();
    let irq_enabled = crate::arch::x86_64::interrupts_enabled();
    let tid = crate::process::current_task_id()
        .map(|t| t.as_u64())
        .unwrap_or(0);
    let task_name = crate::process::current_task_clone()
        .map(|t| t.name)
        .unwrap_or("<none>");

    crate::serial_println!(
        "[heap][oom] cpu={} irq={} tid={} task={} size={} align={} effective={}",
        cpu,
        irq_enabled,
        tid,
        task_name,
        layout.size(),
        layout.align(),
        effective
    );
}

fn log_buddy_snapshot() -> Option<(usize, usize, usize)> {
    if let Some(guard) = crate::memory::buddy::get_allocator().try_lock() {
        if let Some(alloc) = guard.as_ref() {
            let (total_pages, allocated_pages) = alloc.page_totals();
            let free_pages = total_pages.saturating_sub(allocated_pages);
            let fail_counts = crate::memory::buddy::buddy_alloc_fail_counts_snapshot();

            crate::serial_println!(
                "[heap][oom] buddy: total={} alloc={} free={}",
                total_pages,
                allocated_pages,
                free_pages
            );

            let mut fail_line = alloc::string::String::from("[heap][oom] buddy_fail_by_order:");
            for (i, &count) in fail_counts.iter().enumerate() {
                use core::fmt::Write;
                let _ = write!(fail_line, " o{}={} ", i, count);
            }
            crate::serial_println!("{}", fail_line);
            return Some((total_pages, allocated_pages, free_pages));
        }
        crate::serial_println!("[heap][oom] buddy: allocator uninitialized");
        return None;
    }

    crate::serial_println!("[heap][oom] buddy: allocator locked");
    None
}

fn log_heap_failure_policy(layout: Layout) {
    match last_heap_failure_snapshot() {
        Some(snapshot) => {
            crate::serial_println!(
                "[heap][oom] last_failure backend={:?} requested={} align={} effective={} error={:?}",
                snapshot.backend,
                snapshot.requested_size,
                snapshot.align,
                snapshot.effective_size,
                snapshot.error
            );
            if snapshot.requested_size != layout.size() || snapshot.align != layout.align() {
                crate::serial_println!(
                    "[heap][oom] note=last_heap_failure does not exactly match current layout; using best-effort context"
                );
            }
        }
        None => crate::serial_println!("[heap][oom] last_heap_failure unavailable"),
    }
}

/// Allocates error handler.
#[alloc_error_handler]
fn alloc_error_handler(layout: Layout) -> ! {
    let effective = layout.size().max(layout.align());
    let pages_needed = (effective.saturating_add(4095)) / 4096;
    let order = if pages_needed == 0 {
        0
    } else {
        pages_needed.next_power_of_two().trailing_zeros() as u8
    };
    log_common_oom_header(layout, effective);

    if effective <= MAX_SLAB_SIZE {
        crate::serial_println!(
            "[heap][oom] backend=slab effective={} class_max={} refill_order=0",
            effective,
            MAX_SLAB_SIZE
        );
        log_heap_failure_policy(layout);
        if let Some((total_pages, _, free_pages)) = log_buddy_snapshot() {
            crate::serial_println!(
                "[heap][oom] slab-refill pages={} buddy_order={}",
                pages_needed,
                order
            );
            if free_pages > (total_pages / 4) {
                crate::serial_println!(
                    "[heap][oom] diagnosis=slab order-0 refill failed despite remaining free pages \
                     ({} free pages): allocator pressure, zone exhaustion, or transient allocator state",
                    free_pages,
                );
            }
        }
    } else {
        crate::serial_println!(
            "[heap][oom] backend=vmalloc request_pages={} legacy_buddy_order_hint={}",
            pages_needed,
            order
        );
        log_heap_failure_policy(layout);
        match crate::memory::vmalloc::last_failure_snapshot() {
            Some(snapshot) => {
                crate::serial_println!(
                    "[heap][oom] vmalloc_last_failure size={} pages={} error={:?}",
                    snapshot.size,
                    snapshot.pages,
                    snapshot.error
                );
                match snapshot.error {
                    crate::memory::vmalloc::VmallocError::SizeExceedsPolicy {
                        requested,
                        max_allowed,
                    } => {
                        crate::serial_println!(
                            "[heap][oom] diagnosis=vmalloc policy limit exceeded requested={} max_allowed={}",
                            requested,
                            max_allowed
                        );
                    }
                    crate::memory::vmalloc::VmallocError::VirtualRangeExhausted => {
                        crate::serial_println!(
                            "[heap][oom] diagnosis=kernel virtual allocation arena exhausted or fragmented"
                        );
                    }
                    crate::memory::vmalloc::VmallocError::PhysicalMemoryExhausted => {
                        crate::serial_println!(
                            "[heap][oom] diagnosis=vmalloc could not acquire enough physical pages"
                        );
                    }
                    crate::memory::vmalloc::VmallocError::MetadataAllocationFailed => {
                        crate::serial_println!(
                            "[heap][oom] diagnosis=vmalloc metadata allocation failed"
                        );
                    }
                    crate::memory::vmalloc::VmallocError::KernelMapFailed => {
                        crate::serial_println!(
                            "[heap][oom] diagnosis=kernel page-table mapping failed during vmalloc"
                        );
                    }
                    crate::memory::vmalloc::VmallocError::ZeroSize => {
                        crate::serial_println!("[heap][oom] diagnosis=zero-sized vmalloc request");
                    }
                }
            }
            None => {
                crate::serial_println!("[heap][oom] vmalloc_last_failure unavailable");
            }
        }
        let _ = log_buddy_snapshot();
    }
    crate::serial_println!(
        "[heap][oom] policy=fatal_global_alloc_path use try_alloc_kernel_heap()/allocate_kernel_virtual() on recoverable paths"
    );
    panic!("fatal kernel heap allocation failure: {:?}", layout)
}

/// Dump heap and buddy allocator diagnostics to the serial console.
///
/// Safe to call from the shell or debug tooling. Prints:
/// - Total/allocated/free pages
/// - Per-order buddy free list head counts
/// - Buddy allocation failure counts by order (fragmentation indicator)
/// - Slab free list head pointers
pub fn dump_diagnostics() {
    crate::serial_println!("[heap][diag] === Heap Diagnostics ===");

    // Buddy allocator stats
    if let Some(guard) = crate::memory::buddy::get_allocator().try_lock() {
        if let Some(alloc) = guard.as_ref() {
            let (total_pages, allocated_pages) = alloc.page_totals();
            crate::serial_println!(
                "[heap][diag] buddy: total={} pages, allocated={} pages, free={} pages",
                total_pages,
                allocated_pages,
                total_pages.saturating_sub(allocated_pages)
            );

            // Per-zone free list heads
            for zi in 0..crate::memory::zone::ZoneType::COUNT {
                let zone = alloc.get_zone(zi);
                let zone_name = match zi {
                    x if x == crate::memory::zone::ZoneType::DMA as usize => "DMA",
                    x if x == crate::memory::zone::ZoneType::Normal as usize => "Normal",
                    _ => "HighMem",
                };
                let mut line = alloc::string::String::from("[heap][diag] ");
                use core::fmt::Write;
                let _ = write!(line, "zone={} free_heads:", zone_name);
                for order in 0..=crate::memory::zone::MAX_ORDER {
                    let count = zone.free_list_count(order as u8);
                    if count > 0 {
                        let _ = write!(line, " o{}={} ", order, count);
                    }
                }
                crate::serial_println!("{}", line);
            }
        }
    } else {
        crate::serial_println!("[heap][diag] buddy: allocator locked (retry later)");
    }

    // Buddy failure counts
    let fail_counts = crate::memory::buddy::buddy_alloc_fail_counts_snapshot();
    let mut has_fails = false;
    for (i, &count) in fail_counts.iter().enumerate() {
        if count > 0 {
            has_fails = true;
        }
        crate::serial_println!("[heap][diag] buddy_fail[{}]: {}", i, count);
    }
    if has_fails {
        crate::serial_println!(
            "[heap][diag] => non-zero buddy_fail counts indicate fragmentation pressure"
        );
    }

    // Slab stats
    {
        let alloc = SLAB_PAGES_ALLOCATED.load(AtomicOrdering::Relaxed);
        let reclaim = SLAB_PAGES_RECLAIMED.load(AtomicOrdering::Relaxed);
        crate::serial_println!(
            "[heap][diag] slab: pages_allocated={} pages_reclaimed={} pages_live={}",
            alloc,
            reclaim,
            alloc.saturating_sub(reclaim)
        );
    }
    if let Some(mut guard) = SLAB_ALLOC.try_lock() {
        // SAFETY: we hold the slab lock; raw pointer traversal is safe.
        guard.with_mut_and_token(|s, _| unsafe {
            for ci in 0..NUM_SLABS {
                let mut head = s.partial_pages[ci];
                if head.is_null() {
                    continue;
                }
                let mut page_count = 0usize;
                let mut free_blocks = 0u32;
                while !head.is_null() {
                    page_count += 1;
                    free_blocks = free_blocks.saturating_add((*head).free_count);
                    head = (*head).next_partial;
                }
                crate::serial_println!(
                    "[heap][diag] slab[{}]: partial_pages={} free_blocks={}",
                    SLAB_SIZES[ci],
                    page_count,
                    free_blocks
                );
            }
        });
    } else {
        crate::serial_println!("[heap][diag] slab: locked (retry later)");
    }

    // Contiguous-physical allocation telemetry
    {
        let d = crate::memory::phys_contiguous_diag();
        crate::serial_println!(
            "[heap][diag] phys_contiguous: pages_allocated={} pages_freed={} pages_live={} alloc_failures={}",
            d.pages_allocated,
            d.pages_freed,
            d.pages_live,
            d.alloc_fail_count
        );
    }

    if let Some(snapshot) = last_heap_failure_snapshot() {
        crate::serial_println!(
            "[heap][diag] last_heap_failure: backend={:?} requested={} align={} effective={} error={:?}",
            snapshot.backend,
            snapshot.requested_size,
            snapshot.align,
            snapshot.effective_size,
            snapshot.error
        );
    }

    crate::memory::vmalloc::dump_diagnostics();

    crate::serial_println!("[heap][diag] === End Diagnostics ===");
}
