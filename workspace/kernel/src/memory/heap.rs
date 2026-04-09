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
};
//use x86_64::PhysAddr;

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
/// | Class range | Step  | Max waste |
/// |-------------|-------|-----------|
/// |  8 –  64 B  | 2× / 1.5× | ≤ 32 B  |
/// | 64 – 256 B  | ~1.25×    | ≤ 64 B  |
/// |256 – 2048 B | 1.25×     | ≤ 512 B |
///
/// Example improvement:
///   - 700 B request: old → 1024 (324 B wasted, 32%), new → 768 (68 B, 9%)
///   - 100 B request: old → 128  (28 B wasted, 22%),  new → 112 (12 B, 11%)
const SLAB_SIZES: [usize; 26] = [
    8, 16, 24, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 640, 768,
    896, 1024, 1280, 1536, 1792, 2048,
];
const NUM_SLABS: usize = SLAB_SIZES.len();
/// Allocations with effective size above this threshold bypass the slab.
const MAX_SLAB_SIZE: usize = 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KernelHeapBackend {
    Slab,
    Vmalloc,
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
// CRITICAL: Slab corruption detection
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
// SlabState
// ---------------------------------------------------------------------------

/// Per-size-class free lists.  Each element is the head of an intrusive
/// singly-linked list stored *in* the free blocks themselves.
struct SlabState {
    /// `free_lists[i]` is the head of the free list for `SLAB_SIZES[i]`.
    free_lists: [*mut u8; NUM_SLABS],
}

// SAFETY: protected exclusively through `SLAB_ALLOC: SpinLock<SlabState>`.
unsafe impl Send for SlabState {}
unsafe impl Sync for SlabState {}

impl SlabState {
    /// Creates a new instance.
    const fn new() -> Self {
        SlabState {
            free_lists: [ptr::null_mut(); NUM_SLABS],
        }
    }

    /// Return the slab class index for `effective` bytes (already rounded up
    /// via `max(size, align)`).  Panics if called with `effective > MAX_SLAB_SIZE`.
    #[inline]
    fn class_index(effective: usize) -> usize {
        for (i, &s) in SLAB_SIZES.iter().enumerate() {
            if effective <= s {
                return i;
            }
        }
        unreachable!("class_index called with effective > MAX_SLAB_SIZE")
    }

    /// Carve one buddy page into blocks of size `SLAB_SIZES[ci]` and prepend
    /// them all to the free list for that class.
    ///
    /// Requests one order-0 frame through the memory frame helpers.
    /// Requires `token` from the SpinLockGuard that holds the slab lock.
    unsafe fn refill(&mut self, ci: usize, token: &crate::sync::IrqDisabledToken) {
        let slab_size = SLAB_SIZES[ci];

        // Allocate one page (order-0) from the buddy allocator.
        // IRQs are disabled via the SpinLock guardian; token proves it.
        let frame = match memory::allocate_frame(token) {
            Ok(f) => f,
            Err(_) => return, // OOM — caller will return null
        };

        let page_virt = super::phys_to_virt(frame.start_address.as_u64()) as *mut u8;
        let num_blocks = 4096 / slab_size;

        // Link all blocks into the free list (highest address first so the
        // first block handed out is at the lowest address — irrelevant for
        // correctness but tidy).
        let mut head = self.free_lists[ci];
        for i in (0..num_blocks).rev() {
            let block = page_virt.add(i * slab_size);
            // Store the next-free pointer in the first word of the free block.
            *(block as *mut *mut u8) = head;
            if HEAP_POISON_ENABLED {
                // Poison bytes [8..slab_size-4] and place canary at the tail.
                let end = slab_size.saturating_sub(4);
                for off in 8..end {
                    *block.add(off) = POISON_BYTE;
                }
                if slab_size >= 12 {
                    let cp = block.add(slab_size - 4) as *mut u32;
                    *cp = SLAB_CANARY;
                }
            }
            head = block;
        }
        self.free_lists[ci] = head;
    }

    /// Pop a block from the free list for class `ci`, refilling from a buddy
    /// page if the list is empty.  Returns null on OOM.
    unsafe fn alloc_block(&mut self, ci: usize, token: &crate::sync::IrqDisabledToken) -> *mut u8 {
        if self.free_lists[ci].is_null() {
            self.refill(ci, token);
        }
        let head = self.free_lists[ci];
        if head.is_null() {
            return ptr::null_mut();
        }
        // Read the next pointer stored at the start of the block.
        let next = *(head as *const *mut u8);
        self.free_lists[ci] = next;

        if HEAP_POISON_ENABLED {
            let slab_size = SLAB_SIZES[ci];
            // Bytes [8..slab_size-4] should still hold POISON_BYTE.
            // Bytes [0..8] held the free-list pointer, exempt from check.
            let end = slab_size.saturating_sub(4);
            let mut bad_off: Option<usize> = None;
            for off in 8..end {
                if *head.add(off) != POISON_BYTE {
                    bad_off = Some(off);
                    break;
                }
            }
            if let Some(off) = bad_off {
                let b0 = *head.add(off);
                let b1 = if off + 1 < slab_size {
                    *head.add(off + 1)
                } else {
                    0
                };
                let b2 = if off + 2 < slab_size {
                    *head.add(off + 2)
                } else {
                    0
                };
                let b3 = if off + 3 < slab_size {
                    *head.add(off + 3)
                } else {
                    0
                };
                crate::serial_println!(
                    "\x1b[1;31m[HEAP] USE-AFTER-FREE: slab[{}] block={:#x} off={} bytes=[{:02x} {:02x} {:02x} {:02x}]\x1b[0m",
                    slab_size, head as u64, off, b0, b1, b2, b3
                );
            }
            // Verify the canary at the tail of the block.
            if slab_size >= 12 {
                let canary = *(head.add(slab_size - 4) as *const u32);
                if canary != SLAB_CANARY {
                    crate::serial_println!(
                        "\x1b[1;31m[HEAP] CANARY OVERFLOW: slab[{}] block={:#x} expected={:#x} got={:#x}\x1b[0m",
                        slab_size, head as u64, SLAB_CANARY, canary
                    );
                }
            }
        }

        head
    }

    /// Push a block back onto the free list for class `ci`.
    unsafe fn dealloc_block(&mut self, ptr: *mut u8, ci: usize) {
        if HEAP_POISON_ENABLED {
            let slab_size = SLAB_SIZES[ci];
            // Canary at tail, then poison the body (skip the first 8 bytes
            // which will be overwritten by the free-list pointer below).
            if slab_size >= 12 {
                let cp = ptr.add(slab_size - 4) as *mut u32;
                *cp = SLAB_CANARY;
            }
            let end = slab_size.saturating_sub(4);
            for off in 8..end {
                *ptr.add(off) = POISON_BYTE;
            }
        }
        // Overwrite the first word of the freed block with the current head.
        *(ptr as *mut *mut u8) = self.free_lists[ci];
        self.free_lists[ci] = ptr;
    }
}

static SLAB_ALLOC: SpinLock<SlabState> = SpinLock::new(SlabState::new());

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
        // Effective size must satisfy both the size and alignment requirements.
        let effective = layout.size().max(layout.align());
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
                slab.with_mut_and_token(|s, token| s.alloc_block(ci, token))
            }
            KernelHeapBackend::Vmalloc => {
                // --- vmalloc path (large allocation) ---
                if boot_reg {
                    crate::serial_println!("[trace][heap] alloc vmalloc size={}", effective);
                }

                crate::sync::with_irqs_disabled(|token| {
                    crate::memory::allocate_kernel_virtual(effective, token)
                        .unwrap_or(ptr::null_mut())
                })
            }
        };

        result
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
                // was used for alloc — a GlobalAlloc contract violation.
                #[cfg(debug_assertions)]
                {
                    let addr = ptr as u64;
                    if addr >= crate::memory::vmalloc::VMALLOC_VIRT_START
                        && addr < crate::memory::vmalloc::VMALLOC_VIRT_END
                    {
                        crate::serial_println!(
                            "[heap][bug] slab dealloc: ptr {:#x} is in vmalloc range — layout mismatch",
                            addr
                        );
                        debug_assert!(
                            false,
                            "slab dealloc with vmalloc pointer — alloc/dealloc layout mismatch"
                        );
                    }
                }
                let mut slab = SLAB_ALLOC.lock();
                slab.dealloc_block(ptr, ci);
            }
            KernelHeapBackend::Vmalloc => {
                // --- vmalloc path: free via the vmalloc arena ---
                let addr = ptr as u64;
                if addr >= crate::memory::vmalloc::VMALLOC_VIRT_START
                    && addr < crate::memory::vmalloc::VMALLOC_VIRT_END
                {
                    crate::sync::with_irqs_disabled(|token| {
                        crate::memory::free_kernel_virtual(ptr, token);
                    });
                } else {
                    // Pointer is outside the vmalloc arena with a large-allocation
                    // layout. This is a leak — warn loudly in debug builds.
                    #[cfg(debug_assertions)]
                    {
                        crate::serial_println!(
                            "[heap][bug] vmalloc dealloc: ptr {:#x} outside vmalloc arena \
                             [{:#x}..{:#x}] — memory leaked",
                            addr,
                            crate::memory::vmalloc::VMALLOC_VIRT_START,
                            crate::memory::vmalloc::VMALLOC_VIRT_END,
                        );
                        debug_assert!(
                            false,
                            "vmalloc dealloc with out-of-range pointer — memory leaked"
                        );
                    }
                }
            }
        }
    }
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
    HEAP_ALLOCATOR.alloc(layout)
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
        if let Some((total_pages, _, free_pages)) = log_buddy_snapshot() {
            crate::serial_println!(
                "[heap][oom] slab-refill pages={} buddy_order={}",
                pages_needed,
                order
            );
            if free_pages > (total_pages / 4) && order >= 8 {
                crate::serial_println!(
                    "[heap][oom] diagnosis=fragmentation-induced high-order buddy failure \
                     ({} free pages but no order-{} block)",
                    free_pages,
                    order
                );
            }
        }
    } else {
        crate::serial_println!(
            "[heap][oom] backend=vmalloc request_pages={} legacy_buddy_order_hint={}",
            pages_needed,
            order
        );
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
    panic!("allocation error: {:?}", layout)
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
    if let Some(_guard) = SLAB_ALLOC.try_lock() {
        crate::serial_println!(
            "[heap][diag] slab: lock acquired (diagnostic info not yet tracked per-class)"
        );
    } else {
        crate::serial_println!("[heap][diag] slab: locked (retry later)");
    }

    crate::memory::vmalloc::dump_diagnostics();

    crate::serial_println!("[heap][diag] === End Diagnostics ===");
}
