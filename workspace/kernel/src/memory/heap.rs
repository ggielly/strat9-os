// Heap allocator: slab sub-allocator + buddy fallback for large objects.
//
// Small allocations (effective size ≤ 2048 B) come from per-size-class slab
// free lists.  Each slab class draws whole pages from the buddy allocator and
// carves them into fixed-size blocks.  Freed blocks return to the slab free
// list, so the buddy's page counter stabilises after warm-up instead of
// growing on every tiny allocation.
//
// Large allocations (> 2048 B) go directly to the buddy allocator, exactly
// as before.
//
// Lock ordering: SLAB_ALLOC (outer) may call the frame-allocation helpers.
// Those helpers can hit a CPU-local cache (no global buddy lock) or fall back
// to the global buddy lock as needed.

use crate::{
    memory::{self, frame::PhysFrame, zone::MAX_ORDER},
    sync::SpinLock,
};
use core::{
    alloc::{GlobalAlloc, Layout},
    ptr,
};
use x86_64::PhysAddr;

// ---------------------------------------------------------------------------
// Slab size classes
// ---------------------------------------------------------------------------

/// Power-of-two block sizes handled by the slab allocator.
const SLAB_SIZES: [usize; 9] = [8, 16, 32, 64, 128, 256, 512, 1024, 2048];
const NUM_SLABS: usize = SLAB_SIZES.len();
/// Allocations with effective size above this threshold bypass the slab.
const MAX_SLAB_SIZE: usize = 2048;

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
    unsafe fn refill(&mut self, ci: usize) {
        let slab_size = SLAB_SIZES[ci];

        // Allocate one page (order-0) from the buddy allocator.
        // SAFETY: refill is called while SLAB_ALLOC is locked; SpinLock::lock()
        // disables IRQs via save_flags_and_cli before acquiring the lock, so
        // IRQs are guaranteed to be disabled here.
        let token = unsafe { crate::sync::IrqDisabledToken::new_unchecked() };
        let frame = match memory::allocate_frame(&token) {
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
    unsafe fn alloc_block(&mut self, ci: usize) -> *mut u8 {
        if self.free_lists[ci].is_null() {
            self.refill(ci);
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

        if effective <= MAX_SLAB_SIZE {
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
            slab.alloc_block(ci)
        } else {
            // --- buddy path (large allocation) ---
            let pages_needed = (effective + 4095) / 4096;
            let max_pages = 1usize << MAX_ORDER;
            if pages_needed > max_pages {
                return ptr::null_mut();
            }
            let order = pages_needed.next_power_of_two().trailing_zeros() as u8;
            if boot_reg {
                crate::serial_println!(
                    "[trace][heap] alloc buddy order={} pages_needed={}",
                    order,
                    pages_needed
                );
            }

            crate::sync::with_irqs_disabled(|token| match memory::allocate_frames(token, order) {
                Ok(frame) => super::phys_to_virt(frame.start_address.as_u64()) as *mut u8,
                Err(_) => ptr::null_mut(),
            })
        }
    }

    /// Performs the dealloc operation.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let effective = layout.size().max(layout.align());

        if effective <= MAX_SLAB_SIZE {
            // --- slab path: return block to free list ---
            let ci = SlabState::class_index(effective);
            // Race/corruption diagnostic: log dealloc when IRQs disabled (rate-limited).
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
            let mut slab = SLAB_ALLOC.lock();
            slab.dealloc_block(ptr, ci);
        } else {
            // --- buddy path: return page(s) to buddy ---
            let pages_needed = (effective + 4095) / 4096;
            let max_pages = 1usize << MAX_ORDER;
            if pages_needed > max_pages {
                return;
            }
            let order = pages_needed.next_power_of_two().trailing_zeros() as u8;

            let hhdm = super::HHDM_OFFSET.load(core::sync::atomic::Ordering::Relaxed);
            let phys_addr = (ptr as u64).wrapping_sub(hhdm);

            if let Ok(frame) = PhysFrame::from_start_address(PhysAddr::new(phys_addr)) {
                crate::sync::with_irqs_disabled(|token| {
                    memory::free_frames(token, frame, order);
                });
            }
        }
    }
}

#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap = LockedHeap;

/// Allocates error handler.
#[alloc_error_handler]
fn alloc_error_handler(layout: Layout) -> ! {
    panic!("allocation error: {:?}", layout)
}
