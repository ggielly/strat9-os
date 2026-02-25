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
// Lock ordering: SLAB_ALLOC (outer) → buddy allocator (inner, only when a slab
// class needs a fresh page).  No code path holds the buddy lock and then tries
// to acquire SLAB_ALLOC, so there is no deadlock.

use crate::{
    memory::{
        buddy::get_allocator,
        frame::{FrameAllocator, PhysFrame},
    },
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
    /// Acquires the buddy allocator lock *inside* the caller's SLAB_ALLOC
    /// lock — this is safe because the buddy allocator never calls back into
    /// the heap allocator.
    unsafe fn refill(&mut self, ci: usize) {
        let slab_size = SLAB_SIZES[ci];

        // Allocate one page (order-0) from the buddy allocator.
        let frame = {
            let buddy_lock = get_allocator();
            let mut guard = buddy_lock.lock();
            match guard.as_mut() {
                Some(buddy) => match buddy.alloc(0) {
                    Ok(f) => f,
                    Err(_) => return, // OOM — caller will return null
                },
                None => return,
            }
            // `guard` (buddy lock) is released here
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
        head
    }

    /// Push a block back onto the free list for class `ci`.
    unsafe fn dealloc_block(&mut self, ptr: *mut u8, ci: usize) {
        // Overwrite the first word of the freed block with the current head.
        *(ptr as *mut *mut u8) = self.free_lists[ci];
        self.free_lists[ci] = ptr;
    }
}

static SLAB_ALLOC: SpinLock<SlabState> = SpinLock::new(SlabState::new());

// ---------------------------------------------------------------------------
// GlobalAlloc implementation
// ---------------------------------------------------------------------------

pub struct LockedHeap;

unsafe impl GlobalAlloc for LockedHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Effective size must satisfy both the size and alignment requirements.
        let effective = layout.size().max(layout.align());

        if effective <= MAX_SLAB_SIZE {
            // --- slab path ---
            let ci = SlabState::class_index(effective);
            let mut slab = SLAB_ALLOC.lock();
            slab.alloc_block(ci)
        } else {
            // --- buddy path (large allocation) ---
            let pages_needed = (effective + 4095) / 4096;
            let order = (pages_needed.next_power_of_two().trailing_zeros() as u8).min(11);

            let buddy_lock = get_allocator();
            let mut guard = buddy_lock.lock();
            if let Some(ref mut buddy) = *guard {
                match buddy.alloc(order) {
                    Ok(frame) => super::phys_to_virt(frame.start_address.as_u64()) as *mut u8,
                    Err(_) => ptr::null_mut(),
                }
            } else {
                ptr::null_mut()
            }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let effective = layout.size().max(layout.align());

        if effective <= MAX_SLAB_SIZE {
            // --- slab path: return block to free list ---
            let ci = SlabState::class_index(effective);
            let mut slab = SLAB_ALLOC.lock();
            slab.dealloc_block(ptr, ci);
        } else {
            // --- buddy path: return page(s) to buddy ---
            let pages_needed = (effective + 4095) / 4096;
            let order = (pages_needed.next_power_of_two().trailing_zeros() as u8).min(11);

            let hhdm = super::HHDM_OFFSET.load(core::sync::atomic::Ordering::Relaxed);
            let phys_addr = (ptr as u64).wrapping_sub(hhdm);

            let buddy_lock = get_allocator();
            let mut guard = buddy_lock.lock();
            if let Some(ref mut buddy) = *guard {
                if let Ok(frame) = PhysFrame::from_start_address(PhysAddr::new(phys_addr)) {
                    buddy.free(frame, order);
                }
            }
        }
    }
}

#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap = LockedHeap;

#[alloc_error_handler]
fn alloc_error_handler(layout: Layout) -> ! {
    panic!("allocation error: {:?}", layout)
}
