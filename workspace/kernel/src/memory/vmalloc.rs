//! VM-backed allocator for large heap objects.
//!
//! Provides virtually contiguous allocations backed by individually allocated
//! physical pages. Unlike the buddy allocator, `vmalloc` does **not** require
//! physically contiguous memory — it maps each page individually into a
//! dedicated kernel virtual memory arena.
//!
//! ## Arena layout
//!
//! ```text
//! VMALLOC_VIRT_START = 0xffffc000_0000_0000  (256 GiB boundary)
//! VMALLOC_SIZE       = 1 GiB
//! VMALLOC_VIRT_END   = 0xffffc040_0000_0000
//! ```
//!
//! This region sits well above the HHDM direct map (starting at
//! 0xffff8000_0000_0000) and kernel code/data.
//!
//! ## Allocation strategy
//!
//! 1. Find a free virtual range of the requested size (bitmap allocator).
//! 2. Allocate individual physical pages via the buddy allocator.
//! 3. Map each page into the kernel page tables at the virtual address.
//!
//! ## Deallocation
//!
//! 1. Unmap each page from the kernel page tables.
//! 2. Free each physical page back to the buddy allocator.
//! 3. Mark the virtual range as free in the bitmap.
//!
//! ## Thread safety
//!
//! Protected by a single `SpinLock<Vmalloc>`. IRQs are disabled during
//! allocation to prevent deadlock with the buddy allocator.

use crate::{
    arch::x86_64::tlb::shootdown_all,
    memory::{
        frame::PhysFrame,
        paging::{map_page_kernel, unmap_page_kernel},
        phys_to_virt,
    },
    serial_println,
    sync::{IrqDisabledToken, SpinLock},
};
use core::mem::size_of;
use x86_64::{
    structures::paging::{Page, PageTableFlags, PhysFrame as X86PhysFrame, Size4KiB},
    VirtAddr,
};

// ─── Arena constants ─────────────────────────────────────────────────────────

/// Base virtual address of the vmalloc arena.
/// Placed at 0xffffc000_0000_0000 — well above the HHDM direct map.
pub const VMALLOC_VIRT_START: u64 = 0xffff_c000_0000_0000;

/// Total size of the vmalloc arena: 1 GiB.
/// Increased from the initial 256 MiB to accommodate heavy workloads.
pub const VMALLOC_SIZE: usize = 1024 * 1024 * 1024;

/// End virtual address of the vmalloc arena.
pub const VMALLOC_VIRT_END: u64 = VMALLOC_VIRT_START + VMALLOC_SIZE as u64;

/// Number of pages in the arena.
const VMALLOC_PAGES: usize = VMALLOC_SIZE / 4096;

/// Maximum single allocation size: 256 MiB.
/// Increased from 64 MiB to accommodate large buffers without fragmentation.
const VMALLOC_MAX_ALLOC: usize = 256 * 1024 * 1024;

/// Maximum number of concurrent vmalloc allocations tracked in the
/// fixed-size record array. 512 is sized for heavy workloads (many large
/// temporary buffers, many simultaneous tasks). If this limit is reached,
/// new vmalloc calls will fail even if virtual address space is available.
const VMALLOC_ALLOC_SLOTS: usize = 512;

struct FrameList {
    ptr: *mut PhysFrame,
    len: usize,
    storage_frame: PhysFrame,
    storage_order: u8,
}

impl FrameList {
    fn new(len: usize, token: &IrqDisabledToken) -> Option<Self> {
        let bytes = len.checked_mul(size_of::<PhysFrame>())?;
        let pages_needed = bytes.saturating_add(4095) / 4096;
        let order = if pages_needed <= 1 {
            0
        } else {
            pages_needed.next_power_of_two().trailing_zeros() as u8
        };
        let storage_frame = crate::memory::allocate_frames(token, order).ok()?;
        let ptr = phys_to_virt(storage_frame.start_address.as_u64()) as *mut PhysFrame;
        Some(Self {
            ptr,
            len,
            storage_frame,
            storage_order: order,
        })
    }

    fn get(&self, index: usize) -> PhysFrame {
        debug_assert!(index < self.len);
        unsafe { *self.ptr.add(index) }
    }

    fn set(&mut self, index: usize, frame: PhysFrame) {
        debug_assert!(index < self.len);
        unsafe { *self.ptr.add(index) = frame };
    }

    fn free_storage(self, token: &IrqDisabledToken) {
        crate::memory::free_frames(token, self.storage_frame, self.storage_order);
    }
}

// SAFETY: `FrameList` owns a contiguous region of physical memory allocated
// from the buddy allocator. The raw pointer is never aliased — access is
// exclusively mediated through `get`/`set` and always occurs while the
// caller holds the VMALLOC spinlock (which disables IRQs). Transferring
// ownership to another thread is safe because the backing storage frame
// and all frames stored within are valid physical addresses that travel
// with the struct.
unsafe impl Send for FrameList {}

// ─── Bitmap-based virtual range allocator ────────────────────────────────────

/// Simple bitmap tracking free/allocated pages in the vmalloc arena.
///
/// A set bit (1) means the page is allocated. A clear bit (0) means free.
/// We allocate contiguous runs of set bits for each `vmalloc` allocation.
struct VmallocBitmap {
    bits: [u64; (VMALLOC_PAGES + 63) / 64],
}

impl VmallocBitmap {
    const fn new() -> Self {
        Self {
            bits: [0u64; (VMALLOC_PAGES + 63) / 64],
        }
    }

    /// Find a contiguous run of `count` free pages starting at or after `hint`.
    /// Returns the page index, or `None` if not found.
    fn find_contiguous(&self, count: usize, hint: usize) -> Option<usize> {
        if count == 0 {
            return Some(0);
        }
        let start = hint.min(VMALLOC_PAGES - 1);

        /// Scan `[range_start, range_end)` for a contiguous run of `count` free pages.
        fn scan_range(
            bits: &[u64; (VMALLOC_PAGES + 63) / 64],
            range_start: usize,
            range_end: usize,
            count: usize,
        ) -> Option<usize> {
            let mut run_start: Option<usize> = None;
            let mut run_len = 0usize;
            let mut i = range_start;
            while i < range_end {
                let word_idx = i / 64;
                let bit_off = i % 64;
                let word = bits[word_idx];

                if bit_off == 0 {
                    if word == u64::MAX {
                        run_start = None;
                        run_len = 0;
                        i = (i + 64).min(range_end);
                        continue;
                    }
                    if word == 0 {
                        if run_start.is_none() {
                            run_start = Some(i);
                        }
                        run_len += (range_end - i).min(64);
                        if run_len >= count {
                            return run_start;
                        }
                        i = (i + 64).min(range_end);
                        continue;
                    }
                }

                let word_end = ((word_idx + 1) * 64).min(range_end);
                while i < word_end {
                    let word = bits[word_idx];
                    if (word & (1u64 << (i % 64))) != 0 {
                        run_start = None;
                        run_len = 0;
                    } else {
                        if run_start.is_none() {
                            run_start = Some(i);
                        }
                        run_len += 1;
                        if run_len >= count {
                            return run_start;
                        }
                    }
                    i += 1;
                }
            }
            None
        }

        if let Some(idx) = scan_range(&self.bits, start, VMALLOC_PAGES, count) {
            return Some(idx);
        }
        scan_range(&self.bits, 0, start, count)
    }

    /// Mark `count` pages starting at `page_idx` as allocated.
    fn allocate_range(&mut self, page_idx: usize, count: usize) {
        for i in 0..count {
            self.set(page_idx + i);
        }
    }

    /// Mark `count` pages starting at `page_idx` as free.
    fn free_range(&mut self, page_idx: usize, count: usize) {
        for i in 0..count {
            self.clear(page_idx + i);
        }
    }

    fn test(&self, bit: usize) -> bool {
        let word = bit / 64;
        let offset = bit % 64;
        debug_assert!(word < self.bits.len());
        (self.bits[word] & (1u64 << offset)) != 0
    }

    fn set(&mut self, bit: usize) {
        let word = bit / 64;
        let offset = bit % 64;
        debug_assert!(word < self.bits.len());
        self.bits[word] |= 1u64 << offset;
    }

    fn clear(&mut self, bit: usize) {
        let word = bit / 64;
        let offset = bit % 64;
        debug_assert!(word < self.bits.len());
        self.bits[word] &= !(1u64 << offset);
    }

    /// Count allocated pages for diagnostics.
    fn allocated_pages(&self) -> usize {
        let mut count = 0usize;
        for word in &self.bits {
            count += word.count_ones() as usize;
        }
        count
    }
}

// ─── VM allocator state ─────────────────────────────────────────────────────

/// A single vmalloc allocation record.
struct VmallocAlloc {
    /// Virtual address of the allocation (page-aligned).
    virt_start: u64,
    /// Number of pages in this allocation.
    page_count: usize,
    /// Physical frames backing this allocation, stored outside the heap to
    /// avoid recursive vmalloc metadata allocation.
    frames: FrameList,
}

struct Vmalloc {
    /// One-time init flag.
    initialized: bool,
    /// Whether the vmalloc kernel subtree exists in the canonical kernel CR3.
    subtree_ready: bool,
    /// Bitmap tracking free/allocated virtual pages.
    bitmap: VmallocBitmap,
    /// Active allocations. Fixed-size array to avoid heap allocation during
    /// init (which would recursively call vmalloc and deadlock).
    /// Increased from 128 to 512 to accommodate heavy workloads.
    allocations: [Option<VmallocAlloc>; VMALLOC_ALLOC_SLOTS],
    /// Number of valid entries in `allocations`.
    alloc_count: usize,
    /// Total allocation failures.
    fail_count: usize,
    /// Hint for the next allocation search.
    search_hint: usize,
}

impl Vmalloc {
    const fn new() -> Self {
        Self {
            initialized: false,
            subtree_ready: false,
            bitmap: VmallocBitmap::new(),
            allocations: [const { None }; VMALLOC_ALLOC_SLOTS],
            alloc_count: 0,
            fail_count: 0,
            search_hint: 0,
        }
    }
}

static VMALLOC: SpinLock<Vmalloc> = SpinLock::new(Vmalloc::new());

/// Ensure the vmalloc kernel subtree exists in the canonical kernel page table.
///
/// The map/unmap bootstrap intentionally leaves the intermediate page-table
/// nodes allocated even though the leaf mapping is removed immediately.
/// `unmap_page_kernel()` removes only the leaf PTE; it does not reclaim empty
/// upper-level tables. That is exactly what we want here.
///
/// This is normally done during init, before user address spaces are created,
/// but we also keep it available as a lazy, idempotent fallback.
fn ensure_kernel_subtree_ready(token: &IrqDisabledToken) {
    let mut guard = VMALLOC.lock();
    if guard.subtree_ready {
        return;
    }

    let Ok(frame) = crate::memory::allocate_frame(token) else {
        serial_println!("[vmalloc] bootstrap: failed to allocate bootstrap frame");
        return;
    };

    let page = Page::containing_address(VirtAddr::new(VMALLOC_VIRT_START));
    let x86_frame = X86PhysFrame::containing_address(frame.start_address);
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;

    if map_page_kernel(page, x86_frame, flags).is_ok() {
        let _ = unmap_page_kernel(page);
        guard.subtree_ready = true;
    } else {
        serial_println!("[vmalloc] bootstrap: failed to map bootstrap page");
    }

    crate::memory::free_frame(token, frame);
}

/// Ensure the vmalloc subsystem is initialized.
///
/// Called on every vmalloc/vfree call. Safe to call concurrently — only
/// the first caller performs the actual initialization.
fn ensure_init() {
    let mut guard = VMALLOC.lock();
    if guard.initialized {
        return;
    }
    guard.initialized = true;
    serial_println!(
        "[vmalloc] initialized: VA=0x{:x}..0x{:x} ({} pages, {} MiB)",
        VMALLOC_VIRT_START,
        VMALLOC_VIRT_END,
        VMALLOC_PAGES,
        VMALLOC_SIZE / (1024 * 1024)
    );
}

/// Initialize the vmalloc subsystem.
///
/// Called during kernel initialization, after the buddy allocator and paging
/// are set up. This is a no-op if already initialized (e.g. via first use).
pub fn init() {
    ensure_init();
    crate::sync::with_irqs_disabled(|token| ensure_kernel_subtree_ready(token));
}

/// Allocate `size` bytes of virtually contiguous memory.
///
/// The memory is backed by individually allocated physical pages — no
/// requirement for physical contiguity. Returns a kernel virtual address
/// through the HHDM mapping.
///
/// **Must be called with IRQs disabled** (the `token` parameter proves it).
///
/// Returns `None` if:
/// - No contiguous virtual address range is available
/// - Buddy allocator cannot provide enough physical pages
pub fn vmalloc(size: usize, token: &IrqDisabledToken) -> Option<*mut u8> {
    if size == 0 || size > VMALLOC_MAX_ALLOC {
        return None;
    }

    // Ensure initialized (lazy init on first use).
    ensure_init();
    ensure_kernel_subtree_ready(token);

    let pages = (size + 4095) / 4096;
    let page_flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;

    // Phase 1: allocate backing-frame metadata from raw buddy pages, not the
    // heap, so vmalloc metadata never recurses back into vmalloc.
    let mut frames = FrameList::new(pages, token)?;
    for i in 0..pages {
        match crate::memory::allocate_frame(token) {
            Ok(frame) => {
                frames.set(i, frame);
            }
            Err(_) => {
                // Rollback already-allocated pages.
                for j in 0..i {
                    crate::memory::free_frame(token, frames.get(j));
                }
                frames.free_storage(token);
                return None;
            }
        }
    }

    // Phase 2: Acquire the VMALLOC lock and find a virtual range.
    let mut guard = VMALLOC.lock();
    let vm = &mut *guard;

    let Some(page_idx) = vm.bitmap.find_contiguous(pages, vm.search_hint) else {
        // Rollback physical pages — no virtual range available.
        for i in 0..pages {
            crate::memory::free_frame(token, frames.get(i));
        }
        frames.free_storage(token);
        vm.fail_count += 1;
        return None;
    };

    let virt_base = VMALLOC_VIRT_START + (page_idx as u64 * 4096);

    // Map each physical page into the kernel page tables at the virtual address.
    for i in 0..pages {
        let frame = frames.get(i);
        let page_virt = virt_base + (i as u64 * 4096);
        let page = Page::containing_address(VirtAddr::new(page_virt));
        let x86_frame = X86PhysFrame::containing_address(frame.start_address);
        if map_page_kernel(page, x86_frame, page_flags).is_err() {
            // Rollback mappings and physical pages.
            for j in 0..i {
                let pv = virt_base + (j as u64 * 4096);
                let pg = Page::containing_address(VirtAddr::new(pv));
                let _ = unmap_page_kernel(pg);
            }
            for j in 0..pages {
                crate::memory::free_frame(token, frames.get(j));
            }
            frames.free_storage(token);
            vm.fail_count += 1;
            return None;
        }
    }

    // Mark the virtual range as allocated.
    vm.bitmap.allocate_range(page_idx, pages);
    vm.search_hint = (page_idx + pages) % VMALLOC_PAGES;

    // Find a free slot in the fixed-size array.
    if vm.alloc_count >= vm.allocations.len() {
        // Out of allocation slots — return the memory we just allocated
        // to avoid leaking physical frames.
        for i in 0..pages {
            let pv = virt_base + (i as u64 * 4096);
            let pg = Page::containing_address(VirtAddr::new(pv));
            let _ = unmap_page_kernel(pg);
            crate::memory::free_frame(token, frames.get(i));
        }
        frames.free_storage(token);
        vm.fail_count += 1;
        return None;
    }
    vm.allocations[vm.alloc_count] = Some(VmallocAlloc {
        virt_start: virt_base,
        page_count: pages,
        frames,
    });
    vm.alloc_count += 1;

    Some(virt_base as *mut u8)
}

/// Free a vmalloc'd allocation.
///
/// **Must be called with IRQs disabled** (the `token` parameter proves it).
///
/// Unmaps each page from the kernel page tables and returns physical pages
/// to the buddy allocator.
///
/// ## Metadata safety
///
/// Frame metadata is stored in raw buddy-allocated pages rather than a heap
/// `Vec`, so vmalloc bookkeeping never recurses back into vmalloc itself.
pub fn vfree(ptr: *mut u8, token: &IrqDisabledToken) {
    if ptr.is_null() {
        return;
    }

    let addr = ptr as u64;
    if addr < VMALLOC_VIRT_START || addr >= VMALLOC_VIRT_END {
        // Not a vmalloc pointer — could be from some other allocator.
        return;
    }

    // Extract allocation data inside the lock scope, keep the VA reserved
    // until the kernel mappings are gone on all CPUs.
    let frames = {
        let mut guard = VMALLOC.lock();
        let vm = &mut *guard;

        // Find the allocation record.
        let mut found_idx: Option<usize> = None;
        for i in 0..vm.alloc_count {
            if let Some(ref a) = vm.allocations[i] {
                if a.virt_start == addr {
                    found_idx = Some(i);
                    break;
                }
            }
        }

        let Some(pos) = found_idx else {
            serial_println!("[vmalloc] vfree: no allocation record for 0x{:x}", addr);
            return;
        };

        // Move the Vec and metadata out of the record.
        let alloc = vm.allocations[pos].take().unwrap();
        let frames = alloc.frames;
        let page_count = alloc.page_count;
        let virt_start = alloc.virt_start;
        let start_idx = ((virt_start - VMALLOC_VIRT_START) / 4096) as usize;

        // Unmap the old mappings while the VA is still reserved in the bitmap.
        for i in 0..page_count {
            let page_start = virt_start + (i as u64 * 4096);
            let page = Page::containing_address(VirtAddr::new(page_start));
            let _ = unmap_page_kernel(page);
        }

        // Flush stale translations on all CPUs before the physical frames can
        // be returned to the buddy allocator and potentially reused.
        //
        // NOTE: `shootdown_all()` is conservative. On systems with many CPUs,
        // only CPUs that have accessed these mappings actually need a flush.
        // A targeted IPI-based shootdown (tracking per-CPU access bitmaps)
        // could reduce overhead as a future optimization.
        shootdown_all();

        // Only now make the VA available for reuse.
        vm.bitmap.free_range(start_idx, page_count);
        vm.search_hint = vm.search_hint.min(start_idx);

        // Swap the last entry into the freed slot to keep the array compact.
        let last = vm.alloc_count - 1;
        if pos != last {
            vm.allocations[pos] = vm.allocations[last].take();
        }
        vm.alloc_count -= 1;

        frames
    }; // VMALLOC lock released here — frames Vec is now outside the lock

    for i in 0..frames.len {
        crate::memory::free_frame(token, frames.get(i));
    }
    frames.free_storage(token);
}

/// Dump vmalloc diagnostics to the serial console.
pub fn dump_diagnostics() {
    let guard = VMALLOC.lock();
    let vm = &*guard;
    if !vm.initialized {
        serial_println!("[vmalloc][diag] not initialized");
        return;
    }

    let alloc_pages = vm.bitmap.allocated_pages();
    serial_println!(
        "[vmalloc][diag] arena=0x{:x}..0x{:x} allocs={} alloc_pages={} free_pages={} fails={}",
        VMALLOC_VIRT_START,
        VMALLOC_VIRT_END,
        vm.alloc_count,
        alloc_pages,
        VMALLOC_PAGES - alloc_pages,
        vm.fail_count
    );
}
