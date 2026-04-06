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
//! VMALLOC_SIZE       = 256 MiB
//! VMALLOC_VIRT_END   = 0xffffc010_0000_0000
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
    memory::{
        frame::PhysFrame,
        paging::{map_page, unmap_page},
        phys_to_virt,
    },
    serial_println,
    sync::{IrqDisabledToken, SpinLock},
};
use alloc::vec::Vec;
use core::ptr;
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{Page, PageTableFlags, Size4KiB, PhysFrame as X86PhysFrame},
};

// ─── Arena constants ─────────────────────────────────────────────────────────

/// Base virtual address of the vmalloc arena.
/// Placed at 0xffffc000_0000_0000 — well above the HHDM direct map.
pub const VMALLOC_VIRT_START: u64 = 0xffff_c000_0000_0000;

/// Total size of the vmalloc arena: 256 MiB.
pub const VMALLOC_SIZE: usize = 256 * 1024 * 1024;

/// End virtual address of the vmalloc arena.
pub const VMALLOC_VIRT_END: u64 = VMALLOC_VIRT_START + VMALLOC_SIZE as u64;

/// Number of pages in the arena.
const VMALLOC_PAGES: usize = VMALLOC_SIZE / 4096;

/// Maximum single allocation size: 64 MiB (limited by bitmap allocator).
const VMALLOC_MAX_ALLOC: usize = 64 * 1024 * 1024;

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
        let mut run_start: Option<usize> = None;
        let mut run_len = 0usize;
        let start = hint.min(VMALLOC_PAGES - 1);

        for i in start..VMALLOC_PAGES {
            if self.test(i) {
                // Page is allocated — reset run.
                run_start = None;
                run_len = 0;
            } else {
                // Page is free — extend run.
                if run_start.is_none() {
                    run_start = Some(i);
                }
                run_len += 1;
                if run_len >= count {
                    return run_start;
                }
            }
        }

        // Wrap around to beginning.
        for i in 0..start {
            if self.test(i) {
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
        }

        None
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
        (self.bits[word] & (1u64 << offset)) != 0
    }

    fn set(&mut self, bit: usize) {
        let word = bit / 64;
        let offset = bit % 64;
        self.bits[word] |= 1u64 << offset;
    }

    fn clear(&mut self, bit: usize) {
        let word = bit / 64;
        let offset = bit % 64;
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
    /// Physical frames backing this allocation (stored inline for small allocs).
    /// For large allocations, this is a Vec allocated via the slab.
    frames: alloc::vec::Vec<PhysFrame>,
}

struct Vmalloc {
    /// Bitmap tracking free/allocated virtual pages.
    bitmap: VmallocBitmap,
    /// Active allocations. Fixed-size array to avoid heap allocation during
    /// init (which would recursively call vmalloc and deadlock).
    allocations: [Option<VmallocAlloc>; 128],
    /// Number of valid entries in `allocations`.
    alloc_count: usize,
    /// Total allocation failures.
    fail_count: usize,
    /// Hint for the next allocation search.
    search_hint: usize,
}

use core::sync::atomic::{AtomicBool, Ordering};

static VMALLOC: SpinLock<Option<Vmalloc>> = SpinLock::new(None);
static VMALLOC_INITED: AtomicBool = AtomicBool::new(false);

/// Ensure the vmalloc subsystem is initialized.
///
/// Called on every vmalloc/vfree call. Safe to call concurrently — only
/// the first caller performs the actual initialization.
fn ensure_init() {
    if VMALLOC_INITED.load(Ordering::Relaxed) {
        return;
    }
    let mut guard = VMALLOC.lock();
    if guard.is_some() {
        return; // Race: another thread initialized.
    }
    *guard = Some(Vmalloc {
        bitmap: VmallocBitmap::new(),
        allocations: core::array::from_fn(|_| None),
        alloc_count: 0,
        fail_count: 0,
        search_hint: 0,
    });
    VMALLOC_INITED.store(true, Ordering::Release);
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

    let pages = (size + 4095) / 4096;
    let page_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;

    // Phase 1: Allocate physical pages and map them into a temporary VA.
    // We do this BEFORE acquiring the VMALLOC lock to avoid recursive lock
    // acquisition (the Vec heap allocation may call vmalloc for large sizes).
    let mut frames = alloc::vec::Vec::with_capacity(pages);
    for i in 0..pages {
        match crate::memory::allocate_frame(token) {
            Ok(frame) => {
                frames.push(frame);
            }
            Err(_) => {
                // Rollback already-allocated pages.
                for j in 0..frames.len() {
                    crate::memory::free_frame(token, frames[j]);
                }
                return None;
            }
        }
    }

    // Phase 2: Acquire the VMALLOC lock and find a virtual range.
    let mut guard = VMALLOC.lock();
    let vm = guard.as_mut()?;

    let Some(page_idx) = vm.bitmap.find_contiguous(pages, vm.search_hint) else {
        // Rollback physical pages — no virtual range available.
        for frame in &frames {
            crate::memory::free_frame(token, *frame);
        }
        vm.fail_count += 1;
        return None;
    };

    let virt_base = VMALLOC_VIRT_START + (page_idx as u64 * 4096);

    // Map each physical page into the kernel page tables at the virtual address.
    for (i, frame) in frames.iter().enumerate() {
        let page_virt = virt_base + (i as u64 * 4096);
        let page = Page::containing_address(VirtAddr::new(page_virt));
        let x86_frame = X86PhysFrame::containing_address(frame.start_address);
        if map_page(page, x86_frame, page_flags).is_err() {
            // Rollback mappings and physical pages.
            for j in 0..i {
                let pv = virt_base + (j as u64 * 4096);
                let pg = Page::containing_address(VirtAddr::new(pv));
                let _ = unmap_page(pg);
            }
            for frame in &frames {
                crate::memory::free_frame(token, *frame);
            }
            vm.fail_count += 1;
            return None;
        }
        // Zero the page.
        unsafe {
            ptr::write_bytes(phys_to_virt(frame.start_address.as_u64()) as *mut u8, 0, 4096);
        }
    }

    // Mark the virtual range as allocated.
    vm.bitmap.allocate_range(page_idx, pages);
    vm.search_hint = page_idx + pages;

    // Find a free slot in the fixed-size array.
    if vm.alloc_count >= vm.allocations.len() {
        // Out of allocation slots — return the memory we just allocated
        // to avoid leaking physical frames.
        for i in 0..pages {
            let pv = virt_base + (i as u64 * 4096);
            let pg = Page::containing_address(VirtAddr::new(pv));
            let _ = unmap_page(pg);
            crate::memory::free_frame(token, frames[i]);
        }
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
pub fn vfree(ptr: *mut u8, token: &IrqDisabledToken) {
    if ptr.is_null() {
        return;
    }

    let mut guard = VMALLOC.lock();
    let vm = guard.as_mut().unwrap();

    let addr = ptr as u64;
    if addr < VMALLOC_VIRT_START || addr >= VMALLOC_VIRT_END {
        serial_println!("[vmalloc] vfree: pointer 0x{:x} outside arena", addr);
        return;
    }

    let page_idx = ((addr - VMALLOC_VIRT_START) / 4096) as usize;

    // Find the allocation record.
    let mut found_idx: Option<usize> = None;
    for i in 0..vm.alloc_count {
        if let Some(ref a) = vm.allocations[i] {
            let a_start = (a.virt_start - VMALLOC_VIRT_START) / 4096;
            let a_end = a_start + (a.page_count as u64);
            let pi = page_idx as u64;
            if (pi >= a_start) && (pi < a_end) {
                found_idx = Some(i);
                break;
            }
        }
    }

    let Some(pos) = found_idx else {
        serial_println!("[vmalloc] vfree: no allocation record for 0x{:x}", addr);
        return;
    };

    let alloc = vm.allocations[pos].take().unwrap();

    // Unmap and free each physical page.
    for (i, frame) in alloc.frames.iter().enumerate() {
        let page_virt = alloc.virt_start + (i as u64 * 4096);
        let page = Page::containing_address(VirtAddr::new(page_virt));
        let _ = unmap_page(page);
        crate::memory::free_frame(token, *frame);
    }

    // Mark the virtual range as free.
    let start_idx = (alloc.virt_start - VMALLOC_VIRT_START) / 4096;
    vm.bitmap.free_range(start_idx as usize, alloc.page_count);
    vm.search_hint = vm.search_hint.min(start_idx as usize);
    // Swap the last entry into the freed slot to keep the array compact.
    let last = vm.alloc_count - 1;
    if pos != last {
        vm.allocations[pos] = vm.allocations[last].take();
    }
    vm.alloc_count -= 1;
}

/// Dump vmalloc diagnostics to the serial console.
pub fn dump_diagnostics() {
    let guard = VMALLOC.lock();
    let Some(vm) = guard.as_ref() else {
        serial_println!("[vmalloc][diag] not initialized");
        return;
    };

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
