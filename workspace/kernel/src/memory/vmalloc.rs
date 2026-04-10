//! VM-backed allocator for large heap objects.
//!
//! Provides virtually contiguous allocations backed by individually allocated
//! physical pages. Unlike the buddy allocator, `vmalloc` does **not** require
//! physically contiguous memory : it maps each page individually into a
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
//! 1. Allocate backing physical pages individually from the frame allocator.
//! 2. Reserve a virtually contiguous range from the vmalloc extent allocator.
//! 3. Map each page into the kernel page tables at the virtual address.
//!
//! ## Deallocation
//!
//! 1. Unmap each page from the kernel page tables.
//! 2. Flush stale TLB entries across CPUs for the unmapped range.
//! 3. Return the virtual range to the extent allocator.
//! 4. Free each physical page back to the frame allocator.
//!
//! ## Metadata model
//!
//! The allocator no longer uses a fixed allocation-record table or a bitmap.
//! It maintains:
//! - a sorted free-extent list;
//! - a sorted active-allocation list;
//! - a metadata node pool carved from raw buddy pages, independent from the
//!   general kernel heap.
//!
//! This removes the old fixed-slot ceiling and keeps vmalloc bookkeeping from
//! recursing back into heap allocation.
//!
//! ## Thread safety
//!
//! Protected by a single `SpinLock<Vmalloc>`. IRQs are disabled during
//! allocation to prevent deadlock with the buddy allocator.

use crate::{
    arch::x86_64::tlb::shootdown_range,
    memory::{
        frame::PhysFrame,
        paging::{map_page_kernel, unmap_page_kernel},
        phys_to_virt,
    },
    serial_println,
    sync::{IrqDisabledToken, SpinLock},
};
use core::{
    mem::size_of,
    panic::Location,
    ptr,
    sync::atomic::{AtomicU64, Ordering as AtomicOrdering},
};
use x86_64::{
    VirtAddr,
    structures::paging::{Page, PageTableFlags, PhysFrame as X86PhysFrame},
};

//  Arena constants =====================================================

/// Base virtual address of the vmalloc arena.
/// Placed at 0xffffc000_0000_0000 — well above the HHDM direct map.
pub const VMALLOC_VIRT_START: u64 = 0xffff_c000_0000_0000;

/// Total size of the vmalloc arena: 1 GiB.
pub const VMALLOC_SIZE: usize = 1024 * 1024 * 1024;

/// End virtual address of the vmalloc arena.
pub const VMALLOC_VIRT_END: u64 = VMALLOC_VIRT_START + VMALLOC_SIZE as u64;

/// Number of pages in the arena.
const VMALLOC_PAGES: usize = VMALLOC_SIZE / 4096;

/// First allocatable page index inside the arena.
///
/// Page 0 (`VMALLOC_VIRT_START`) is permanently mapped by the bootstrap frame
/// allocated in `ensure_kernel_subtree_ready()`.  Keeping that mapping alive
/// anchors the intermediate page-table nodes (PDPT → PD → PT) so they are
/// inherited by every address space cloned after `init()` runs.
/// The free-extent list therefore starts at page 1.
const ARENA_START_PAGE: usize = 1;

/// Maximum single allocation size.
///
/// The backend is now bounded by the actual vmalloc arena size rather than an
/// arbitrary low ceiling.
const VMALLOC_MAX_ALLOC: usize = VMALLOC_SIZE;

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
        let storage_frame = crate::memory::buddy::alloc(token, order).ok()?;
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
        crate::memory::buddy::free(token, self.storage_frame, self.storage_order);
    }
}

// SAFETY: `FrameList` owns a contiguous region of physical memory allocated
// from the buddy allocator. The raw pointer is never aliased — access is
// exclusively mediated through `get`/`set`. Transferring ownership across
// threads is safe because the backing storage frame and all frames stored
// within are plain physical addresses that travel with the struct.
unsafe impl Send for FrameList {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmallocError {
    ZeroSize,
    SizeExceedsPolicy {
        requested: usize,
        max_allowed: usize,
    },
    MetadataAllocationFailed,
    PhysicalMemoryExhausted,
    VirtualRangeExhausted,
    KernelMapFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmallocFailureSnapshot {
    pub size: usize,
    pub pages: usize,
    pub error: VmallocError,
}

/// Unified metadata node used both for free extents and live allocations.
///
/// `frames == None` means the node describes a free extent.
/// `frames == Some(_)` means the node describes an active allocation.
///
/// `attr` is only meaningful when `frames.is_some()`; it is zero-initialized
/// for free-extent nodes.
struct VmallocNode {
    start_page: usize,
    page_count: usize,
    next: *mut VmallocNode,
    frames: Option<FrameList>,
    /// Attribution captured at allocation time. Used by leak diagnostics.
    attr: VmallocAttr,
}

// SAFETY: access to nodes is serialized by `VMALLOC`; the struct only contains
// plain integers, raw pointers forming intrusive lists, and `FrameList`, which
// is already `Send`.
unsafe impl Send for VmallocNode {}

struct Vmalloc {
    initialized: bool,
    subtree_ready: bool,
    /// True once the initial single-spanning free extent has been inserted.
    /// Replaces the ambiguous `!free_head.is_null() || !alloc_head.is_null()`
    /// guard that read as a free-space check rather than an init-state check.
    arena_initialized: bool,
    /// Bootstrap frame permanently mapped at `VMALLOC_VIRT_START` (arena page 0).
    ///
    /// Keeping this mapping live anchors the intermediate page-table nodes
    /// (PDPT → PD → PT) so they are present in the canonical kernel L4 table
    /// and inherited by every address space created after `init()`.  The frame
    /// must never be freed while the kernel is running.
    bootstrap_frame: Option<PhysFrame>,
    free_head: *mut VmallocNode,
    alloc_head: *mut VmallocNode,
    node_pool_free: *mut VmallocNode,
    alloc_count: usize,
    allocated_pages: usize,
    metadata_pages: usize,
    fail_count: usize,
    last_failure: Option<VmallocFailureSnapshot>,
}

// SAFETY: all access to the intrusive raw-pointer lists in `Vmalloc` is
// serialized by `VMALLOC: SpinLock<Vmalloc>`. The raw pointers point only to
// allocator-owned metadata nodes managed under that lock.
unsafe impl Send for Vmalloc {}

impl Vmalloc {
    const fn new() -> Self {
        Self {
            initialized: false,
            subtree_ready: false,
            arena_initialized: false,
            bootstrap_frame: None,
            free_head: ptr::null_mut(),
            alloc_head: ptr::null_mut(),
            node_pool_free: ptr::null_mut(),
            alloc_count: 0,
            allocated_pages: 0,
            metadata_pages: 0,
            fail_count: 0,
            last_failure: None,
        }
    }

    fn record_failure(&mut self, size: usize, pages: usize, error: VmallocError) -> VmallocError {
        self.fail_count = self.fail_count.saturating_add(1);
        self.last_failure = Some(VmallocFailureSnapshot { size, pages, error });
        error
    }

    unsafe fn refill_node_pool(&mut self, token: &IrqDisabledToken) -> Result<(), VmallocError> {
        let frame = crate::memory::buddy::alloc(token, 0)
            .map_err(|_| self.record_failure(0, 0, VmallocError::MetadataAllocationFailed))?;
        let base = phys_to_virt(frame.start_address.as_u64()) as *mut VmallocNode;
        // Compile-time guarantee that at least one node fits in a page.
        const _: () = assert!(
            core::mem::size_of::<VmallocNode>() < 4096,
            "VmallocNode exceeds one page — refill_node_pool logic must be revised"
        );
        let nodes_per_page = 4096 / size_of::<VmallocNode>();

        for i in 0..nodes_per_page {
            let node = base.add(i);
            ptr::write(
                node,
                VmallocNode {
                    start_page: 0,
                    page_count: 0,
                    next: self.node_pool_free,
                    frames: None,
                    attr: VmallocAttr::default(),
                },
            );
            self.node_pool_free = node;
        }
        self.metadata_pages = self.metadata_pages.saturating_add(1);
        Ok(())
    }

    unsafe fn alloc_node(
        &mut self,
        token: &IrqDisabledToken,
    ) -> Result<*mut VmallocNode, VmallocError> {
        if self.node_pool_free.is_null() {
            self.refill_node_pool(token)?;
        }
        let node = self.node_pool_free;
        self.node_pool_free = (*node).next;
        (*node).next = ptr::null_mut();
        (*node).start_page = 0;
        (*node).page_count = 0;
        (*node).frames = None;
        (*node).attr = VmallocAttr::default();
        Ok(node)
    }

    unsafe fn release_node(&mut self, node: *mut VmallocNode) {
        // Releasing a node that still holds a FrameList would silently drop the
        // physical frames without freeing them — an unrecoverable leak / potential
        // double-free if the frames are later re-allocated.  Free nodes must
        // always have `frames == None` before being returned to the pool.
        debug_assert!(
            (*node).frames.is_none(),
            "release_node: node at {:p} still has live frames (start_page={}) — \
             caller must take() frames before releasing",
            node,
            (*node).start_page,
        );
        (*node).frames = None; // belt-and-suspenders in release builds
        (*node).start_page = 0;
        (*node).page_count = 0;
        (*node).next = self.node_pool_free;
        self.node_pool_free = node;
    }

    unsafe fn ensure_arena_ready(&mut self, token: &IrqDisabledToken) -> Result<(), VmallocError> {
        if self.arena_initialized {
            return Ok(());
        }
        let node = self.alloc_node(token)?;
        // Page 0 (VMALLOC_VIRT_START) is reserved for the bootstrap mapping
        // established by `ensure_kernel_subtree_ready()`. The allocatable arena
        // begins at ARENA_START_PAGE to avoid colliding with that frame.
        (*node).start_page = ARENA_START_PAGE;
        (*node).page_count = VMALLOC_PAGES - ARENA_START_PAGE;
        (*node).next = ptr::null_mut();
        (*node).frames = None;
        self.free_head = node;
        self.arena_initialized = true;
        Ok(())
    }

    unsafe fn reserve_range(
        &mut self,
        pages: usize,
        token: &IrqDisabledToken,
    ) -> Result<*mut VmallocNode, VmallocError> {
        let mut best_prev = ptr::null_mut();
        let mut best = ptr::null_mut();
        let mut best_size = usize::MAX;

        let mut prev = ptr::null_mut();
        let mut cur = self.free_head;
        while !cur.is_null() {
            if (*cur).page_count >= pages && (*cur).page_count < best_size {
                best = cur;
                best_prev = prev;
                best_size = (*cur).page_count;
                if best_size == pages {
                    break;
                }
            }
            prev = cur;
            cur = (*cur).next;
        }

        if best.is_null() {
            return Err(VmallocError::VirtualRangeExhausted);
        }

        if (*best).page_count == pages {
            let next = (*best).next;
            if best_prev.is_null() {
                self.free_head = next;
            } else {
                (*best_prev).next = next;
            }
            (*best).next = ptr::null_mut();
            return Ok(best);
        }

        let alloc = self.alloc_node(token)?;
        (*alloc).start_page = (*best).start_page;
        (*alloc).page_count = pages;
        (*alloc).next = ptr::null_mut();
        (*alloc).frames = None;

        (*best).start_page = (*best).start_page.saturating_add(pages);
        (*best).page_count = (*best).page_count.saturating_sub(pages);
        Ok(alloc)
    }

    unsafe fn insert_alloc_node(&mut self, node: *mut VmallocNode) {
        let mut prev: *mut VmallocNode = ptr::null_mut();
        let mut cur = self.alloc_head;
        while !cur.is_null() && (*cur).start_page < (*node).start_page {
            prev = cur;
            cur = (*cur).next;
        }
        (*node).next = cur;
        if prev.is_null() {
            self.alloc_head = node;
        } else {
            (*prev).next = node;
        }
    }

    unsafe fn take_alloc_node(&mut self, start_page: usize) -> *mut VmallocNode {
        let mut prev: *mut VmallocNode = ptr::null_mut();
        let mut cur = self.alloc_head;
        while !cur.is_null() {
            if (*cur).start_page == start_page {
                let next = (*cur).next;
                if prev.is_null() {
                    self.alloc_head = next;
                } else {
                    (*prev).next = next;
                }
                (*cur).next = ptr::null_mut();
                return cur;
            }
            if (*cur).start_page > start_page {
                break;
            }
            prev = cur;
            cur = (*cur).next;
        }
        ptr::null_mut()
    }

    unsafe fn insert_free_node_merge(&mut self, node: *mut VmallocNode) {
        debug_assert!((*node).frames.is_none());

        let mut prev: *mut VmallocNode = ptr::null_mut();
        let mut cur = self.free_head;
        while !cur.is_null() && (*cur).start_page < (*node).start_page {
            prev = cur;
            cur = (*cur).next;
        }

        (*node).next = cur;
        if prev.is_null() {
            self.free_head = node;
        } else {
            (*prev).next = node;
        }

        let mut merged = node;
        if !prev.is_null() && (*prev).start_page + (*prev).page_count == (*node).start_page {
            (*prev).page_count = (*prev).page_count.saturating_add((*node).page_count);
            (*prev).next = (*node).next;
            self.release_node(node);
            merged = prev;
        }

        while !(*merged).next.is_null() {
            let next = (*merged).next;
            if (*merged).start_page + (*merged).page_count != (*next).start_page {
                break;
            }
            (*merged).page_count = (*merged).page_count.saturating_add((*next).page_count);
            (*merged).next = (*next).next;
            self.release_node(next);
        }
    }

    unsafe fn free_extent_count(&self) -> usize {
        let mut count = 0usize;
        let mut cur = self.free_head;
        while !cur.is_null() {
            count = count.saturating_add(1);
            cur = (*cur).next;
        }
        count
    }

    unsafe fn largest_free_extent_pages(&self) -> usize {
        let mut largest = 0usize;
        let mut cur = self.free_head;
        while !cur.is_null() {
            largest = largest.max((*cur).page_count);
            cur = (*cur).next;
        }
        largest
    }

    unsafe fn node_pool_free_count(&self) -> usize {
        let mut count = 0usize;
        let mut cur = self.node_pool_free;
        while !cur.is_null() {
            count = count.saturating_add(1);
            cur = (*cur).next;
        }
        count
    }
}

static VMALLOC: SpinLock<Vmalloc> = SpinLock::new(Vmalloc::new());

/// Counts ZeroSize / policy-limit rejections.
pub static VMALLOC_POLICY_REJECT_COUNT: AtomicU64 = AtomicU64::new(0);

/// Monotonic sequence number — incremented once per successful `vmalloc` call.
///
/// Provides a stable ordering for leak analysis: lower `alloc_seq` means an
/// earlier allocation, so the oldest live allocations are easy to spot.
pub static VMALLOC_ALLOC_SEQ: AtomicU64 = AtomicU64::new(0);

/// High-watermark of simultaneously allocated pages (updated on every alloc).
pub static VMALLOC_PEAK_PAGES: AtomicU64 = AtomicU64::new(0);

/// Attribution snapshot captured at vmalloc time.
///
/// Stored inside each live allocation node so that `dump_live_allocations()`
/// can attribute each mapping to a task and silo without external state.
///
/// Designed for post-mortem leak analysis:
/// - `alloc_seq` gives ordering (smallest = oldest live alloc).
/// - `pid`/`tid`/`silo_id` identify the requesting workload.
/// - `size` is the **requested** byte count, not the page-rounded value.
#[derive(Clone, Copy, Debug, Default)]
pub struct VmallocAttr {
    /// Scheduler task id (`0` = kernel or pre-scheduler context).
    pub task_id: u64,
    /// PID of the requesting task (`0` = kernel or pre-scheduler context).
    pub pid: u32,
    /// TID of the requesting task.
    pub tid: u32,
    /// Silo that owns the task (`0` = kernel / silo lookup failed / not in silo).
    pub silo_id: u32,
    /// Requested allocation size in bytes (before page-rounding).
    pub size: usize,
    /// Monotonic per-boot sequence number (see [`VMALLOC_ALLOC_SEQ`]).
    pub alloc_seq: u64,
    /// Best-effort callsite file of the allocator request.
    pub caller_file: &'static str,
    /// Best-effort callsite line of the allocator request.
    pub caller_line: u32,
    /// Best-effort callsite column of the allocator request.
    pub caller_column: u32,
}

/// Capture attribution for the calling task, without holding VMALLOC.
///
/// Must be called **before** acquiring the VMALLOC lock to maintain
/// the VMALLOC → SILO_MANAGER lock ordering and to avoid deadlocking
/// if vmalloc is called from within silo or scheduler code.
///
/// Uses `current_task_clone_try()` (non-blocking) so that vmalloc called
/// from within a scheduler path cannot deadlock on the per-CPU scheduler lock.
fn capture_attr(size: usize, caller: &'static Location<'static>) -> VmallocAttr {
    let alloc_seq = VMALLOC_ALLOC_SEQ.fetch_add(1, AtomicOrdering::Relaxed);

    let (task_id, pid, tid, silo_id) = match crate::process::current_task_clone_try() {
        Some(task) => {
            let task_id = task.id.as_u64();
            let pid = task.pid;
            let tid = task.tid;
            // Non-blocking: if SILO_MANAGER is held by an outer frame on this
            // CPU, we just record silo_id=0 rather than risk a deadlock.
            let silo_id = crate::silo::try_silo_id_for_task(task.id).unwrap_or(0);
            (task_id, pid, tid, silo_id)
        }
        // No scheduler running yet, or per-CPU lock is contended.
        None => (0, 0, 0, 0),
    };

    VmallocAttr {
        task_id,
        pid,
        tid,
        silo_id,
        size,
        alloc_seq,
        caller_file: caller.file(),
        caller_line: caller.line(),
        caller_column: caller.column(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmallocAllocBackend {
    KernelVirtual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmallocLiveAllocationSnapshot {
    pub seq: u64,
    pub task_id: u64,
    pub pid: u32,
    pub tid: u32,
    pub silo_id: u32,
    pub size: usize,
    pub pages: usize,
    pub vaddr: u64,
    pub backend: VmallocAllocBackend,
    pub caller_file: &'static str,
    pub caller_line: u32,
    pub caller_column: u32,
}

/// Pre-allocate the intermediate page-table nodes (PML4 → PDPT → PD) for the
/// vmalloc virtual address range in the **canonical kernel page table**.
///
/// ## Why this is necessary
///
/// Every new user address space clones `PML4[256..512]` from the kernel L4 at
/// creation time.  If the PDPT/PD nodes for the vmalloc arena do not exist at
/// that point, the new address space inherits `PML4[256] = 0` (not present).
/// Any subsequent kernel access to a vmalloc address in that process's context
/// will fault, because its page-table walk stops at the missing PML4 entry.
///
/// By touching (map + immediately unmap) a page inside the arena during
/// `init()`, we force the page-table allocator to create and wire all
/// intermediate nodes.  `unmap_page_kernel()` removes only the leaf PTE; it
/// does **not** reclaim intermediate tables — that is exactly what we need.
///
/// ## Caller contract
///
/// **Called only from `init()`**, which runs before any user address space is
/// created.  Do **not** call this from `vmalloc()`: the check (`subtree_ready`)
/// would always succeed after boot and would add a gratuitous VMALLOC lock
/// acquire on every allocation hot path.
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
        // Keep the frame permanently mapped at VMALLOC_VIRT_START (arena page 0).
        //
        // We deliberately do NOT unmap here.  The goal is to keep the intermediate
        // page-table nodes (PDPT → PD → PT) alive in the canonical kernel L4 so
        // that every address space cloned after this point inherits them.
        //
        // Previously the code did map + immediate unmap, relying on the fact that
        // `unmap_page_kernel` only removes the leaf PTE and never reclaims empty
        // intermediate tables.  That invariant is not guaranteed to hold forever;
        // anchoring through a live mapping makes the intent explicit and robust.
        //
        // The vmalloc arena consequently starts at ARENA_START_PAGE (page 1) to
        // avoid handing out the bootstrap virtual address to callers.
        guard.bootstrap_frame = Some(frame);
        guard.subtree_ready = true;
    } else {
        // Mapping failed — free the frame; the arena will be unusable.
        crate::memory::free_frame(token, frame);
        serial_println!("[vmalloc] bootstrap: failed to map bootstrap page");
    }
}

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

pub fn init() {
    ensure_init();
    crate::sync::with_irqs_disabled(|token| {
        ensure_kernel_subtree_ready(token);
        let mut guard = VMALLOC.lock();
        let _ = unsafe { guard.ensure_arena_ready(token) };
    });
}

pub fn last_failure_snapshot() -> Option<VmallocFailureSnapshot> {
    let guard = VMALLOC.lock();
    guard.last_failure
}

/// Allocate `size` bytes of virtually contiguous kernel memory.
///
/// Prefer [`crate::memory::allocate_kernel_virtual`] over calling this
/// directly.
#[track_caller]
pub(crate) fn vmalloc(size: usize, token: &IrqDisabledToken) -> Result<*mut u8, VmallocError> {
    if size == 0 {
        // Pure policy reject — no allocation attempted, no per-call context
        // worth recording. VMALLOC_POLICY_REJECT_COUNT captures the count.
        VMALLOC_POLICY_REJECT_COUNT.fetch_add(1, AtomicOrdering::Relaxed);
        return Err(VmallocError::ZeroSize);
    }
    if size > VMALLOC_MAX_ALLOC {
        VMALLOC_POLICY_REJECT_COUNT.fetch_add(1, AtomicOrdering::Relaxed);
        return Err(VmallocError::SizeExceedsPolicy {
            requested: size,
            max_allowed: VMALLOC_MAX_ALLOC,
        });
    }

    // Capture attribution before acquiring VMALLOC to respect lock ordering
    // (VMALLOC → SILO_MANAGER) and to avoid a re-entrancy deadlock if this
    // vmalloc call originates from within scheduler or silo code.
    let attr = capture_attr(size, Location::caller());

    ensure_init();

    let pages = (size + 4095) / 4096;
    let page_flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;

    // Two-phase lock pattern:
    //
    // Phase A (no VMALLOC lock): allocate all physical frames from the buddy.
    // Phase B (VMALLOC lock held): reserve a virtual range and map the frames.
    //
    // Keeping Phase A outside the lock allows the buddy to run concurrently with
    // other vmalloc/vfree calls.  The trade-off is that another thread may exhaust
    // the virtual arena between A and B, in which case the frames are rolled back
    // and `VirtualRangeExhausted` is returned.  This is acceptable: physical frames
    // are cheap to allocate and free compared to holding a global spinlock across
    // potentially dozens of buddy allocations.
    let mut frames = match FrameList::new(pages, token) {
        Some(frames) => frames,
        None => {
            let mut guard = VMALLOC.lock();
            return Err(guard.record_failure(size, pages, VmallocError::MetadataAllocationFailed));
        }
    };

    for i in 0..pages {
        match crate::memory::allocate_frame(token) {
            Ok(frame) => frames.set(i, frame),
            Err(_) => {
                for j in 0..i {
                    crate::memory::free_frame(token, frames.get(j));
                }
                frames.free_storage(token);
                let mut guard = VMALLOC.lock();
                return Err(guard.record_failure(
                    size,
                    pages,
                    VmallocError::PhysicalMemoryExhausted,
                ));
            }
        }
    }

    let mut guard = VMALLOC.lock();
    let vm = &mut *guard;
    unsafe {
        if let Err(error) = vm.ensure_arena_ready(token) {
            for i in 0..pages {
                crate::memory::free_frame(token, frames.get(i));
            }
            frames.free_storage(token);
            return Err(vm.record_failure(size, pages, error));
        }

        let alloc_node = match vm.reserve_range(pages, token) {
            Ok(node) => node,
            Err(error) => {
                for i in 0..pages {
                    crate::memory::free_frame(token, frames.get(i));
                }
                frames.free_storage(token);
                return Err(vm.record_failure(size, pages, error));
            }
        };

        let virt_base = VMALLOC_VIRT_START + ((*alloc_node).start_page as u64 * 4096);

        for i in 0..pages {
            let frame = frames.get(i);
            let page_virt = virt_base + (i as u64 * 4096);
            let page = Page::containing_address(VirtAddr::new(page_virt));
            let x86_frame = X86PhysFrame::containing_address(frame.start_address);
            if map_page_kernel(page, x86_frame, page_flags).is_err() {
                for j in 0..i {
                    let pv = virt_base + (j as u64 * 4096);
                    let pg = Page::containing_address(VirtAddr::new(pv));
                    let _ = unmap_page_kernel(pg);
                }
                (*alloc_node).frames = None;
                vm.insert_free_node_merge(alloc_node);
                for j in 0..pages {
                    crate::memory::free_frame(token, frames.get(j));
                }
                frames.free_storage(token);
                return Err(vm.record_failure(size, pages, VmallocError::KernelMapFailed));
            }
        }

        (*alloc_node).frames = Some(frames);
        (*alloc_node).attr = attr;
        vm.insert_alloc_node(alloc_node);
        vm.alloc_count = vm.alloc_count.saturating_add(1);
        vm.allocated_pages = vm.allocated_pages.saturating_add(pages);
        vm.last_failure = None;

        // Update peak-pages high watermark (lock-free, best-effort).
        let current_pages = vm.allocated_pages as u64;
        let mut peak = VMALLOC_PEAK_PAGES.load(AtomicOrdering::Relaxed);
        while current_pages > peak {
            match VMALLOC_PEAK_PAGES.compare_exchange_weak(
                peak,
                current_pages,
                AtomicOrdering::Relaxed,
                AtomicOrdering::Relaxed,
            ) {
                Ok(_) => break,
                Err(p) => peak = p,
            }
        }

        Ok(virt_base as *mut u8)
    }
}

/// Free a vmalloc allocation.
///
/// Structured as three phases to avoid a spinlock-under-IPI deadlock:
///
/// 1. **Under VMALLOC lock** : unmap pages (acquires/releases KERNEL_PT_LOCK per
///    page), collect the frame list, update allocator bookkeeping, return the
///    virtual extent to the free list.
/// 2. **Lock released** : TLB shootdown. Remote CPUs servicing the IPI must
///    acknowledge before returning. If VMALLOC were still held here, any
///    remote CPU blocked on VMALLOC could not reach the acknowledgement path,
///    causing a deadlock. Releasing first eliminates the hazard.
/// 3. **No lock** : free physical frames back to the buddy allocator.
pub fn vfree(ptr: *mut u8, token: &IrqDisabledToken) {
    if ptr.is_null() {
        return;
    }

    let addr = ptr as u64;
    if addr < VMALLOC_VIRT_START || addr >= VMALLOC_VIRT_END {
        return;
    }

    // Phase 1 — unmap and collect under VMALLOC lock.
    let (frames, range_start, range_end) = {
        let mut guard = VMALLOC.lock();
        let vm = &mut *guard;
        let start_page = ((addr - VMALLOC_VIRT_START) / 4096) as usize;

        unsafe {
            let node = vm.take_alloc_node(start_page);
            if node.is_null() {
                serial_println!("[vmalloc] vfree: no allocation record for 0x{:x}", addr);
                return;
            }

            let page_count = (*node).page_count;
            let virt_start = VMALLOC_VIRT_START + ((*node).start_page as u64 * 4096);
            let frames = (*node).frames.take().unwrap();

            for i in 0..page_count {
                let page_start = virt_start + (i as u64 * 4096);
                let page = Page::containing_address(VirtAddr::new(page_start));
                // unmap_page_kernel acquires/releases KERNEL_PT_LOCK internally.
                // Lock order: VMALLOC → KERNEL_PT_LOCK — consistent with vmalloc().
                let _ = unmap_page_kernel(page);
            }

            let range_start = VirtAddr::new(virt_start);
            let range_end = VirtAddr::new(virt_start + (page_count as u64 * 4096));

            vm.alloc_count = vm.alloc_count.saturating_sub(1);
            vm.allocated_pages = vm.allocated_pages.saturating_sub(page_count);
            vm.insert_free_node_merge(node);
            (frames, range_start, range_end)
        }
    }; // Phase 1 end — VMALLOC lock released here.

    // Phase 2 — TLB shootdown with no lock held.
    // All remote CPUs can freely enter vmalloc/vfree while processing the IPI.
    shootdown_range(range_start, range_end);

    // Phase 3 — return physical frames to the buddy allocator.
    for i in 0..frames.len {
        crate::memory::free_frame(token, frames.get(i));
    }
    frames.free_storage(token);
}

/// Dump all live large allocations with attribution to the serial console.
///
/// Output format (one line per allocation, sorted by `start_page`):
/// ```text
/// [vmalloc][live] seq=N pid=P tid=T silo=S size=B pages=N vaddr=0x...
/// ```
///
/// A `silo=0` entry means the allocation was made by kernel code with no
/// associated silo, or that the silo lookup failed (SILO_MANAGER contended).
///
/// This is the primary tool for leak investigation: run it periodically under
/// a long-lived workload, diff the outputs, and identify growing sequences.
pub fn dump_live_allocations() {
    const MAX_SNAPSHOT: usize = 256;
    let mut snapshot = [VmallocLiveAllocationSnapshot {
        seq: 0,
        task_id: 0,
        pid: 0,
        tid: 0,
        silo_id: 0,
        size: 0,
        pages: 0,
        vaddr: 0,
        backend: VmallocAllocBackend::KernelVirtual,
        caller_file: "",
        caller_line: 0,
        caller_column: 0,
    }; MAX_SNAPSHOT];
    let count = live_allocations_snapshot(&mut snapshot);
    if count == 0 {
        let guard = VMALLOC.lock();
        if !guard.initialized {
            serial_println!("[vmalloc][live] not initialized");
            return;
        }
    }

    let mut total_pages = 0usize;
    for entry in snapshot.iter().take(count) {
        serial_println!(
            "[vmalloc][live] seq={} backend={:?} task={} pid={} tid={} silo={} size={} pages={} vaddr=0x{:x} caller={}:{}:{}",
            entry.seq,
            entry.backend,
            entry.task_id,
            entry.pid,
            entry.tid,
            entry.silo_id,
            entry.size,
            entry.pages,
            entry.vaddr,
            entry.caller_file,
            entry.caller_line,
            entry.caller_column,
        );
        total_pages = total_pages.saturating_add(entry.pages);
    }

    let peak = VMALLOC_PEAK_PAGES.load(AtomicOrdering::Relaxed);
    let guard = VMALLOC.lock();
    let live_count = guard.alloc_count;
    let live_pages = guard.allocated_pages;
    serial_println!(
        "[vmalloc][live] total: {} allocs, {} pages ({} KiB), peak_pages={}",
        live_count,
        live_pages,
        live_pages.saturating_mul(4),
        peak,
    );
    if live_count > count {
        serial_println!(
            "[vmalloc][live] snapshot truncated: {} additional allocations not shown",
            live_count - count,
        );
    }
}

/// Copy live vmalloc allocations into `out`, in allocation-address order.
///
/// Returns the number of entries written. If `out` is too small, the snapshot is
/// truncated; callers can compare the returned length with allocator totals to
/// detect truncation.
pub fn live_allocations_snapshot(out: &mut [VmallocLiveAllocationSnapshot]) -> usize {
    let guard = VMALLOC.lock();
    let vm = &*guard;
    if !vm.initialized {
        return 0;
    }

    let mut count = 0usize;
    let mut cur = vm.alloc_head;
    while !cur.is_null() && count < out.len() {
        let node = unsafe { &*cur };
        out[count] = VmallocLiveAllocationSnapshot {
            seq: node.attr.alloc_seq,
            task_id: node.attr.task_id,
            pid: node.attr.pid,
            tid: node.attr.tid,
            silo_id: node.attr.silo_id,
            size: node.attr.size,
            pages: node.page_count,
            vaddr: VMALLOC_VIRT_START + (node.start_page as u64 * 4096),
            backend: VmallocAllocBackend::KernelVirtual,
            caller_file: node.attr.caller_file,
            caller_line: node.attr.caller_line,
            caller_column: node.attr.caller_column,
        };
        count += 1;
        cur = node.next;
    }
    count
}

/// Dump vmalloc diagnostics to the serial console.
pub fn dump_diagnostics() {
    let guard = VMALLOC.lock();
    let vm = &*guard;
    if !vm.initialized {
        serial_println!("[vmalloc][diag] not initialized");
        return;
    }

    let policy_rejects = VMALLOC_POLICY_REJECT_COUNT.load(AtomicOrdering::Relaxed);
    let peak_pages = VMALLOC_PEAK_PAGES.load(AtomicOrdering::Relaxed);
    let total_seq = VMALLOC_ALLOC_SEQ.load(AtomicOrdering::Relaxed);
    let (free_extents, largest_free, node_pool_free) = unsafe {
        (
            vm.free_extent_count(),
            vm.largest_free_extent_pages(),
            vm.node_pool_free_count(),
        )
    };
    serial_println!(
        "[vmalloc][diag] arena=0x{:x}..0x{:x} allocs={} alloc_pages={} free_pages={} \
         peak_pages={} total_seq={} fails={} policy_rejects={}",
        VMALLOC_VIRT_START,
        VMALLOC_VIRT_END,
        vm.alloc_count,
        vm.allocated_pages,
        (VMALLOC_PAGES - ARENA_START_PAGE).saturating_sub(vm.allocated_pages),
        peak_pages,
        total_seq,
        vm.fail_count,
        policy_rejects
    );
    serial_println!(
        "[vmalloc][diag] extents={} largest_free_pages={} metadata_pages={} node_pool_free={}",
        free_extents,
        largest_free,
        vm.metadata_pages,
        node_pool_free
    );
    if let Some(last) = vm.last_failure {
        serial_println!(
            "[vmalloc][diag] last_failure: size={} pages={} error={:?}",
            last.size,
            last.pages,
            last.error
        );
    }
    // Print live allocations when any are present — useful for routine health checks.
    if vm.alloc_count > 0 {
        drop(guard); // release VMALLOC before re-acquiring inside dump_live_allocations
        dump_live_allocations();
    }
}
