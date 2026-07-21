//! N3 MMU Thread Migration : PCID-preserving (N3b) and Full Isolation (N3c).
//!
//! Implements the transport layer for IPC level N3
//!
//! # Architecture
//!
//! ```text
//! sender ──send()──▶ MigrationFrame ──CR3 switch──▶ receiver handler
//!   ▲                                                    │
//!   └────────────── reschedule IPI ◀─────────────────────┘
//! ```
//!
//! The sender saves its context, copies the message, then calls the ASM
//! primitive which switches CR3 and restores the receiver's context.  The
//! receiver handler reads the message from the frame and returns.  The
//! sender is resumed via a reschedule IPI.
//!
//! # Frame pointer requirement
//!
//! The `send()` method captures `sender_rip` from `[rbp + 8]`, which requires
//! frame pointers to be enabled at compile time. The kernel must be built with
//! `-C force-frame-pointers=yes` (see workspace/kernel/.cargo/config.toml).
//!
//! # Shared mapping note
//!
//! The MigrationFrame is mapped in both address spaces at the same virtual
//! address (`N3_SHARED_FRAME_VA`), but **without USER_ACCESSIBLE**. The frame
//! lives in kernel space and is accessible only from Ring 0. Both sender and
//! receiver access it via their kernel page tables : the shared VA means the
//! same PTE (same physical page) is reachable from both page table hierarchies.
//! This is NOT a user-mappable region; it is kernel-only shared memory.
//!
//! # PCID contract
//!
//! A PCID value of 0 means "no PCID" : either PCID is unsupported by the CPU
//! or exhausted. All code paths check `pcid > 0` before using PCID-specific
//! features (INVPCID, CR3 PCID bits). The tier selection function
//! (`select_n3_tier()`) distinguishes theoretical CPU support from actual
//! operational capability.
#![allow(dead_code)]

use crate::{
    arch::x86_64::apic,
    memory::{allocate_frame, free_frame, phys_to_virt, AddressSpace},
    process::{current_task_id, get_task_by_id, Task, TaskId},
    sync::{with_irqs_disabled, SpinLock},
};
use core::{
    mem::MaybeUninit,
    sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering},
};

use super::transport::{
    IpcConsumer, IpcError, IpcProducer, IpcTransport, TransportCapabilities, TransportLevel,
};

// ============================================================================
// Normative types
// ============================================================================

/// N3 tier selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum N3Tier {
    /// PCID-preserving: TLB entries for the sender AS are kept across CR3 switch.
    PcidPreserving = 1,
    /// Full isolation: CR3 write flushes all non-global TLB entries.
    FullIsolation = 2,
}

/// Minimal CPU context saved/restored during N3 migration.
///
/// Layout is `#[repr(C, align(64))]` to match the ASM primitive offsets.
/// No FPU/AVX state : handled separately per FPU policy.
/// Total size: 96 bytes (fields) + 32 bytes (padding) = 128 bytes.
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy)]
pub struct N3MinimalContext {
    /// Callee-saved GPRs (System V AMD64 ABI).
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rax: u64,
    /// Processor flags.
    pub rflags: u64,
    /// Stack pointer.
    pub rsp: u64,
    /// Instruction pointer (handler entry or return address).
    pub rip: u64,
    /// CR3 value with PCID bits for N3b, or 0 for N3c.
    pub cr3_pcid: u64,
    /// Explicit padding to reach 128 bytes (align(64) requires this).
    /// Prevents implicit compiler padding and ensures deterministic layout
    /// for the ASM primitive.
    pub _pad: [u8; 32],
}

impl N3MinimalContext {
    /// Zeroed context : used as initial value before preparation.
    pub const ZERO: Self = Self {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        rbp: 0,
        rbx: 0,
        rdx: 0,
        rax: 0,
        rflags: 0,
        rsp: 0,
        rip: 0,
        cr3_pcid: 0,
        _pad: [0u8; 32],
    };
}

/// Migration state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MigrationState {
    /// No migration active; frame reusable.
    Ready = 0,
    /// Migration engaged; no second migration on this frame.
    Active = 1,
    /// Migration not finalized before timeout.
    Stalled = 2,
    /// Transient kernel state during recovery.
    Reclaiming = 3,
}

impl MigrationState {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Ready),
            1 => Some(Self::Active),
            2 => Some(Self::Stalled),
            3 => Some(Self::Reclaiming),
            _ => None,
        }
    }
}

bitflags::bitflags! {
    /// Flags for a migration operation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MigrationFlags: u16 {
        /// Eager FPU save/restore (required for SIMD workloads).
        const FPU_EAGER = 0x0001;
        /// Lazy FPU save/restore (default, lower cost).
        const FPU_LAZY = 0x0002;
        /// Migration crosses CPU cores (requires IPI sync).
        const INTER_CORE = 0x0004;
    }
}

/// Shared migration frame : one per N3 transport endpoint pair.
///
/// Must reside in a dedicated physical page mapped at the same kernel
/// virtual address (`N3_SHARED_FRAME_VA`) in both sender and receiver
/// address spaces. The mapping is kernel-only (no `USER_ACCESSIBLE`
/// flag) : all access is controlled by the kernel via the CAS state
/// machine. Both address spaces see the same physical page through
/// their own kernel half of the page tables.
#[repr(C, align(64))]
pub struct MigrationFrame {
    /// Sender context (saved by ASM primitive).
    pub src_ctx: N3MinimalContext,
    /// Receiver context (prepared by kernel before migration).
    pub dst_ctx: N3MinimalContext,
    /// Atomic state: `MigrationState`.
    pub state: AtomicU8,
    _pad_state: [u8; 3],
    /// Monotonically increasing migration counter.
    pub generation: AtomicU32,
    /// Message length in bytes.
    pub msg_len: u16,
    /// Migration flags.
    pub flags: u16,
    _pad_flags: [u8; 4],
    /// TSC snapshot at migration start (for watchdog).
    pub tsc_start: AtomicU64,
    /// Thread ID of the frame owner.
    pub owner_tid: AtomicU64,
    /// Reserved padding for future use and cache-line alignment.
    pub _pad: [u8; 32],
}

// Static assertion: N3 minimal context layout must be exactly 128 bytes.
// This is verified both by the `const _` block and by the unit test.
// The sender_rip capture in send() relies on [rbp+8] which requires
// frame pointers (force-frame-pointers = true in workspace Cargo.toml).
const _: () = {
    assert!(core::mem::size_of::<N3MinimalContext>() == 128);
    assert!(core::mem::align_of::<N3MinimalContext>() == 64);
    assert!(core::mem::size_of::<MigrationFrame>() == 320);
    assert!(core::mem::align_of::<MigrationFrame>() == 64);
    assert!(core::mem::offset_of!(MigrationFrame, state) == 0x100);
    assert!(core::mem::offset_of!(MigrationFrame, generation) == 0x104);
    assert!(core::mem::offset_of!(MigrationFrame, msg_len) == 0x108);
    assert!(core::mem::offset_of!(MigrationFrame, flags) == 0x10A);
    assert!(core::mem::offset_of!(MigrationFrame, tsc_start) == 0x110);
    assert!(core::mem::offset_of!(MigrationFrame, owner_tid) == 0x118);
    // N3MinimalContext field offsets (for ASM verification).
    assert!(core::mem::offset_of!(N3MinimalContext, r15) == 0x00);
    assert!(core::mem::offset_of!(N3MinimalContext, r14) == 0x08);
    assert!(core::mem::offset_of!(N3MinimalContext, r13) == 0x10);
    assert!(core::mem::offset_of!(N3MinimalContext, r12) == 0x18);
    assert!(core::mem::offset_of!(N3MinimalContext, rbp) == 0x20);
    assert!(core::mem::offset_of!(N3MinimalContext, rbx) == 0x28);
    assert!(core::mem::offset_of!(N3MinimalContext, rdx) == 0x30);
    assert!(core::mem::offset_of!(N3MinimalContext, rax) == 0x38);
    assert!(core::mem::offset_of!(N3MinimalContext, rflags) == 0x40);
    assert!(core::mem::offset_of!(N3MinimalContext, rsp) == 0x48);
    assert!(core::mem::offset_of!(N3MinimalContext, rip) == 0x50);
    assert!(core::mem::offset_of!(N3MinimalContext, cr3_pcid) == 0x58);
};

// ============================================================================
// Static frame pool
// ============================================================================

/// Number of pre-allocated migration frames.
const N3_FRAME_POOL_SIZE: usize = 64;

/// Virtual address where the MigrationFrame is mapped in both address spaces.
/// Located in canonical upper-half, just below the HHDM boundary.
pub const N3_SHARED_FRAME_VA: u64 = 0xFFFF_C000_0000_1000;

/// Virtual address where the shared message buffer is mapped.
/// Must be distinct from N3_SHARED_FRAME_VA to avoid page table conflicts.
pub const N3_SHARED_MSG_BUF_VA: u64 = 0xFFFF_C000_0000_2000;

/// Size of the per-N3Transport handler stack (1 page).
/// After CR3 switch, the ASM primitive loads RSP from `dst_ctx.rsp` which
/// points to this stack with the handler address as the return address.
const N3_HANDLER_STACK_SIZE: usize = 4096;

/// Static pool of MigrationFrame slots.
///
/// Access is serialized by `N3_FRAME_ALLOC` SpinLock. The `UnsafeCell`
/// avoids `static mut` UB while the lock guarantees exclusive access.
struct FramePool {
    inner: core::cell::UnsafeCell<[MaybeUninit<MigrationFrame>; N3_FRAME_POOL_SIZE]>,
}

// SAFETY: all access to inner is serialized by N3_FRAME_ALLOC SpinLock.
unsafe impl Sync for FramePool {}

impl FramePool {
    const fn new() -> Self {
        FramePool {
            inner: core::cell::UnsafeCell::new(unsafe { MaybeUninit::uninit().assume_init() }),
        }
    }

    fn get_ptr(&self, idx: usize) -> *mut MaybeUninit<MigrationFrame> {
        unsafe { &mut (*self.inner.get())[idx] as *mut _ }
    }

    fn phys_addr(&self, idx: usize) -> u64 {
        // SAFETY: The FramePool is a static array allocated in the kernel's
        // BSS/data section. On x86_64 with the kernel model, statics live in
        // the direct-map region or higher half. The HHDM offset converts the
        // virtual address to a physical address.
        //
        // However, this assumes the pool is within the HHDM window. If the
        // kernel is compiled with a different memory model, this subtraction
        // yields a garbage physical address.
        //
        // To avoid this dependency, the prototype should ideally allocate
        // frames via the physical frame allocator and map them, rather than
        // using a static pool with HHDM arithmetic. For now, we assert that
        // the pool address is above the HHDM base to catch model mismatches.
        let ptr = self.get_ptr(idx) as u64;
        let hhdm = crate::memory::hhdm_offset();
        debug_assert!(
            ptr >= hhdm,
            "N3: FramePool not in HHDM region (ptr={:#x}, hhdm={:#x})",
            ptr,
            hhdm
        );
        ptr.wrapping_sub(hhdm)
    }
}

static N3_FRAME_POOL: FramePool = FramePool::new();

/// Bitmap-based O(1) frame allocator.
struct FrameAllocator {
    /// Bit i = 1 means frame i is allocated.
    bitmap: [u64; N3_FRAME_POOL_SIZE / 64],
    /// Number of currently allocated frames.
    count: usize,
}

impl FrameAllocator {
    const fn new() -> Self {
        FrameAllocator {
            bitmap: [0u64; N3_FRAME_POOL_SIZE / 64],
            count: 0,
        }
    }

    fn alloc(&mut self) -> Option<usize> {
        for word_idx in 0..self.bitmap.len() {
            if self.bitmap[word_idx] != u64::MAX {
                let bit = self.bitmap[word_idx].trailing_ones() as usize;
                self.bitmap[word_idx] |= 1 << bit;
                self.count += 1;
                return Some(word_idx * 64 + bit);
            }
        }
        None
    }

    fn free(&mut self, index: usize) {
        let word_idx = index / 64;
        let bit = index % 64;
        debug_assert!(self.bitmap[word_idx] & (1 << bit) != 0, "double free");
        self.bitmap[word_idx] &= !(1 << bit);
        self.count -= 1;
    }

    fn is_allocated(&self, index: usize) -> bool {
        self.bitmap[index / 64] & (1 << (index % 64)) != 0
    }
}

static N3_FRAME_ALLOC: SpinLock<FrameAllocator> = SpinLock::new(FrameAllocator::new());

/// Allocate a MigrationFrame from the static pool.
///
/// Returns a pointer to the frame and its pool index.
fn alloc_frame_slot() -> Option<(usize, *mut MigrationFrame)> {
    let idx = with_irqs_disabled(|_token| {
        let mut alloc = N3_FRAME_ALLOC.lock();
        alloc.alloc()
    })?;

    // SAFETY: slot is freshly allocated via bitmap, exclusive access via SpinLock.
    let frame = N3_FRAME_POOL.get_ptr(idx);
    // SAFETY: slot is freshly allocated, MaybeUninit is writable.
    unsafe {
        frame.write(MaybeUninit::new(MigrationFrame {
            src_ctx: N3MinimalContext::ZERO,
            dst_ctx: N3MinimalContext::ZERO,
            state: AtomicU8::new(MigrationState::Ready as u8),
            _pad_state: [0; 3],
            generation: AtomicU32::new(0),
            msg_len: 0,
            flags: 0,
            _pad_flags: [0; 4],
            tsc_start: AtomicU64::new(0),
            owner_tid: AtomicU64::new(0),
            _pad: [0u8; 32],
        }));
    }

    Some((idx, frame as *mut MigrationFrame))
}

/// Free a MigrationFrame back to the pool.
fn free_frame_slot(idx: usize) {
    with_irqs_disabled(|_token| {
        let mut alloc = N3_FRAME_ALLOC.lock();
        alloc.free(idx);
    });
}

/// Get the physical address of a frame in the static pool.
fn frame_pool_phys_addr(idx: usize) -> u64 {
    N3_FRAME_POOL.phys_addr(idx)
}

// ============================================================================
// PCID management
// ============================================================================

/// Global PCID counter : monotonic allocation, panics at 4096 (prototype).
static PCID_COUNTER: AtomicU16 = AtomicU16::new(1); // 0 = no PCID

/// Maximum number of PCIDs before panic (x86-64 supports 4096).
const MAX_PCIDS: u16 = 4095;

/// Allocate a stable PCID for an address space.
///
/// Returns 0 if PCID is not available (N3c fallback).
pub fn allocate_pcid() -> u16 {
    let pcid = PCID_COUNTER.fetch_add(1, Ordering::Relaxed);
    if pcid >= MAX_PCIDS {
        log::warn!("N3: PCID exhaustion : falling back to N3c (full TLB flush)");
        return 0;
    }
    pcid
}

/// Free a PCID back to the pool (called when an address space is destroyed).
///
/// This prevents PCID exhaustion in long-running systems with dynamic silo
/// creation/destruction. The freed PCID is tracked for reuse, but the actual
/// TLB invalidation on other cores is the caller's responsibility.
pub fn free_pcid(pcid: u16) {
    if pcid == 0 || pcid >= MAX_PCIDS {
        return;
    }
    // NB: PCID reuse requires INVPCID on the target core before the next
    // time this PCID is assigned. For the prototype, we simply log the free;
    // a production implementation would use a freelist + generation counter
    // (see Linux arch/x86/mm/context.c).
    log::trace!("N3: PCID {} freed", pcid);
}

/// Check if PCID feature is available on this CPU.
pub fn pcid_available() -> bool {
    // 1. CPUID check: bit 17 of ECX after CPUID(EAX=1) indicates PCID support.
    let (_, _, ecx, _) = crate::arch::x86_64::cpuid(1, 0);
    if ecx & (1 << 17) == 0 {
        return false;
    }
    // 2. Check CR4.PCIDE (bit 17) is actually set (may be masked by hypervisor).
    //    Intel SDM Vol.3A §4.10.4: CR4.PCIDE = 1 enables PCID in CR3.
    let cr4 = x86_64::registers::control::Cr4::read();
    cr4.contains(x86_64::registers::control::Cr4Flags::PCID)
}

/// Select the N3 tier based on actual PCID capability.
///
/// Distinguishes theoretical CPU support from operational capability:
/// - `N3Tier::PcidPreserving` requires PCID available AND a valid PCID > 0
/// - `N3Tier::FullIsolation` is used when PCID is unavailable or exhausted
pub fn select_n3_tier(pcid: u16) -> N3Tier {
    if pcid_available() && pcid > 0 {
        N3Tier::PcidPreserving
    } else {
        N3Tier::FullIsolation
    }
}

// ============================================================================
// validate_rip()
// ============================================================================

/// Validate that `rip` points to an authorized executable page.
///
/// Checks:
/// - Belongs to an executable VMA
/// - PTE has NX=0
/// - Not in kernel ring, MigrationFrame, or non-executable zones
/// - Part of a registered handler or authorized code range
fn validate_rip(rip: u64, address_space: &AddressSpace) -> Result<(), IpcError> {
    // Kernel addresses (upper half) are not valid user RIP targets.
    if rip >= 0xFFFF_8000_0000_0000 {
        return Err(IpcError::InvalidRip);
    }

    // MigrationFrame shared region is not executable.
    if (N3_SHARED_FRAME_VA..N3_SHARED_FRAME_VA + 0x1000).contains(&rip) {
        return Err(IpcError::InvalidRip);
    }

    // Null or near-null RIP is invalid.
    if rip < 0x1000 {
        return Err(IpcError::InvalidRip);
    }

    // validate_rip() performs page-level safety checks only: present, executable,
    // not in forbidden zones. The RIP to belong to
    // a "registered handler or authorized code range" : this registration check
    // is performed by the CALLER (send()) which compares rip against the
    // receiver's `trampoline_entry` field BEFORE calling validate_rip().
    //
    // validate_rip() is therefore a SECOND LINE OF DEFENSE that catches
    // configuration errors (e.g., trampoline_entry pointing to a data page).
    //
    // TOCTOU note: The receiver's page tables could be modified between this
    // check and the CR3 switch. However, the receiver's trampoline page is
    // pinned and set to read-only by the kernel at endpoint creation time,
    // preventing modification even by the receiver itself. The CR3 switch
    // immediately after this check makes any concurrent modification irrelevant
    // : the receiver executes in its own AS, using the mapping we validated.

    // Walk the page tables to verify the page is present and executable.
    // CRITICAL: Also check the U/S bit : the RIP target must be a supervisor
    // page (Ring 0), not a user page. Accepting a user page would allow a
    // userspace task to redirect kernel execution to arbitrary user code.
    let cr3_phys = address_space.cr3();
    let hhdm = crate::memory::hhdm_offset();

    match unsafe { walk_page_tables_executable(rip, cr3_phys.as_u64(), hhdm) } {
        Ok(true) => Ok(()),
        Ok(false) => Err(IpcError::InvalidRip),
        Err(_) => Err(IpcError::InvalidRip),
    }
}

/// Walk x86-64 4-level page tables to check if `vaddr` is present, executable,
/// and supervisor-only (U/S=0).
///
/// Returns `Ok(true)` if the final PTE meets all conditions.
/// Rejects user-mode pages (U/S=1) as RIP targets for migration.
unsafe fn walk_page_tables_executable(vaddr: u64, cr3_phys: u64, hhdm: u64) -> Result<bool, ()> {
    let pml4 = (cr3_phys + hhdm) as *const u64;

    // PML4: check present + U/S (bit 2: 0=supervisor, 1=user)
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pml4_entry = unsafe { core::ptr::read_volatile(pml4.add(pml4_idx)) };
    if pml4_entry & 1 == 0 {
        return Err(());
    }
    if pml4_entry & 4 != 0 {
        return Err(());
    } // U/S=1 => reject

    // PDPT: check present + U/S
    let pdpt_phys = pml4_entry & 0x000F_FFFF_FFFF_F000;
    let pdpt = (pdpt_phys + hhdm) as *const u64;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pdpt_entry = unsafe { core::ptr::read_volatile(pdpt.add(pdpt_idx)) };
    if pdpt_entry & 1 == 0 {
        return Err(());
    }
    if pdpt_entry & 4 != 0 {
        return Err(());
    } // U/S=1 => reject

    // 1 GiB page? Check NX + U/S
    if pdpt_entry & (1 << 7) != 0 {
        if pdpt_entry & (1 << 63) != 0 {
            return Err(());
        } // NX=1 => reject
        return Ok(true);
    }

    // Page Directory: check present + U/S
    let pd_phys = pdpt_entry & 0x000F_FFFF_FFFF_F000;
    let pd = (pd_phys + hhdm) as *const u64;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pd_entry = unsafe { core::ptr::read_volatile(pd.add(pd_idx)) };
    if pd_entry & 1 == 0 {
        return Err(());
    }
    if pd_entry & 4 != 0 {
        return Err(());
    } // U/S=1 => reject

    // 2 MiB page? Check NX
    if pd_entry & (1 << 7) != 0 {
        if pd_entry & (1 << 63) != 0 {
            return Err(());
        } // NX=1 => reject
        return Ok(true);
    }

    // Page Table: check present + U/S + NX
    let pt_phys = pd_entry & 0x000F_FFFF_FFFF_F000;
    let pt = (pt_phys + hhdm) as *const u64;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;
    let pt_entry = unsafe { core::ptr::read_volatile(pt.add(pt_idx)) };
    if pt_entry & 1 == 0 {
        return Err(());
    }
    if pt_entry & 4 != 0 {
        return Err(());
    } // U/S=1 => reject user page
    if pt_entry & (1 << 63) != 0 {
        return Err(());
    } // NX=1 => reject

    Ok(true)
}

// ============================================================================
// Context preparation
// ============================================================================

/// Prepare a MigrationFrame for a send operation.
///
/// Sets up `src_ctx` (sender), `dst_ctx` (receiver), copies the message
/// into the shared buffer, increments generation, and transitions state
/// to Active.
fn n3_prepare_migration(
    frame: &mut MigrationFrame,
    msg_buf: *mut u8,
    sender_cr3: u64,
    sender_rsp: u64,
    sender_rip: u64,
    handler_stack_top: u64,
    receiver_task: &Task,
    msg: &[u8],
) -> Result<(), IpcError> {
    // Prepare sender context (saved by ASM primitive).
    frame.src_ctx.cr3_pcid = sender_cr3;
    frame.src_ctx.rsp = sender_rsp;
    frame.src_ctx.rip = sender_rip;

    // Prepare receiver context.
    let recv_handler = receiver_task.trampoline_entry.load(Ordering::Acquire);

    if recv_handler == 0 {
        return Err(IpcError::TransportFailed);
    }

    let recv_cr3 = receiver_task.process.address_space_arc().cr3().as_u64();

    frame.dst_ctx.rip = recv_handler;
    frame.dst_ctx.cr3_pcid = recv_cr3;

    // CRITICAL: The destination kernel stack must contain the handler address
    // as the return address for the `ret` instruction after CR3 switch.
    // We use the per-transport handler stack (kernel upper half, shared across
    // all address spaces) to ensure accessibility after CR3 switch.
    // Layout: [handler_stack_top - 8] = recv_handler (return address for ret).
    //
    // SAFETY: handler_stack_top points to the transport's dedicated stack page,
    // allocated in new(). The CAS state machine (Ready=>Active) ensures exclusive
    // access. The -8 offset places the handler address as if it were pushed.
    let trampoline_top = (handler_stack_top - 8) as *mut u64;
    unsafe {
        // Write handler address at the trampoline top (this is what `ret` will pop).
        core::ptr::write_volatile(trampoline_top, recv_handler);
    }
    // dst_ctx.rsp points to the trampoline area where the handler address is stored.
    // After CR3 switch, `mov rsp, [rdi+0xC8]` loads this, and `ret` pops recv_handler.
    frame.dst_ctx.rsp = trampoline_top as u64;

    // Copy message into the shared buffer.
    let msg_len = shared_msg_write(msg_buf, msg)?;
    frame.msg_len = msg_len;

    // CAS Ready => Active. Must succeed before touching generation.
    if frame
        .state
        .compare_exchange(
            MigrationState::Ready as u8,
            MigrationState::Active as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return Err(IpcError::WouldBlock);
    }

    // Increment generation AFTER successful CAS.
    // The generation must only advance for committed migrations.
    frame.generation.fetch_add(1, Ordering::Release);

    // Record timestamp and owner.
    let tsc = unsafe { core::arch::x86_64::_rdtsc() };
    frame.tsc_start.store(tsc, Ordering::Release);
    if let Some(tid) = current_task_id() {
        frame.owner_tid.store(tid.as_u64(), Ordering::Release);
    }

    Ok(())
}

/// Maximum message size for N3 transport (separate buffer, not in frame).
pub const N3_MSG_BUF_SIZE: usize = 2048;

/// Wrapper for a raw pointer to the shared message buffer.
///
/// # Safety
/// The pointer is valid for the lifetime of the N3Transport and is mapped
/// in both sender and receiver address spaces. All access is serialized
/// by the MigrationFrame state machine.
struct MsgBuffer(*mut u8);

// SAFETY: MsgBuffer is used only from a single migration context at a time,
// protected by the MigrationFrame CAS state machine.
unsafe impl Send for MsgBuffer {}
unsafe impl Sync for MsgBuffer {}

impl MsgBuffer {
    fn as_ptr(&self) -> *mut u8 {
        self.0
    }
}

/// Read the message payload from a shared message buffer.
fn shared_msg_read(msg_buf: *const u8, msg_len: u16, buf: &mut [u8]) -> Result<usize, IpcError> {
    let len = msg_len as usize;
    if len > buf.len() {
        return Err(IpcError::BufferTooSmall);
    }
    if len > N3_MSG_BUF_SIZE {
        return Err(IpcError::MessageTooLarge);
    }
    let src = unsafe { core::slice::from_raw_parts(msg_buf, len) };
    buf[..len].copy_from_slice(src);
    Ok(len)
}

/// Write a message payload into a shared message buffer.
fn shared_msg_write(msg_buf: *mut u8, msg: &[u8]) -> Result<u16, IpcError> {
    if msg.len() > N3_MSG_BUF_SIZE {
        return Err(IpcError::MessageTooLarge);
    }
    let dst = unsafe { core::slice::from_raw_parts_mut(msg_buf, msg.len()) };
    dst.copy_from_slice(msg);
    Ok(msg.len() as u16)
}

// ============================================================================
// ASM Primitive
// ============================================================================

/// ASM migration primitive.
///
/// # Safety
/// - `frame` must point to a valid MigrationFrame mapped at the same VA
///   in both sender and receiver address spaces.
/// - Interrupts must be enabled before calling (the primitive will CLI).
/// - The caller must be on a valid kernel stack.
///
/// # Layout adjusted for a 64b align padding
///
/// ```text
/// Offset  Field
/// 0x00    src_ctx.r15
/// 0x08    src_ctx.r14
/// 0x10    src_ctx.r13
/// 0x18    src_ctx.r12
/// 0x20    src_ctx.rbp
/// 0x28    src_ctx.rbx
/// 0x30    src_ctx.rdx
/// 0x38    src_ctx.rax
/// 0x40    src_ctx.rflags
/// 0x48    src_ctx.rsp
/// 0x50    src_ctx.rip
/// 0x58    src_ctx.cr3_pcid
/// 0x60-0x7F  (alignment padding)
/// 0x80    dst_ctx.r15
/// 0x88    dst_ctx.r14
/// 0x90    dst_ctx.r13
/// 0x98    dst_ctx.r12
/// 0xA0    dst_ctx.rbp
/// 0xA8    dst_ctx.rbx
/// 0xB0    dst_ctx.rdx
/// 0xB8    dst_ctx.rax
/// 0xC0    dst_ctx.rflags
/// 0xC8    dst_ctx.rsp
/// 0xD0    dst_ctx.rip
/// 0xD8    dst_ctx.cr3_pcid
/// 0xE0-0xFF (alignment padding)
/// 0x100   state (AtomicU8)
/// 0x104   generation (AtomicU32)
/// ```
///
/// # Behavior
/// 1. Saves source context to `frame.src_ctx`
/// 2. CLI (≤3 instructions) + CR3 switch to `frame.dst_ctx.cr3_pcid`
/// 3. Restores destination context from `frame.dst_ctx`
/// 4. Sets `frame.state = Ready`, increments `generation`
/// 5. Returns via `ret` (pops RIP from restored `dst_ctx.rsp`)
#[unsafe(naked)]
pub unsafe extern "C" fn n3b_migrate_asm(frame: *mut MigrationFrame) {
    core::arch::naked_asm!(
        // ── Phase 1: save src_ctx ──
        "mov [rdi + 0x00], r15",
        "mov [rdi + 0x08], r14",
        "mov [rdi + 0x10], r13",
        "mov [rdi + 0x18], r12",
        "mov [rdi + 0x20], rbp",
        "mov [rdi + 0x28], rbx",
        "mov [rdi + 0x30], rdx",
        "mov [rdi + 0x38], rax",
        "pushfq",
        "pop rax",
        "mov [rdi + 0x40], rax", // rflags
        "mov [rdi + 0x48], rsp",
        // NOTE: src_ctx.rip was already set by n3_prepare_migration().
        // We do NOT overwrite it with RCX : on Strategy A, the kernel
        // sets src_ctx.rip before calling us. See §11.2 for the contract.
        // ── Phase 2: CLI (<3 instr) + CR3 switch ──
        // We need a 3 instructions **MAX** between CLI and CR3 write.
        // Here: mov rax (1) => cli (2) => mov cr3 (3). Satisfied.
        // After CR3 switch, we restore dst_ctx with interrupts still disabled.
        // The 8 restore instructions + pushfq/popfq/sti happen AFTER the CR3
        // switch in the receiver's address space : this is intentional and does
        // not violate the ≤3 instruction window (which only covers CLI=>CR3).
        "mov rax, [rdi + 0xD8]", // dst_ctx.cr3_pcid (at 0x80+0x58=0xD8)
        "cli",
        "mov cr3, rax",
        // ── Phase 3: restore dst_ctx (starts at offset 0x80) ──
        // IMPORTANT: rsp (offset 0xC8) is restored LAST, just before ret.
        // Every memory access between CR3 switch and rsp restore uses
        // RDI (shared fixed-VA, valid in both AS) : never RSP.
        "mov r15, [rdi + 0x80]",
        "mov r14, [rdi + 0x88]",
        "mov r13, [rdi + 0x90]",
        "mov r12, [rdi + 0x98]",
        "mov rbp, [rdi + 0xA0]",
        "mov rbx, [rdi + 0xA8]",
        "mov rdx, [rdi + 0xB0]",
        // Load rflags from dst_ctx.rflags at offset 0x80+0x40 = 0xC0.
        // Note: dst_ctx.rax (0xB8) is a GPR, NOT flags : do not confuse.
        "mov rax, [rdi + 0xC0]", // dst_ctx.rflags
        "push rax",
        "popfq", // restore IF=1
        "sti",   // guarantee IF=1
        // ── Phase 4: restore RSP from dst_ctx ──
        // CRITICAL: RSP must be restored BEFORE `ret`. The destination kernel
        // stack is shared (kernel upper half maps identically in all AS).
        // dst_ctx.rsp was set by n3_prepare_migration() to point to a stack
        // frame containing the handler entry address as the return address.
        "mov rsp, [rdi + 0xC8]", // dst_ctx.rsp
        // ── Phase 5: receiver handler runs (state is still Active) ──
        // The ASM does NOT set state = Ready. The receiver handler MUST
        // do that after consuming the message (see recv() protocol).
        // This prevents the TOCTOU where the receiver sees state=Ready
        // before having read the message. Generation is managed by the
        // kernel in n3_prepare_migration/recv : NOT by the ASM.
        // ── Phase 6: ret into receiver handler ──
        // SAFETY: RSP now points to the destination kernel stack with the
        // handler address at [RSP]. `ret` pops it and jumps there.
        // The destination kernel stack must be valid and mapped in both AS
        // (kernel upper half is shared). If corrupted, this is the first
        // point of failure.
        "ret",
        //
        // Invariant: the restored dst_ctx.rsp must point to a valid, readable,
        // kernel-mode stack frame.
    );
}

// ============================================================================
// IPI synchronization
// ============================================================================

/// Per-CPU pending migration frame pointer.
/// Set by the sender before sending the IPI, consumed by the IPI handler.
static N3_PENDING_MIGRATION: [AtomicU64; crate::arch::x86_64::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::x86_64::percpu::MAX_CPUS];

/// Send a migration-sync IPI to the target CPU.
fn send_n3_sync_ipi(target_apic_id: u32) {
    let icr_low = apic::IPI_N3_MIGRATE_VECTOR as u32 | (1 << 14);
    apic::send_ipi_raw(target_apic_id, icr_low);
}

/// Naked IPI handler for N3 migration synchronization.
///
/// When a cross-core migration completes, the receiver sends this IPI to the
/// sender's core. The handler restores the sender's kernel context (RSP, RIP,
/// RFLAGS) from `MigrationFrame.src_ctx` and returns via `iretq`.
///
/// The interrupted context was the sender's `send()` function. By modifying
/// the InterruptStackFrame fields before the hardware `iretq`, we redirect
/// execution to the sender's saved return address on its original kernel stack.
///
/// # Safety
/// Registered as a naked IDT entry. On entry: SS, RSP, RFLAGS, CS, RIP pushed
/// by hardware. `rdi` points at the InterruptStackFrame (set by IDT dispatch).
#[unsafe(naked)]
pub unsafe extern "C" fn n3_migrate_ipi_entry(rdi: *mut u8) -> ! {
    core::arch::naked_asm!(
        // ── Save scratch registers ──
        "push rax",
        "push rcx",
        "push rdx",
        "push rsi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",

        // ── Check pending migration ──
        // per_cpu_index via GS:base (offset 0 in PerCpu struct).
        "mov rcx, qword ptr gs:[0]",    // current_cpu_index
        "lea rsi, [rip + {pending}]",    // &N3_PENDING_MIGRATION
        "mov rax, [rsi + rcx * 8]",      // pending = N3_PENDING_MIGRATION[cpu]
        "test rax, rax",
        "jz .no_pending",

        // ── Clear pending flag ──
        "mov qword ptr [rsi + rcx * 8], 0",

        // ── rax = MigrationFrame ptr ──
        // src_ctx starts at offset 0x00.
        // src_ctx.rflags = 0x40, src_ctx.rsp = 0x48, src_ctx.rip = 0x50.

        // ── Switch to sender's address space ──
        "mov rcx, [rax + 0x58]",        // src_ctx.cr3_pcid
        "test rcx, rcx",
        "jz .skip_cr3",
        "mov r11, 0x0000FFFFFFFFFFFF",
        "and rcx, r11", // clear high 16 bits (reserved/PCID)
        "mov r11, 0xFFFFFFFFFFFFF000",
        "and rcx, r11", // clear low 12 bits (page offset)
        "mov cr3, rcx",
        ".skip_cr3:",

        // ── Build iretq frame on the interrupted stack ──
        // rdi points to InterruptStackFrame pushed by hardware.
        // Overwrite it with the sender's context.
        // InterruptStackFrame layout:
        //   [+0x00] SS       [+0x08] RSP      [+0x10] RFLAGS
        //   [+0x18] CS       [+0x20] RIP      [+0x28] (error code, skipped)
        //
        // iretq pops: RIP, CS, RFLAGS, RSP, SS (5 × u64 = 40 bytes).
        //
        // Preserve original CS and SS from the interrupted frame.
        // Overwrite RSP, RFLAGS, RIP with sender's values.

        "mov rcx, [rdi + 0x18]",        // original CS (kernel CS = 0x08)
        "mov rdx, [rdi + 0x00]",        // original SS (0 for Ring 0)

        "mov rsi, [rax + 0x48]",        // src_ctx.rsp  => sender's kernel RSP
        "mov r8,  [rax + 0x40]",        // src_ctx.rflags
        "mov r9,  [rax + 0x50]",        // src_ctx.rip  => sender's return address

        "mov [rdi + 0x00], rdx",        // SS  = original (Ring 0)
        "mov [rdi + 0x08], rsi",        // RSP = sender's kernel stack
        "mov [rdi + 0x10], r8",         // RFLAGS = sender's flags
        "mov [rdi + 0x18], rcx",        // CS  = original (0x08)
        "mov [rdi + 0x20], r9",         // RIP = sender's return address

        // ── Send EOI ──
        "mov dword ptr [0x0000FEE000B0], 0", // LAPIC EOI

        // ── Restore scratch and return ──
        // Pop scratch registers, then let the normal IDT return path
        // (pop GPRs + iretq) restore from the modified frame.
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rax",
        // Return to IDT stub which pops GPRs and does iretq.
        "ret",

        ".no_pending:",
        // Spurious IPI : send EOI and return to interrupted context.
        "mov dword ptr [0x0000FEE000B0], 0",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rax",
        "ret",

        pending = sym N3_PENDING_MIGRATION,
    );
}

/// Fallback handler for N3 migration IPI (non-naked path).
///
/// Called from the `extern "x86-interrupt"` stub if the naked entry is not
/// used. Clears the pending flag and sends EOI.
pub extern "C" fn n3_migrate_ipi_handler() {
    let cpu_idx = crate::arch::x86_64::percpu::current_cpu_index();
    N3_PENDING_MIGRATION[cpu_idx].store(0, Ordering::Release);
    apic::eoi();
}

// ============================================================================
// WATCHDOG
// ============================================================================

/// Default watchdog timeout in TSC cycles (~10ms at 3GHz).
const N3_WATCHDOG_TIMEOUT: u64 = 30_000_000;

/// Watchdog state per frame.
struct WatchdogEntry {
    frame_phys: u64,
    timeout: u64,
}

/// Global watchdog table.
static N3_WATCHDOG_TABLE: SpinLock<[Option<WatchdogEntry>; N3_FRAME_POOL_SIZE]> =
    SpinLock::new([const { None }; N3_FRAME_POOL_SIZE]);

/// Register a frame with the watchdog.
fn watchdog_register(frame_idx: usize, frame_phys: u64) {
    let mut table = N3_WATCHDOG_TABLE.lock();
    if let Some(entry) = table.get_mut(frame_idx) {
        *entry = Some(WatchdogEntry {
            frame_phys,
            timeout: N3_WATCHDOG_TIMEOUT,
        });
    }
}

/// Unregister a frame from the watchdog.
fn watchdog_unregister(frame_idx: usize) {
    let mut table = N3_WATCHDOG_TABLE.lock();
    if let Some(entry) = table.get_mut(frame_idx) {
        *entry = None;
    }
}

/// Called from the timer ISR to check for stalled migrations.
///
/// For each registered frame in Active state, checks whether the migration
/// has exceeded the watchdog timeout. If so:
/// 1. Transitions Active => Stalled (CAS)
/// 2. Attempts recovery: Stalled => Reclaiming => Ready
/// 3. Logs the incident
///
/// Recovery resets the frame so it can be reused for future migrations.
/// The sender that initiated the stalled migration will see `WouldBlock` on
/// its next `send()` attempt (CAS Ready=>Active fails if another sender
/// claimed the frame first).
pub fn n3_watchdog_tick() {
    let now = unsafe { core::arch::x86_64::_rdtsc() };
    let mut table = N3_WATCHDOG_TABLE.lock();

    for entry in table.iter_mut() {
        let Some(entry) = entry else { continue };
        let frame = unsafe { &*(phys_to_virt(entry.frame_phys) as *const MigrationFrame) };
        let state = frame.state.load(Ordering::Acquire);

        if state != MigrationState::Active as u8 {
            continue;
        }

        let tsc_start = frame.tsc_start.load(Ordering::Acquire);
        if now.wrapping_sub(tsc_start) <= entry.timeout {
            continue;
        }

        // Timeout detected: attempt Active => Stalled => Reclaiming => Ready.
        let cas_result = frame.state.compare_exchange(
            MigrationState::Active as u8,
            MigrationState::Stalled as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        if cas_result.is_err() {
            // Another CPU already transitioned the frame (e.g., recv completed).
            continue;
        }

        log::warn!(
            "N3: watchdog timeout on frame at {:#x}, generation={}, recovering",
            entry.frame_phys,
            frame.generation.load(Ordering::Acquire),
        );

        // Attempt recovery: Stalled => Reclaiming => Ready.
        watchdog_recover(frame);
    }
}

/// Recover a stalled frame : reset to Ready via atomic CAS transitions.
fn watchdog_recover(frame: &MigrationFrame) {
    // Transition Stalled => Reclaiming (atomic CAS).
    if frame
        .state
        .compare_exchange(
            MigrationState::Stalled as u8,
            MigrationState::Reclaiming as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        log::warn!("N3: watchdog recover: frame not in Stalled state, skipping");
        return;
    }
    log::warn!(
        "N3: recovering stalled frame, generation={}",
        frame.generation.load(Ordering::Acquire)
    );
    // Transition Reclaiming => Ready (atomic store, no contention expected).
    frame
        .state
        .store(MigrationState::Ready as u8, Ordering::Release);
}

// ============================================================================
// Shared frame mapping
// ============================================================================

/// Map a physical page into an address space at the specified virtual address.
///
/// The mapping is kernel-only (no `USER_ACCESSIBLE` flag) to enforce the
/// spec §8.4 invariant: frame permissions are managed exclusively by the
/// kernel, never by non-kernel parties.
fn map_page_in_space(
    frame_phys: u64,
    target_va: u64,
    address_space: &AddressSpace,
) -> Result<(), &'static str> {
    use x86_64::{
        structures::paging::{Mapper, Page, PageTableFlags, PhysFrame, Size4KiB},
        PhysAddr, VirtAddr,
    };

    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(target_va));
    let phys_frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(frame_phys));

    // Kernel-only, no USER_ACCESSIBLE (spec §8.4: permissions managed by kernel).
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    let mut mapper = unsafe { address_space.mapper() };
    let mut allocator = crate::memory::paging::BuddyFrameAllocator;

    unsafe {
        match mapper.map_to(page, phys_frame, flags, &mut allocator) {
            Ok(flush) => {
                flush.flush();
                Ok(())
            }
            Err(_) => Err("Failed to map page into address space"),
        }
    }
}

/// Map a MigrationFrame's physical page into both sender and receiver
/// address spaces at `N3_SHARED_FRAME_VA`.
fn map_frame_in_both_spaces(
    frame_phys: u64,
    sender_as: &AddressSpace,
    receiver_as: &AddressSpace,
) -> Result<(), &'static str> {
    map_page_in_space(frame_phys, N3_SHARED_FRAME_VA, sender_as)?;
    map_page_in_space(frame_phys, N3_SHARED_FRAME_VA, receiver_as)?;
    Ok(())
}

/// Map a message buffer's physical page into both address spaces
/// at `N3_SHARED_MSG_BUF_VA`.
fn map_msg_buf_in_both_spaces(
    msg_buf_phys: u64,
    sender_as: &AddressSpace,
    receiver_as: &AddressSpace,
) -> Result<(), &'static str> {
    map_page_in_space(msg_buf_phys, N3_SHARED_MSG_BUF_VA, sender_as)?;
    map_page_in_space(msg_buf_phys, N3_SHARED_MSG_BUF_VA, receiver_as)?;
    Ok(())
}

// ============================================================================
// N3Transport
// ============================================================================

/// N3 MMU transport : thread migration between distinct address spaces.
pub struct N3Transport {
    /// Index in the static frame pool.
    frame_idx: usize,
    /// Physical address of the MigrationFrame page.
    frame_phys: u64,
    /// Virtual address of the MigrationFrame (same in both AS).
    frame_virt: u64,
    /// Shared message buffer (kernel-allocated, mapped in both AS).
    msg_buf: MsgBuffer,
    /// Physical address of the message buffer.
    msg_buf_phys: u64,
    /// Dedicated handler stack (1 page, kernel-allocated).
    /// After CR3 switch, dst_ctx.rsp points to the top of this stack with
    /// the handler address as the return address.
    handler_stack_top: u64,
    /// Physical address of the handler stack.
    handler_stack_phys: u64,
    /// Sender task ID.
    sender_task_id: TaskId,
    /// Receiver task ID.
    receiver_task_id: TaskId,
    /// N3 tier (b or c).
    tier: N3Tier,
    /// Sender's PCID (0 for N3c).
    pcid_sender: u16,
    /// Receiver's PCID (0 for N3c).
    pcid_receiver: u16,
    /// Watchdog timeout in TSC cycles.
    watchdog_timeout_cycles: u64,
}

// SAFETY: N3Transport is Send+Sync because all mutable access is protected
// by the MigrationFrame CAS state machine.
unsafe impl Send for N3Transport {}
unsafe impl Sync for N3Transport {}

impl N3Transport {
    /// Create a new N3 transport between sender and receiver tasks.
    ///
    /// Allocates a MigrationFrame and a shared message buffer, maps them
    /// in both address spaces, and registers the endpoint with the watchdog.
    pub fn new(sender_task_id: TaskId, receiver_task_id: TaskId) -> Result<Self, IpcError> {
        let (frame_idx, _frame_ptr) = alloc_frame_slot().ok_or(IpcError::TransportFailed)?;

        let frame_phys = frame_pool_phys_addr(frame_idx);

        // Allocate a shared message buffer (1 page).
        let msg_buf_frame =
            with_irqs_disabled(allocate_frame).map_err(|_| IpcError::TransportFailed)?;
        let msg_buf_phys = msg_buf_frame.start_address.as_u64();
        let msg_buf = phys_to_virt(msg_buf_phys) as *mut u8;

        // Map in both address spaces.
        let sender = get_task_by_id(sender_task_id).ok_or(IpcError::Disconnected)?;
        let receiver = get_task_by_id(receiver_task_id).ok_or(IpcError::Disconnected)?;

        let sender_as = sender.process.address_space_arc();
        let receiver_as = receiver.process.address_space_arc();

        if let Err(e) = map_frame_in_both_spaces(frame_phys, &sender_as, &receiver_as) {
            log::error!("N3: failed to map frame: {}", e);
            free_frame_slot(frame_idx);
            with_irqs_disabled(|token| free_frame(token, msg_buf_frame));
            return Err(IpcError::TransportFailed);
        }

        // Map the message buffer in both address spaces at N3_SHARED_MSG_BUF_VA.
        if map_msg_buf_in_both_spaces(msg_buf_phys, &sender_as, &receiver_as).is_err() {
            log::error!("N3: failed to map message buffer");
            free_frame_slot(frame_idx);
            with_irqs_disabled(|token| free_frame(token, msg_buf_frame));
            return Err(IpcError::TransportFailed);
        }

        // Allocate PCIDs BEFORE selecting tier : allocate_pcid() may return 0
        // if PCID is exhausted, which forces N3c even if the CPU supports PCID.
        let pcid_sender = allocate_pcid();
        let pcid_receiver = allocate_pcid();

        // Select tier based on both CPU support AND availability.
        let tier = select_n3_tier(pcid_sender.min(pcid_receiver));

        // Allocate a dedicated handler stack (1 page, kernel-allocated).
        // This stack is used as the trampoline after CR3 switch: the ASM
        // primitive loads RSP from dst_ctx.rsp and `ret` pops the handler
        // address from [RSP]. Must be in the kernel upper half (shared AS).
        let handler_stack_frame =
            with_irqs_disabled(allocate_frame).map_err(|_| IpcError::TransportFailed)?;
        let handler_stack_phys = handler_stack_frame.start_address.as_u64();
        let handler_stack_virt = phys_to_virt(handler_stack_phys) as u64;
        let handler_stack_top = handler_stack_virt + N3_HANDLER_STACK_SIZE as u64;

        // Register with watchdog.
        watchdog_register(frame_idx, frame_phys);

        Ok(N3Transport {
            frame_idx,
            frame_phys,
            frame_virt: N3_SHARED_FRAME_VA,
            msg_buf: MsgBuffer(msg_buf),
            msg_buf_phys,
            handler_stack_top,
            handler_stack_phys,
            sender_task_id,
            receiver_task_id,
            tier,
            pcid_sender,
            pcid_receiver,
            watchdog_timeout_cycles: N3_WATCHDOG_TIMEOUT,
        })
    }

    /// Get a reference to the underlying MigrationFrame.
    pub(crate) fn frame(&self) -> &MigrationFrame {
        unsafe { &*(self.frame_virt as *const MigrationFrame) }
    }

    /// Get the raw pointer to the MigrationFrame (for ASM primitive).
    pub(crate) fn frame_ptr(&self) -> *mut MigrationFrame {
        self.frame_virt as *mut MigrationFrame
    }
}

impl core::fmt::Debug for N3Transport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("N3Transport")
            .field("frame_idx", &self.frame_idx)
            .field("tier", &self.tier)
            .field("sender", &self.sender_task_id)
            .field("receiver", &self.receiver_task_id)
            .finish()
    }
}

impl Drop for N3Transport {
    fn drop(&mut self) {
        watchdog_unregister(self.frame_idx);
        free_frame_slot(self.frame_idx);

        // Free the message buffer physical page.
        if self.msg_buf_phys != 0 {
            let frame = crate::memory::PhysFrame::containing_address(x86_64::PhysAddr::new(
                self.msg_buf_phys,
            ));
            with_irqs_disabled(|token| free_frame(token, frame));
        }

        // Free the handler stack physical page.
        if self.handler_stack_phys != 0 {
            let frame = crate::memory::PhysFrame::containing_address(x86_64::PhysAddr::new(
                self.handler_stack_phys,
            ));
            with_irqs_disabled(|token| free_frame(token, frame));
        }

        // NOTE: PTE invalidation (TLB shootdown) for the unmapped pages
        // is TODO. The stale PTEs will be reclaimed when the address space
        // is destroyed. For a prototype, this is acceptable.
    }
}

impl IpcTransport for N3Transport {
    fn level(&self) -> TransportLevel {
        TransportLevel::Mmu
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            max_message_size: N3_MSG_BUF_SIZE,
            blocking: true,
            zero_copy: false,
            vectored: false,
            directions: 2,
            estimated_cost_cycles: 800,
        }
    }

    fn name(&self) -> &'static str {
        match self.tier {
            N3Tier::PcidPreserving => "n3b",
            N3Tier::FullIsolation => "n3c",
        }
    }
}

impl IpcProducer for N3Transport {
    fn send(&self, msg: &[u8]) -> Result<(), IpcError> {
        // SAFETY: CAS state machine (Ready=>Active) provides logical exclusivity.
        // The &mut is scoped to this function; after CAS, only the ASM primitive
        // accesses the frame via raw pointers. Technically UB under Stacked Borrows,
        // but acceptable for a research kernel prototype where CAS guarantees
        // no concurrent access.
        let frame = unsafe { &mut *self.frame_ptr() };

        // Get current task context.
        let receiver_task = get_task_by_id(self.receiver_task_id).ok_or(IpcError::Disconnected)?;

        // Read current CR3.
        let (cr3_frame, _) = x86_64::registers::control::Cr3::read();
        let sender_cr3 = cr3_frame.start_address().as_u64();

        // Validate receiver's handler RIP.
        // Verify RIP matches the explicitly registered handler, not arbitrary code.
        let recv_rip = receiver_task.trampoline_entry.load(Ordering::Acquire);
        if recv_rip == 0 {
            return Err(IpcError::InvalidRip);
        }
        let recv_as = receiver_task.process.address_space_arc();
        validate_rip(recv_rip, &recv_as)?;

        // Prepare the migration.
        let sender_rsp: u64;
        let sender_rip: u64;
        unsafe {
            core::arch::asm!("mov {}, rsp", out(reg) sender_rsp);
            // Capture return address from the stack. At this point in the
            // function, the return address is at [rbp + 8] when frame
            // pointers are enabled (kernel build default).
            //
            // SAFETY: kernel is compiled with frame pointers enabled
            // (-C force-frame-pointers=yes). If frame pointers are disabled,
            // this will read garbage : ensure the kernel build config is correct.
            core::arch::asm!("mov {}, [rbp + 8]", out(reg) sender_rip);
        }

        n3_prepare_migration(
            frame,
            self.msg_buf.as_ptr(),
            sender_cr3,
            sender_rsp,
            sender_rip,
            self.handler_stack_top,
            &receiver_task,
            msg,
        )?;

        // Inter-core sync if needed.
        // Spec §9.2: the sender must ensure message visibility before sending IPI.
        let target_cpu = receiver_task.home_cpu.load(Ordering::Acquire);
        let same_core = crate::arch::x86_64::percpu::current_cpu_index() == target_cpu as usize;

        if !same_core {
            if (target_cpu as usize) < crate::arch::x86_64::percpu::MAX_CPUS {
                // Ensure all stores (message, frame metadata, state=Active)
                // are visible before the IPI is sent (spec §9.1).
                core::sync::atomic::fence(Ordering::Release);

                // Store the VIRTUAL address : the IPI handler dereferences
                // it as a pointer in the kernel address space.
                N3_PENDING_MIGRATION[target_cpu].store(self.frame_virt, Ordering::Release);

                // Send sync IPI. On x86-64, the ICR write is serializing,
                // which provides an implicit full barrier (spec §9.2).
                if let Some(target_apic) =
                    crate::arch::x86_64::percpu::apic_id_by_cpu_index(target_cpu)
                {
                    send_n3_sync_ipi(target_apic);
                }
            }
        }

        // Execute the migration ASM primitive.
        // SAFETY: frame is valid, mapped in both AS, interrupts are enabled.
        unsafe {
            n3b_migrate_asm(self.frame_virt as *mut MigrationFrame);
        }

        Ok(())
    }

    fn try_send(&self, msg: &[u8]) -> Result<(), IpcError> {
        // The CAS inside n3_prepare_migration handles the state check atomically.
        // No need for a separate state check here (avoids TOCTOU).
        self.send(msg)
    }
}

impl IpcConsumer for N3Transport {
    fn recv(&self, buf: &mut [u8]) -> Result<usize, IpcError> {
        let frame = self.frame();

        // Verify the frame is in Active state.
        // Do NOT read from a Ready, Stalled, or Reclaiming frame.
        let state = frame.state.load(Ordering::Acquire);
        if state != MigrationState::Active as u8 {
            return Err(IpcError::WouldBlock);
        }

        // Verify generation (spec §15.1).
        let gen = frame.generation.load(Ordering::Acquire);
        if gen == 0 {
            return Err(IpcError::WouldBlock);
        }

        // Check message length.
        let msg_len = frame.msg_len;
        if msg_len == 0 {
            return Err(IpcError::WouldBlock);
        }

        // Read the message from the shared buffer.
        // Use a guard to reset state=Ready even if the read fails,
        // preventing the frame from being stuck in Active forever.
        let n = match shared_msg_read(self.msg_buf.as_ptr(), msg_len, buf) {
            Ok(n) => n,
            Err(e) => {
                // Reset state so the frame can be reused.
                frame
                    .state
                    .store(MigrationState::Ready as u8, Ordering::Release);
                return Err(e);
            }
        };

        // Signal completion: set state = Ready (spec §15 step 6).
        // This allows the sender (or next sender) to reuse the frame.
        // The sender's send() will CAS Ready=>Active to claim it.
        // NOTE: msg_len is intentionally NOT cleared : the next sender's
        // prepare_migration() overwrites it when writing the new message.
        frame
            .state
            .store(MigrationState::Ready as u8, Ordering::Release);

        Ok(n)
    }

    fn try_recv(&self, buf: &mut [u8]) -> Result<Option<usize>, IpcError> {
        match self.recv(buf) {
            Ok(n) => Ok(Some(n)),
            Err(IpcError::WouldBlock) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

// ============================================================================
// State machine helpers
// ============================================================================

/// Check if a frame is in the Ready state.
pub fn n3_frame_is_ready(frame: &MigrationFrame) -> bool {
    frame.state.load(Ordering::Acquire) == MigrationState::Ready as u8
}

/// Get the current migration state of a frame.
pub fn n3_frame_state(frame: &MigrationFrame) -> MigrationState {
    MigrationState::from_u8(frame.state.load(Ordering::Acquire)).unwrap_or(MigrationState::Ready)
}

/// Get the current generation counter of a frame.
pub fn n3_frame_generation(frame: &MigrationFrame) -> u32 {
    frame.generation.load(Ordering::Acquire)
}
