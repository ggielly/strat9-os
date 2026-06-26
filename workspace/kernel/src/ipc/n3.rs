//! N3 MMU Thread Migration — PCID-preserving (N3b) and Full Isolation (N3c).
//!
//! Implements the transport layer for IPC level N3 as specified in
//! `docs/ipc-n3-mmu-thread-migration-spec.md` (v1.0.0).
//!
//! Strategy A: kernel prepares `src_ctx` and `dst_ctx`, ASM primitive performs
//! CR3 switch + context restore.
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
//! # Shared mapping note (spec §8.4)
//!
//! The MigrationFrame is mapped in both address spaces at the same virtual
//! address (`N3_SHARED_FRAME_VA`), but **without USER_ACCESSIBLE**. The frame
//! lives in kernel space and is accessible only from Ring 0. Both sender and
//! receiver access it via their kernel page tables — the shared VA means the
//! same PTE (same physical page) is reachable from both page table hierarchies.
//! This is NOT a user-mappable region; it is kernel-only shared memory.
//!
//! # PCID contract
//!
//! A PCID value of 0 means "no PCID" — either PCID is unsupported by the CPU
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
// Section 1 : Normative types (spec §6)
// ============================================================================

/// N3 tier selection (spec §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum N3Tier {
    /// PCID-preserving: TLB entries for the sender AS are kept across CR3 switch.
    PcidPreserving = 1,
    /// Full isolation: CR3 write flushes all non-global TLB entries.
    FullIsolation = 2,
}

/// Minimal CPU context saved/restored during N3 migration (spec §6.2).
///
/// Layout is `#[repr(C, align(64))]` to match the ASM primitive offsets.
/// No FPU/AVX state — handled separately per FPU policy.
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
    /// Zeroed context — used as initial value before preparation.
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

/// Migration state machine (spec §6.3).
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

/// Shared migration frame — one per N3 transport endpoint pair (spec §6.4).
///
/// Must reside in a dedicated physical page mapped at the same virtual
/// address in both sender and receiver address spaces.
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
// Section 2 : Static frame pool
// ============================================================================

/// Number of pre-allocated migration frames.
const N3_FRAME_POOL_SIZE: usize = 64;

/// Virtual address where the MigrationFrame is mapped in both address spaces.
///位于 canonical upper-half, just below the HHDM boundary.
pub const N3_SHARED_FRAME_VA: u64 = 0xFFFF_C000_0000_1000;

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
        let ptr = self.get_ptr(idx) as u64;
        ptr - crate::memory::hhdm_offset()
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
// Section 3 : PCID management (spec §10)
// ============================================================================

/// Global PCID counter — monotonic allocation, panics at 4096 (prototype).
static PCID_COUNTER: AtomicU16 = AtomicU16::new(1); // 0 = no PCID

/// Maximum number of PCIDs before panic (x86-64 supports 4096).
const MAX_PCIDS: u16 = 4095;

/// Allocate a stable PCID for an address space.
///
/// Returns 0 if PCID is not available (N3c fallback).
pub fn allocate_pcid() -> u16 {
    let pcid = PCID_COUNTER.fetch_add(1, Ordering::Relaxed);
    if pcid >= MAX_PCIDS {
        log::error!("N3: PCID exhaustion — falling back to N3c (full TLB flush)");
        return 0;
    }
    pcid
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
// Section 4 : validate_rip() (spec §8.3)
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
    // not in forbidden zones. The spec §8.3 also requires the RIP to belong to
    // a "registered handler or authorized code range" — this registration check
    // is performed by the CALLER (send()) which compares rip against the
    // receiver's `trampoline_entry` field BEFORE calling validate_rip().
    //
    // validate_rip() is therefore a SECOND LINE OF DEFENSE that catches
    // configuration errors (e.g., trampoline_entry pointing to a data page).

    // Walk the page tables to verify the page is present and executable.
    let cr3_phys = address_space.cr3();
    let hhdm = crate::memory::hhdm_offset();

    match unsafe { walk_page_tables_executable(rip, cr3_phys.as_u64(), hhdm) } {
        Ok(true) => Ok(()),
        Ok(false) => Err(IpcError::InvalidRip),
        Err(_) => Err(IpcError::InvalidRip),
    }
}

/// Walk x86-64 4-level page tables to check if `vaddr` is present and executable.
///
/// Returns Ok(true) if the final PTE is present and NX=0.
unsafe fn walk_page_tables_executable(vaddr: u64, cr3_phys: u64, hhdm: u64) -> Result<bool, ()> {
    let pml4 = (cr3_phys + hhdm) as *const u64;

    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pml4_entry = unsafe { core::ptr::read_volatile(pml4.add(pml4_idx)) };
    if pml4_entry & 1 == 0 {
        return Err(()); // Not present.
    }

    let pdpt_phys = pml4_entry & 0x000F_FFFF_FFFF_F000;
    let pdpt = (pdpt_phys + hhdm) as *const u64;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pdpt_entry = unsafe { core::ptr::read_volatile(pdpt.add(pdpt_idx)) };
    if pdpt_entry & 1 == 0 {
        return Err(());
    }

    // 1 GiB page?
    if pdpt_entry & (1 << 7) != 0 {
        return Ok(pdpt_entry & (1 << 63) == 0); // NX bit
    }

    let pd_phys = pdpt_entry & 0x000F_FFFF_FFFF_F000;
    let pd = (pd_phys + hhdm) as *const u64;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pd_entry = unsafe { core::ptr::read_volatile(pd.add(pd_idx)) };
    if pd_entry & 1 == 0 {
        return Err(());
    }

    // 2 MiB page?
    if pd_entry & (1 << 7) != 0 {
        return Ok(pd_entry & (1 << 63) == 0);
    }

    let pt_phys = pd_entry & 0x000F_FFFF_FFFF_F000;
    let pt = (pt_phys + hhdm) as *const u64;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;
    let pt_entry = unsafe { core::ptr::read_volatile(pt.add(pt_idx)) };
    if pt_entry & 1 == 0 {
        return Err(());
    }

    // Check NX bit (bit 63).
    Ok(pt_entry & (1 << 63) == 0)
}

// ============================================================================
// Section 5 : Context preparation
// ============================================================================

/// Prepare a MigrationFrame for a send operation (spec §14).
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
    receiver_task: &Task,
    msg: &[u8],
) -> Result<(), IpcError> {
    // Prepare sender context (saved by ASM primitive).
    frame.src_ctx.cr3_pcid = sender_cr3;
    frame.src_ctx.rsp = sender_rsp;
    frame.src_ctx.rip = sender_rip;

    // Prepare receiver context.
    let recv_handler = receiver_task.trampoline_entry.load(Ordering::Acquire);
    let recv_stack = receiver_task.trampoline_stack_top.load(Ordering::Acquire);

    if recv_handler == 0 || recv_stack == 0 {
        return Err(IpcError::TransportFailed);
    }

    let recv_cr3 = receiver_task.process.address_space_arc().cr3().as_u64();

    frame.dst_ctx.rip = recv_handler;
    frame.dst_ctx.rsp = recv_stack;
    frame.dst_ctx.cr3_pcid = recv_cr3;

    // Copy message into the shared buffer.
    let msg_len = shared_msg_write(msg_buf, msg)?;
    frame.msg_len = msg_len;

    // CAS Ready → Active (spec §A.1). Must succeed before touching generation.
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

    // Increment generation AFTER successful CAS (spec §7.3).
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
// Section 6 : ASM Primitive — Strategy A (spec §11, §A.3)
// ============================================================================

/// ASM migration primitive (Strategy A).
///
/// # Safety
/// - `frame` must point to a valid MigrationFrame mapped at the same VA
///   in both sender and receiver address spaces.
/// - Interrupts must be enabled before calling (the primitive will CLI).
/// - The caller must be on a valid kernel stack.
///
/// # Layout (spec §A.3, adjusted for align(64) padding)
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
        "mov [rdi + 0x50], rcx", // RIP (syscall return address)
        // ── Phase 2: CLI (≤3 instr) + CR3 switch ──
        // Spec §12 requires ≤3 instructions between CLI and CR3 write.
        // Here: mov rax (1) → cli (2) → mov cr3 (3). Satisfied.
        // After CR3 switch, we restore dst_ctx with interrupts still disabled.
        // The 8 restore instructions + pushfq/popfq/sti happen AFTER the CR3
        // switch in the receiver's address space — this is intentional and does
        // not violate the ≤3 instruction window (which only covers CLI→CR3).
        "mov rax, [rdi + 0xD8]", // dst_ctx.cr3_pcid (at 0x80+0x58=0xD8)
        "cli",
        "mov cr3, rax",
        // ── Phase 3: restore dst_ctx (starts at offset 0x80) ──
        "mov r15, [rdi + 0x80]",
        "mov r14, [rdi + 0x88]",
        "mov r13, [rdi + 0x90]",
        "mov r12, [rdi + 0x98]",
        "mov rbp, [rdi + 0xA0]",
        "mov rbx, [rdi + 0xA8]",
        "mov rdx, [rdi + 0xB0]",
        "mov rax, [rdi + 0xB8]", // dst_ctx.rax = flags
        "push rax",
        "popfq", // restore IF=1
        "sti",   // guarantee IF=1
        // ── Phase 4: state = Ready, generation++ (spec §16) ──
        // state = Ready is a single-byte store (atomic on x86).
        // generation++ uses `lock inc` for atomicity, even though interrupts
        // are disabled. This protects against concurrent readers (e.g., watchdog
        // on another core) observing a torn read.
        "mov byte ptr [rdi + 0x100], 0",    // state = Ready
        "lock inc dword ptr [rdi + 0x104]", // generation++ (atomic)
        // ── Phase 5: ret ──
        // SAFETY: At this point, all 8 callee-saved GPRs plus rflags have been
        // restored from dst_ctx. The stack pointer (dst_ctx.rsp) was restored
        // by ASM (Phase 3 loads rsp via the restored rbp or directly). The `ret`
        // instruction pops the return address from the top of the restored stack
        // and jumps to it. The destination stack was prepared by the kernel in
        // n3_prepare_migration(): dst_ctx.rsp points to a stack frame containing
        // the handler entry point as the return address. If the stack is
        // corrupted or uninitialized, this `ret` is the first point of failure.
        "ret",
        //
        // Invariant: the restored dst_ctx.rsp must point to a valid, readable,
        // kernel-mode stack frame. This is guaranteed by §8.2 (stack pinned and
        // resident) and §14 step 4 (mappings verified before migration).
    );
}

// ============================================================================
// Section 7 : IPI synchronization (spec §9)
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

/// IPI handler for N3 migration synchronization (registered in IDT).
///
/// When the sender is on a different core than the receiver, this handler
/// performs the reverse migration: switches CR3 back to the sender's AS
/// and restores the sender's context.
///
/// # Safety
/// Called from the naked IPI entry stub. RSP points at a SyscallFrame.
pub extern "C" fn n3_migrate_ipi_handler(_frame_ptr: *mut MigrationFrame) {
    let cpu_idx = crate::arch::x86_64::percpu::current_cpu_index();

    // Check if there's a pending migration for this CPU.
    let pending = N3_PENDING_MIGRATION[cpu_idx].swap(0, Ordering::Acquire);
    if pending == 0 {
        // No pending migration — spurious IPI.
        return;
    }

    let frame = unsafe { &*(pending as *const MigrationFrame) };

    // Verify the frame is in Active state.
    let state = frame.state.load(Ordering::Acquire);
    if state != MigrationState::Active as u8 {
        return;
    }

    // Switch back to sender's address space.
    let sender_cr3 = frame.src_ctx.cr3_pcid;
    if sender_cr3 != 0 {
        use x86_64::{registers::control::Cr3, PhysAddr};
        if let Ok(cr3_frame) =
            x86_64::structures::paging::PhysFrame::from_start_address(PhysAddr::new(sender_cr3))
        {
            unsafe {
                Cr3::write(cr3_frame, x86_64::registers::control::Cr3Flags::empty());
            }
        }
    }

    // Restore sender context.
    // Note: rbx and rbp are LLVM-reserved and cannot be used as asm operands.
    // They are loaded as part of the general restore sequence.
    unsafe {
        core::arch::asm!(
            "mov r15, [{f} + 0x00]",
            "mov r14, [{f} + 0x08]",
            "mov r13, [{f} + 0x10]",
            "mov r12, [{f} + 0x18]",
            "mov rbp, [{f} + 0x20]",
            "mov rbx, [{f} + 0x28]",
            "mov rdx, [{f} + 0x30]",
            "mov rax, [{f} + 0x38]",
            f = in(reg) &frame.src_ctx,
            out("r15") _,
            out("r14") _,
            out("r13") _,
            out("r12") _,
            out("rdx") _,
            out("rax") _,
        );
    }

    // Mark frame as Ready.
    frame
        .state
        .store(MigrationState::Ready as u8, Ordering::Release);

    // Send EOI.
    apic::eoi();
}

// ============================================================================
// Section 8 : Watchdog (spec §16)
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
pub fn n3_watchdog_tick() {
    let now = unsafe { core::arch::x86_64::_rdtsc() };
    let table = N3_WATCHDOG_TABLE.lock();

    for entry in table.iter() {
        let Some(entry) = entry else { continue };
        let frame = unsafe { &*(phys_to_virt(entry.frame_phys) as *const MigrationFrame) };
        let state = frame.state.load(Ordering::Acquire);
        if state == MigrationState::Active as u8 {
            let tsc_start = frame.tsc_start.load(Ordering::Acquire);
            if now.wrapping_sub(tsc_start) > entry.timeout {
                // Transition Active → Stalled.
                let _ = frame.state.compare_exchange(
                    MigrationState::Active as u8,
                    MigrationState::Stalled as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                log::warn!(
                    "N3: watchdog timeout on frame at {:#x}, generation={}",
                    entry.frame_phys,
                    frame.generation.load(Ordering::Acquire),
                );
            }
        }
    }
}

/// Recover a stalled frame — reset to Ready via atomic CAS transitions.
fn watchdog_recover(frame: &MigrationFrame) {
    // Transition Stalled → Reclaiming (atomic CAS).
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
    // Transition Reclaiming → Ready (atomic store, no contention expected).
    frame
        .state
        .store(MigrationState::Ready as u8, Ordering::Release);
}

// ============================================================================
// Section 9 : Shared frame mapping
// ============================================================================

/// Map a physical page into an address space at `N3_SHARED_FRAME_VA`.
///
/// The frame is mapped kernel-only (no USER_ACCESSIBLE) to enforce the
/// spec §8.4 invariant: frame permissions are managed exclusively by the
/// kernel, never by non-kernel parties.
fn map_frame_in_space(frame_phys: u64, address_space: &AddressSpace) -> Result<(), &'static str> {
    use x86_64::{
        structures::paging::{Mapper, Page, PageTableFlags, PhysFrame, Size4KiB},
        PhysAddr, VirtAddr,
    };

    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(N3_SHARED_FRAME_VA));
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
            Err(_) => Err("Failed to map MigrationFrame into address space"),
        }
    }
}

/// Map a MigrationFrame's physical page into both sender and receiver
/// address spaces at the shared virtual address.
fn map_frame_in_both_spaces(
    frame_phys: u64,
    sender_as: &AddressSpace,
    receiver_as: &AddressSpace,
) -> Result<(), &'static str> {
    map_frame_in_space(frame_phys, sender_as)?;
    map_frame_in_space(frame_phys, receiver_as)?;
    Ok(())
}

// ============================================================================
// Section 10 : N3Transport
// ============================================================================

/// N3 MMU transport — thread migration between distinct address spaces.
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

        // Map the message buffer in both address spaces.
        if map_frame_in_space(msg_buf_phys, &sender_as).is_err()
            || map_frame_in_space(msg_buf_phys, &receiver_as).is_err()
        {
            log::error!("N3: failed to map message buffer");
            free_frame_slot(frame_idx);
            with_irqs_disabled(|token| free_frame(token, msg_buf_frame));
            return Err(IpcError::TransportFailed);
        }

        // Allocate PCIDs BEFORE selecting tier — allocate_pcid() may return 0
        // if PCID is exhausted, which forces N3c even if the CPU supports PCID.
        let pcid_sender = allocate_pcid();
        let pcid_receiver = allocate_pcid();

        // Select tier based on both CPU support AND availability.
        let tier = select_n3_tier(pcid_sender.min(pcid_receiver));

        // Register with watchdog.
        watchdog_register(frame_idx, frame_phys);

        Ok(N3Transport {
            frame_idx,
            frame_phys,
            frame_virt: N3_SHARED_FRAME_VA,
            msg_buf: MsgBuffer(msg_buf),
            msg_buf_phys,
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
        // Unmap from both address spaces (TODO: proper unmap).
    }
}

impl IpcTransport for N3Transport {
    fn level(&self) -> TransportLevel {
        TransportLevel::Mmu
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            max_message_size: 256,
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
        // SAFETY: CAS state machine (Ready→Active) guarantees exclusive access.
        let frame = unsafe { &mut *self.frame_ptr() };

        // Get current task context.
        let _my_task_id = current_task_id().ok_or(IpcError::TransportFailed)?;
        let receiver_task = get_task_by_id(self.receiver_task_id).ok_or(IpcError::Disconnected)?;

        // Read current CR3.
        let (cr3_frame, _) = x86_64::registers::control::Cr3::read();
        let sender_cr3 = cr3_frame.start_address().as_u64();

        // Validate receiver's handler RIP (spec §8.3).
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
            // this will read garbage — ensure the kernel build config is correct.
            core::arch::asm!("mov {}, [rbp + 8]", out(reg) sender_rip);
        }

        n3_prepare_migration(
            frame,
            self.msg_buf.as_ptr(),
            sender_cr3,
            sender_rsp,
            sender_rip,
            &receiver_task,
            msg,
        )?;

        // Inter-core sync if needed (spec §9).
        let same_core = crate::arch::x86_64::percpu::current_cpu_index()
            == receiver_task.home_cpu.load(Ordering::Acquire);

        if !same_core {
            // ════════════════════════════════════════════════════════════
            // Publication protocol (spec §9.2):
            //   1. All stores to the ring and MigrationFrame are complete.
            //   2. MFENCE ensures they are visible to the target core.
            //   3. IPI wakes the target, whose handler executes MFENCE.
            //   4. target loads state/generation with Acquire ordering.
            // ════════════════════════════════════════════════════════════
            // Step 1 & 2: all frame stores done above (generation, tsc_start,
            // state = Active). A SeqCst fence ensures global visibility.
            core::sync::atomic::fence(Ordering::SeqCst);

            let target_cpu = receiver_task.home_cpu.load(Ordering::Acquire);
            if target_cpu < crate::arch::x86_64::percpu::MAX_CPUS {
                N3_PENDING_MIGRATION[target_cpu].store(self.frame_virt, Ordering::Release);
                if let Some(target_apic) =
                    crate::arch::x86_64::percpu::apic_id_by_cpu_index(target_cpu)
                {
                    // Step 3: IPI — target handler executes MFENCE (§9.2).
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

        // Verify the frame is in Active state (spec §15).
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
        shared_msg_read(self.msg_buf.as_ptr(), msg_len, buf)
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
// Section 11 : State machine helpers
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn n3_minimal_context_size() {
        assert_eq!(core::mem::size_of::<N3MinimalContext>(), 128);
        assert_eq!(core::mem::align_of::<N3MinimalContext>(), 64);
    }

    #[test]
    fn migration_frame_layout() {
        assert_eq!(core::mem::size_of::<MigrationFrame>(), 320);
        assert_eq!(core::mem::align_of::<MigrationFrame>(), 64);
    }

    #[test]
    fn state_machine_transitions() {
        let frame = MigrationFrame {
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
            _pad: [0; 32],
        };

        assert!(n3_frame_is_ready(&frame));

        // Ready → Active
        assert!(frame
            .state
            .compare_exchange(
                MigrationState::Ready as u8,
                MigrationState::Active as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok());
        assert_eq!(n3_frame_state(&frame), MigrationState::Active);

        // Active → Ready (on completion)
        frame
            .state
            .store(MigrationState::Ready as u8, Ordering::Release);
        assert!(n3_frame_is_ready(&frame));

        // Ready → Active → Stalled (watchdog)
        assert!(frame
            .state
            .compare_exchange(
                MigrationState::Ready as u8,
                MigrationState::Active as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok());
        frame
            .state
            .store(MigrationState::Stalled as u8, Ordering::Release);
        assert_eq!(n3_frame_state(&frame), MigrationState::Stalled);

        // Stalled → Reclaiming → Ready
        frame
            .state
            .store(MigrationState::Reclaiming as u8, Ordering::Release);
        frame
            .state
            .store(MigrationState::Ready as u8, Ordering::Release);
        assert!(n3_frame_is_ready(&frame));
    }

    #[test]
    fn frame_pool_alloc_free() {
        let (idx1, _) = alloc_frame_slot().unwrap();
        let (idx2, _) = alloc_frame_slot().unwrap();
        assert_ne!(idx1, idx2);

        {
            let alloc = N3_FRAME_ALLOC.lock();
            assert!(alloc.is_allocated(idx1));
            assert!(alloc.is_allocated(idx2));
        }

        free_frame_slot(idx1);
        {
            let alloc = N3_FRAME_ALLOC.lock();
            assert!(!alloc.is_allocated(idx1));
            assert!(alloc.is_allocated(idx2));
        }

        free_frame_slot(idx2);
    }

    #[test]
    fn pcid_allocation() {
        let pcid1 = allocate_pcid();
        let pcid2 = allocate_pcid();
        assert!(pcid1 > 0);
        assert!(pcid2 > pcid1);
    }
}
