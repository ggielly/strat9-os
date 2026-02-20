//! TLB (Translation Lookaside Buffer) shootdown for SMP.
//!
//! When page table entries are modified (COW, munmap, etc.), all CPUs must
//! invalidate their TLB entries for the affected virtual addresses. Otherwise,
//! stale TLB entries can lead to data corruption or security vulnerabilities.
//!
//! # Design
//!
//! - Single-page invalidation: `invlpg` instruction + IPI to other CPUs
//! - Range invalidation: multiple `invlpg` or full flush if range is large
//! - Global flush: reload CR3 (expensive, used sparingly)
//!
//! # References
//!
//! - Intel SDM Vol 3A, Chapter 4.10: Caching Translation Information
//! - Linux kernel: arch/x86/mm/tlb.c
//! - xv6 RISC-V: kernel/vm.c (sfence.vma)

use core::sync::atomic::{AtomicU32, Ordering};
use x86_64::VirtAddr;

use crate::sync::SpinLock;

/// IPI vector for TLB shootdown (must be >= 32 and not conflict with other IPIs).
const TLB_SHOOTDOWN_VECTOR: u8 = 0xF0;

/// Maximum number of CPUs we can support.
const MAX_CPUS: usize = 256;

/// Globally shared TLB shootdown request.
static TLB_SHOOTDOWN_REQUEST: SpinLock<TlbShootdownRequest> = SpinLock::new(TlbShootdownRequest {
    kind: TlbShootdownKind::None,
    vaddr_start: 0,
    vaddr_end: 0,
    pending_mask: 0,
});

/// Atomic acknowledgement counter: each CPU increments when it processes the shootdown.
static TLB_ACK_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Expected acknowledgement count (set by the initiating CPU).
static TLB_EXPECTED_ACKS: AtomicU32 = AtomicU32::new(0);

/// Type of TLB shootdown operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlbShootdownKind {
    /// No pending shootdown.
    None,
    /// Invalidate a single page.
    SinglePage,
    /// Invalidate a range of pages.
    Range,
    /// Flush all TLB entries (full CR3 reload).
    Full,
}

/// TLB shootdown request data.
struct TlbShootdownRequest {
    kind: TlbShootdownKind,
    vaddr_start: u64,
    vaddr_end: u64,
    pending_mask: u64, // Bitmask of CPUs that need to acknowledge
}

/// Initialize TLB shootdown system.
///
/// Registers the TLB shootdown IPI handler in the IDT.
/// Must be called during early boot, single-threaded.
pub fn init() {
    // TODO: Register TLB_SHOOTDOWN_VECTOR in IDT to call tlb_shootdown_ipi_handler
    log::debug!("TLB shootdown initialized (vector {:#x})", TLB_SHOOTDOWN_VECTOR);
}

/// Invalidate a single page on all CPUs.
///
/// Sends an IPI to all other CPUs and waits for acknowledgement.
/// The local CPU's TLB is also flushed.
pub fn shootdown_page(vaddr: VirtAddr) {
    if !crate::arch::x86_64::apic::is_initialized() {
        // SMP not active, just flush local TLB.
        unsafe {
            invlpg(vaddr);
        }
        return;
    }

    let num_cpus = crate::arch::x86_64::smp::cpu_count();
    if num_cpus <= 1 {
        // Single-CPU system, no IPI needed.
        unsafe {
            invlpg(vaddr);
        }
        return;
    }

    // Acquire shootdown lock to serialize TLB operations.
    let mut req = TLB_SHOOTDOWN_REQUEST.lock();
    
    // Reset acknowledgement counter.
    TLB_ACK_COUNTER.store(0, Ordering::Release);
    
    // We expect (num_cpus - 1) acknowledgements (all CPUs except ourselves).
    TLB_EXPECTED_ACKS.store((num_cpus - 1) as u32, Ordering::Release);
    
    // Build target mask: all CPUs except the current one.
    let current_apic_id = crate::arch::x86_64::apic::lapic_id();
    let current_cpu_id = crate::arch::x86_64::percpu::cpu_index_by_apic(current_apic_id).unwrap_or(0);
    let mut target_mask: u64 = 0;
    for i in 0..num_cpus {
        if i != current_cpu_id {
            target_mask |= 1u64 << i;
        }
    }
    
    // Set up the shootdown request.
    req.kind = TlbShootdownKind::SinglePage;
    req.vaddr_start = vaddr.as_u64();
    req.vaddr_end = vaddr.as_u64() + 4096;
    req.pending_mask = target_mask;
    
    // Flush local TLB first.
    unsafe {
        invlpg(vaddr);
    }
    
    // Send IPI to all other CPUs.
    broadcast_ipi_except_self(TLB_SHOOTDOWN_VECTOR);
    
    // Wait for all CPUs to acknowledge (with timeout).
    wait_for_acks((num_cpus - 1) as u32);
    
    // Clear the request.
    req.kind = TlbShootdownKind::None;
    drop(req);
    
    log::trace!("TLB shootdown complete for page {:#x}", vaddr.as_u64());
}

/// Invalidate a range of pages on all CPUs.
///
/// If the range is large (> 64 pages), falls back to a full TLB flush.
pub fn shootdown_range(start: VirtAddr, end: VirtAddr) {
    let page_count = (end.as_u64() - start.as_u64()) / 4096;
    
    // For large ranges, full flush is cheaper than many invlpg instructions.
    if page_count > 64 {
        shootdown_all();
        return;
    }
    
    if !crate::arch::x86_64::apic::is_initialized() {
        for i in 0..page_count {
            let addr = start + (i * 4096);
            unsafe {
                invlpg(addr);
            }
        }
        return;
    }
    
    let num_cpus = crate::arch::x86_64::smp::cpu_count();
    if num_cpus <= 1 {
        for i in 0..page_count {
            let addr = start + (i * 4096);
            unsafe {
                invlpg(addr);
            }
        }
        return;
    }
    
    let mut req = TLB_SHOOTDOWN_REQUEST.lock();
    TLB_ACK_COUNTER.store(0, Ordering::Release);
    TLB_EXPECTED_ACKS.store((num_cpus - 1) as u32, Ordering::Release);
    
    let current_apic_id = crate::arch::x86_64::apic::lapic_id();
    let current_cpu_id = crate::arch::x86_64::percpu::cpu_index_by_apic(current_apic_id).unwrap_or(0);
    let mut target_mask: u64 = 0;
    for i in 0..num_cpus {
        if i != current_cpu_id {
            target_mask |= 1u64 << i;
        }
    }
    
    req.kind = TlbShootdownKind::Range;
    req.vaddr_start = start.as_u64();
    req.vaddr_end = end.as_u64();
    req.pending_mask = target_mask;
    
    // Flush local TLB.
    for i in 0..page_count {
        let addr = start + (i * 4096);
        unsafe {
            invlpg(addr);
        }
    }
    
    broadcast_ipi_except_self(TLB_SHOOTDOWN_VECTOR);
    wait_for_acks((num_cpus - 1) as u32);
    
    req.kind = TlbShootdownKind::None;
    drop(req);
    
    log::trace!("TLB shootdown complete for range {:#x}..{:#x}", start.as_u64(), end.as_u64());
}

/// Flush all TLB entries on all CPUs (expensive).
///
/// Used for major page table restructuring or when the range is too large.
pub fn shootdown_all() {
    if !crate::arch::x86_64::apic::is_initialized() {
        unsafe {
            flush_tlb_all();
        }
        return;
    }
    
    let num_cpus = crate::arch::x86_64::smp::cpu_count();
    if num_cpus <= 1 {
        unsafe {
            flush_tlb_all();
        }
        return;
    }
    
    let mut req = TLB_SHOOTDOWN_REQUEST.lock();
    TLB_ACK_COUNTER.store(0, Ordering::Release);
    TLB_EXPECTED_ACKS.store((num_cpus - 1) as u32, Ordering::Release);
    
    let current_apic_id = crate::arch::x86_64::apic::lapic_id();
    let current_cpu_id = crate::arch::x86_64::percpu::cpu_index_by_apic(current_apic_id).unwrap_or(0);
    let mut target_mask: u64 = 0;
    for i in 0..num_cpus {
        if i != current_cpu_id {
            target_mask |= 1u64 << i;
        }
    }
    
    req.kind = TlbShootdownKind::Full;
    req.pending_mask = target_mask;
    
    // Flush local TLB.
    unsafe {
        flush_tlb_all();
    }
    
    broadcast_ipi_except_self(TLB_SHOOTDOWN_VECTOR);
    wait_for_acks((num_cpus - 1) as u32);
    
    req.kind = TlbShootdownKind::None;
    drop(req);
    
    log::trace!("Full TLB shootdown complete");
}

/// IPI handler for TLB shootdown (called on receiving CPU).
///
/// Processes the global shootdown request and increments the acknowledgement counter.
pub fn tlb_shootdown_ipi_handler() {
    let req = TLB_SHOOTDOWN_REQUEST.lock();
    
    match req.kind {
        TlbShootdownKind::None => {
            // Spurious IPI, ignore.
        }
        TlbShootdownKind::SinglePage => {
            let vaddr = VirtAddr::new(req.vaddr_start);
            unsafe {
                invlpg(vaddr);
            }
        }
        TlbShootdownKind::Range => {
            let start = req.vaddr_start;
            let end = req.vaddr_end;
            let page_count = (end - start) / 4096;
            for i in 0..page_count {
                let addr = VirtAddr::new(start + i * 4096);
                unsafe {
                    invlpg(addr);
                }
            }
        }
        TlbShootdownKind::Full => {
            unsafe {
                flush_tlb_all();
            }
        }
    }
    
    drop(req);
    
    // Acknowledge processing.
    TLB_ACK_COUNTER.fetch_add(1, Ordering::SeqCst);
    
    // Send EOI to LAPIC.
    crate::arch::x86_64::apic::eoi();
}

/// Invalidate a single TLB entry (local CPU only).
#[inline]
unsafe fn invlpg(vaddr: VirtAddr) {
    core::arch::asm!("invlpg [{}]", in(reg) vaddr.as_u64(), options(nostack, preserves_flags));
}

/// Flush all TLB entries by reloading CR3 (local CPU only).
#[inline]
unsafe fn flush_tlb_all() {
    use x86_64::registers::control::Cr3;
    let (frame, flags) = Cr3::read();
    Cr3::write(frame, flags);
}

/// Broadcast an IPI to all CPUs except the current one.
fn broadcast_ipi_except_self(vector: u8) {
    // Use APIC shortcuts: destination shorthand 11b = all-excluding-self.
    // ICR format: [63:32] = reserved/destination, [31:0] = vector | delivery mode | level | etc.
    // Shorthand 11b is bits 19-18.
    unsafe {
        let icr_low: u32 = (vector as u32) | (1 << 14) | (3 << 18); // Fixed delivery, all-excluding-self
        crate::arch::x86_64::apic::write_reg(crate::arch::x86_64::apic::REG_ICR_LOW, icr_low);
    }
}

/// Wait for all target CPUs to acknowledge the shootdown.
///
/// Spins with a timeout to avoid deadlock if a CPU is hung.
fn wait_for_acks(expected: u32) {
    const MAX_WAIT_CYCLES: usize = 10_000_000; // ~10ms on a 1GHz CPU
    
    for _ in 0..MAX_WAIT_CYCLES {
        if TLB_ACK_COUNTER.load(Ordering::Acquire) >= expected {
            return;
        }
        core::hint::spin_loop();
    }
    
    // Timeout: log warning but continue (CPU might be dead).
    log::warn!(
        "TLB shootdown timeout: expected {} acks, got {}",
        expected,
        TLB_ACK_COUNTER.load(Ordering::Acquire)
    );
}
