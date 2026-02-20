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
use alloc::vec::Vec;
use x86_64::VirtAddr;

use crate::sync::SpinLock;

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
    super::idt::register_tlb_shootdown_handler(tlb_shootdown_ipi_handler);
    log::debug!("TLB shootdown initialized (vector {:#x})", crate::arch::x86_64::apic::IPI_TLB_SHOOTDOWN_VECTOR);
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

    let targets = collect_tlb_targets();
    if targets.is_empty() {
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
    
    // We expect acknowledgements only from CPUs that are online and TLB-ready.
    TLB_EXPECTED_ACKS.store(targets.len() as u32, Ordering::Release);

    let mut target_mask: u64 = 0;
    for i in 0..crate::arch::x86_64::percpu::MAX_CPUS {
        if crate::arch::x86_64::percpu::tlb_ready(i) {
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

    // Release request lock before sending IPIs and waiting for ACKs.
    drop(req);

    // Send IPI only to target CPUs.
    for apic_id in targets.iter().copied() {
        send_tlb_ipi(apic_id);
    }

    // Wait for all target CPUs to acknowledge (with timeout).
    wait_for_acks(targets.len() as u32);

    // Clear the request.
    let mut req = TLB_SHOOTDOWN_REQUEST.lock();
    req.kind = TlbShootdownKind::None;
    req.pending_mask = 0;
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
    
    let targets = collect_tlb_targets();
    if targets.is_empty() {
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
    TLB_EXPECTED_ACKS.store(targets.len() as u32, Ordering::Release);

    let mut target_mask: u64 = 0;
    for i in 0..crate::arch::x86_64::percpu::MAX_CPUS {
        if crate::arch::x86_64::percpu::tlb_ready(i) {
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
    
    // Release request lock before sending IPIs and waiting for ACKs.
    drop(req);

    for apic_id in targets.iter().copied() {
        send_tlb_ipi(apic_id);
    }
    wait_for_acks(targets.len() as u32);

    let mut req = TLB_SHOOTDOWN_REQUEST.lock();
    req.kind = TlbShootdownKind::None;
    req.pending_mask = 0;
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
    
    let targets = collect_tlb_targets();
    if targets.is_empty() {
        unsafe {
            flush_tlb_all();
        }
        return;
    }
    
    let mut req = TLB_SHOOTDOWN_REQUEST.lock();
    TLB_ACK_COUNTER.store(0, Ordering::Release);
    TLB_EXPECTED_ACKS.store(targets.len() as u32, Ordering::Release);

    let mut target_mask: u64 = 0;
    for i in 0..crate::arch::x86_64::percpu::MAX_CPUS {
        if crate::arch::x86_64::percpu::tlb_ready(i) {
            target_mask |= 1u64 << i;
        }
    }
    
    req.kind = TlbShootdownKind::Full;
    req.pending_mask = target_mask;
    
    // Flush local TLB.
    unsafe {
        flush_tlb_all();
    }
    
    // Release request lock before sending IPIs and waiting for ACKs.
    drop(req);

    for apic_id in targets.iter().copied() {
        send_tlb_ipi(apic_id);
    }
    wait_for_acks(targets.len() as u32);

    let mut req = TLB_SHOOTDOWN_REQUEST.lock();
    req.kind = TlbShootdownKind::None;
    req.pending_mask = 0;
    drop(req);
    
    log::trace!("Full TLB shootdown complete");
}

/// IPI handler for TLB shootdown (called on receiving CPU).
///
/// Processes the global shootdown request and increments the acknowledgement counter.
pub extern "C" fn tlb_shootdown_ipi_handler() {
    let mut should_ack = false;
    if let Some(req) = TLB_SHOOTDOWN_REQUEST.try_lock() {
        match req.kind {
            TlbShootdownKind::None => {
                // Spurious IPI, ignore.
            }
            TlbShootdownKind::SinglePage => {
                let vaddr = VirtAddr::new(req.vaddr_start);
                unsafe {
                    invlpg(vaddr);
                }
                should_ack = true;
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
                should_ack = true;
            }
            TlbShootdownKind::Full => {
                unsafe {
                    flush_tlb_all();
                }
                should_ack = true;
            }
        }
        drop(req);
    } else {
        // Hardened fallback: if request lock is contended, perform a full local
        // flush and ACK. This avoids deadlocks/timeouts during bring-up races.
        unsafe {
            flush_tlb_all();
        }
        should_ack = true;
    }

    // Acknowledge only real shootdown requests.
    if should_ack {
        TLB_ACK_COUNTER.fetch_add(1, Ordering::SeqCst);
    }
    
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

fn send_tlb_ipi(target_apic_id: u32) {
    // SAFETY: APIC base is valid and mapped; ICR MMIO is 32-bit aligned.
    unsafe {
        crate::arch::x86_64::apic::write_reg(crate::arch::x86_64::apic::REG_ESR, 0);
        crate::arch::x86_64::apic::write_reg(crate::arch::x86_64::apic::REG_ICR_HIGH, target_apic_id << 24);
        let icr_low = crate::arch::x86_64::apic::IPI_TLB_SHOOTDOWN_VECTOR as u32 | (1 << 14);
        crate::arch::x86_64::apic::write_reg(crate::arch::x86_64::apic::REG_ICR_LOW, icr_low);
    }
}

fn collect_tlb_targets() -> Vec<u32> {
    let current_apic_id = crate::arch::x86_64::apic::lapic_id();
    let mut targets = Vec::new();
    for cpu_idx in 0..crate::arch::x86_64::percpu::MAX_CPUS {
        if !crate::arch::x86_64::percpu::tlb_ready(cpu_idx) {
            continue;
        }
        let Some(apic_id) = crate::arch::x86_64::percpu::apic_id_by_cpu_index(cpu_idx) else {
            continue;
        };
        if apic_id != current_apic_id {
            targets.push(apic_id);
        }
    }
    targets
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
